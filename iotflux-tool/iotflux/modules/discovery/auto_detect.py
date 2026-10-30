"""
auto_detect.py - Environment-Agnostic IoT Service Discovery Engine for IoTFlux
Authorized Security Assessment & Conformance Validation Framework

Performs strictly read-only enumeration across authorized assessment segments:
1. Runtime LPM CIDR scope enforcement via core/scope_manager.py (assessment_scope.yaml)
   and core/scope_validator.py (lab-scope.env).
2. mDNS/SSDP/UPnP discovery across user-specified interfaces (--interface).
3. Rate-limited TCP port reachability probing bounded by max_concurrent_probes and probe_timeout_seconds.
4. Read-only HTTP banner extraction (/rpc/Shelly.GetInfo, /api/version, /rootDesc.xml, /device/info).
5. Read-only MQTT broker detection via anonymous CONNECT/CONNACK header probe (no subscription/publish).
6. Outputs structured inventory to assessment_targets.json (or discovered_devices.json):
   {device_id, ip_address, mac_address, open_ports, service_fingerprints, detected_protocol, network_segment}
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import re
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from iotflux.core.audit_log import audit_trail
from iotflux.core.logger import logger
from iotflux.core.scope_manager import DEFAULT_ASSESSMENT_SCOPE_PATH, ScopeManager
from iotflux.core.scope_validator import (
    LabScopeViolationError,
    ScopeViolationError,
    enforce_docker_lab_scope,
    expand_scoped_targets,
    is_scope_dry_run,
    load_scope_config,
    validate_target_ip,
)
from iotflux.core.session import FluxSession
from iotflux.modules.base import BaseValidationModule, ValidationFinding


STANDARD_DISCOVERY_PORTS = (80, 443, 1883, 554, 8080)

# Thread-visible authorize flag so nested probe helpers honor --authorize
_ACTIVE_AUTHORIZE_OVERRIDE = False

METADATA_PROBES = (
    "/rpc/Shelly.GetInfo",
    "/rpc/Shelly.GetDeviceInfo",
    "/api/version",
    "/rootDesc.xml",
    "/device/info",
)


def _default_scoped_subnet() -> str:
    """Derives the default discovery subnet dynamically from assessment_scope.yaml or lab-scope.env."""
    if DEFAULT_ASSESSMENT_SCOPE_PATH.exists():
        try:
            mgr = ScopeManager(DEFAULT_ASSESSMENT_SCOPE_PATH)
            if mgr.config.allowed_networks:
                first = mgr.config.allowed_networks[0].network
                return f"{first.network_address}/24" if first.prefixlen < 24 else str(first)
        except Exception:
            pass
    cfg = load_scope_config()
    if cfg.allowed_subnets:
        first = cfg.allowed_subnets[0]
        if first.prefixlen < 24:
            return f"{first.network_address}/24"
        return str(first)
    return "0.0.0.0/32"


def _authorized_validate_target_ip(ip: str, env_path=None) -> bool:
    """validate_target_ip that honors the active --authorize override."""
    return validate_target_ip(
        ip,
        env_path=env_path,
        authorize_override=_ACTIVE_AUTHORIZE_OVERRIDE,
    )


def generate_device_id_from_mac_or_seed(mac_address: Optional[str], ip_address: str, fingerprint_seed: str = "") -> str:
    """
    Generates a deterministic, unique device_id based on the MAC address hash
    (or hardware fingerprint seed if L2 MAC is unavailable). Never uses hardcoded vendor names.
    """
    normalized_mac = (mac_address or "").strip().upper()
    if normalized_mac and normalized_mac != "UNKNOWN":
        basis = normalized_mac.encode("utf-8")
    else:
        basis = f"iotflux-node:{ip_address}:{fingerprint_seed}".encode("utf-8")
    digest = hashlib.sha256(basis).hexdigest()[:10]
    return f"dev_{digest}"


def probe_mdns_ssdp_fingerprints(
    ip: str,
    timeout: float = 0.5,
    interface_ip: Optional[str] = None,
) -> Dict[str, str]:
    """
    Performs read-only SSDP/UPnP unicast M-SEARCH and mDNS service inquiry
    across user-specified interfaces after validating target IP against active scope.
    """
    _authorized_validate_target_ip(ip)
    if is_scope_dry_run():
        return {}

    hints: Dict[str, str] = {}
    ssdp_req = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {ip}:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode("utf-8")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        if interface_ip and interface_ip not in ("0.0.0.0", "any", "default"):
            sock.bind((interface_ip, 0))
        sock.sendto(ssdp_req, (ip, 1900))
        data, _ = sock.recvfrom(2048)
        text = data.decode("utf-8", errors="replace")
        for line in text.splitlines():
            low = line.lower()
            if low.startswith("server:"):
                hints["ssdp_server"] = line.split(":", 1)[1].strip()
            elif low.startswith("st:"):
                hints["ssdp_service_type"] = line.split(":", 1)[1].strip()
            elif low.startswith("location:"):
                hints["upnp_location"] = line.split(":", 1)[1].strip()
    except Exception:
        pass
    finally:
        sock.close()
    return hints


def check_tcp_port(ip: str, port: int, timeout: float = 0.4) -> bool:
    """Read-only TCP reachability check gated by runtime scope validation."""
    _authorized_validate_target_ip(ip)
    if is_scope_dry_run():
        return False

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        sock.close()


def probe_mqtt_connect_readonly(ip: str, port: int = 1883, timeout: float = 1.0) -> Dict[str, Any]:
    """
    Performs a strictly read-only MQTT v3.1.1 anonymous CONNECT probe to detect MQTT brokers
    and inspect the CONNACK return code without subscribing or publishing to any topics.
    Immediately sends DISCONNECT after receiving CONNACK.
    """
    _authorized_validate_target_ip(ip)
    if is_scope_dry_run():
        return {}

    # Fixed MQTT v3.1.1 CONNECT packet with CleanSession=1, KeepAlive=10s, ClientID='flux'
    connect_pkt = b"\x10\x10\x00\x04MQTT\x04\x02\x00\x0a\x00\x04flux"
    disconnect_pkt = b"\xe0\x00"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((ip, port)) != 0:
            return {}
        sock.sendall(connect_pkt)
        resp = sock.recv(4)
        try:
            sock.sendall(disconnect_pkt)
        except Exception:
            pass

        if len(resp) >= 4 and (resp[0] & 0xF0) == 0x20:
            return_code = resp[3]
            return {
                "mqtt_broker_detected": True,
                "mqtt_connack_code": return_code,
                "mqtt_anonymous_allowed": return_code == 0,
                "service_type": "MQTT Broker",
            }
    except Exception:
        pass
    finally:
        sock.close()
    return {}


def grab_http_metadata(ip: str, port: int, timeout: float = 1.0) -> Dict[str, Any]:
    """
    Executes strictly read-only HTTP GET requests against standard IoT device metadata endpoints
    (/rpc/Shelly.GetInfo, /rpc/Shelly.GetDeviceInfo, /api/version, /rootDesc.xml, /device/info)
    after verifying target IP scope via validate_target_ip().
    """
    _authorized_validate_target_ip(ip)
    if is_scope_dry_run():
        return {}

    metadata: Dict[str, Any] = {}
    scheme = "https" if port == 443 else "http"

    for path in METADATA_PROBES:
        url = f"{scheme}://{ip}:{port}{path}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "IoTFlux-AssessmentInventory/3.0", "Accept": "application/json, text/xml, */*"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                server_hdr = resp.headers.get("Server", "")
                if server_hdr:
                    metadata["http_server"] = server_hdr
                if resp.status != 200:
                    continue
                body = resp.read(4096).decode("utf-8", errors="replace").strip()
                if not body:
                    continue

                if body.startswith("{"):
                    try:
                        parsed = json.loads(body)
                        payload = parsed.get("result", parsed) if isinstance(parsed, dict) else {}
                        if isinstance(payload, dict):
                            metadata["endpoint"] = path
                            for key in ("id", "mac", "model", "app", "ver", "fw_id", "version", "vendor", "device_type", "hardware"):
                                if key in payload and payload[key] is not None:
                                    metadata[key] = payload[key]
                            if "Shelly" in path or "shelly" in str(payload).lower():
                                metadata["service_type"] = "Shelly RPC"
                            elif path == "/device/info":
                                metadata["service_type"] = "IoT Device Info API"
                            elif "version" in payload:
                                metadata["service_type"] = "REST API"
                            break
                    except Exception:
                        pass
                elif "<root" in body or "urn:schemas-upnp-org" in body:
                    metadata["endpoint"] = path
                    metadata["service_type"] = "UPnP IGD"
                    m_match = re.search(r"<manufacturer>([^<]+)</manufacturer>", body, re.IGNORECASE)
                    mdl_match = re.search(r"<modelName>([^<]+)</modelName>", body, re.IGNORECASE)
                    if m_match:
                        metadata["vendor"] = m_match.group(1).strip()
                    if mdl_match:
                        metadata["model"] = mdl_match.group(1).strip()
                    break
        except Exception:
            continue

    return metadata


def classify_device_services(open_ports: List[int], fingerprints: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """
    Maps open ports and banner metadata to high-level service labels and protocol identifiers.
    """
    services: List[str] = []
    protocols: List[str] = []

    svc_hint = fingerprints.get("service_type", "")
    if svc_hint:
        services.append(svc_hint)

    if 80 in open_ports or 8080 in open_ports or 443 in open_ports:
        protocols.append("http")
        if "Shelly RPC" not in services and "UPnP IGD" not in services and "IoT Device Info API" not in services:
            services.append("HTTP Management / REST API")

    if 1883 in open_ports:
        protocols.append("mqtt")
        if "MQTT Broker" not in services:
            services.append("MQTT Broker")

    if 554 in open_ports:
        protocols.append("rtsp")
        services.append("RTSP Stream")

    if not protocols:
        protocols.append("tcp")

    return services, protocols


class AutoDetectScanner(BaseValidationModule):
    """
    Environment-Agnostic IoT Service Discovery Engine.
    Validates target ranges against assessment_scope.yaml (or lab-scope.env) and exports
    structured inventory to assessment_targets.json / discovered_devices.json.
    """

    name = "discovery/auto_detect"
    description = "Environment-agnostic read-only IoT discovery (mDNS/SSDP/UPnP, TCP, HTTP, MQTT CONNECT probe)."
    tier = "Field Assessment & Dynamic Integration"
    references = ["CWE-306", "SHELLY-RPC-2.0", "MQTT-5.0-SEC", "RFC-2326-RTSP"]
    author = "Defensive Security Research Team"

    def __init__(
        self,
        port_check_fn: Optional[Callable[[str, int, float], bool]] = None,
        metadata_fn: Optional[Callable[[str, int, float], Dict[str, Any]]] = None,
        mdns_ssdp_fn: Optional[Callable[..., Dict[str, str]]] = None,
        mqtt_probe_fn: Optional[Callable[[str, int, float], Dict[str, Any]]] = None,
        scope_env_path: Optional[str | Path] = None,
        scope_yaml_path: Optional[str | Path] = None,
    ) -> None:
        super().__init__()
        self._port_check_fn = port_check_fn or check_tcp_port
        self._metadata_fn = metadata_fn or grab_http_metadata
        self._mdns_ssdp_fn = mdns_ssdp_fn or probe_mdns_ssdp_fingerprints
        self._mqtt_probe_fn = mqtt_probe_fn or probe_mqtt_connect_readonly
        self._scope_env_path = scope_env_path
        self._scope_yaml_path = scope_yaml_path
        self._authorize_override = False

        default_subnet = _default_scoped_subnet()
        self.register_option("SUBNET", default_subnet, "Authorized target range CIDR or IP (--target-range)")
        self.register_option("INTERFACE", "default", "Network interface IP for mDNS/SSDP/UPnP binding")
        self.register_option("PORTS", "80,443,1883,554,8080", "Comma-separated TCP ports for service enumeration")
        self.register_option("OUTPUT_FILE", "assessment_targets.json", "Output JSON path for discovered targets")
        self.register_option("SCOPE_CONFIG", "assessment_scope.yaml", "Path to assessment_scope.yaml")
        self.register_option("TIMEOUT", 0.5, "Per-socket connection timeout in seconds")

    def _probe_single_host(
        self,
        ip: str,
        ports: Tuple[int, ...],
        timeout: float,
        interface_ip: Optional[str],
        scope_mgr: Optional[ScopeManager],
        env_file: Optional[str | Path],
    ) -> Optional[Dict[str, Any]]:
        if scope_mgr is not None:
            scope_mgr.validate_target(ip)
        else:
            validate_target_ip(
                ip,
                env_path=env_file,
                authorize_override=self._authorize_override or _ACTIVE_AUTHORIZE_OVERRIDE,
            )

        open_ports: List[int] = []
        for p in ports:
            if self._port_check_fn(ip, p, timeout):
                open_ports.append(p)

        if not open_ports:
            return None

        fingerprints: Dict[str, Any] = {}
        try:
            discovery_hints = self._mdns_ssdp_fn(ip, timeout, interface_ip)
        except TypeError:
            discovery_hints = self._mdns_ssdp_fn(ip, timeout)
        if discovery_hints:
            fingerprints.update(discovery_hints)

        for web_port in (80, 8080, 443):
            if web_port in open_ports:
                meta = self._metadata_fn(ip, web_port, timeout)
                if meta:
                    fingerprints.update(meta)
                    break

        if 1883 in open_ports:
            mqtt_meta = self._mqtt_probe_fn(ip, 1883, timeout)
            if mqtt_meta:
                fingerprints.update(mqtt_meta)

        services, protocols = classify_device_services(open_ports, fingerprints)
        fingerprints["detected_services"] = services

        mac_addr = str(fingerprints.get("mac", "UNKNOWN"))
        seed_str = f"{open_ports}:{fingerprints.get('model', '')}:{fingerprints.get('service_type', '')}"
        device_id = generate_device_id_from_mac_or_seed(mac_addr, ip, seed_str)
        network_segment = (
            scope_mgr.get_network_segment(ip)
            if scope_mgr is not None
            else f"Scoped Segment ({ip})"
        )

        return {
            "device_id": device_id,
            "ip_address": ip,
            "mac_address": mac_addr,
            "open_ports": open_ports,
            "service_fingerprints": fingerprints,
            "detected_protocol": protocols[0] if len(protocols) == 1 else protocols,
            "protocols": protocols,
            "network_segment": network_segment,
            "interface": interface_ip or "default",
            "discovered_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    def discover_network(
        self,
        subnet_or_ip: Optional[str] = None,
        ports: Tuple[int, ...] = STANDARD_DISCOVERY_PORTS,
        timeout: Optional[float] = None,
        output_file: Optional[str | Path] = None,
        scope_env_path: Optional[str | Path] = None,
        scope_yaml_path: Optional[str | Path] = None,
        interface_ip: Optional[str] = None,
        override_safety: bool = False,
        authorize_override: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Executes rate-limited, read-only service enumeration across the validated target range
        and writes the structured inventory to output_file (e.g. assessment_targets.json).
        Pass authorize_override=True (--authorize) to assess an out-of-scope target
        (SCOPE_OVERRIDE_AUTHORIZED). Does not enable state changes.
        """
        global _ACTIVE_AUTHORIZE_OVERRIDE
        # --authorize and --override-safety are mutual aliases for scope override purposes
        effective_authorize = bool(authorize_override or override_safety)
        self._authorize_override = effective_authorize
        _ACTIVE_AUTHORIZE_OVERRIDE = effective_authorize
        # Also mirror into session so any validate_target_ip session-fallback path works
        if effective_authorize:
            try:
                from iotflux.core.session import session as _sess
                _sess.set_option("AUTHORIZE", True)
            except Exception:
                pass

        env_file = scope_env_path or self._scope_env_path
        yaml_file = Path(scope_yaml_path or self._scope_yaml_path) if (scope_yaml_path or self._scope_yaml_path) else None

        scope_mgr: Optional[ScopeManager] = None
        if yaml_file and yaml_file.exists() and env_file is None:
            scope_mgr = ScopeManager(
                config_path=yaml_file,
                override_safety=override_safety,
                authorize_override=effective_authorize,
            )

        target_spec = subnet_or_ip or _default_scoped_subnet()
        if scope_mgr is not None:
            target_ips = scope_mgr.expand_target_range(target_spec)
            effective_timeout = timeout if timeout is not None else scope_mgr.config.probe_timeout_seconds
            max_workers = max(1, min(scope_mgr.config.max_concurrent_probes, len(target_ips) or 1))
            dry_run = scope_mgr.config.validation_mode == "dry-run"
        else:
            target_ips = expand_scoped_targets(
                target_spec,
                env_path=env_file,
                authorize_override=effective_authorize,
            )
            effective_timeout = timeout if timeout is not None else 0.5
            max_workers = 1
            dry_run = is_scope_dry_run(env_path=env_file)

        discovered: List[Dict[str, Any]] = []

        if dry_run:
            logger.info(
                f"[DRY-RUN] Scope validated for {target_spec} ({len(target_ips)} host(s)). "
                "Skipping live network socket probes because validation_mode=dry-run."
            )
            audit_trail.log_event(
                event_type="DEVICE_DISCOVERY_DRY_RUN",
                action="auto_detect_inventory",
                details={
                    "target_scope": target_spec,
                    "hosts_validated": len(target_ips),
                    "dry_run": True,
                },
                scope_file=yaml_file,
                targets_file=output_file,
            )
            return discovered

        logger.info(
            f"Starting read-only inventory enumeration across {len(target_ips)} address(es) "
            f"in {target_spec} (ports: {list(ports)}, concurrency: {max_workers}, timeout: {effective_timeout}s)..."
        )

        if max_workers == 1 or len(target_ips) <= 1:
            for ip in target_ips:
                rec = self._probe_single_host(ip, ports, effective_timeout, interface_ip, scope_mgr, env_file)
                if rec is not None:
                    discovered.append(rec)
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = [
                    pool.submit(self._probe_single_host, ip, ports, effective_timeout, interface_ip, scope_mgr, env_file)
                    for ip in target_ips
                ]
                for fut in futures:
                    rec = fut.result()
                    if rec is not None:
                        discovered.append(rec)

        inventory_json = json.dumps(discovered, indent=2)
        out_path: Optional[Path] = Path(output_file) if output_file else None
        if out_path is not None:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(inventory_json, encoding="utf-8")
            logger.success(f"Discovery complete. Saved {len(discovered)} target(s) to {out_path}.")
        else:
            print(inventory_json)
            logger.success(f"Discovery complete. {len(discovered)} target(s) (stdout).")

        audit_trail.log_event(
            event_type="DEVICE_DISCOVERY",
            action="auto_detect_lab_inventory",
            details={
                "target_scope": target_spec,
                "interface": interface_ip or "default",
                "hosts_scanned": len(target_ips),
                "devices_discovered": len(discovered),
                "output_file": str(out_path) if out_path else "stdout",
                "device_ids": [d["device_id"] for d in discovered],
            },
            scope_file=yaml_file,
            targets_file=out_path if out_path else "assessment_targets.json",
        )

        _ACTIVE_AUTHORIZE_OVERRIDE = False
        return discovered

    def run(self, session: FluxSession) -> List[ValidationFinding]:
        self.findings.clear()
        subnet = str(self.get_option("SUBNET", session) or _default_scoped_subnet())
        mod_target = str(self.get_option("TARGET", None) or "").strip()
        if mod_target:
            subnet = mod_target
        elif session and session.get_option("TARGET"):
            sess_target = str(session.get_option("TARGET")).strip()
            if sess_target and sess_target != "127.0.0.1":
                subnet = sess_target

        ports_raw = str(self.get_option("PORTS", session) or "80,443,1883,554,8080")
        ports = tuple(int(p.strip()) for p in ports_raw.split(",") if p.strip().isdigit())
        output_file = str(self.get_option("OUTPUT_FILE", session) or "assessment_targets.json")
        timeout = float(self.get_option("TIMEOUT", session) or 0.5)
        interface_ip = str(self.get_option("INTERFACE", session) or "default")
        scope_cfg = str(self.get_option("SCOPE_CONFIG", session) or "")

        try:
            devices = self.discover_network(
                subnet_or_ip=subnet,
                ports=ports,
                timeout=timeout,
                output_file=output_file,
                scope_yaml_path=scope_cfg if scope_cfg and Path(scope_cfg).exists() else None,
                interface_ip=interface_ip,
            )
        except ScopeViolationError as exc:
            logger.failure(str(exc))
            self.add_finding(
                finding_id="DISCOVERY-SCOPE-REJECTED",
                target=subnet,
                title="Discovery Target Rejected by Runtime Assessment Scope Validator",
                spec_id="CWE-306",
                cwe="CWE-284",
                status="COMPLIANT",
                details=str(exc),
                remediation="Inspect active scope rules via 'iotflux scope validate --config assessment_scope.yaml'.",
            )
            return self.findings

        for dev in devices:
            self.add_finding(
                finding_id=f"INVENTORY-{dev['device_id'].upper()}",
                target=dev["ip_address"],
                title=f"Target Inventoried: {dev['device_id']} ({', '.join(dev['protocols'])}) [{dev['network_segment']}]",
                spec_id="SHELLY-RPC-2.0" if "Shelly RPC" in dev["service_fingerprints"].get("detected_services", []) else "CWE-306",
                cwe="CWE-200",
                status="INFORMATIONAL",
                details=(
                    f"Discovered active node at {dev['ip_address']} ({dev['network_segment']}) "
                    f"with open TCP ports {dev['open_ports']}. "
                    f"Detected services: {dev['service_fingerprints'].get('detected_services', [])}."
                ),
                remediation="Generate a baseline YAML profile via 'iotflux profile generate' and verify authorization.",
                evidence=dev,
            )

        return self.findings
