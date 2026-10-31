"""
nmap_import.py - Read-only nmap output ingest & next-module direction engine for IoTFlux
Authorized Security Assessment & Conformance Validation Framework

Parses nmap XML (-oX), greppable (-oG), or normal (-oN) scan output and maps each
open port/service to suggested IoTFlux validation / discovery modules with ready
CLI commands. Performs NO network actions -- file/stdin parsing only.
"""

from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from iotflux.core.logger import logger


# ---------------------------------------------------------------------------
# Port / service -> module direction map (general guidance)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ModuleDirection:
    module: str
    reason: str
    command_template: str  # uses {target} and optional {authorize_flag}


# Exact TCP port mappings
PORT_DIRECTIONS: Dict[int, List[ModuleDirection]] = {
    80: [
        ModuleDirection(
            module="validation/web_cloud_auditor",
            reason="HTTP management / embedded web console surface",
            command_template="python -m iotflux validate validation/web_cloud_auditor --target {target}{authorize_flag}",
        ),
    ],
    443: [
        ModuleDirection(
            module="validation/web_cloud_auditor",
            reason="HTTPS management / embedded web console surface",
            command_template="python -m iotflux validate validation/web_cloud_auditor --target {target} --port 443{authorize_flag}",
        ),
    ],
    8080: [
        ModuleDirection(
            module="validation/web_cloud_auditor",
            reason="Alternate HTTP management port",
            command_template="python -m iotflux validate validation/web_cloud_auditor --target {target} --port 8080{authorize_flag}",
        ),
    ],
    8443: [
        ModuleDirection(
            module="validation/web_cloud_auditor",
            reason="Alternate HTTPS management port",
            command_template="python -m iotflux validate validation/web_cloud_auditor --target {target} --port 8443{authorize_flag}",
        ),
    ],
    554: [
        ModuleDirection(
            module="validation/camera_auditor",
            reason="RTSP video stream (RFC 2326) -- check unauthenticated playback",
            command_template="python -m iotflux validate validation/camera_auditor --target {target}{authorize_flag}",
        ),
    ],
    8554: [
        ModuleDirection(
            module="validation/camera_auditor",
            reason="Alternate RTSP port -- check unauthenticated playback",
            command_template="python -m iotflux validate validation/camera_auditor --target {target}{authorize_flag}",
        ),
    ],
    1883: [
        ModuleDirection(
            module="validation/mqtt_telemetry_checker",
            reason="MQTT broker -- anonymous CONNECT / cleartext telemetry risk",
            command_template="python -m iotflux validate validation/mqtt_telemetry_checker --target {target}{authorize_flag}",
        ),
    ],
    8883: [
        ModuleDirection(
            module="validation/mqtt_telemetry_checker",
            reason="MQTT over TLS broker surface",
            command_template="python -m iotflux validate validation/mqtt_telemetry_checker --target {target} --port 8883{authorize_flag}",
        ),
    ],
    502: [
        ModuleDirection(
            module="validation/modbus_auditor",
            reason="Modbus TCP supervisory control surface",
            command_template="python -m iotflux validate validation/modbus_auditor --target {target}{authorize_flag}",
        ),
    ],
    7547: [
        ModuleDirection(
            module="validation/tr069_auditor",
            reason="CWMP / TR-069 remote management (ACS) -- CWE-306 / CVE-2016-10372 risk class",
            command_template="python -m iotflux validate validation/tr069_auditor --target {target}{authorize_flag}",
        ),
    ],
    1900: [
        ModuleDirection(
            module="discovery/upnp_scanner",
            reason="SSDP / UPnP discovery surface",
            command_template="python -m iotflux validate discovery/upnp_scanner --target {target}{authorize_flag}",
        ),
    ],
    5683: [
        ModuleDirection(
            module="discovery/coap_scanner",
            reason="CoAP IoT application protocol",
            command_template="python -m iotflux validate discovery/coap_scanner --target {target}{authorize_flag}",
        ),
    ],
    5353: [
        ModuleDirection(
            module="discovery/mdns_scanner",
            reason="mDNS / DNS-SD responder surface",
            command_template="python -m iotflux validate discovery/mdns_scanner --target {target}{authorize_flag}",
        ),
    ],
}

# High-numbered vendor proprietary cloud/control channels commonly seen on cameras
PROPRIETARY_CLOUD_PORTS = {56789, 56790, 34567, 34599, 10001}


def _proprietary_direction(port: int) -> ModuleDirection:
    return ModuleDirection(
        module="(manual) banner / TLS fingerprint",
        reason=(
            f"Unknown/proprietary high port {port} -- often vendor cloud/control or media "
            "tunnel (e.g. JOOAN/CAM720-class). No dedicated IoTFlux module yet; "
            "fingerprint with nmap -sV / openssl s_client / nc banner grab."
        ),
        command_template=(
            "nmap -Pn -sV --version-intensity 9 -p {port} {target}"
            "  # then consider adding validation/cloud_tunnel_profiler"
        ).replace("{port}", str(port)),
    )


def directions_for_port(port: int, service_name: str = "") -> List[ModuleDirection]:
    """Return suggested module directions for an open TCP port."""
    dirs = list(PORT_DIRECTIONS.get(port, []))
    svc = (service_name or "").lower()

    # Service-name fallbacks when port is non-standard
    if not dirs:
        if "rtsp" in svc:
            dirs.append(
                ModuleDirection(
                    module="validation/camera_auditor",
                    reason=f"Service fingerprint '{service_name}' suggests RTSP",
                    command_template="python -m iotflux validate validation/camera_auditor --target {target}{authorize_flag}",
                )
            )
        elif svc in ("http", "https", "http-proxy", "http-alt"):
            dirs.append(
                ModuleDirection(
                    module="validation/web_cloud_auditor",
                    reason=f"Service fingerprint '{service_name}' suggests HTTP(S)",
                    command_template="python -m iotflux validate validation/web_cloud_auditor --target {target} --port {port}{authorize_flag}".replace(
                        "{port}", str(port)
                    ),
                )
            )
        elif "mqtt" in svc:
            dirs.append(
                ModuleDirection(
                    module="validation/mqtt_telemetry_checker",
                    reason=f"Service fingerprint '{service_name}' suggests MQTT",
                    command_template="python -m iotflux validate validation/mqtt_telemetry_checker --target {target} --port {port}{authorize_flag}".replace(
                        "{port}", str(port)
                    ),
                )
            )
        elif svc in ("cwmp", "tr-069", "tr069") or "cwmp" in svc:
            dirs.append(
                ModuleDirection(
                    module="validation/tr069_auditor",
                    reason=f"Service fingerprint '{service_name}' suggests CWMP/TR-069",
                    command_template="python -m iotflux validate validation/tr069_auditor --target {target}{authorize_flag}",
                )
            )
        elif "modbus" in svc:
            dirs.append(
                ModuleDirection(
                    module="validation/modbus_auditor",
                    reason=f"Service fingerprint '{service_name}' suggests Modbus",
                    command_template="python -m iotflux validate validation/modbus_auditor --target {target}{authorize_flag}",
                )
            )

    if port in PROPRIETARY_CLOUD_PORTS or (not dirs and port >= 49152):
        dirs.append(_proprietary_direction(port))

    if not dirs:
        dirs.append(
            ModuleDirection(
                module="(manual) service identification",
                reason=f"No IoTFlux module mapped for TCP/{port} ({service_name or 'unknown'}). Identify with nmap -sV.",
                command_template=f"nmap -Pn -sV -p {port} {{target}}",
            )
        )
    return dirs


# ---------------------------------------------------------------------------
# Parsed structures
# ---------------------------------------------------------------------------

@dataclass
class OpenPort:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""


@dataclass
class HostInventory:
    address: str
    hostname: str = ""
    open_ports: List[OpenPort] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _parse_xml(text: str) -> List[HostInventory]:
    root = ET.fromstring(text)
    hosts: List[HostInventory] = []
    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is not None and status.get("state", "up") not in ("up", "unknown"):
            continue
        addr = ""
        for a in host_el.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6") or not addr:
                if a.get("addrtype") == "ipv4":
                    addr = a.get("addr", "")
                    break
                if not addr:
                    addr = a.get("addr", "")
        if not addr:
            continue
        hostname = ""
        hnames = host_el.find("hostnames")
        if hnames is not None:
            hn = hnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "") or ""
        ports: List[OpenPort] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                state_el = p.find("state")
                state = state_el.get("state", "") if state_el is not None else ""
                if state != "open":
                    continue
                svc_el = p.find("service")
                ports.append(
                    OpenPort(
                        port=int(p.get("portid", "0")),
                        protocol=p.get("protocol", "tcp"),
                        state=state,
                        service=(svc_el.get("name", "") if svc_el is not None else ""),
                        product=(svc_el.get("product", "") if svc_el is not None else ""),
                        version=(svc_el.get("version", "") if svc_el is not None else ""),
                        extrainfo=(svc_el.get("extrainfo", "") if svc_el is not None else ""),
                    )
                )
        hosts.append(HostInventory(address=addr, hostname=hostname, open_ports=ports))
    return hosts


_GREP_HOST_RE = re.compile(
    r"Host:\s+(\S+)\s+\(([^)]*)\)\s+Status:\s+(\S+)",
    re.IGNORECASE,
)
_GREP_PORTS_RE = re.compile(
    r"Host:\s+(\S+)\s+\(([^)]*)\)\s+Ports:\s+(.*?)(?:\tIgnored|\tSeq|\s*$)",
    re.IGNORECASE,
)


def _parse_greppable(text: str) -> List[HostInventory]:
    """Parse nmap -oG greppable output."""
    by_addr: Dict[str, HostInventory] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m_host = _GREP_HOST_RE.search(line)
        if m_host and "Ports:" not in line:
            addr, hostname, status = m_host.group(1), m_host.group(2), m_host.group(3)
            if status.lower() != "up":
                continue
            by_addr.setdefault(addr, HostInventory(address=addr, hostname=hostname))
            continue
        m_ports = _GREP_PORTS_RE.search(line)
        if not m_ports:
            # Fallback: Host: x.x.x.x () Ports: ...
            if line.startswith("Host:") and "Ports:" in line:
                parts = line.split("Ports:", 1)
                host_part = parts[0]
                addr_m = re.search(r"Host:\s+(\S+)", host_part)
                hn_m = re.search(r"\(([^)]*)\)", host_part)
                if not addr_m:
                    continue
                addr = addr_m.group(1)
                hostname = hn_m.group(1) if hn_m else ""
                port_blob = parts[1].split("Ignored")[0].split("Seq")[0]
            else:
                continue
        else:
            addr, hostname, port_blob = m_ports.group(1), m_ports.group(2), m_ports.group(3)

        inv = by_addr.setdefault(addr, HostInventory(address=addr, hostname=hostname))
        if hostname and not inv.hostname:
            inv.hostname = hostname
        for entry in port_blob.split(","):
            entry = entry.strip()
            if not entry:
                continue
            # format: 80/open/tcp//http/// or 80/open/tcp/syn-ack/http//
            fields = entry.split("/")
            if len(fields) < 3:
                continue
            try:
                port_num = int(fields[0])
            except ValueError:
                continue
            state = fields[1]
            proto = fields[2]
            if state != "open":
                continue
            service = fields[4] if len(fields) > 4 else ""
            inv.open_ports.append(
                OpenPort(port=port_num, protocol=proto or "tcp", state=state, service=service)
            )
    return list(by_addr.values())


_NORMAL_HOST_RE = re.compile(
    r"^Nmap scan report for (?:(\S+) \((\d+\.\d+\.\d+\.\d+)\)|(\d+\.\d+\.\d+\.\d+))$"
)
_NORMAL_PORT_RE = re.compile(
    r"^(\d+)(/tcp|/udp)\s+(open)\s+(\S+)(?:\s+(.*))?$",
    re.IGNORECASE,
)


def _parse_normal(text: str) -> List[HostInventory]:
    """Parse nmap -oN normal text output (best-effort)."""
    hosts: List[HostInventory] = []
    current: Optional[HostInventory] = None
    for raw in text.splitlines():
        line = raw.rstrip()
        m_host = _NORMAL_HOST_RE.match(line.lstrip("\ufeff"))
        if m_host:
            # Groups: (hostname, ip_in_parens) OR (bare_ip,)
            if m_host.group(3):
                hostname, addr = "", m_host.group(3)
            else:
                hostname, addr = (m_host.group(1) or ""), m_host.group(2)
            current = HostInventory(address=addr, hostname=hostname)
            hosts.append(current)
            continue
        if current is None:
            continue
        m_port = _NORMAL_PORT_RE.match(line.strip())
        if m_port:
            port_num = int(m_port.group(1))
            proto = m_port.group(2).lstrip("/")
            state = m_port.group(3).lower()
            service = m_port.group(4) or ""
            version = (m_port.group(5) or "").strip()
            current.open_ports.append(
                OpenPort(
                    port=port_num,
                    protocol=proto,
                    state=state,
                    service=service,
                    product=version,
                )
            )
    return hosts


def detect_and_parse(text: str) -> Tuple[str, List[HostInventory]]:
    """
    Auto-detect nmap format and parse.
    Returns (format_label, hosts).
    """
    text = text.lstrip("\ufeff")
    stripped = text.lstrip()
    if not stripped.strip():
        return "empty", []

    if stripped.startswith("<?xml") or "<nmaprun" in stripped[:500]:
        return "xml", _parse_xml(text)

    # Greppable lines typically start with Host: or comment #
    sample_lines = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if sample_lines and all(
        ln.startswith("Host:") or ln.startswith("#") for ln in text.splitlines() if ln.strip()
    ):
        return "greppable", _parse_greppable(text)
    if any(ln.startswith("Host:") and "Ports:" in ln for ln in sample_lines):
        return "greppable", _parse_greppable(text)

    if "Nmap scan report for" in text or "PORT" in text and "STATE" in text:
        return "normal", _parse_normal(text)

    # Last resorts
    if "<host" in text and "<port" in text:
        return "xml", _parse_xml(text)
    if any(ln.startswith("Host:") for ln in sample_lines):
        return "greppable", _parse_greppable(text)

    return "unknown", _parse_normal(text)


# ---------------------------------------------------------------------------
# Scope helper (read-only check -- does not open sockets)
# ---------------------------------------------------------------------------

def host_needs_authorize(ip: str) -> bool:
    """
    Returns True when the host is outside configured assessment scope, so
    suggested commands should include --authorize.
    Fail-open to True (suggest --authorize) if scope config is missing/unreadable
    so operators are not steered into a scope violation.
    """
    try:
        from iotflux.core.scope_validator import (
            evaluate_target_against_config,
            load_scope_config,
        )

        cfg = load_scope_config()
        if not cfg.allowed_subnets:
            # Also try YAML scope if present
            from pathlib import Path as _P
            from iotflux.core.scope_manager import DEFAULT_ASSESSMENT_SCOPE_PATH, ScopeManager

            if DEFAULT_ASSESSMENT_SCOPE_PATH.exists():
                mgr = ScopeManager(DEFAULT_ASSESSMENT_SCOPE_PATH)
                is_allowed, _, _, _ = mgr.evaluate_target(ip)
                return not is_allowed
            return True
        is_allowed, _, _, _ = evaluate_target_against_config(ip, cfg)
        return not is_allowed
    except Exception:
        try:
            from iotflux.core.scope_manager import DEFAULT_ASSESSMENT_SCOPE_PATH, ScopeManager

            if DEFAULT_ASSESSMENT_SCOPE_PATH.exists():
                mgr = ScopeManager(DEFAULT_ASSESSMENT_SCOPE_PATH)
                is_allowed, _, _, _ = mgr.evaluate_target(ip)
                return not is_allowed
        except Exception:
            pass
        return True


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

@dataclass
class SuggestedAction:
    port: int
    service: str
    module: str
    reason: str
    command: str


@dataclass
class HostPlan:
    address: str
    hostname: str
    out_of_scope: bool
    open_ports: List[Dict[str, Any]]
    suggestions: List[SuggestedAction]


def build_host_plan(host: HostInventory) -> HostPlan:
    oos = host_needs_authorize(host.address)
    auth_flag = " --authorize" if oos else ""
    suggestions: List[SuggestedAction] = []
    seen_cmds: set[str] = set()

    for op in sorted(host.open_ports, key=lambda p: p.port):
        if op.protocol and op.protocol.lower() not in ("tcp", ""):
            # UDP guidance is limited; still note proprietary/known if mapped
            pass
        for direction in directions_for_port(op.port, op.service):
            cmd = direction.command_template.format(
                target=host.address,
                authorize_flag=auth_flag,
            )
            # Proprietary templates may not use authorize_flag
            if oos and "--authorize" not in cmd and cmd.startswith("python -m iotflux"):
                cmd = cmd + " --authorize"
            if cmd in seen_cmds:
                continue
            seen_cmds.add(cmd)
            suggestions.append(
                SuggestedAction(
                    port=op.port,
                    service=op.service or op.product or "",
                    module=direction.module,
                    reason=direction.reason,
                    command=cmd,
                )
            )

    return HostPlan(
        address=host.address,
        hostname=host.hostname,
        out_of_scope=oos,
        open_ports=[
            {
                "port": op.port,
                "protocol": op.protocol,
                "state": op.state,
                "service": op.service,
                "product": op.product,
                "version": op.version,
            }
            for op in sorted(host.open_ports, key=lambda p: p.port)
        ],
        suggestions=suggestions,
    )


def format_text_report(fmt: str, plans: List[HostPlan]) -> str:
    lines: List[str] = []
    lines.append("=" * 76)
    lines.append("  IOTFLUX NMAP IMPORT -- NEXT-MODULE DIRECTION")
    lines.append("=" * 76)
    lines.append(f"  Source format : {fmt}")
    lines.append(f"  Hosts parsed  : {len(plans)}")
    lines.append("  Mode          : read-only file parse (no network actions)")
    lines.append("")

    if not plans:
        lines.append("  No hosts with open ports found in the provided nmap output.")
        lines.append("")
        return "\n".join(lines)

    for plan in plans:
        scope_tag = "OUT-OF-SCOPE (suggested commands include --authorize)" if plan.out_of_scope else "IN-SCOPE"
        title = plan.address
        if plan.hostname:
            title = f"{plan.hostname} ({plan.address})"
        lines.append("-" * 76)
        lines.append(f"  Host : {title}")
        lines.append(f"  Scope: {scope_tag}")
        if not plan.open_ports:
            lines.append("  Open ports: (none)")
            lines.append("")
            continue

        lines.append("  Open ports:")
        for op in plan.open_ports:
            svc = op["service"] or "?"
            prod = f" ({op['product']} {op['version']})".rstrip() if op.get("product") or op.get("version") else ""
            lines.append(f"    - {op['port']}/{op['protocol']}  {svc}{prod}")

        lines.append("")
        lines.append("  Suggested IoTFlux next steps:")
        if not plan.suggestions:
            lines.append("    (no mapped modules)")
        for idx, sug in enumerate(plan.suggestions, 1):
            lines.append(f"    {idx}. [{sug.port}/{sug.service or 'unknown'}] -> {sug.module}")
            lines.append(f"       Why : {sug.reason}")
            lines.append(f"       Cmd : {sug.command}")
        lines.append("")

    lines.append("=" * 76)
    lines.append("  Tip: re-run nmap with -oX camera.xml for richest ingest, e.g.")
    lines.append("       nmap -Pn -p- -oX camera.xml <ip>")
    lines.append("       python -m iotflux nmap-import camera.xml")
    lines.append("=" * 76)
    return "\n".join(lines)


def plans_to_json(fmt: str, plans: List[HostPlan]) -> str:
    payload = {
        "format": fmt,
        "mode": "read-only-parse",
        "hosts": [
            {
                "address": p.address,
                "hostname": p.hostname,
                "out_of_scope": p.out_of_scope,
                "open_ports": p.open_ports,
                "suggestions": [asdict(s) for s in p.suggestions],
            }
            for p in plans
        ],
    }
    return json.dumps(payload, indent=2)


def load_nmap_text(path: Optional[str]) -> str:
    """Load nmap output from a file path, or stdin when path is None / '-'."""
    if path is None or path == "-":
        if sys.stdin.isatty():
            raise ValueError(
                "No input file given and stdin is a TTY. "
                "Pass an nmap -oX/-oG/-oN file path, or pipe nmap output via stdin."
            )
        return sys.stdin.read()
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"nmap output file not found: {p}")
    return p.read_text(encoding="utf-8-sig", errors="replace")


def run_nmap_import(
    path: Optional[str] = None,
    as_json: bool = False,
) -> int:
    """
    CLI entry helper. Returns process exit code.
    """
    try:
        text = load_nmap_text(path)
    except (ValueError, FileNotFoundError) as exc:
        logger.failure(str(exc))
        return 1

    fmt, hosts = detect_and_parse(text)
    if fmt == "empty":
        logger.failure("nmap input was empty.")
        return 1
    if fmt == "unknown" and not hosts:
        logger.failure(
            "Could not detect nmap XML (-oX), greppable (-oG), or normal (-oN) format "
            "in the provided input."
        )
        return 1

    # Drop hosts with zero open ports from the actionable plan (still countable)
    plans = [build_host_plan(h) for h in hosts]
    logger.info(
        f"Parsed nmap {fmt} output: {len(hosts)} host(s), "
        f"{sum(len(h.open_ports) for h in hosts)} open port(s). Building module directions..."
    )

    if as_json:
        print(plans_to_json(fmt, plans))
    else:
        print(format_text_report(fmt, plans))
    return 0
