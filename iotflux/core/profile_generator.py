"""
profile_generator.py - Dynamic Device Profile Generation Engine for IoTFlux
Authorized Defensive Security Validation Lab

Converts discovered_devices.json inventory records into schema-validated YAML
device profiles in profiles/auto_generated/:
1. Maps detected services to predefined capability templates (Shelly RPC -> http_endpoints,
   MQTT Broker -> mqtt_broker, RTSP Stream -> rtsp_endpoints, UPnP IGD -> upnp_endpoints).
2. Generates deterministic device_id hashes from MAC address / hardware fingerprint.
3. Enforces default-deny authorization (authorized: false) unless explicitly listed in lab_whitelist.txt.
4. Leaves credential fields empty by default; requires manual operator entry via 'profiles set-creds'.
5. Validates profile schema before disk persistence and logs events to audit_log.json.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import yaml

from iotflux.core.audit_log import audit_trail
from iotflux.core.logger import logger
from iotflux.core.profiles import DeviceProfile, load_profile


CAPABILITY_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "Shelly RPC": {
        "http": {
            "base_url": "http://{ip}",
            "state_changing_endpoints": [
                {
                    "path": "/rpc/Shelly.GetDeviceInfo",
                    "method": "GET",
                    "expect_auth": True,
                    "description": "Shelly Gen2+ device metadata & authentication posture endpoint",
                },
                {
                    "path": "/rpc/Switch.Set?id=0&on=true",
                    "method": "GET",
                    "expect_auth": True,
                    "description": "Shelly Gen2+ bounded relay actuation endpoint",
                },
            ],
        },
        "flagged_ports": [
            {
                "port": 80,
                "reason": "Local HTTP JSON-RPC control interface exposed",
                "damage_score": {"physical_safety": 2, "privacy": 1, "availability": 1},
            }
        ],
    },
    "MQTT Broker": {
        "mqtt": {
            "topic_prefix": "#",
            "expected_tls": True,
            "broker_port": 1883,
            "credentials_to_test": [],
        },
        "flagged_ports": [
            {
                "port": 1883,
                "reason": "Unencrypted MQTT telemetry broker port exposed",
                "damage_score": {"privacy": 2, "chaining_depth": 2, "availability": 1},
            }
        ],
    },
    "RTSP Stream": {
        "rtsp": {
            "port": 554,
            "endpoints": [
                {"path": "/stream1", "expect_auth": True, "description": "Primary H.264 RTSP video stream"},
                {"path": "/live/ch0", "expect_auth": True, "description": "Secondary RTSP media channel"},
            ],
        },
        "flagged_ports": [
            {
                "port": 554,
                "reason": "RTSP video streaming port exposed",
                "damage_score": {"privacy": 3, "availability": 1},
            }
        ],
    },
    "UPnP IGD": {
        "http": {
            "base_url": "http://{ip}:5000",
            "state_changing_endpoints": [
                {
                    "path": "/rootDesc.xml",
                    "method": "GET",
                    "expect_auth": False,
                    "description": "UPnP root device descriptor",
                }
            ],
        },
        "flagged_ports": [
            {
                "port": 5000,
                "reason": "UPnP IGD service descriptor port",
                "damage_score": {"chaining_depth": 2, "availability": 1},
            }
        ],
    },
    "HTTP Management / REST API": {
        "http": {
            "base_url": "http://{ip}",
            "state_changing_endpoints": [
                {
                    "path": "/api/version",
                    "method": "GET",
                    "expect_auth": True,
                    "description": "Embedded REST API version & status endpoint",
                }
            ],
        },
        "flagged_ports": [
            {
                "port": 80,
                "reason": "Embedded HTTP management console",
                "damage_score": {"privacy": 1, "availability": 1},
            }
        ],
    },
}


REQUIRED_PROFILE_KEYS = {"device_id", "vendor", "model", "protocols", "authorized", "network", "credentials"}


class ProfileSchemaValidationError(ValueError):
    """Raised when a generated profile dictionary fails schema validation."""


class SafetyLimitValidationError(ValueError):
    """Raised when device safety_limits fail datasheet-derived bounds validation."""


def validate_device_safety_limits(limits: Any) -> Dict[str, Any]:
    """
    Validates device safety limits:
    - limits must be a dictionary mapping.
    - 'max_pulse': must be 'N/A' (case-insensitive) or duration <= 2.0s (e.g. '2.0s', '1.5s', 2.0).
    - 'auto_revert': must be a non-empty string defining the deterministic baseline revert action.
    """
    if not isinstance(limits, dict):
        raise SafetyLimitValidationError("safety_limits must be a dictionary mapping.")

    if "max_pulse" not in limits:
        raise SafetyLimitValidationError("safety_limits missing required 'max_pulse' definition.")
    if "auto_revert" not in limits or not str(limits["auto_revert"]).strip():
        raise SafetyLimitValidationError("safety_limits missing required non-empty 'auto_revert' mechanism.")

    max_pulse_raw = limits["max_pulse"]
    if isinstance(max_pulse_raw, (int, float)):
        pulse_val = float(max_pulse_raw)
        if pulse_val > 2.0:
            raise SafetyLimitValidationError(
                f"max_pulse duration {pulse_val}s exceeds strict 2.0s hardware safety bound."
            )
        if pulse_val < 0:
            raise SafetyLimitValidationError(f"max_pulse cannot be negative: {pulse_val}")
    elif isinstance(max_pulse_raw, str):
        pulse_str = max_pulse_raw.strip().lower()
        if pulse_str != "n/a":
            if pulse_str.endswith("s"):
                val_part = pulse_str[:-1].strip()
            else:
                val_part = pulse_str
            try:
                pulse_val = float(val_part)
            except ValueError:
                raise SafetyLimitValidationError(
                    f"max_pulse '{max_pulse_raw}' is invalid; must be numeric duration <= 2.0s or 'N/A'."
                )
            if pulse_val > 2.0:
                raise SafetyLimitValidationError(
                    f"max_pulse duration {pulse_val}s exceeds strict 2.0s hardware safety bound."
                )
            if pulse_val < 0:
                raise SafetyLimitValidationError(f"max_pulse cannot be negative: {pulse_val}")
    else:
        raise SafetyLimitValidationError(
            f"max_pulse '{max_pulse_raw}' must be a duration string (e.g., '2.0s') or 'N/A'."
        )

    return limits


def load_authorized_devices_registry(registry_path: Optional[str | Path] = None) -> Dict[str, Dict[str, Any]]:
    """
    Loads authorized devices registry from authorized_devices.yaml or authorized_devices.txt.
    Returns mapping of lowercase IP/device_id -> device record (with safety_limits, role, zone).
    """
    candidates = []
    if registry_path:
        candidates.append(Path(registry_path))
    candidates.extend([Path("authorized_devices.yaml"), Path("authorized_devices.txt")])

    for p in candidates:
        if p.exists():
            try:
                data = yaml.safe_load(p.read_text(encoding="utf-8"))
                if isinstance(data, dict) and "authorized_devices" in data:
                    registry: Dict[str, Dict[str, Any]] = {}
                    for item in data["authorized_devices"]:
                        if isinstance(item, dict):
                            ip = str(item.get("ip", "")).strip().lower()
                            dev_id = str(item.get("device_id", "")).strip().lower()
                            if ip:
                                registry[ip] = item
                            if dev_id:
                                registry[dev_id] = item
                    return registry
            except Exception as ex:
                logger.warning(f"Failed parsing authorized devices registry {p}: {ex}")
    return {}


def load_lab_whitelist(whitelist_path: str | Path = "lab_whitelist.txt") -> Set[str]:
    """
    Loads explicitly authorized device IDs, IP addresses, or MAC addresses from lab_whitelist.txt.
    Lines starting with '#' or empty lines are ignored.
    """
    path = Path(whitelist_path)
    if not path.exists():
        return set()
    entries: Set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        cleaned = line.split("#", 1)[0].strip()
        if cleaned:
            entries.add(cleaned.lower())
    return entries


def compute_mac_device_id(mac_address: Optional[str], ip_address: str, fallback_seed: str = "") -> str:
    """Generates a unique, non-hardcoded device_id derived from MAC address SHA-256 hash."""
    mac_clean = (mac_address or "").strip().upper()
    if mac_clean and mac_clean != "UNKNOWN":
        raw_seed = mac_clean.encode("utf-8")
    else:
        raw_seed = f"docker-lab-mac-fallback:{ip_address}:{fallback_seed}".encode("utf-8")
    return f"dev_{hashlib.sha256(raw_seed).hexdigest()[:10]}"


def validate_profile_schema(profile_dict: Dict[str, Any]) -> None:
    """
    Validates a candidate profile dictionary against the IoTFlux profile schema
    before writing to disk. Raises ProfileSchemaValidationError on any mismatch.
    """
    if not isinstance(profile_dict, dict):
        raise ProfileSchemaValidationError("Profile root must be a dictionary.")

    missing = REQUIRED_PROFILE_KEYS - set(profile_dict.keys())
    if missing:
        raise ProfileSchemaValidationError(f"Profile missing required schema keys: {sorted(missing)}")

    dev_id = profile_dict.get("device_id", "")
    if not isinstance(dev_id, str) or not dev_id.startswith("dev_"):
        raise ProfileSchemaValidationError(
            f"device_id '{dev_id}' must be a hash-derived identifier starting with 'dev_'."
        )

    if not isinstance(profile_dict.get("protocols"), list) or not profile_dict["protocols"]:
        raise ProfileSchemaValidationError("Profile 'protocols' must be a non-empty list.")

    if not isinstance(profile_dict.get("authorized"), bool):
        raise ProfileSchemaValidationError("Profile 'authorized' field must be a boolean.")

    creds = profile_dict.get("credentials")
    if not isinstance(creds, dict):
        raise ProfileSchemaValidationError("Profile 'credentials' block must be a mapping.")
    if creds.get("username") or creds.get("encrypted_secret"):
        raise ProfileSchemaValidationError(
            "Newly generated profiles must leave credential fields empty by default."
        )


class DynamicProfileGenerator:
    """Converts discovered_devices.json into validated YAML profiles under profiles/auto_generated/."""

    def __init__(
        self,
        output_dir: str | Path = "profiles/auto_generated",
        whitelist_path: str | Path = "lab_whitelist.txt",
        mirror_pkg_dir: Optional[str | Path] = None,
        registry_path: Optional[str | Path] = None,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.whitelist_path = Path(whitelist_path)
        self.registry_path = Path(registry_path) if registry_path else None
        if mirror_pkg_dir is not None:
            self.mirror_dir: Optional[Path] = Path(mirror_pkg_dir)
        else:
            self.mirror_dir = Path(__file__).resolve().parent.parent / "profiles" / "auto_generated"

    def build_profile_dict(
        self,
        device_record: Dict[str, Any],
        whitelist: Optional[Set[str]] = None,
        registry: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        if whitelist is None:
            whitelist = load_lab_whitelist(self.whitelist_path)
        if registry is None:
            registry = load_authorized_devices_registry(self.registry_path)

        ip_addr = str(device_record.get("ip_address", "")).strip()
        mac_addr = str(device_record.get("mac_address", "UNKNOWN")).strip()
        open_ports = device_record.get("open_ports", [])
        fingerprints = device_record.get("service_fingerprints", {}) or {}

        # Always derive or verify hash-based device_id
        existing_id = str(device_record.get("device_id", ""))
        if existing_id.startswith("dev_"):
            device_id = existing_id
        else:
            device_id = compute_mac_device_id(mac_addr, ip_addr, str(open_ports))

        vendor = str(fingerprints.get("vendor") or ("Shelly" if "Shelly" in str(fingerprints) else "Generic-Lab-Node"))
        model = str(fingerprints.get("model") or fingerprints.get("app") or f"AutoDetected-{open_ports}")

        detected_proto = device_record.get("protocols") or device_record.get("detected_protocol") or ["tcp"]
        if isinstance(detected_proto, str):
            protocols = [detected_proto]
        else:
            protocols = list(detected_proto)

        detected_services: List[str] = fingerprints.get("detected_services", [])
        if not detected_services:
            if 1883 in open_ports:
                detected_services.append("MQTT Broker")
            if 554 in open_ports:
                detected_services.append("RTSP Stream")
            if 80 in open_ports or 8080 in open_ports:
                detected_services.append("HTTP Management / REST API")

        network_block: Dict[str, Any] = {}
        flagged_ports: List[Dict[str, Any]] = []

        for svc in detected_services:
            tpl = CAPABILITY_TEMPLATES.get(svc)
            if not tpl:
                continue
            for net_key in ("http", "mqtt", "rtsp", "coap"):
                if net_key in tpl and net_key not in network_block:
                    # Deep copy via json serialization
                    net_copy = json.loads(json.dumps(tpl[net_key]))
                    if "base_url" in net_copy:
                        net_copy["base_url"] = net_copy["base_url"].replace("{ip}", ip_addr)
                    network_block[net_key] = net_copy
            for fp in tpl.get("flagged_ports", []):
                if fp["port"] in open_ports and fp not in flagged_ports:
                    flagged_ports.append(json.loads(json.dumps(fp)))

        # Check whitelist by device_id, IP, or MAC
        is_whitelisted = any(
            candidate.lower() in whitelist
            for candidate in (device_id, ip_addr, mac_addr)
            if candidate and candidate != "UNKNOWN"
        )

        # Check authorized devices registry
        registry_entry: Optional[Dict[str, Any]] = None
        if registry:
            for cand in (ip_addr, device_id, mac_addr):
                if cand and cand.lower() in registry:
                    registry_entry = registry[cand.lower()]
                    break

        # Check if safety limits are defined directly in device_record or in registry entry
        safety_limits = None
        if "safety_limits" in device_record:
            safety_limits = device_record["safety_limits"]
        elif registry_entry and "safety_limits" in registry_entry:
            safety_limits = registry_entry["safety_limits"]

        is_authorized = bool(is_whitelisted or registry_entry or device_record.get("authorized", False))

        # Physical lab safety boundary check
        is_physical = False
        try:
            if ip_addr and ipaddress.ip_address(ip_addr) in ipaddress.ip_network("10.10.0.0/16"):
                is_physical = True
        except ValueError:
            pass

        if safety_limits is not None:
            # Validate explicit safety limits
            validate_device_safety_limits(safety_limits)
        elif is_physical and is_authorized:
            raise SafetyLimitValidationError(
                f"Physical lab device {device_id} ({ip_addr}) requires explicit datasheet-derived safety_limits before authorization."
            )
        elif is_physical:
            is_authorized = False

        profile_data: Dict[str, Any] = {
            "device_id": device_id,
            "vendor": vendor,
            "model": model,
            "ip_address": ip_addr,
            "mac_address": mac_addr,
            "open_ports": open_ports,
            "protocols": protocols,
            "authorized": bool(is_authorized),
            "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "credentials": {
                "username": "",
                "encrypted_secret": "",
                "encryption_scheme": "fernet-aes128-cbc-hmac-sha256",
                "configured": False,
                "updated_at_utc": None,
                "notice": "Credentials intentionally blank. Run 'iotflux profiles set-creds <device_id>' to configure.",
            },
            "network": network_block,
            "flagged_ports": flagged_ports,
            "known_cves": [],
        }

        if safety_limits is not None:
            profile_data["safety_limits"] = safety_limits

        validate_profile_schema(profile_data)
        return profile_data

    def generate_from_file(
        self,
        discovered_json_path: str | Path = "discovered_devices.json",
    ) -> List[Path]:
        in_path = Path(discovered_json_path)
        if not in_path.exists():
            raise FileNotFoundError(f"Discovery inventory file not found: {in_path}")

        devices = json.loads(in_path.read_text(encoding="utf-8"))
        if not isinstance(devices, list):
            raise ValueError("discovered_devices.json must contain a JSON list of device objects.")

        whitelist = load_lab_whitelist(self.whitelist_path)
        registry = load_authorized_devices_registry(self.registry_path)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if self.mirror_dir:
            self.mirror_dir.mkdir(parents=True, exist_ok=True)

        written_paths: List[Path] = []
        for dev in devices:
            profile_dict = self.build_profile_dict(dev, whitelist, registry)
            dev_id = profile_dict["device_id"]
            yaml_text = yaml.safe_dump(profile_dict, sort_keys=False)

            out_file = self.output_dir / f"{dev_id}.yaml"
            out_file.write_text(yaml_text, encoding="utf-8")

            # Verify round-trip loading via DeviceProfile loader
            _ = load_profile(out_file)
            written_paths.append(out_file)

            if self.mirror_dir and self.mirror_dir.resolve() != self.output_dir.resolve():
                mirror_file = self.mirror_dir / f"{dev_id}.yaml"
                mirror_file.write_text(yaml_text, encoding="utf-8")

            audit_trail.log_event(
                event_type="PROFILE_GENERATION",
                action="generate_auto_profile",
                details={
                    "device_id": dev_id,
                    "ip_address": profile_dict["ip_address"],
                    "authorized": profile_dict["authorized"],
                    "protocols": profile_dict["protocols"],
                    "profile_path": str(out_file),
                },
            )
            logger.success(
                f"Generated profile {out_file} (authorized={profile_dict['authorized']}, "
                f"protocols={profile_dict['protocols']})"
            )

        return written_paths
