"""
profiles.py - Hardware & Virtual Device Profile Catalog for IoTFlux
Authorized Defensive Security Validation Lab
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

from iotflux.core.logger import logger


@dataclass
class HttpEndpoint:
    path: str
    method: str = "GET"
    expect_auth: bool = True
    description: str = ""
    injectable_params: List[str] = field(default_factory=list)
    param_template: str = "{param_name}={value}"


@dataclass
class FlaggedPort:
    port: int
    reason: str
    damage: Dict[str, int] = field(default_factory=dict)


@dataclass
class KnownCve:
    id: str
    description: str
    cvss: Optional[float] = None
    damage: Dict[str, int] = field(default_factory=dict)


@dataclass
class DeviceProfile:
    device_id: str
    vendor: str
    model: str
    protocols: List[str]
    http_base_url: Optional[str] = None
    http_endpoints: List[HttpEndpoint] = field(default_factory=list)
    mqtt_topic_prefix: Optional[str] = None
    mqtt_expected_tls: bool = False
    ble_name_pattern: Optional[str] = None
    known_cves: List[KnownCve] = field(default_factory=list)
    flagged_ports: List[FlaggedPort] = field(default_factory=list)
    coap_endpoints: List[HttpEndpoint] = field(default_factory=list)
    authorized: bool = False
    safety_limits: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)
    mqtt_credentials_to_test: List[Dict[str, str]] = field(default_factory=list)
    credentials: Dict[str, Any] = field(default_factory=dict)
    profile_path: Optional[Path] = None

    def supports(self, protocol: str) -> bool:
        return protocol.lower() in [p.lower() for p in self.protocols]

    def has_credentials(self) -> bool:
        return bool(
            self.credentials.get("configured")
            and self.credentials.get("username")
            and self.credentials.get("encrypted_secret")
        )


def _parse_http(raw: Dict[str, Any]) -> tuple[Optional[str], List[HttpEndpoint]]:
    http_cfg = raw.get("network", {}).get("http")
    if not http_cfg:
        return None, []
    base_url = http_cfg.get("base_url")
    endpoints = [
        HttpEndpoint(
            path=e["path"],
            method=e.get("method", "GET"),
            expect_auth=e.get("expect_auth", True),
            description=e.get("description", ""),
            injectable_params=e.get("injectable_params", []),
        )
        for e in http_cfg.get("state_changing_endpoints", [])
        if "path" in e
    ]
    return base_url, endpoints


def _parse_mqtt(raw: Dict[str, Any]) -> tuple[Optional[str], bool, List[Dict[str, str]]]:
    mqtt_cfg = raw.get("network", {}).get("mqtt")
    if not mqtt_cfg:
        return None, False, []
    creds = mqtt_cfg.get("credentials_to_test", [])
    return mqtt_cfg.get("topic_prefix"), bool(mqtt_cfg.get("expected_tls", False)), creds


def _parse_ble(raw: Dict[str, Any]) -> Optional[str]:
    ble_cfg = raw.get("network", {}).get("ble")
    if not ble_cfg:
        return None
    return ble_cfg.get("name_pattern")


def _parse_cves(raw: Dict[str, Any]) -> List[KnownCve]:
    out = []
    for c in raw.get("known_cves", []):
        out.append(
            KnownCve(
                id=c["id"],
                description=c.get("description", ""),
                cvss=c.get("cvss"),
                damage=c.get("damage_score", {}),
            )
        )
    return out


def _parse_coap(raw: Dict[str, Any]) -> List[HttpEndpoint]:
    coap_cfg = raw.get("network", {}).get("coap")
    if not coap_cfg:
        return []
    return [
        HttpEndpoint(
            path=e["path"],
            method=e.get("method", "GET"),
            expect_auth=e.get("expect_auth", True),
            description=e.get("description", ""),
        )
        for e in coap_cfg.get("endpoints", [])
        if "path" in e
    ]


def _parse_flagged_ports(raw: Dict[str, Any]) -> List[FlaggedPort]:
    out = []
    for p in raw.get("flagged_ports", []):
        out.append(
            FlaggedPort(
                port=p["port"],
                reason=p.get("reason", ""),
                damage=p.get("damage_score", {}),
            )
        )
    return out


def load_profile(path: str | Path) -> DeviceProfile:
    path = Path(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    http_base_url, http_endpoints = _parse_http(raw)
    mqtt_prefix, mqtt_tls, mqtt_creds = _parse_mqtt(raw)
    ble_pattern = _parse_ble(raw)

    return DeviceProfile(
        device_id=raw.get("device_id", path.stem),
        vendor=raw.get("vendor", "unknown"),
        model=raw.get("model", "unknown"),
        protocols=raw.get("protocols", []),
        http_base_url=http_base_url,
        http_endpoints=http_endpoints,
        mqtt_topic_prefix=mqtt_prefix,
        mqtt_expected_tls=mqtt_tls,
        ble_name_pattern=ble_pattern,
        known_cves=_parse_cves(raw),
        flagged_ports=_parse_flagged_ports(raw),
        coap_endpoints=_parse_coap(raw),
        authorized=bool(raw.get("authorized", False)),
        safety_limits=raw.get("safety_limits", {}) if isinstance(raw.get("safety_limits"), dict) else {},
        raw=raw,
        mqtt_credentials_to_test=mqtt_creds,
        credentials=raw.get("credentials", {}) if isinstance(raw.get("credentials"), dict) else {},
        profile_path=path,
    )


class ProfileCatalog:
    """Central registry and search provider for IoTFlux device profiles."""

    def __init__(self, profiles_dir: Optional[str | Path] = None) -> None:
        if profiles_dir:
            self.base_dir = Path(profiles_dir)
        else:
            # Look in iotflux/profiles
            self.base_dir = Path(__file__).resolve().parent.parent / "profiles"

        self._profiles: Dict[str, DeviceProfile] = {}
        self.reload()

    def reload(self) -> None:
        self._profiles.clear()
        search_dirs = [
            self.base_dir,
            self.base_dir / "auto_generated",
            Path("profiles") / "auto_generated",
        ]
        seen_paths = set()
        for d in search_dirs:
            if not d.exists():
                continue
            for f in sorted(d.glob("*.yaml")):
                if f.name.startswith("_"):
                    continue
                resolved = f.resolve()
                if resolved in seen_paths:
                    continue
                seen_paths.add(resolved)
                try:
                    prof = load_profile(f)
                    self._profiles[prof.device_id] = prof
                except Exception as ex:
                    logger.warning(f"Failed to load profile {f.name}: {ex}")

    def list_profiles(self) -> List[DeviceProfile]:
        return list(self._profiles.values())

    def get_profile(self, device_id: str) -> Optional[DeviceProfile]:
        clean_id = device_id.strip().lower()
        if clean_id in self._profiles:
            return self._profiles[clean_id]
        # Check by filename stem or partial prefix/suffix match
        for pid, prof in self._profiles.items():
            if pid.lower() == clean_id or clean_id in pid.lower() or pid.lower().startswith(clean_id):
                return prof
        return None

    def find_by_protocol(self, protocol: str) -> List[DeviceProfile]:
        return [p for p in self._profiles.values() if p.supports(protocol)]

    def find_by_vendor(self, vendor: str) -> List[DeviceProfile]:
        return [p for p in self._profiles.values() if p.vendor.lower() == vendor.lower()]


catalog = ProfileCatalog()
