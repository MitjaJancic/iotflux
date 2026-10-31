"""
scope_manager.py - Dynamic YAML Scope Management System for IoTFlux Field & Physical Lab Assessments
Authorized Security Assessment & Conformance Validation Framework

Implements:
1. Strict startup schema & CIDR validation for assessment_scope.yaml.
2. Longest-Prefix Match (LPM) runtime target evaluation with network segment attribution.
3. Physical Lab Two-Key Safety Gate (10.10.0.0/16):
   - Requires explicit `physical_lab: true` metadata on physical lab subnets (10.10.0.0/16).
   - Requires explicit `--authorize` confirmation for ALL operations on `physical_lab: true` subnets.
4. Immutable 'enforce' default safety gate: 'warn' and 'dry-run' modes require explicit
   --override-safety + --justification (or --authorize) logged to assessment_audit.jsonl.
5. System interface verification ('iotflux scope validate --config assessment_scope.yaml')
   and template initialization ('iotflux scope init --output assessment_scope.yaml').
"""

from __future__ import annotations

import ipaddress
import json
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from iotflux.core.audit_log import audit_trail, compute_file_sha256
from iotflux.core.logger import Colors, logger
from iotflux.core.scope_validator import (
    AUTHORIZE_AUDIT_NOTE,
    ScopeViolationError,
    _AUTHORIZE_WARNED_TARGETS,
    normalize_authorize_note,
)


DEFAULT_ASSESSMENT_SCOPE_PATH = Path("assessment_scope.yaml")
VALID_ASSESSMENT_MODES = ("enforce", "warn", "dry-run")
PHYSICAL_LAB_SUPERNET = ipaddress.ip_network("10.10.0.0/16")

DEFAULT_SCOPE_YAML_TEMPLATE = """# Operator-defined assessment boundaries
allowed_networks:
  - cidr: "172.28.0.0/24"
    description: "Isolated Docker validation bridge (iotsploit lab)"
    physical_lab: false
  - cidr: "10.10.0.0/16"
    description: "Physical Raspberry Pi 5 Smart Home Lab (OpenWrt Zone-Isolated)"
    physical_lab: true
  - cidr: "10.42.0.0/16"
    description: "Corporate IoT VLAN"
    physical_lab: false
  - cidr: "192.168.50.0/24"
    description: "Residential test segment"
    physical_lab: false
denied_networks:
  - cidr: "0.0.0.0/0"
    description: "Default deny all external"
validation_mode: enforce  # enforce | warn | dry-run
max_concurrent_probes: 10
probe_timeout_seconds: 3
"""


class ScopeConfigurationError(ValueError):
    """Raised when assessment_scope.yaml contains invalid YAML syntax, schema, or CIDRs."""


class ScopeSafetyGateError(PermissionError):
    """Raised when warn or dry-run mode is requested without --override-safety and justification."""


class PhysicalLabMetadataError(ScopeViolationError):
    """Raised when 10.10.0.0/16 is configured without explicit physical_lab: true metadata."""


class PhysicalLabAuthorizationError(ScopeViolationError):
    """Raised when an operation targets a physical_lab: true subnet without --authorize."""


@dataclass
class NetworkBoundaryRule:
    network: ipaddress.IPv4Network
    description: str
    physical_lab: bool = False

    @property
    def cidr(self) -> str:
        return str(self.network)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cidr": str(self.network),
            "description": self.description,
            "physical_lab": self.physical_lab,
        }


@dataclass
class AssessmentScopeConfig:
    allowed_networks: List[NetworkBoundaryRule] = field(default_factory=list)
    denied_networks: List[NetworkBoundaryRule] = field(default_factory=list)
    validation_mode: str = "enforce"
    max_concurrent_probes: int = 10
    probe_timeout_seconds: float = 3.0
    source_path: str = "assessment_scope.yaml"
    config_hash: str = "sha256:absent"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_path": self.source_path,
            "config_hash": self.config_hash,
            "validation_mode": self.validation_mode,
            "max_concurrent_probes": self.max_concurrent_probes,
            "probe_timeout_seconds": self.probe_timeout_seconds,
            "allowed_networks": [r.to_dict() for r in self.allowed_networks],
            "denied_networks": [r.to_dict() for r in self.denied_networks],
        }


def _parse_network_rules(raw_list: Any, section_name: str) -> List[NetworkBoundaryRule]:
    if not isinstance(raw_list, list):
        raise ScopeConfigurationError(f"'{section_name}' in assessment_scope.yaml must be a YAML list.")
    rules: List[NetworkBoundaryRule] = []
    for idx, entry in enumerate(raw_list):
        phys_lab = False
        if isinstance(entry, str):
            cidr_str = entry.strip()
            desc_str = f"{section_name}[{idx}]"
        elif isinstance(entry, dict):
            if "cidr" not in entry or not str(entry["cidr"]).strip():
                raise ScopeConfigurationError(f"Missing 'cidr' key in {section_name}[{idx}].")
            cidr_str = str(entry["cidr"]).strip()
            desc_str = str(entry.get("description") or f"{section_name}[{idx}]").strip()
            phys_lab = bool(entry.get("physical_lab", False))
        else:
            raise ScopeConfigurationError(f"Invalid entry type in {section_name}[{idx}]: expected mapping with 'cidr'.")

        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
        except ValueError as exc:
            raise ScopeConfigurationError(f"Invalid CIDR '{cidr_str}' in {section_name}[{idx}]: {exc}") from exc

        if not isinstance(net, ipaddress.IPv4Network):
            raise ScopeConfigurationError(f"Only IPv4 CIDRs are supported in {section_name} (got '{cidr_str}').")

        rules.append(NetworkBoundaryRule(network=net, description=desc_str, physical_lab=phys_lab))
    return rules


class ScopeManager:
    """
    Runtime CIDR Scope Manager using Longest-Prefix Match (LPM).
    Enforces safety gates on non-default validation modes, enforces Two-Key
    physical lab authorization (physical_lab: true + --authorize) for 10.10.0.0/16,
    and attributes targets to their named operational network segments.
    """

    def __init__(
        self,
        config_path: str | Path = DEFAULT_ASSESSMENT_SCOPE_PATH,
        override_safety: bool = False,
        justification: Optional[str] = None,
        authorize_override: bool = False,
    ) -> None:
        self.config_path = Path(config_path)
        self.override_safety = bool(override_safety or authorize_override)
        self.authorize_override = bool(authorize_override)
        self.justification = (justification or "").strip()
        self.config = self._load_and_validate()

    def _load_and_validate(self) -> AssessmentScopeConfig:
        if not self.config_path.exists():
            raise ScopeConfigurationError(
                f"Scope configuration file '{self.config_path}' does not exist. "
                "Initialize one via 'iotflux scope init --output assessment_scope.yaml'."
            )

        raw_text = self.config_path.read_text(encoding="utf-8")
        try:
            parsed = yaml.safe_load(raw_text)
        except Exception as exc:
            raise ScopeConfigurationError(f"Malformed YAML in '{self.config_path}': {exc}") from exc

        if not isinstance(parsed, dict):
            raise ScopeConfigurationError(f"Root of '{self.config_path}' must be a YAML mapping.")

        if "allowed_networks" not in parsed:
            raise ScopeConfigurationError(f"Missing required key 'allowed_networks' in '{self.config_path}'.")
        if "denied_networks" not in parsed:
            raise ScopeConfigurationError(f"Missing required key 'denied_networks' in '{self.config_path}'.")

        allowed_rules = _parse_network_rules(parsed["allowed_networks"], "allowed_networks")
        denied_rules = _parse_network_rules(parsed["denied_networks"], "denied_networks")

        if not allowed_rules:
            raise ScopeConfigurationError(f"'allowed_networks' in '{self.config_path}' cannot be empty.")

        mode = str(parsed.get("validation_mode", "enforce")).strip().lower()
        if mode not in VALID_ASSESSMENT_MODES:
            raise ScopeConfigurationError(
                f"Invalid validation_mode '{mode}' in '{self.config_path}'. "
                f"Must be one of {VALID_ASSESSMENT_MODES}."
            )

        # Safety Gate: 'warn' and 'dry-run' require explicit --override-safety (or --authorize)
        if mode in ("warn", "dry-run"):
            has_valid_override = self.authorize_override or self.override_safety
            if not has_valid_override:
                audit_trail.log_event(
                    event_type="SCOPE_SAFETY_GATE_REJECTED",
                    action="load_assessment_scope",
                    details={
                        "requested_mode": mode,
                        "override_safety": self.override_safety,
                        "reason": "Non-enforce validation_mode requires --override-safety with --justification (or --authorize).",
                    },
                    scope_file=self.config_path,
                )
                raise ScopeSafetyGateError(
                    f"SAFETY GATE BLOCKED: Scope configuration '{self.config_path}' specifies "
                    f"validation_mode='{mode}', but 'enforce' is the mandatory default. "
                    "To use 'warn' or 'dry-run', pass '--override-safety --justification \"<reason>\"' (or '--authorize')."
                )

            audit_trail.log_event(
                event_type="SCOPE_SAFETY_OVERRIDE_AUTHORIZED",
                action="load_assessment_scope",
                details={
                    "validation_mode": mode,
                    "override_safety": True,
                    "justification": self.justification or AUTHORIZE_AUDIT_NOTE,
                    "scope_file": str(self.config_path),
                },
                scope_file=self.config_path,
            )

        try:
            max_probes = int(parsed.get("max_concurrent_probes", 10))
            timeout_sec = float(parsed.get("probe_timeout_seconds", 3.0))
        except (TypeError, ValueError) as exc:
            raise ScopeConfigurationError(
                f"'max_concurrent_probes' and 'probe_timeout_seconds' must be numeric: {exc}"
            ) from exc

        if max_probes < 1 or max_probes > 256:
            raise ScopeConfigurationError(f"'max_concurrent_probes' must be between 1 and 256 (got {max_probes}).")
        if timeout_sec <= 0 or timeout_sec > 60:
            raise ScopeConfigurationError(f"'probe_timeout_seconds' must be between 0.05 and 60 (got {timeout_sec}).")

        return AssessmentScopeConfig(
            allowed_networks=allowed_rules,
            denied_networks=denied_rules,
            validation_mode=mode,
            max_concurrent_probes=max_probes,
            probe_timeout_seconds=timeout_sec,
            source_path=str(self.config_path),
            config_hash=compute_file_sha256(self.config_path),
        )

    def evaluate_target(self, target_ip_or_cidr: str) -> Tuple[bool, Optional[NetworkBoundaryRule], Optional[NetworkBoundaryRule], str]:
        """
        Evaluates target IP or CIDR using Longest-Prefix Match (LPM):
        - Must be a subnet of at least one rule in allowed_networks.
        - If it also overlaps a rule in denied_networks, the allowed rule's prefix length
          must be strictly greater than the matching denied rule's prefix length.
        """
        clean = target_ip_or_cidr.strip()
        try:
            target_net = ipaddress.ip_network(clean, strict=False)
        except ValueError as exc:
            raise ScopeViolationError(f"Invalid IPv4 address or CIDR '{clean}': {exc}") from exc

        if not isinstance(target_net, ipaddress.IPv4Network):
            raise ScopeViolationError(f"IPv6 target '{clean}' is outside IPv4 assessment scope.")

        matching_allows = [r for r in self.config.allowed_networks if target_net.subnet_of(r.network)]
        matching_denies = [
            r for r in self.config.denied_networks
            if target_net.subnet_of(r.network) or r.network.subnet_of(target_net)
        ]

        best_allow = max(matching_allows, key=lambda r: r.network.prefixlen) if matching_allows else None
        best_deny = max(matching_denies, key=lambda r: r.network.prefixlen) if matching_denies else None

        if best_allow is None:
            deny_desc = f" (matched deny rule: {best_deny.cidr} '{best_deny.description}')" if best_deny else ""
            return (
                False,
                None,
                best_deny,
                f"Target '{clean}' is not within any allowed_networks in {self.config.source_path}{deny_desc}.",
            )

        if best_deny is not None and best_deny.network.prefixlen >= best_allow.network.prefixlen:
            return (
                False,
                best_allow,
                best_deny,
                f"Target '{clean}' is blocked by denied_networks rule '{best_deny.cidr}' ({best_deny.description}) "
                f"with specificity /{best_deny.network.prefixlen} >= allowed rule '{best_allow.cidr}' /{best_allow.prefixlen}.",
            )

        return (
            True,
            best_allow,
            best_deny,
            f"Target '{clean}' permitted in segment '{best_allow.description}' ({best_allow.cidr}).",
        )

    def validate_target(
        self,
        target_ip_or_cidr: str,
        authorize: Optional[bool] = None,
    ) -> bool:
        """
        Validates target_ip_or_cidr under the active assessment scope configuration:
        1. Physical Lab Subnet Gate (10.10.0.0/16):
           - Requires `physical_lab: true` metadata on the matching allowed_networks entry.
           - Requires explicit `--authorize` confirmation (authorize=True or authorize_override=True)
             for ALL operations on physical_lab subnets (no exceptions).
        2. Standard LPM scope check for Docker/field subnets.
        """
        clean = target_ip_or_cidr.strip()
        try:
            target_net = ipaddress.ip_network(clean, strict=False)
        except ValueError as exc:
            raise ScopeViolationError(f"Invalid IPv4 address or CIDR '{clean}': {exc}") from exc

        is_allowed, allow_rule, deny_rule, reason = self.evaluate_target(target_ip_or_cidr)
        effective_authorize = bool(self.authorize_override if authorize is None else (authorize or self.authorize_override))
        mode = self.config.validation_mode

        # Physical Lab Safety Gate: Any target within 10.10.0.0/16 or matching a physical_lab rule
        is_in_physical_range = isinstance(target_net, ipaddress.IPv4Network) and (
            target_net.subnet_of(PHYSICAL_LAB_SUPERNET) or PHYSICAL_LAB_SUPERNET.subnet_of(target_net)
        )
        if is_in_physical_range or (allow_rule is not None and allow_rule.physical_lab):
            if not is_allowed or allow_rule is None or not allow_rule.physical_lab:
                audit_trail.log_event(
                    event_type="PHYSICAL_LAB_METADATA_MISSING",
                    action="validate_target",
                    details={
                        "target": target_ip_or_cidr,
                        "matched_allow": allow_rule.to_dict() if allow_rule else None,
                        "reason": "10.10.0.0/16 requires explicit physical_lab: true metadata in assessment_scope.yaml",
                    },
                    scope_file=self.config_path,
                )
                raise PhysicalLabMetadataError(
                    f"PHYSICAL LAB SCOPE GATE REJECTED [{self.config.source_path}]: "
                    f"Target '{target_ip_or_cidr}' falls within physical lab subnet 10.10.0.0/16, "
                    "which is ONLY accepted when 'physical_lab: true' metadata is present in allowed_networks."
                )

            if not effective_authorize:
                audit_trail.log_event(
                    event_type="PHYSICAL_LAB_AUTHORIZE_REQUIRED",
                    action="validate_target",
                    details={
                        "target": target_ip_or_cidr,
                        "matched_allow": allow_rule.to_dict(),
                        "authorize": False,
                        "reason": "Operations on physical_lab: true subnet require explicit --authorize flag.",
                    },
                    scope_file=self.config_path,
                )
                raise PhysicalLabAuthorizationError(
                    f"PHYSICAL LAB TWO-KEY GATE BLOCKED [{self.config.source_path}]: "
                    f"Target '{target_ip_or_cidr}' resides on physical lab subnet '{allow_rule.cidr}' "
                    "(physical_lab: true). All operations on physical hardware require the explicit --authorize flag."
                )

            audit_trail.log_event(
                event_type="PHYSICAL_LAB_TARGET_AUTHORIZED",
                action="validate_target",
                details={
                    "target": target_ip_or_cidr,
                    "segment": allow_rule.description,
                    "cidr": allow_rule.cidr,
                    "physical_lab": True,
                    "authorize": True,
                },
                scope_file=self.config_path,
            )
            return True

        if not is_allowed and effective_authorize:
            authorize_note = normalize_authorize_note(True)
            if target_ip_or_cidr not in _AUTHORIZE_WARNED_TARGETS:
                _AUTHORIZE_WARNED_TARGETS.add(target_ip_or_cidr)
                logger.warning(
                    f"SAFETY NOTICE: SCOPE OVERRIDE AUTHORIZED for out-of-scope target "
                    f"'{target_ip_or_cidr}'. Operator --authorize + logged. Bounded state "
                    f"changes remain time-capped (<=2.0s auto-revert default)."
                )
            audit_trail.log_event(
                event_type="SCOPE_OVERRIDE_AUTHORIZED",
                action="validate_target",
                details={
                    "target": target_ip_or_cidr,
                    "mode": mode,
                    "is_allowed": False,
                    "matched_allow": allow_rule.to_dict() if allow_rule else None,
                    "matched_deny": deny_rule.to_dict() if deny_rule else None,
                    "reason": reason,
                    "justification": authorize_note,
                    "authorize_override": True,
                    "scope_file": str(self.config_path),
                },
                scope_file=self.config_path,
            )
            return True

        if mode == "dry-run":
            logger.info(f"[DRY-RUN SCOPE] {reason}")
            audit_trail.log_event(
                event_type="ASSESSMENT_SCOPE_DRY_RUN",
                action="validate_target",
                details={
                    "target": target_ip_or_cidr,
                    "is_allowed": is_allowed,
                    "matched_allow": allow_rule.to_dict() if allow_rule else None,
                    "matched_deny": deny_rule.to_dict() if deny_rule else None,
                    "reason": reason,
                },
                scope_file=self.config_path,
            )
            if not is_allowed:
                raise ScopeViolationError(
                    f"SCOPE VIOLATION (dry-run): {reason} "
                    "To assess an out-of-scope target, pass --authorize."
                )
            return True

        if not is_allowed:
            if mode == "warn":
                logger.warning(f"SCOPE WARNING (mode=warn): {reason}")
                audit_trail.log_event(
                    event_type="ASSESSMENT_SCOPE_WARNING",
                    action="validate_target",
                    details={
                        "target": target_ip_or_cidr,
                        "is_allowed": False,
                        "reason": reason,
                        "justification": self.justification,
                    },
                    scope_file=self.config_path,
                )
                return True

            audit_trail.log_event(
                event_type="ASSESSMENT_SCOPE_VIOLATION",
                action="validate_target",
                details={
                    "target": target_ip_or_cidr,
                    "is_allowed": False,
                    "matched_allow": allow_rule.to_dict() if allow_rule else None,
                    "matched_deny": deny_rule.to_dict() if deny_rule else None,
                    "reason": reason,
                },
                scope_file=self.config_path,
            )
            raise ScopeViolationError(
                f"ASSESSMENT SCOPE VIOLATION [{self.config.source_path}]: {reason} "
                "To assess an out-of-scope target or enable bounded state changes, pass --authorize."
            )

        return True

    def get_network_segment(self, ip_address: str) -> str:
        """Returns the human-readable network segment description and CIDR for an in-scope IP."""
        is_allowed, allow_rule, _, _ = self.evaluate_target(ip_address)
        if is_allowed and allow_rule is not None:
            return f"{allow_rule.description} ({allow_rule.cidr})"
        return "Unclassified / Out-of-Scope Segment"

    def expand_target_range(
        self,
        target_cidr_or_ip: Optional[str] = None,
        max_hosts: int = 254,
        authorize: Optional[bool] = None,
    ) -> List[str]:
        """
        Expands an operator-specified target range (or the primary allowed network if omitted)
        into individual IPv4 host addresses after verifying scope compliance.
        """
        if target_cidr_or_ip:
            self.validate_target(target_cidr_or_ip, authorize=authorize)
            clean = target_cidr_or_ip.strip()
            if "/" in clean:
                net = ipaddress.ip_network(clean, strict=False)
                hosts = [str(ip) for ip in net.hosts()]
                return hosts[:max_hosts] if hosts else [str(net.network_address)]
            return [str(ipaddress.ip_address(clean))]

        first_net = self.config.allowed_networks[0].network
        hosts = [str(ip) for ip in first_net.hosts()]
        return hosts[:max_hosts] if hosts else [str(first_net.network_address)]


def get_local_interface_ipv4_addresses() -> List[str]:
    """Enumerates local system IPv4 addresses across active network interfaces."""
    local_ips: List[str] = ["127.0.0.1"]
    try:
        hostname = socket.gethostname()
        _, _, addrs = socket.gethostbyname_ex(hostname)
        for addr in addrs:
            if addr not in local_ips and ":" not in addr:
                local_ips.append(addr)
    except Exception:
        pass
    return local_ips


def init_scope_config(output_path: str | Path = DEFAULT_ASSESSMENT_SCOPE_PATH, overwrite: bool = True) -> Path:
    """
    Implements `iotflux scope init --output assessment_scope.yaml`.
    Writes a baseline assessment_scope.yaml template and logs initialization to assessment_audit.jsonl.
    """
    out = Path(output_path)
    if out.exists() and not overwrite:
        raise FileExistsError(f"Scope file '{out}' already exists.")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(DEFAULT_SCOPE_YAML_TEMPLATE, encoding="utf-8")

    audit_trail.log_event(
        event_type="SCOPE_CONFIG_INITIALIZED",
        action="scope_init",
        details={
            "output_path": str(out),
            "config_hash": compute_file_sha256(out),
        },
        scope_file=out,
    )
    logger.success(f"Initialized assessment scope configuration template at {out}")
    return out


def validate_scope_config_cli(
    config_path: str | Path = DEFAULT_ASSESSMENT_SCOPE_PATH,
    override_safety: bool = False,
    justification: Optional[str] = None,
    as_json: bool = False,
    authorize_override: bool = False,
) -> Dict[str, Any]:
    """
    Implements `iotflux scope validate --config assessment_scope.yaml`.
    Verifies YAML syntax, CIDR rules, safety mode constraints, and local system interfaces,
    reporting any misconfigurations (e.g., 0.0.0.0/0 in allowed_networks or shadowed rules).
    """
    mgr = ScopeManager(
        config_path=config_path,
        override_safety=override_safety,
        justification=justification,
        authorize_override=authorize_override,
    )
    cfg = mgr.config
    warnings: List[str] = []

    for rule in cfg.allowed_networks:
        if rule.network.prefixlen == 0:
            raise ScopeConfigurationError(
                "MISCONFIGURATION: '0.0.0.0/0' is prohibited in allowed_networks. Define explicit assessment CIDRs."
            )
        if rule.network.prefixlen < 16 and not rule.network.is_loopback:
            warnings.append(
                f"Broad subnet '{rule.cidr}' ({rule.description}) has prefix /{rule.network.prefixlen}; "
                "consider narrowing to /16 or /24 per engagement scope."
            )

    for a_rule in cfg.allowed_networks:
        for d_rule in cfg.denied_networks:
            if a_rule.network.subnet_of(d_rule.network) and d_rule.network.prefixlen >= a_rule.network.prefixlen:
                warnings.append(
                    f"Allowed rule '{a_rule.cidr}' ({a_rule.description}) is completely shadowed by "
                    f"denied rule '{d_rule.cidr}' ({d_rule.description})."
                )

    local_ips = get_local_interface_ipv4_addresses()
    reachable_segments: List[str] = []
    for ip in local_ips:
        ok, allow_rule, _, _ = mgr.evaluate_target(ip)
        if ok and allow_rule:
            seg = f"{allow_rule.description} ({allow_rule.cidr}) via local IP {ip}"
            if seg not in reachable_segments:
                reachable_segments.append(seg)

    report = {
        "valid": True,
        "scope_config": cfg.to_dict(),
        "local_interface_ips": local_ips,
        "directly_attached_scope_segments": reachable_segments,
        "warnings": warnings,
    }

    audit_trail.log_event(
        event_type="SCOPE_CONFIG_VALIDATED",
        action="scope_validate",
        details=report,
        scope_file=config_path,
    )

    if as_json:
        print(json.dumps(report, indent=2))
        return report

    logger.header("IOTFLUX ASSESSMENT SCOPE VALIDATION REPORT")
    print(f" Configuration File   : {Colors.BOLD}{cfg.source_path}{Colors.RESET}")
    print(f" Configuration Hash   : {cfg.config_hash}")
    print(f" Validation Mode      : {Colors.GREEN}{cfg.validation_mode.upper()}{Colors.RESET}")
    print(f" Max Concurrent Probes: {cfg.max_concurrent_probes}")
    print(f" Probe Timeout (sec)  : {cfg.probe_timeout_seconds}s")
    print(f" Local Interface IPs  : {', '.join(local_ips)}")
    print("\n Allowed Assessment Networks:")
    for r in cfg.allowed_networks:
        phys_tag = f" {Colors.YELLOW}[physical_lab: true | requires --authorize]{Colors.RESET}" if r.physical_lab else ""
        print(f"   + {r.cidr:<18} -- {r.description}{phys_tag}")
    print("\n Denied Networks:")
    for r in cfg.denied_networks:
        print(f"   - {r.cidr:<18} -- {r.description}")
    if warnings:
        print(f"\n {Colors.YELLOW}Configuration Warnings:{Colors.RESET}")
        for w in warnings:
            print(f"   ! {w}")
    else:
        logger.success("Scope validation passed with zero misconfiguration warnings.")
    print()
    return report
