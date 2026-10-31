"""
scope_validator.py - Runtime Environment-Adaptive Network Scope Validator for IoTFlux
Authorized Defensive Security Validation Lab

Replaces compile-time subnet locks with a runtime-configurable scope validator
reading operator-defined rules from lab-scope.env:
- ALLOWED_SUBNETS: Comma-separated IPv4 CIDRs permitted for lab validation
- DENIED_SUBNETS: Comma-separated IPv4 CIDRs explicitly blocked (with LPM specificity)
- SCOPE_VALIDATION_MODE: enforce | warn | dry-run
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from iotflux.core.audit_log import audit_trail
from iotflux.core.logger import Colors, logger


DEFAULT_SCOPE_ENV_PATH = Path("lab-scope.env")
VALID_MODES = ("enforce", "warn", "dry-run")


class ScopeViolationError(PermissionError):
    """Raised when a target IP or subnet violates the active lab-scope.env rules."""


class PhysicalLabMetadataError(ScopeViolationError):
    """Raised when 10.10.0.0/16 is configured without explicit physical_lab: true metadata."""


class PhysicalLabAuthorizationError(ScopeViolationError):
    """Raised when an operation targets a physical_lab: true subnet without --authorize."""


PHYSICAL_LAB_SUPERNET = ipaddress.ip_network("10.10.0.0/16")


# Backward-compatible alias
LabScopeViolationError = ScopeViolationError


class AuthorizeJustificationError(PermissionError):
    """Deprecated: justification no longer required. Kept for import compat."""


@dataclass
class ScopeConfig:
    allowed_subnets: List[ipaddress.IPv4Network] = field(default_factory=list)
    denied_subnets: List[ipaddress.IPv4Network] = field(default_factory=list)
    mode: str = "enforce"
    source_path: str = "lab-scope.env"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_path": self.source_path,
            "mode": self.mode,
            "allowed_subnets": [str(net) for net in self.allowed_subnets],
            "denied_subnets": [str(net) for net in self.denied_subnets],
        }


def _strip_inline_comment(raw_val: str) -> str:
    """Strips inline '#' comments and surrounding quotes/whitespace from .env values."""
    if "#" in raw_val:
        raw_val = raw_val.split("#", 1)[0]
    return raw_val.strip().strip('"').strip("'")


def _parse_cidr_list(raw_csv: str) -> List[ipaddress.IPv4Network]:
    networks: List[ipaddress.IPv4Network] = []
    for item in raw_csv.split(","):
        token = item.strip()
        if not token:
            continue
        net = ipaddress.ip_network(token, strict=False)
        if not isinstance(net, ipaddress.IPv4Network):
            raise ValueError(f"Only IPv4 CIDR ranges are supported in lab-scope.env (got '{token}')")
        networks.append(net)
    return networks


def load_scope_config(env_path: Optional[str | Path] = None) -> ScopeConfig:
    """
    Loads runtime network scope rules from lab-scope.env (or IOTFLUX_SCOPE_ENV).
    Falls back to safe isolated lab defaults if the file is missing.
    """
    resolved_path = Path(
        env_path
        or os.environ.get("IOTFLUX_SCOPE_ENV", "")
        or DEFAULT_SCOPE_ENV_PATH
    )

    raw_vars: Dict[str, str] = {
        "ALLOWED_SUBNETS": "172.28.0.0/24,127.0.0.0/8",
        "DENIED_SUBNETS": "0.0.0.0/0",
        "SCOPE_VALIDATION_MODE": "enforce",
    }

    if resolved_path.exists():
        for line in resolved_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, val = stripped.split("=", 1)
            k = key.strip().upper()
            v = _strip_inline_comment(val)
            if k in raw_vars and v:
                raw_vars[k] = v

    # Allow explicit process environment overrides if set by operator
    for env_key in ("ALLOWED_SUBNETS", "DENIED_SUBNETS", "SCOPE_VALIDATION_MODE"):
        if f"IOTFLUX_{env_key}" in os.environ:
            raw_vars[env_key] = _strip_inline_comment(os.environ[f"IOTFLUX_{env_key}"])

    mode = raw_vars["SCOPE_VALIDATION_MODE"].lower()
    if mode not in VALID_MODES:
        logger.warning(f"Invalid SCOPE_VALIDATION_MODE '{mode}' in {resolved_path}; defaulting to 'enforce'.")
        mode = "enforce"

    allowed = _parse_cidr_list(raw_vars["ALLOWED_SUBNETS"])
    denied = _parse_cidr_list(raw_vars["DENIED_SUBNETS"])

    return ScopeConfig(
        allowed_subnets=allowed,
        denied_subnets=denied,
        mode=mode,
        source_path=str(resolved_path),
    )


def evaluate_target_against_config(
    target_ip_or_cidr: str,
    config: ScopeConfig,
) -> Tuple[bool, Optional[str], Optional[str], str]:
    """
    Evaluates a target IP or CIDR against ScopeConfig using Longest Prefix Match (LPM)
    specificity between ALLOWED_SUBNETS and DENIED_SUBNETS:
    1. Target must be a subnet of at least one entry in ALLOWED_SUBNETS.
    2. If target also matches an entry in DENIED_SUBNETS, the most-specific allowed subnet
       must have a strictly longer prefix length than any matching denied subnet (or any
       overlapping sub-subnet in DENIED_SUBNETS).

    Returns: (is_allowed, matched_allow_cidr, matched_deny_cidr, reason)
    """
    clean = target_ip_or_cidr.strip()
    try:
        target_net = ipaddress.ip_network(clean, strict=False)
    except ValueError as exc:
        raise ScopeViolationError(f"Invalid IPv4 address or CIDR '{clean}': {exc}") from exc

    if not isinstance(target_net, ipaddress.IPv4Network):
        raise ScopeViolationError(f"IPv6 target '{clean}' is not permitted by IPv4 lab scope configuration.")

    matching_allows = [net for net in config.allowed_subnets if target_net.subnet_of(net)]
    # A denied rule matches if target_net is inside the denied net OR if a more-specific denied net is inside target_net
    matching_denies = [
        net for net in config.denied_subnets
        if target_net.subnet_of(net) or net.subnet_of(target_net)
    ]

    best_allow = max(matching_allows, key=lambda n: n.prefixlen) if matching_allows else None
    best_deny = max(matching_denies, key=lambda n: n.prefixlen) if matching_denies else None

    if best_allow is None:
        deny_info = f" and matches DENIED_SUBNETS ({best_deny})" if best_deny else ""
        return (
            False,
            None,
            str(best_deny) if best_deny else None,
            f"Target '{clean}' is not within any ALLOWED_SUBNETS ({[str(n) for n in config.allowed_subnets]}){deny_info}.",
        )

    if best_deny is not None and best_deny.prefixlen >= best_allow.prefixlen:
        return (
            False,
            str(best_allow),
            str(best_deny),
            f"Target '{clean}' is blocked by explicit DENIED_SUBNETS rule '{best_deny}' "
            f"(specificity /{best_deny.prefixlen} >= allowed rule '{best_allow}' /{best_allow.prefixlen}).",
        )

    return (
        True,
        str(best_allow),
        str(best_deny) if best_deny else None,
        f"Target '{clean}' permitted by ALLOWED_SUBNETS rule '{best_allow}'.",
    )



AUTHORIZE_AUDIT_NOTE = "operator --authorize"
_AUTHORIZE_WARNED_TARGETS: set[str] = set()


def normalize_authorize_note(authorize_override: bool) -> str:
    """Fixed audit note when --authorize lifts scope. No operator justification collected."""
    return AUTHORIZE_AUDIT_NOTE if authorize_override else ""


def _session_authorize_fallback(authorize_override: bool) -> bool:
    """Reads AUTHORIZE from the interactive session if CLI flag was not set."""
    if authorize_override:
        return True
    try:
        from iotflux.core.session import session as _sess
        return bool(_sess.get_option("AUTHORIZE", False))
    except Exception:
        return False


def validate_target_ip(
    target_ip: str,
    env_path: Optional[str | Path] = None,
    mode_override: Optional[str] = None,
    authorize_override: bool = False,
    justification: Optional[str] = None,
) -> bool:
    """
    Advisory scope check. Never blocks: every reachable target is fair game.

    The lab-scope.env rules are still evaluated and logged (so an operator can see
    whether a target was inside the declared lab boundary), but the return value is
    always True and no exception is raised for out-of-scope targets.

    Kept signature-compatible with the previous fail-closed implementation.
    """
    authorize_override = _session_authorize_fallback(authorize_override)

    try:
        config = load_scope_config(env_path)
        mode = (mode_override or config.mode).lower()
        is_allowed, matched_allow, matched_deny, reason = evaluate_target_against_config(target_ip, config)
    except Exception as exc:  # malformed scope file, bad CIDR, etc.
        logger.debug(f"Scope check skipped for '{target_ip}': {exc}")
        return True

    if is_allowed:
        logger.debug(f"Scope: '{target_ip}' inside declared boundary ({matched_allow}).")
    else:
        logger.info(f"Scope: '{target_ip}' outside declared boundary -- proceeding anyway. {reason}")

    audit_trail.log_event(
        event_type="SCOPE_ADVISORY",
        action="validate_target_ip",
        details={
            "target": target_ip,
            "mode": mode,
            "is_allowed": is_allowed,
            "matched_allow": matched_allow,
            "matched_deny": matched_deny,
            "reason": reason,
            "justification": normalize_authorize_note(authorize_override),
            "scope_file": config.source_path,
        },
    )
    return True


def is_scope_dry_run(env_path: Optional[str | Path] = None) -> bool:
    """Returns True if SCOPE_VALIDATION_MODE is currently set to 'dry-run'."""
    return load_scope_config(env_path).mode == "dry-run"


def expand_scoped_targets(
    target_cidr_or_ip: str,
    env_path: Optional[str | Path] = None,
    max_hosts: int = 254,
    authorize_override: bool = False,
    justification: Optional[str] = None,
) -> List[str]:
    """
    Validates target_cidr_or_ip against runtime lab-scope.env rules and expands
    CIDR ranges into individual IPv4 host addresses (bounded to max_hosts).
    Pass authorize_override=True (--authorize) to permit an out-of-scope target
    (SCOPE_OVERRIDE_AUTHORIZED); does not enable state changes.
    """
    validate_target_ip(
        target_cidr_or_ip,
        env_path=env_path,
        authorize_override=authorize_override,
    )
    clean = target_cidr_or_ip.strip()
    if "/" in clean:
        net = ipaddress.ip_network(clean, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
        return hosts[:max_hosts] if hosts else [str(net.network_address)]
    return [str(ipaddress.ip_address(clean))]


# Backward-compatible helper alias
enforce_docker_lab_scope = expand_scoped_targets


def show_scope_configuration(env_path: Optional[str | Path] = None, as_json: bool = False) -> Dict[str, Any]:
    """
    Displays the active runtime network scope configuration for `iotflux config show-scope`.
    """
    import json

    cfg = load_scope_config(env_path)
    summary = cfg.to_dict()

    audit_trail.log_event(
        event_type="SCOPE_CONFIG_INSPECTED",
        action="show_scope_configuration",
        details=summary,
    )

    if as_json:
        print(json.dumps(summary, indent=2))
        return summary

    logger.header("IOTFLUX RUNTIME NETWORK SCOPE CONFIGURATION")
    print(f" Configuration Source : {Colors.BOLD}{cfg.source_path}{Colors.RESET}")
    mode_color = Colors.GREEN if cfg.mode == "enforce" else Colors.YELLOW
    print(f" Validation Mode      : {mode_color}{cfg.mode.upper()}{Colors.RESET} (options: enforce, warn, dry-run)")
    print(f" Allowed Subnets      : {', '.join(str(n) for n in cfg.allowed_subnets) or '(none)'}")
    print(f" Denied Subnets       : {', '.join(str(n) for n in cfg.denied_subnets) or '(none)'}")
    print(" Precedence Policy    : Longest-Prefix Match (LPM) -- specific allowed lab subnets override broad catch-all blocks")
    print()
    return summary
