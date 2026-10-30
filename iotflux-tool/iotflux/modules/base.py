"""
base.py - Base validation module abstraction for IoTFlux
Authorized Security Assessment & Conformance Validation Framework
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from iotflux.core.logger import logger
from iotflux.core.session import FluxSession
from iotflux.core.specification import get_spec


@dataclass
class ValidationFinding:
    finding_id: str
    target: str
    title: str
    spec_id: str
    cwe: str
    status: str  # COMPLIANT, NON_COMPLIANT, CRITICAL_NON_COMPLIANT, INFORMATIONAL
    details: str
    remediation: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "target": self.target,
            "title": self.title,
            "spec_id": self.spec_id,
            "cwe": self.cwe,
            "status": self.status,
            "details": self.details,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }


class BaseValidationModule:
    """Base class for all IoTFlux discovery, validation, and conformance modules."""

    name: str = "base_module"
    description: str = "Base validation module"
    tier: str = "General"
    references: List[str] = []
    author: str = "Defensive Security Research Team"

    def __init__(self) -> None:
        self.module_options: Dict[str, Dict[str, Any]] = {}
        self.findings: List[ValidationFinding] = []
        self.register_option("TARGET", "", "Target host IP, CIDR, or URL")
        self.register_option("REQUIRE_CREDS", False, "Require configured profile credentials for state-changing checks")
        self.register_option("REQUIRE_AUTH", False, "Require valid, non-expired, privileged credentials (--require-auth)")
        self.register_option("DEVICE_ID", "", "Target device profile identifier for credential lookup")
        self.register_option("SCOPE_CONFIG", "", "Assessment scope YAML path for runtime validation")

    def register_option(self, name: str, default: Any, description: str) -> None:
        self.module_options[name.upper()] = {
            "value": default,
            "default": default,
            "description": description,
        }

    def set_option(self, name: str, value: Any) -> None:
        k = name.upper()
        if k in self.module_options:
            self.module_options[k]["value"] = value
            logger.success(f"Module option {k} => {value}")
        else:
            logger.warning(f"Unknown module option '{name}'")

    def get_option(self, name: str, session: Optional[FluxSession] = None) -> Any:
        k = name.upper()
        if k in self.module_options:
            val = self.module_options[k]["value"]
            if val != "" and val is not None and val is not False:
                return val
            if session and k in session.options and session.get_option(k) not in ("", None, False):
                return session.get_option(k)
            return val
        if session:
            return session.get_option(k)
        return None

    def assert_authorized(self, session: FluxSession, action_description: str) -> bool:
        """
        Two-Key Safety Invariant & Authorization/Credential Gate:
        1. State-modifying operations require --authorize (sets AUTHORIZED_TEST).
        2. When --require-auth (REQUIRE_AUTH) or --require-creds (REQUIRE_CREDS) is active,
           verifies that encrypted credentials exist, are not expired, and hold sufficient
           privileges before proceeding.
        """
        if not session.get_option("AUTHORIZED_TEST", False):
            logger.failure(
                f"SAFETY VIOLATION PREVENTED: Cannot execute state change: '{action_description}'. "
                "Module is operating under Read-Only invariant. Pass --authorize to unlock."
            )
            return False

        require_auth = bool(
            self.get_option("REQUIRE_AUTH", session)
            or session.get_option("REQUIRE_AUTH", False)
            or self.get_option("REQUIRE_CREDS", session)
            or session.get_option("REQUIRE_CREDS", False)
        )
        if require_auth:
            from iotflux.core import credential_manager

            lookup_key = str(
                self.get_option("DEVICE_ID", session)
                or session.get_option("DEVICE_ID", "")
                or self.get_option("TARGET", session)
                or ""
            ).strip()

            # Check via verify_profile_credentials_present and verify_device_auth_preflight
            has_creds, _, _ = credential_manager.verify_profile_credentials_present(lookup_key)
            if not has_creds:
                preflight_ok, status_code, info = credential_manager.verify_device_auth_preflight(lookup_key)
                if not preflight_ok:
                    reason = info.get(
                        "reason",
                        f"Credentials missing, expired, or insufficiently privileged ({status_code}).",
                    )
                    logger.failure(
                        f"CREDENTIAL GATE BLOCKED [{status_code}]: '--require-auth/--require-creds' is active for "
                        f"'{action_description}', but validation failed for '{lookup_key}': {reason} "
                        f"Configure via 'iotflux auth set {lookup_key}'."
                    )
                    self.add_finding(
                        finding_id="CREDENTIAL-GATE-BLOCKED",
                        target=lookup_key or "unknown",
                        title=f"State-Changing Check Aborted: {status_code} (--require-auth)",
                        spec_id="CWE-306",
                        cwe="CWE-306",
                        status="INFORMATIONAL",
                        details=(
                            f"State-modifying operation '{action_description}' was aborted because "
                            f"--require-auth/--require-creds is active and pre-flight check returned {status_code}: {reason}"
                        ),
                        remediation=f"Run 'iotflux auth set {lookup_key}' and verify with 'iotflux auth verify {lookup_key}'.",
                    )
                    return False

        logger.warning(f"AUTHORIZED SAFETY GATE CONFIRMED: Executing bounded state change: {action_description}")
        return True

    def add_finding(
        self,
        finding_id: str,
        target: str,
        title: str,
        spec_id: str,
        cwe: str,
        status: str,
        details: str,
        remediation: str,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> ValidationFinding:
        f = ValidationFinding(
            finding_id=finding_id,
            target=target,
            title=title,
            spec_id=spec_id,
            cwe=cwe,
            status=status,
            details=details,
            remediation=remediation,
            evidence=evidence or {},
        )
        self.findings.append(f)
        if "NON_COMPLIANT" in status:
            logger.failure(f"[{status}] {title} on {target} ({cwe})")
        else:
            logger.success(f"[{status}] {title} on {target}")
        return f

    def show_info(self) -> None:
        logger.header(f"MODULE: {self.name}")
        print(f" Description: {self.description}")
        print(f" Target Tier: {self.tier}")
        print(f" Author:      {self.author}")
        if self.references:
            print(" References & Specifications:")
            for r in self.references:
                sp = get_spec(r)
                if sp:
                    print(f"   * {sp.spec_id} - {sp.title} ({sp.reference_url})")
                else:
                    print(f"   * {r}")
        print()
        if self.module_options:
            print(f" {'Option':<18} {'Value':<22} {'Description'}")
            print(f" {'-'*18} {'-'*22} {'-'*30}")
            for opt, data in sorted(self.module_options.items()):
                print(f" {opt:<18} {str(data['value']):<22} {data['description']}")
            print()

    def run(self, session: FluxSession) -> List[ValidationFinding]:
        raise NotImplementedError("Subclasses must implement run()")
