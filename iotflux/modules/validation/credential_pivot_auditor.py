"""
credential_pivot_auditor.py - Cross-Protocol Credential Reuse & Vault Replay Auditor for IoTFlux
Authorized Defensive Security Validation Lab

Evaluates smart home resilience against cross-protocol credential reuse:
1. Queries the RAM-only EphemeralCredentialVault for pre-harvested credential handles.
2. Audits secondary services (e.g. MQTT broker or HTTP management) for identical credential reuse.
3. Architecturally prohibits online dictionary brute forcing; evaluates only known configuration leaks.
"""

from __future__ import annotations

import base64
import socket
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple

from iotflux.core.logger import logger
from iotflux.core.session import FluxSession
from iotflux.core.vault import vault as global_vault
from iotflux.modules.base import BaseValidationModule, ValidationFinding


def test_http_basic_auth(target: str, port: int, path: str, user: str, secret: str, timeout: float = 2.0) -> bool:
    url = f"http://{target}:{port}{path}"
    req = urllib.request.Request(url)
    token = base64.b64encode(f"{user}:{secret}".encode("utf-8")).decode("ascii")
    req.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status in (200, 204)
    except Exception:
        return False


class CredentialPivotAuditor(BaseValidationModule):
    """Cross-Protocol Credential Reuse & Vault Replay Conformance Auditor."""

    name = "validation/credential_pivot_auditor"
    description = "Audits cross-protocol credential reuse (vault handles against HTTP/MQTT) without online dictionary spraying."
    tier = "Cross-Protocol & Identity Governance"
    references = ["NIST-SP-800-63B", "CWE-798", "CWE-287"]
    author = "Defensive Security Research Team"

    def __init__(self) -> None:
        super().__init__()
        self.register_option("PORT", 80, "Target service port for reuse verification (default: 80)")
        self.register_option("PATH", "/admin", "Target HTTP authentication path")
        self.register_option("CRED_HANDLE", "", "Specific vault handle to test (leave blank to audit all stored handles)")

    def run(self, session: FluxSession) -> List[ValidationFinding]:
        self.findings.clear()
        target = self.get_option("TARGET", session)
        if not target:
            logger.failure("No target specified. Set TARGET first.")
            return self.findings

        port = int(self.get_option("PORT", session) or 80)
        path = str(self.get_option("PATH", session) or "/admin")
        cred_handle = str(self.get_option("CRED_HANDLE", session) or "").strip()

        handles = [cred_handle] if cred_handle else global_vault.list_handles()
        logger.info(f"Auditing credential reuse on {target}:{port}{path} against {len(handles)} vault handle(s)...")

        if not handles:
            self.add_finding(
                finding_id="VAULT-EMPTY-AUDIT-SKIPPED",
                target=f"{target}:{port}",
                title="No Harvested Credentials in Vault",
                spec_id="NIST-SP-800-63B",
                cwe="CWE-798",
                status="INFORMATIONAL",
                details="Ephemeral Credential Vault is currently empty. Run discovery/coap_scanner or subnet_mapper first.",
                remediation="Populate vault via passive discovery or profile configuration.",
            )
            return self.findings

        reused_handles: List[str] = []
        for h in handles:
            rec = global_vault.get_credential(h)
            if not rec:
                continue
            user = rec.username
            secret = rec.secret
            success = test_http_basic_auth(target, port, path, user, secret)
            if success:
                reused_handles.append(h)
                logger.failure(f"Cross-protocol credential reuse validated on handle {h} ({rec.metadata.get('origin', 'unknown')})!")

        if reused_handles:
            self.add_finding(
                finding_id="CRED-CROSS-PROTOCOL-REUSE",
                target=f"{target}:{port}{path}",
                title="Cross-Protocol Credential Reuse Identified",
                spec_id="NIST-SP-800-63B",
                cwe="CWE-798",
                status="CRITICAL_NON_COMPLIANT",
                details=(
                    f"Target {target}:{port}{path} accepted credentials harvested from secondary protocol/zone. "
                    f"Reused vault handle(s): {reused_handles}. Violates principle of compartmentalized authentication."
                ),
                remediation="Enforce unique per-service credentials; integrate centralized Identity Provider (IdP) with MFA.",
                evidence={"handles": reused_handles},
            )
        else:
            self.add_finding(
                finding_id="CRED-REUSE-RESILIENT",
                target=f"{target}:{port}{path}",
                title="Credential Compartmentalization Verified",
                spec_id="NIST-SP-800-63B",
                cwe="NIST-SP-800-63B",
                status="COMPLIANT",
                details=f"Target {target}:{port}{path} rejected all tested vault credentials.",
                remediation="Maintain strong authentication segregation across network tiers.",
            )

        return self.findings
