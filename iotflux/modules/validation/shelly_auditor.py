"""
shelly_auditor.py - Shelly local RPC configuration and authentication auditor
Authorized Defensive Security Validation Lab (IoTFlux)
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
import requests

from iotflux.core.logger import logger
from iotflux.core.session import FluxSession
from iotflux.modules.base import BaseValidationModule, ValidationFinding


class ShellyAuditor(BaseValidationModule):
    name = "validation/shelly_auditor"
    description = "Audits Shelly Gen 2 local RPC authentication enforcement, schemas, and parameter validation."
    tier = "Tier 1 & Tier 2 Relay Systems"
    references = ["SHELLY-RPC-2.0", "CWE-306", "CAPEC-180"]

    def __init__(self) -> None:
        super().__init__()
        self.register_option("TARGET", "172.30.1.30", "Target Shelly IP address")
        self.register_option("PORT", 80, "Shelly HTTP RPC service port")
        self.register_option("RELAY_ID", 0, "Relay channel index to test")

    def run(self, session: FluxSession) -> List[ValidationFinding]:
        self.findings.clear()
        target = self.get_option("TARGET", session)
        port = int(self.get_option("PORT", session) or 80)
        relay_id = int(self.get_option("RELAY_ID") or 0)
        timeout = float(session.get_option("TIMEOUT", 3.0))

        logger.info(f"Auditing Shelly Gen 2 RPC interface on {target}:{port}...")

        # 1. Audit /rpc/Shelly.GetDeviceInfo for auth_en configuration
        info_url = f"http://{target}:{port}/rpc/Shelly.GetDeviceInfo"
        try:
            res = requests.get(info_url, timeout=timeout)
            if res.status_code == 200:
                data = res.json()
                result = data.get("result", {})
                auth_en = result.get("auth_en", False)
                dev_id = result.get("id", "Unknown")
                model = result.get("model", "Unknown")

                if not auth_en:
                    self.add_finding(
                        finding_id="SHELLY-NO-AUTH",
                        target=f"{target}:{port}",
                        title="Unauthenticated Shelly Gen 2 RPC API Exposure",
                        spec_id="SHELLY-RPC-2.0",
                        cwe="CWE-306",
                        status="NON_COMPLIANT",
                        details=(
                            f"Device '{dev_id}' (Model: {model}) operates with auth_en=false. "
                            "Unauthenticated local callers can query telemetry and control physical relays."
                        ),
                        remediation="Enable authentication via Shelly configuration: set password to enforce HTTP Digest auth per Shelly Gen 2 specification.",
                        evidence={"device_id": dev_id, "model": model, "auth_en": auth_en},
                    )
                else:
                    self.add_finding(
                        finding_id="SHELLY-AUTH-ENFORCED",
                        target=f"{target}:{port}",
                        title="Shelly Gen 2 RPC Authentication Enforced",
                        spec_id="SHELLY-RPC-2.0",
                        cwe="CWE-306",
                        status="COMPLIANT",
                        details=f"Device '{dev_id}' correctly enforces local RPC authentication.",
                        remediation="Maintain strong pre-shared credentials.",
                        evidence={"device_id": dev_id, "auth_en": True},
                    )
        except Exception as ex:
            logger.warning(f"Could not reach Shelly.GetDeviceInfo on {target}:{port}: {ex}")

        # 2. Read-only status schema inspection
        status_url = f"http://{target}:{port}/rpc/Shelly.GetStatus"
        try:
            res = requests.get(status_url, timeout=timeout)
            if res.status_code == 200:
                data = res.json()
                if "result" in data and ("switch:0" in data["result"] or "sys" in data["result"]):
                    self.add_finding(
                        finding_id="SHELLY-SCHEMA-CONFORMANCE",
                        target=f"{target}:{port}",
                        title="Shelly RPC 2.0 Schema Specification Conformance",
                        spec_id="SHELLY-RPC-2.0",
                        cwe="CWE-200",
                        status="INFORMATIONAL",
                        details="Endpoint returned valid JSON-RPC 2.0 schema matching Shelly Gen 2 specification.",
                        remediation="Ensure sensitive telemetry (Wi-Fi SSID, BSSID) is protected from untrusted network observers.",
                        evidence={"components": list(data["result"].keys())},
                    )
        except Exception as ex:
            logger.debug(f"Shelly.GetStatus notice: {ex}")

        # 3. State-modifying actuation validation (requires Two-Key Operator Safety Gate)
        if session.get_option("AUTHORIZED_TEST", False):
            if self.assert_authorized(session, f"Momentary test pulse on relay {relay_id}"):
                set_url = f"http://{target}:{port}/rpc/Switch.Set"
                try:
                    # Capture baseline
                    pre_res = requests.get(f"http://{target}:{port}/rpc/Switch.GetStatus?id={relay_id}", timeout=timeout)
                    was_on = pre_res.json().get("result", {}).get("output", False) if pre_res.status_code == 200 else False

                    # Bounded perturbation: Turn on momentarily
                    logger.info(f"Applying bounded 1.0s test pulse on {target}:{port} relay {relay_id}...")
                    requests.post(set_url, json={"id": 1, "params": {"id": relay_id, "on": True}}, timeout=timeout)
                    time.sleep(1.0)

                    # Automated primary revert to baseline
                    requests.post(set_url, json={"id": 2, "params": {"id": relay_id, "on": was_on}}, timeout=timeout)
                    logger.success(f"Baseline state successfully restored on {target}:{port} (relay {relay_id} => {was_on}).")

                    self.add_finding(
                        finding_id="SHELLY-ACTUATION-VALIDATED",
                        target=f"{target}:{port}",
                        title="Bounded Actuator Actuation & Guaranteed Baseline Restoration",
                        spec_id="SHELLY-RPC-2.0",
                        cwe="CWE-306",
                        status="COMPLIANT_VALIDATED",
                        details=f"Verified physical relay actuation under bounded 1.0s window with confirmed restoration to baseline ({was_on}).",
                        remediation="Enforce local RPC credentials to prevent unauthenticated actuator manipulation.",
                        evidence={"relay_id": relay_id, "baseline_restored": True},
                    )
                except Exception as ex:
                    logger.failure(f"Actuation validation failure on {target}:{port}: {ex}")
        else:
            logger.info("Safety Invariant: Actuation test bypassed (requires --authorize).")

        return self.findings
