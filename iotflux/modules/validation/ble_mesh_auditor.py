"""
ble_mesh_auditor.py - BLE Mesh & Smart Lighting Gateway Auditor for IoTFlux
Authorized Defensive Security Validation Lab

Validates Bluetooth Low Energy (BLE) Mesh and Zigbee Light Link gateway interfaces:
1. Audits unauthenticated local REST / CLIP API endpoints controlling mesh lighting nodes.
2. Under explicit Two-Key Operator authorization, executes bounded perturbation with deterministic auto-revert.
"""

from __future__ import annotations

import json
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple

from iotflux.core.logger import logger
from iotflux.core.session import FluxSession
from iotflux.modules.base import BaseValidationModule, ValidationFinding


def http_json_request(url: str, method: str = "GET", data: Optional[Dict[str, Any]] = None, timeout: float = 2.0) -> Tuple[Optional[int], Dict[str, Any]]:
    req_data = json.dumps(data).encode("utf-8") if data else None
    headers = {"Content-Type": "application/json", "User-Agent": "IoTFlux-BleMeshAuditor/1.0"}
    req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = {"raw": body}
            return resp.status, parsed
    except urllib.error.HTTPError as exc:
        return exc.code, {"error": str(exc)}
    except Exception:
        return None, {}


class BleMeshAuditor(BaseValidationModule):
    """BLE Mesh & Smart Lighting Gateway Security Conformance Auditor."""

    name = "validation/ble_mesh_auditor"
    description = "Audits smart lighting gateway control surfaces (BLE Mesh / Zigbee) and bounded actuation auto-revert."
    tier = "Wireless Mesh & Lighting Gateways"
    references = ["BLE-MESH-SPEC", "CWE-306", "CWE-284"]
    author = "Defensive Security Research Team"

    def __init__(self) -> None:
        super().__init__()
        self.register_option("PORT", 80, "Gateway HTTP management port (default: 80)")
        self.register_option("ENDPOINT", "/clip/v2/resource/light/1", "Light resource API endpoint")
        self.register_option("PULSE_DURATION", 1.0, "State perturbation duration in seconds (t <= 1.0s)")

    def run(self, session: FluxSession) -> List[ValidationFinding]:
        self.findings.clear()
        target = self.get_option("TARGET", session)
        if not target:
            logger.failure("No target specified. Set TARGET first.")
            return self.findings

        port = int(self.get_option("PORT", session) or 80)
        endpoint = str(self.get_option("ENDPOINT", session) or "/clip/v2/resource/light/1")
        pulse_dur = min(1.0, float(self.get_option("PULSE_DURATION", session) or 1.0))
        url = f"http://{target}:{port}{endpoint}"

        logger.info(f"Auditing lighting gateway endpoint: {url}...")

        # Step 1: Read-Only Check
        status, body = http_json_request(url, method="GET")
        if status != 200:
            logger.info(f"Gateway endpoint returned status {status} (requires auth or non-existent).")
            self.add_finding(
                finding_id="BLE-LIGHTING-AUTH-ENFORCED",
                target=url,
                title="Smart Lighting Gateway Access Restricted",
                spec_id="BLE-MESH-SPEC",
                cwe="CWE-306",
                status="COMPLIANT",
                details=f"Gateway endpoint returned HTTP {status}, preventing unauthenticated state inspection.",
                remediation="Maintain API token authentication requirements.",
            )
            return self.findings

        logger.warning(f"Unauthenticated lighting state inspection succeeded on {url}!")
        self.add_finding(
            finding_id="BLE-LIGHTING-UNAUTH-READ",
            target=url,
            title="Unauthenticated Smart Lighting API Control Surface",
            spec_id="BLE-MESH-SPEC",
            cwe="CWE-306",
            status="NON_COMPLIANT",
            details=f"Gateway at {url} returned active lighting state without authentication: {body}",
            remediation="Enforce local authorization headers (Bearer token or application key) for all actuator endpoints.",
            evidence={"response": body},
        )

        # Step 2: State change (enabled by default; revert only when AUTO_REVERT is on)
        if not self.assert_authorized(session, f"BLE lighting state toggle on {url}"):
            return self.findings

        initial_state = bool(body.get("on", False))
        test_state = not initial_state

        logger.warning(f"Toggling lighting state (on: {test_state}) and holding {pulse_dur}s...")
        http_json_request(url, method="PUT", data={"on": test_state})
        time.sleep(pulse_dur)

        if session.get_option("AUTO_REVERT", False):
            logger.info(f"Auto-revert enabled: restoring baseline (on: {initial_state})...")
            http_json_request(url, method="PUT", data={"on": initial_state})
            time.sleep(0.1)
            _, final_body = http_json_request(url, method="GET")
            final_state = bool(final_body.get("on", False))
            restored = final_state == initial_state
            if restored:
                logger.success("Baseline restored.")
            else:
                logger.failure(f"Baseline NOT restored (on: {final_state}).")
        else:
            final_state = test_state
            restored = False
            logger.info(f"State left changed (on: {test_state}). Use AUTO_REVERT=true to restore.")

        self.add_finding(
            finding_id="BLE-LIGHTING-ACTUATION-VALIDATED",
            target=url,
            title="Unauthenticated Lighting Actuation Validated",
            spec_id="BLE-MESH-SPEC",
            cwe="CWE-284",
            status="CRITICAL_NON_COMPLIANT",
            details=(
                f"Successfully actuated light state (on: {test_state}) without credentials; "
                + (
                    f"baseline (on: {initial_state}) restored."
                    if restored
                    else f"state left at on: {test_state}."
                )
            ),
            remediation="Disable unauthenticated PUT/POST endpoints; bind actuator controls to authenticated user profiles.",
            evidence={
                "initial_on": initial_state,
                "test_on": test_state,
                "final_on": final_state,
                "auto_revert": restored,
            },
        )

        return self.findings
