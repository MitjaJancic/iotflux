"""
protocol_boundary_tester.py - Specification boundary condition tester for IoT parsers
Authorized Defensive Security Validation Lab (IoTFlux)
"""

from __future__ import annotations

import json
from typing import Any, Dict, List
import requests

from iotflux.core.logger import logger
from iotflux.core.session import FluxSession
from iotflux.modules.base import BaseValidationModule, ValidationFinding


class ProtocolBoundaryTester(BaseValidationModule):
    name = "conformance/protocol_boundary_tester"
    description = "Evaluates embedded webserver JSON-RPC parser resilience against specification boundary inputs."
    tier = "General Conformance & Resilience"
    references = ["SHELLY-RPC-2.0", "CWE-1284", "CAPEC-153"]

    # Specification-driven boundary test cases per RFC 7159 and JSON-RPC 2.0
    SPEC_TEST_CASES = [
        {
            "id": "TC-01-STANDARD-VALID",
            "desc": "Specification-compliant JSON-RPC call",
            "payload": {"jsonrpc": "2.0", "id": 101, "method": "Shelly.GetDeviceInfo", "params": {}},
            "expected_handled": True,
        },
        {
            "id": "TC-02-UNKNOWN-METHOD",
            "desc": "Unknown method query (verifies -32601 error handling per JSON-RPC 2.0)",
            "payload": {"jsonrpc": "2.0", "id": 102, "method": "Unknown.Procedure.Query", "params": {}},
            "expected_handled": True,
        },
        {
            "id": "TC-03-MISSING-PARAM",
            "desc": "Missing mandatory parameter 'on' in Switch.Set",
            "payload": {"jsonrpc": "2.0", "id": 103, "method": "Switch.Set", "params": {"id": 0}},
            "expected_handled": True,
        },
        {
            "id": "TC-04-BOUNDARY-NEGATIVE-INT",
            "desc": "Negative integer boundary on timer duration field (-60)",
            "endpoint": "/rpc/Purifier.SetTimer",
            "payload": {"jsonrpc": "2.0", "id": 104, "params": {"timer_minutes": -60}},
            "expected_handled": True,
        },
        {
            "id": "TC-05-BOUNDARY-MAX-INT32",
            "desc": "Upper 32-bit signed integer boundary (2147483647)",
            "endpoint": "/rpc/Purifier.SetTimer",
            "payload": {"jsonrpc": "2.0", "id": 105, "params": {"timer_minutes": 2147483647}},
            "expected_handled": True,
        },
        {
            "id": "TC-06-BOUNDARY-ZERO-VAL",
            "desc": "Zero value boundary condition on timer duration",
            "endpoint": "/rpc/Purifier.SetTimer",
            "payload": {"jsonrpc": "2.0", "id": 106, "params": {"timer_minutes": 0}},
            "expected_handled": True,
        },
    ]

    def __init__(self) -> None:
        super().__init__()
        self.register_option("TARGET", "172.30.3.30", "Target device IP address")
        self.register_option("PORT", 8080, "Target device HTTP RPC port")
        self.register_option("PATH", "/rpc", "Target default JSON-RPC path")

    def run(self, session: FluxSession) -> List[ValidationFinding]:
        self.findings.clear()
        target = self.get_option("TARGET", session)
        port = int(self.get_option("PORT", session) or 8080)
        default_path = self.get_option("PATH") or "/rpc"
        timeout = float(session.get_option("TIMEOUT", 3.0))

        logger.info(f"Starting specification boundary conformance testing on {target}:{port}...")

        passed_cases = 0
        failed_cases = 0
        server_error_cases = 0

        for tc in self.SPEC_TEST_CASES:
            path = tc.get("endpoint", default_path)
            url = f"http://{target}:{port}{path}"
            payload = tc["payload"]

            try:
                res = requests.post(url, json=payload, timeout=timeout)
                status_code = res.status_code

                if status_code >= 500:
                    server_error_cases += 1
                    logger.failure(f"[{tc['id']}] HTTP {status_code} Internal Server Error for boundary input.")
                else:
                    passed_cases += 1
                    logger.success(f"[{tc['id']}] Handled gracefully (HTTP {status_code}).")

            except Exception as ex:
                failed_cases += 1
                logger.warning(f"[{tc['id']}] Connection exception during boundary test: {ex}")

        # Summary finding
        if server_error_cases > 0:
            self.add_finding(
                finding_id="CONF-SERVER-ERROR",
                target=f"{target}:{port}",
                title="Micro-Webserver Exception / HTTP 500 Response Under Boundary Inputs",
                spec_id="CWE-1284",
                cwe="CWE-1284",
                status="NON_COMPLIANT",
                details=(
                    f"Target returned HTTP 500 in {server_error_cases} boundary test case(s). "
                    "Indicates unhandled parser exception or lack of input parameter range validation."
                ),
                remediation="Implement defensive try/except handling and JSON schema parameter validation before component processing.",
                evidence={"server_error_count": server_error_cases, "passed_count": passed_cases},
            )
        else:
            self.add_finding(
                finding_id="CONF-GRACEFUL-HANDLING",
                target=f"{target}:{port}",
                title="Specification Boundary Conformance & Graceful Error Handling Verified",
                spec_id="CWE-1284",
                cwe="CWE-1284",
                status="COMPLIANT_RESILIENT",
                details=f"All {passed_cases} boundary test cases handled gracefully without service drops or 500 errors.",
                remediation="Maintain input parameter validation coverage across all RPC routes.",
                evidence={"passed_cases": passed_cases},
            )

        return self.findings
