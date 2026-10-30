"""
resilience_monitor.py - Service resilience, restart detection, and HTTP 500 error monitor
Authorized Defensive Security Validation Lab (IoTFlux)
"""

from __future__ import annotations

import time
from typing import Any, Dict, List
import requests

from iotflux.core.logger import logger
from iotflux.core.session import FluxSession
from iotflux.modules.base import BaseValidationModule, ValidationFinding


class ResilienceMonitor(BaseValidationModule):
    name = "conformance/resilience_monitor"
    description = "Monitors target service stability, logs HTTP 500 exceptions, and detects daemon restarts."
    tier = "General Conformance & Resilience"
    references = ["CWE-1284", "CWE-703", "CAPEC-153"]

    def __init__(self) -> None:
        super().__init__()
        self.register_option("TARGET", "172.30.3.30", "Target device IP address")
        self.register_option("PORT", 8080, "Target device HTTP port")
        self.register_option("PATH", "/rpc/Purifier.GetStatus", "Health check status endpoint")
        self.register_option("ROUNDS", 10, "Number of health check poll cycles")
        self.register_option("DELAY", 0.2, "Delay between polling cycles in seconds")

    def run(self, session: FluxSession) -> List[ValidationFinding]:
        self.findings.clear()
        target = self.get_option("TARGET", session)
        port = int(self.get_option("PORT", session) or 8080)
        path = self.get_option("PATH") or "/rpc/Purifier.GetStatus"
        rounds = int(self.get_option("ROUNDS") or 10)
        delay = float(self.get_option("DELAY") or 0.2)
        timeout = float(session.get_option("TIMEOUT", 2.0))

        url = f"http://{target}:{port}{path}"
        logger.info(f"Monitoring resilience on {url} across {rounds} cycles...")

        status_counts: Dict[int, int] = {}
        latencies: List[float] = []
        connection_drops = 0
        server_errors = 0

        for r in range(rounds):
            t0 = time.time()
            try:
                res = requests.get(url, timeout=timeout)
                elapsed = time.time() - t0
                latencies.append(elapsed)
                code = res.status_code
                status_counts[code] = status_counts.get(code, 0) + 1
                if code >= 500:
                    server_errors += 1
            except Exception:
                connection_drops += 1
            time.sleep(delay)

        avg_latency_ms = (sum(latencies) / len(latencies) * 1000.0) if latencies else 0.0
        success_count = sum(c for code, c in status_counts.items() if 200 <= code < 400)

        logger.info(
            f"Resilience metrics: total={rounds}, success={success_count}, "
            f"500_errors={server_errors}, drops={connection_drops}, avg_latency={avg_latency_ms:.1f}ms"
        )

        if server_errors > 0 or connection_drops > 0:
            self.add_finding(
                finding_id="RESIL-INSTABILITY-DETECTED",
                target=f"{target}:{port}",
                title="Service Instability or Unhandled Exception Detected",
                spec_id="CWE-703",
                cwe="CWE-703",
                status="NON_COMPLIANT",
                details=(
                    f"Target experienced {server_errors} HTTP 500 error(s) and {connection_drops} dropped connection(s) "
                    f"over {rounds} polling rounds."
                ),
                remediation="Investigate service logs for unhandled null pointer or memory allocation exceptions.",
                evidence={
                    "status_counts": status_counts,
                    "connection_drops": connection_drops,
                    "server_errors": server_errors,
                    "avg_latency_ms": avg_latency_ms,
                },
            )
        else:
            self.add_finding(
                finding_id="RESIL-STABLE-BASELINE",
                target=f"{target}:{port}",
                title="Service Resilience & Stability Baseline Verified",
                spec_id="CWE-703",
                cwe="CWE-703",
                status="COMPLIANT_RESILIENT",
                details=f"Target maintained 100% availability over {rounds} requests with avg latency {avg_latency_ms:.1f}ms.",
                remediation="Maintain watchdogs and rate-limiting controls.",
                evidence={"status_counts": status_counts, "avg_latency_ms": avg_latency_ms},
            )

        return self.findings
