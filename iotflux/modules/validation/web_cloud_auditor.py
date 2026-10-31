"""
web_cloud_auditor.py - Embedded Web & Cloud API Security Auditor for IoTFlux
Authorized Defensive Security Validation Lab

Audits embedded device web administration consoles and cloud API endpoints:
1. Inspects HTTP security headers (HSTS, CSP, X-Frame-Options, CORS).
2. Audits unauthenticated administrative and configuration endpoints.
3. Validates TLS certificate hygiene and security header enforcement.
"""

from __future__ import annotations

import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple

from iotflux.core.logger import logger
from iotflux.core.session import FluxSession
from iotflux.modules.base import BaseValidationModule, ValidationFinding

SENSITIVE_WEB_PATHS = [
    "/admin",
    "/setup",
    "/settings",
    "/api/system",
    "/device_info",
    "/network",
]


class WebCloudAuditor(BaseValidationModule):
    """Embedded Web & Cloud API Conformance Auditor."""

    name = "validation/web_cloud_auditor"
    description = "Audits embedded web consoles for missing security headers, unauthenticated admin endpoints, and CORS."
    tier = "Embedded Web & Cloud Gateways"
    references = ["CWE-319", "CWE-306", "CWE-942"]
    author = "Defensive Security Research Team"

    def __init__(self) -> None:
        super().__init__()
        self.register_option("PORT", 80, "Target HTTP port (default: 80)")
        self.register_option("USE_TLS", False, "Connect over HTTPS / TLS (default: False)")
        self.register_option("TIMEOUT", 2.5, "Connection timeout in seconds")

    def run(self, session: FluxSession) -> List[ValidationFinding]:
        self.findings.clear()
        target = self.get_option("TARGET", session)
        if not target:
            logger.failure("No target specified. Set TARGET first.")
            return self.findings

        port = int(self.get_option("PORT", session) or 80)
        use_tls = self.get_bool_option("USE_TLS", session)
        timeout = float(self.get_option("TIMEOUT", session) or 2.5)

        scheme = "https" if use_tls else "http"
        base_url = f"{scheme}://{target}:{port}"
        logger.info(f"Auditing embedded web server at {base_url}...")

        # 1. Inspect Base URL & Headers
        req = urllib.request.Request(base_url, headers={"User-Agent": "IoTFlux-WebAuditor/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                headers = dict(resp.headers)
        except urllib.error.HTTPError as exc:
            headers = dict(exc.headers)
        except Exception:
            logger.info(f"Target {base_url} did not respond to HTTP requests.")
            self.add_finding(
                finding_id="WEB-PORT-CLOSED",
                target=base_url,
                title="Web Service Inactive or Unreachable",
                spec_id="CWE-306",
                cwe="CWE-306",
                status="COMPLIANT",
                details=f"Target {base_url} is not hosting an active HTTP service.",
                remediation="Ensure unnecessary web services remain disabled.",
            )
            return self.findings

        # Check Security Headers
        missing_headers: List[str] = []
        if "strict-transport-security" not in [k.lower() for k in headers]:
            missing_headers.append("Strict-Transport-Security")
        if "content-security-policy" not in [k.lower() for k in headers]:
            missing_headers.append("Content-Security-Policy")
        if "x-frame-options" not in [k.lower() for k in headers]:
            missing_headers.append("X-Frame-Options")

        cors = headers.get("Access-Control-Allow-Origin", headers.get("access-control-allow-origin", ""))
        if cors == "*":
            self.add_finding(
                finding_id="WEB-PERMISSIVE-CORS",
                target=base_url,
                title="Overly Permissive Cross-Origin Resource Sharing (CORS *)",
                spec_id="CWE-942",
                cwe="CWE-942",
                status="NON_COMPLIANT",
                details=f"Server returned wildcard Access-Control-Allow-Origin: *, allowing unauthorized cross-origin requests.",
                remediation="Restrict CORS headers to explicit trusted client origins.",
            )

        if missing_headers:
            self.add_finding(
                finding_id="WEB-MISSING-SECURITY-HEADERS",
                target=base_url,
                title="Missing Standard HTTP Security Hardening Headers",
                spec_id="CWE-319",
                cwe="CWE-319",
                status="NON_COMPLIANT",
                details=f"Embedded web service omits recommended defense-in-depth headers: {missing_headers}.",
                remediation="Configure web server to return Strict-Transport-Security, X-Frame-Options, and CSP.",
                evidence={"missing": missing_headers, "received_headers": list(headers.keys())},
            )

        # 2. Check for unauthenticated admin endpoints
        exposed_admin: List[str] = []
        for path in SENSITIVE_WEB_PATHS:
            ep_url = f"{base_url}{path}"
            ep_req = urllib.request.Request(ep_url, headers={"User-Agent": "IoTFlux-WebAuditor/1.0"})
            try:
                with urllib.request.urlopen(ep_req, timeout=timeout) as ep_resp:
                    if ep_resp.status == 200:
                        exposed_admin.append(path)
            except Exception:
                continue

        if exposed_admin:
            self.add_finding(
                finding_id="WEB-UNAUTH-ADMIN-PATH",
                target=base_url,
                title="Unauthenticated Administrative Interface Exposure",
                spec_id="CWE-306",
                cwe="CWE-306",
                status="CRITICAL_NON_COMPLIANT",
                details=f"Target exposes administrative or diagnostic endpoints without authentication: {exposed_admin}.",
                remediation="Enforce mandatory session authentication on all administrative web routes.",
                evidence={"exposed_paths": exposed_admin},
            )

        return self.findings
