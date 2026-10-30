"""
tr069_auditor.py - CWMP / TR-069 Remote Management Exposure Auditor for IoTFlux
Authorized Defensive Security Validation Lab

Read-only audit of CPE WAN Management Protocol (CWMP / TR-069) listeners (port 7547):
1. TCP reachability of the CWMP management port.
2. Cleartext HTTP vs TLS (HTTPS) transport on the management endpoint.
3. Unauthenticated ACS-style interaction (GET / and a minimal SOAP CWMP probe).
4. Server / banner header capture for fingerprinting.

Maps findings to CWE-306 (Missing Authentication) and CWE-319 (Cleartext Transmission).
References the TR-069 remote-management risk class (CVE-2016-10372 family) factually
in observation / remediation text where relevant. NO state changes.
"""

from __future__ import annotations

import ssl
import socket
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from iotflux.core.logger import logger
from iotflux.core.session import FluxSession
from iotflux.modules.base import BaseValidationModule, ValidationFinding

# Minimal CWMP SOAP envelope shaped like an ACS InformResponse acknowledgement.
# Sent only to observe whether the CPE accepts unauthenticated CWMP interaction.
# Does not mutate device state (InformResponse is an ACS->CPE acknowledgement).
CWMP_SOAP_INFORM_RESPONSE = (
    '<?xml version="1.0" encoding="UTF-8"?>\r\n'
    '<soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/" '
    'xmlns:cwmp="urn:dslforum-org:cwmp-1-0">\r\n'
    "  <soap-env:Header/>\r\n"
    "  <soap-env:Body>\r\n"
    "    <cwmp:InformResponse>\r\n"
    "      <MaxEnvelopes>1</MaxEnvelopes>\r\n"
    "    </cwmp:InformResponse>\r\n"
    "  </soap-env:Body>\r\n"
    "</soap-env:Envelope>\r\n"
)

CWMP_SOAP_ACTION = '"urn:dslforum-org:cwmp-1-0#InformResponse"'


def check_tcp_port(ip: str, port: int, timeout: float = 2.5) -> bool:
    """Read-only TCP connect probe."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        sock.close()


def _http_probe(
    url: str,
    timeout: float,
    method: str = "GET",
    body: Optional[bytes] = None,
    extra_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Performs a single read-only HTTP(S) request and returns status/headers/snippet.
    TLS certificate verification is deliberately disabled so self-signed CPE certs
    still yield a readable banner (common on consumer cameras / routers).
    """
    headers = {
        "User-Agent": "IoTFlux-TR069Auditor/1.0",
        "Accept": "*/*",
    }
    if extra_headers:
        headers.update(extra_headers)

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read(2048)
            return {
                "reachable": True,
                "status": int(resp.status),
                "headers": dict(resp.headers),
                "server": resp.headers.get("Server", "") or resp.headers.get("server", ""),
                "body_snippet": raw.decode("utf-8", errors="replace")[:400],
                "error": None,
            }
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(2048)
            snippet = raw.decode("utf-8", errors="replace")[:400]
        except Exception:
            snippet = ""
        return {
            "reachable": True,
            "status": int(exc.code),
            "headers": dict(exc.headers) if exc.headers else {},
            "server": (exc.headers.get("Server", "") if exc.headers else "")
            or (exc.headers.get("server", "") if exc.headers else ""),
            "body_snippet": snippet,
            "error": f"HTTPError {exc.code}",
        }
    except Exception as exc:
        return {
            "reachable": False,
            "status": None,
            "headers": {},
            "server": "",
            "body_snippet": "",
            "error": str(exc)[:200],
        }


def probe_cwmp_endpoint(ip: str, port: int, use_tls: bool, timeout: float) -> Dict[str, Any]:
    """GET / then (if the service responds) a minimal unauthenticated CWMP SOAP POST."""
    scheme = "https" if use_tls else "http"
    base_url = f"{scheme}://{ip}:{port}/"
    get_result = _http_probe(base_url, timeout=timeout, method="GET")
    soap_result: Dict[str, Any] = {
        "reachable": False,
        "status": None,
        "headers": {},
        "server": "",
        "body_snippet": "",
        "error": "skipped",
    }
    if get_result["reachable"] or use_tls:
        # Always attempt SOAP when TLS path is requested (GET may fail on some CPE stacks
        # that only accept SOAP POSTs), and whenever GET got any HTTP response.
        soap_result = _http_probe(
            base_url,
            timeout=timeout,
            method="POST",
            body=CWMP_SOAP_INFORM_RESPONSE.encode("utf-8"),
            extra_headers={
                "Content-Type": 'text/xml; charset="utf-8"',
                "SOAPAction": CWMP_SOAP_ACTION,
            },
        )
    return {
        "scheme": scheme,
        "base_url": base_url,
        "get": get_result,
        "soap": soap_result,
    }


def _auth_enforced(status: Optional[int]) -> bool:
    return status in (401, 403)


def _unauth_accepted(status: Optional[int], body: str) -> bool:
    """Heuristic: 2xx to unauthenticated CWMP/GET, or SOAP Fault that still proves ACS interaction."""
    if status is None:
        return False
    if 200 <= status < 300:
        return True
    # SOAP Fault / CWMP error bodies still indicate the CPE processed unauthenticated CWMP input
    low = (body or "").lower()
    if status in (500,) and ("soap" in low or "cwmp" in low or "fault" in low):
        return True
    return False


class TR069Auditor(BaseValidationModule):
    """CWMP / TR-069 Remote Management Conformance Auditor (read-only)."""

    name = "validation/tr069_auditor"
    description = (
        "Audits CWMP/TR-069 (port 7547) for unauthenticated ACS interaction, "
        "cleartext transport, and management banner disclosure."
    )
    tier = "Tier 3 - Perimeter Video & Remote Management"
    references = ["CWE-306", "CWE-319", "CVE-2016-10372"]
    author = "Defensive Security Research Team"

    def __init__(self) -> None:
        super().__init__()
        self.register_option("PORT", 7547, "Target CWMP / TR-069 management port (default: 7547)")
        self.register_option("TIMEOUT", 3.0, "Connection timeout in seconds")

    def run(self, session: FluxSession) -> List[ValidationFinding]:
        self.findings.clear()
        target = self.get_option("TARGET", session)
        if not target:
            logger.failure("No target specified. Set TARGET first.")
            return self.findings

        port = int(self.get_option("PORT", session) or 7547)
        timeout = float(
            self.get_option("TIMEOUT", session)
            or session.get_option("TIMEOUT", 3.0)
            or 3.0
        )

        logger.info(f"Auditing CWMP/TR-069 remote-management endpoint on {target}:{port}...")

        # 1. Port reachability
        if not check_tcp_port(str(target), port, timeout=timeout):
            logger.info(f"CWMP port {port} on {target} is closed or filtered.")
            self.add_finding(
                finding_id="TR069-PORT-CLOSED",
                target=f"{target}:{port}",
                title="CWMP / TR-069 Management Port Inactive or Unreachable",
                spec_id="CWE-306",
                cwe="CWE-306",
                status="COMPLIANT",
                details=(
                    f"Target {target}:{port} did not accept TCP connections for CWMP/TR-069. "
                    "Remote-management surface appears disabled or firewalled."
                ),
                remediation=(
                    "Keep CWMP/TR-069 disabled when unused. If ACS management is required, "
                    "restrict source IPs and prefer TLS-only CWMP."
                ),
            )
            return self.findings

        logger.info(f"CWMP port {port} is open on {target}; probing HTTP and HTTPS endpoints...")

        cleartext = probe_cwmp_endpoint(str(target), port, use_tls=False, timeout=timeout)
        tls = probe_cwmp_endpoint(str(target), port, use_tls=True, timeout=timeout)

        clear_ok = bool(cleartext["get"]["reachable"] or cleartext["soap"]["reachable"])
        tls_ok = bool(tls["get"]["reachable"] or tls["soap"]["reachable"])

        server_banner = (
            cleartext["get"].get("server")
            or cleartext["soap"].get("server")
            or tls["get"].get("server")
            or tls["soap"].get("server")
            or ""
        )

        evidence: Dict[str, Any] = {
            "port": port,
            "server_banner": server_banner,
            "cleartext": {
                "get_status": cleartext["get"].get("status"),
                "soap_status": cleartext["soap"].get("status"),
                "reachable": clear_ok,
            },
            "tls": {
                "get_status": tls["get"].get("status"),
                "soap_status": tls["soap"].get("status"),
                "reachable": tls_ok,
            },
        }

        if not clear_ok and not tls_ok:
            self.add_finding(
                finding_id="TR069-PORT-OPEN-NO-HTTP",
                target=f"{target}:{port}",
                title="CWMP Port Open but No HTTP(S) CWMP Response",
                spec_id="CWE-306",
                cwe="CWE-306",
                status="INFORMATIONAL",
                details=(
                    f"TCP {target}:{port} accepts connections but did not return an HTTP or HTTPS "
                    f"CWMP response to unauthenticated GET/SOAP probes. Banner: '{server_banner or 'none'}'. "
                    "May be a non-HTTP CWMP variant or require a specific ACS handshake."
                ),
                remediation=(
                    "Confirm whether CWMP is required. Disable unused TR-069 listeners. "
                    "Restrict management to authenticated, TLS-only ACS paths."
                ),
                evidence=evidence,
            )
            return self.findings

        # 2. Cleartext transport finding
        if clear_ok:
            self.add_finding(
                finding_id="TR069-CLEARTEXT-TRANSPORT",
                target=f"http://{target}:{port}/",
                title="CWMP / TR-069 Cleartext HTTP Management Transport",
                spec_id="CWE-319",
                cwe="CWE-319",
                status="NON_COMPLIANT",
                details=(
                    f"CWMP endpoint at http://{target}:{port}/ responds over cleartext HTTP "
                    f"(GET status={cleartext['get'].get('status')}, "
                    f"SOAP status={cleartext['soap'].get('status')}). "
                    f"Server banner: '{server_banner or 'unknown'}'. "
                    "Cleartext TR-069/CWMP management has historically been abused for remote "
                    "compromise of CPE devices (risk class associated with CVE-2016-10372 family)."
                ),
                remediation=(
                    "Disable cleartext CWMP. Prefer TLS-only ACS connectivity, restrict source "
                    "addresses, and disable TR-069 entirely when remote management is unused."
                ),
                evidence=evidence,
            )

        # 3. Authentication posture (prefer the transport that actually answered)
        primary = cleartext if clear_ok else tls
        primary_label = primary["scheme"]
        get_status = primary["get"].get("status")
        soap_status = primary["soap"].get("status")
        get_body = primary["get"].get("body_snippet") or ""
        soap_body = primary["soap"].get("body_snippet") or ""

        unauth_get = _unauth_accepted(get_status, get_body)
        unauth_soap = _unauth_accepted(soap_status, soap_body)
        auth_get = _auth_enforced(get_status)
        auth_soap = _auth_enforced(soap_status)

        if unauth_get or unauth_soap:
            which = []
            if unauth_get:
                which.append(f"GET status={get_status}")
            if unauth_soap:
                which.append(f"SOAP InformResponse probe status={soap_status}")
            self.add_finding(
                finding_id="TR069-UNAUTH-ACS",
                target=f"{primary_label}://{target}:{port}/",
                title="Unauthenticated CWMP / TR-069 ACS Interaction Accepted",
                spec_id="CWE-306",
                cwe="CWE-306",
                status="CRITICAL_NON_COMPLIANT",
                details=(
                    f"CWMP service at {primary_label}://{target}:{port}/ accepted unauthenticated "
                    f"management interaction ({', '.join(which)}). "
                    f"Server banner: '{server_banner or 'unknown'}'. "
                    "Missing authentication on TR-069/CWMP remote-management endpoints enables "
                    "unauthorized ACS-style control of the CPE (risk class associated with the "
                    "CVE-2016-10372 / Mirai-era TR-069 exploitation family)."
                ),
                remediation=(
                    "Require ACS authentication (digest/mutual TLS), disable anonymous CWMP, "
                    "firewall port 7547 from untrusted networks, and disable TR-069 if unused."
                ),
                evidence={
                    **evidence,
                    "unauth_get": unauth_get,
                    "unauth_soap": unauth_soap,
                    "get_snippet": get_body[:200],
                    "soap_snippet": soap_body[:200],
                },
            )
        elif auth_get or auth_soap:
            self.add_finding(
                finding_id="TR069-AUTH-ENFORCED",
                target=f"{primary_label}://{target}:{port}/",
                title="CWMP / TR-069 Authentication Enforced",
                spec_id="CWE-306",
                cwe="CWE-306",
                status="COMPLIANT",
                details=(
                    f"CWMP service at {primary_label}://{target}:{port}/ rejected unauthenticated "
                    f"requests (GET={get_status}, SOAP={soap_status}). "
                    f"Server banner: '{server_banner or 'unknown'}'."
                ),
                remediation=(
                    "Maintain CWMP authentication. Prefer TLS-only transport and restrict ACS "
                    "source addresses. Disable TR-069 when remote management is not required."
                ),
                evidence=evidence,
            )
        else:
            self.add_finding(
                finding_id="TR069-SERVICE-REACHABLE",
                target=f"{primary_label}://{target}:{port}/",
                title="CWMP / TR-069 Service Reachable (Auth Posture Inconclusive)",
                spec_id="CWE-306",
                cwe="CWE-306",
                status="INFORMATIONAL",
                details=(
                    f"CWMP endpoint at {primary_label}://{target}:{port}/ is reachable "
                    f"(GET={get_status}, SOAP={soap_status}) but authentication posture could not "
                    f"be classified as clearly enforced or clearly open. "
                    f"Server banner: '{server_banner or 'unknown'}'."
                ),
                remediation=(
                    "Manually verify ACS authentication requirements. Disable unused TR-069 "
                    "listeners and restrict port 7547 exposure."
                ),
                evidence=evidence,
            )

        if tls_ok and not clear_ok:
            self.add_finding(
                finding_id="TR069-TLS-ONLY",
                target=f"https://{target}:{port}/",
                title="CWMP / TR-069 Served Over TLS Only",
                spec_id="CWE-319",
                cwe="CWE-319",
                status="COMPLIANT",
                details=(
                    f"CWMP endpoint responds on HTTPS only at https://{target}:{port}/ "
                    f"(GET={tls['get'].get('status')}, SOAP={tls['soap'].get('status')}). "
                    "Cleartext HTTP CWMP was not observed."
                ),
                remediation="Maintain TLS-only CWMP and keep cleartext listeners disabled.",
                evidence=evidence,
            )

        return self.findings
