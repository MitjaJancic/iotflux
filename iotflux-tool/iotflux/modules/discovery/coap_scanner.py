"""
coap_scanner.py - RFC 7252 / RFC 6690 CoAP Resource & Telemetry Auditor for IoTFlux
Authorized Defensive Security Validation Lab

Discovers and audits Constrained Application Protocol (CoAP) endpoints over UDP port 5683:
1. Queries RFC 6690 resource discovery endpoint (GET /.well-known/core).
2. Parses CoRE Link-Format manifests to enumerate declared URI paths.
3. Audits discovered paths for unauthenticated sensitive configuration or state leakage.
"""

from __future__ import annotations

import re
import socket
import struct
import uuid
from typing import Any, Dict, List, Optional, Tuple

from iotflux.core.logger import logger
from iotflux.core.session import FluxSession
from iotflux.modules.base import BaseValidationModule, ValidationFinding


def encode_coap_get(path: str, message_id: int) -> bytes:
    """Encodes minimal RFC 7252 CoAP GET request: Type=CON, Code=0.01 (GET)."""
    header = bytes([0x40, 0x01]) + struct.pack(">H", message_id)
    options = b""
    prev_option_num = 0
    for segment in [s for s in path.split("/") if s]:
        delta = 11 - prev_option_num  # Uri-Path = Option 11
        seg_bytes = segment.encode("utf-8")
        if delta < 13 and len(seg_bytes) < 13:
            options += bytes([(delta << 4) | len(seg_bytes)]) + seg_bytes
            prev_option_num = 11
    return header + options


def extract_coap_payload(resp: bytes) -> str:
    if not resp or b"\xff" not in resp:
        return ""
    _, _, payload = resp.partition(b"\xff")
    return payload.decode("utf-8", errors="replace").strip()


def probe_coap_endpoint(ip: str, port: int, path: str, timeout: float = 2.0) -> Tuple[Optional[int], str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    msg_id = uuid.uuid4().int & 0xFFFF
    req = encode_coap_get(path, msg_id)
    try:
        sock.sendto(req, (ip, port))
        resp, _ = sock.recvfrom(4096)
        if len(resp) < 2:
            return None, ""
        code = resp[1]
        code_class = code >> 5
        payload = extract_coap_payload(resp)
        return code_class, payload
    except Exception:
        return None, ""
    finally:
        sock.close()


class CoapScanner(BaseValidationModule):
    """RFC 7252 Constrained Application Protocol (CoAP) Discovery & Security Auditor."""

    name = "discovery/coap_scanner"
    description = "Discovers CoAP nodes (UDP 5683), queries /.well-known/core, and audits unauthenticated resources."
    tier = "Constrained IoT & Sensor Mesh"
    references = ["RFC-7252-COAP", "CWE-306", "CWE-319"]
    author = "Defensive Security Research Team"

    def __init__(self) -> None:
        super().__init__()
        self.register_option("PORT", 5683, "CoAP UDP port (default: 5683)")
        self.register_option("TIMEOUT", 2.0, "Socket timeout in seconds")

    def run(self, session: FluxSession) -> List[ValidationFinding]:
        self.findings.clear()
        target = self.get_option("TARGET", session)
        if not target:
            logger.failure("No target specified. Set TARGET first.")
            return self.findings

        port = int(self.get_option("PORT", session) or 5683)
        timeout = float(self.get_option("TIMEOUT", session) or 2.0)

        logger.info(f"Auditing CoAP node on {target}:{port}...")

        # 1. Query /.well-known/core
        code_class, core_links = probe_coap_endpoint(target, port, "/.well-known/core", timeout=timeout)
        if code_class != 2:
            logger.info(f"CoAP endpoint {target}:{port} is unreachable or did not return 2.xx on /.well-known/core.")
            self.add_finding(
                finding_id="COAP-NOT-DETECTED",
                target=f"{target}:{port}",
                title="CoAP Service Not Responsive",
                spec_id="RFC-7252-COAP",
                cwe="CWE-306",
                status="COMPLIANT",
                details=f"Target {target}:{port} did not respond to unauthenticated CoAP discovery probes.",
                remediation="Maintain existing UDP port filtering or DTLS protections.",
            )
            return self.findings

        # Discovered paths
        discovered_paths = re.findall(r"<([^>]+)>", core_links)
        logger.warning(f"CoAP node discovered! Exposed resources: {discovered_paths or core_links}")

        self.add_finding(
            finding_id="COAP-RESOURCE-DISCOVERY-EXPOSED",
            target=f"{target}:{port}",
            title="Unauthenticated CoAP Resource Discovery (.well-known/core)",
            spec_id="RFC-7252-COAP",
            cwe="CWE-306",
            status="NON_COMPLIANT",
            details=(
                f"CoAP server at {target}:{port} answered unauthenticated GET /.well-known/core, "
                f"exposing resource topology: {core_links}"
            ),
            remediation="Enforce Datagram Transport Layer Security (DTLS) per RFC 7252 Section 9 with PSK or RPK.",
            evidence={"links": core_links, "paths": discovered_paths},
        )

        # 2. Probe candidate paths for sensitive configuration or telemetry
        candidate_paths = discovered_paths if discovered_paths else ["/config", "/status", "/device", "/sensor"]
        for p in candidate_paths:
            p_class, p_payload = probe_coap_endpoint(target, port, p, timeout=timeout)
            if p_class == 2 and p_payload:
                is_sensitive = any(k in p.lower() or k in p_payload.lower() for k in ("config", "pass", "cred", "key", "token", "auth"))
                status = "CRITICAL_NON_COMPLIANT" if is_sensitive else "NON_COMPLIANT"
                self.add_finding(
                    finding_id=f"COAP-UNAUTH-READ-{abs(hash(p)) % 10000:04d}",
                    target=f"{target}:{port}{p}",
                    title=f"Unauthenticated CoAP Resource Exposure ({p})",
                    spec_id="RFC-7252-COAP",
                    cwe="CWE-319" if not is_sensitive else "CWE-306",
                    status=status,
                    details=f"Resource {p} returned unauthenticated payload (2.05 Content): {p_payload[:200]}",
                    remediation="Require DTLS authentication before responding to CoAP resource queries.",
                    evidence={"path": p, "payload": p_payload},
                )

        return self.findings
