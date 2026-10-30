"""
matter_auditor.py - Matter / Thread Commissioning Protocol Conformance Auditor for IoTFlux
Authorized Defensive Security Validation Lab

Audits Matter (formerly Project CHIP) and Thread Border Router commissioning interfaces:
1. Tests UDP port 5540 for active commissioning mode.
2. Dispatches a bounded PASE (Passcode-Authenticated Session Establishment) challenge frame.
3. Evaluates protocol response handling and commissioning window exposure without committing fabric credentials.
"""

from __future__ import annotations

import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from iotflux.core.logger import logger
from iotflux.core.session import FluxSession
from iotflux.modules.base import BaseValidationModule, ValidationFinding


def raw_matter_udp_probe(ip: str, port: int, timeout: float = 2.0) -> Tuple[bool, bytes]:
    """Sends a minimal Matter PASE PBKDFParamRequest frame to UDP port 5540."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    # Minimal Matter Message Header: Exchange Flags=0x00, OpCode=0x20 (PBKDFParamRequest), ExchangeID=1, ProtoID=0x0000
    probe_frame = struct.pack(">BBHH", 0x00, 0x20, 0x0001, 0x0000) + b"\x00\x00\x00\x00"
    try:
        sock.sendto(probe_frame, (ip, port))
        data, _ = sock.recvfrom(1024)
        return True, data
    except Exception:
        return False, b""
    finally:
        sock.close()


class MatterAuditor(BaseValidationModule):
    """Matter / Thread Border Router PASE Commissioning Conformance Auditor."""

    name = "conformance/matter_auditor"
    description = "Audits Matter/Thread border routers (UDP 5540) for open commissioning windows and PASE resilience."
    tier = "Smart Home Fabrics & Thread Mesh"
    references = ["CSA-MATTER-1.2", "CWE-287", "CWE-319"]
    author = "Defensive Security Research Team"

    def __init__(self) -> None:
        super().__init__()
        self.register_option("PORT", 5540, "Matter secure session UDP port (default: 5540)")
        self.register_option("TIMEOUT", 2.0, "Socket timeout in seconds")

    def run(self, session: FluxSession) -> List[ValidationFinding]:
        self.findings.clear()
        target = self.get_option("TARGET", session)
        if not target:
            logger.failure("No target specified. Set TARGET first.")
            return self.findings

        port = int(self.get_option("PORT", session) or 5540)
        timeout = float(self.get_option("TIMEOUT", session) or 2.0)

        logger.info(f"Auditing Matter / Thread node at {target}:{port}...")

        responded, resp_bytes = raw_matter_udp_probe(target, port, timeout=timeout)
        if not responded:
            logger.info(f"Matter node {target}:{port} did not respond to PASE probe.")
            self.add_finding(
                finding_id="MATTER-CLOSED-COMMISSIONING",
                target=f"{target}:{port}",
                title="Matter Commissioning Window Closed",
                spec_id="CSA-MATTER-1.2",
                cwe="CWE-287",
                status="COMPLIANT",
                details=f"Target {target}:{port} did not respond to unauthenticated PBKDFParamRequest; commissioning window is securely closed.",
                remediation="Maintain standard CSA Matter commissioning window timeouts (default max 15 minutes).",
            )
            return self.findings

        # Parse OpCode
        opcode = resp_bytes[1] if len(resp_bytes) >= 2 else None
        logger.warning(f"Matter responder returned {len(resp_bytes)} bytes (OpCode: {hex(opcode) if opcode else 'unknown'}).")

        self.add_finding(
            finding_id="MATTER-OPEN-COMMISSIONING-WINDOW",
            target=f"{target}:{port}",
            title="Matter Open Commissioning Window Active",
            spec_id="CSA-MATTER-1.2",
            cwe="CWE-287",
            status="NON_COMPLIANT",
            details=(
                f"Matter device at {target}:{port} responded to PASE commissioning challenge with {len(resp_bytes)} bytes. "
                f"Active commissioning windows allow nearby operators to initiate pairing attempts."
            ),
            remediation="Ensure commissioning mode is only opened on explicit user physical interaction (e.g. button press).",
            evidence={"response_len": len(resp_bytes), "raw_hex": resp_bytes.hex()},
        )

        return self.findings
