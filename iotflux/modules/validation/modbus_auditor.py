"""
modbus_auditor.py - Industrial Modbus TCP & SCADA Conformance Auditor for IoTFlux
Authorized Defensive Security Validation Lab

Evaluates industrial SCADA / PLC / HMI Modbus TCP interfaces (port 502):
1. Audits unauthenticated holding register (FC 0x03) and coil (FC 0x01) read operations.
2. Under explicit Two-Key Operator authorization, validates bounded setpoint perturbation (FC 0x06)
   with deterministic auto-revert within the safety pulse window (t <= 2.0s).
"""

from __future__ import annotations

import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from iotflux.core.logger import logger
from iotflux.core.session import FluxSession
from iotflux.modules.base import BaseValidationModule, ValidationFinding


def raw_modbus_read_holding_register(ip: str, port: int, register: int = 3, timeout: float = 2.0) -> Tuple[bool, Optional[int]]:
    """Sends Modbus TCP FC 0x03 (Read Holding Registers) request."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        # MBAP: TransID=0x0001, ProtoID=0x0000, Len=6, UnitID=1, FC=0x03, RegAddr, Count=1
        req = struct.pack(">HHHBBHH", 0x0001, 0x0000, 6, 1, 0x03, register & 0xFFFF, 1)
        sock.sendall(req)
        resp = sock.recv(1024)
        if len(resp) >= 11 and not (resp[7] & 0x80):
            val = struct.unpack(">H", resp[9:11])[0]
            return True, val
        return False, None
    except Exception:
        return False, None
    finally:
        sock.close()


def raw_modbus_write_register(ip: str, port: int, register: int, value: int, timeout: float = 2.0) -> bool:
    """Sends Modbus TCP FC 0x06 (Write Single Register) request."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        # MBAP: TransID=0x0002, ProtoID=0x0000, Len=6, UnitID=1, FC=0x06, RegAddr, RegVal
        req = struct.pack(">HHHBBHH", 0x0002, 0x0000, 6, 1, 0x06, register & 0xFFFF, value & 0xFFFF)
        sock.sendall(req)
        resp = sock.recv(1024)
        if len(resp) >= 12 and not (resp[7] & 0x80):
            ret_addr, ret_val = struct.unpack(">HH", resp[8:12])
            return ret_addr == (register & 0xFFFF) and ret_val == (value & 0xFFFF)
        return False
    except Exception:
        return False
    finally:
        sock.close()


class ModbusAuditor(BaseValidationModule):
    """Industrial SCADA / Modbus TCP Supervisory Control Conformance Auditor."""

    name = "validation/modbus_auditor"
    description = "Audits Modbus TCP supervisory control exposure (FC 0x03) and bounded register auto-revert (FC 0x06)."
    tier = "Industrial & Operational Technology (OT)"
    references = ["MODBUS-TCP-SPEC", "CWE-306", "CWE-284"]
    author = "Defensive Security Research Team"

    def __init__(self) -> None:
        super().__init__()
        self.register_option("PORT", 502, "Target Modbus TCP supervisory port (default: 502)")
        self.register_option("REGISTER", 3, "Target holding register address to audit")
        self.register_option("BASELINE_VAL", 100, "Expected baseline process setpoint value")
        self.register_option("TEST_VAL", 101, "Bounded test setpoint value for perturbation check")
        self.register_option("PULSE_DURATION", 1.0, "Maximum allowable perturbation duration in seconds (t <= 2.0s)")

    def run(self, session: FluxSession) -> List[ValidationFinding]:
        self.findings.clear()
        target = self.get_option("TARGET", session)
        if not target:
            logger.failure("No target specified. Set TARGET first.")
            return self.findings

        port = int(self.get_option("PORT", session) or 502)
        reg_addr = int(self.get_option("REGISTER", session) or 3)
        baseline_val = int(self.get_option("BASELINE_VAL", session) or 100)
        test_val = int(self.get_option("TEST_VAL", session) or 101)
        pulse_dur = min(2.0, float(self.get_option("PULSE_DURATION", session) or 1.0))

        logger.info(f"Auditing Modbus TCP controller on {target}:{port} (Register {reg_addr})...")

        # Step 1: Read-Only Audit (FC 0x03)
        success, current_val = raw_modbus_read_holding_register(target, port, reg_addr)
        if not success:
            logger.info(f"Modbus port {port} on {target} did not respond to unauthenticated FC 0x03 read.")
            self.add_finding(
                finding_id="MODBUS-UNREACHABLE",
                target=f"{target}:{port}",
                title="Modbus TCP Supervisory Port Inaccessible or Filtered",
                spec_id="MODBUS-TCP-SPEC",
                cwe="CWE-306",
                status="COMPLIANT",
                details=f"Target {target}:{port} did not accept unauthenticated Modbus TCP connections.",
                remediation="Maintain existing firewall rules and protocol filtering on OT perimeter.",
            )
            return self.findings

        logger.warning(f"Unauthenticated Modbus TCP response received: Register {reg_addr} = {current_val}")
        self.add_finding(
            finding_id="MODBUS-UNAUTH-READ-EXPOSED",
            target=f"{target}:{port}",
            title="Unauthenticated Modbus TCP Supervisory Register Exposure",
            spec_id="MODBUS-TCP-SPEC",
            cwe="CWE-306",
            status="NON_COMPLIANT",
            details=(
                f"Modbus controller at {target}:{port} allows unauthenticated FC 0x03 read of Holding Register {reg_addr} "
                f"(current value: {current_val}). In industrial environments, unauthenticated access permits process telemetry reconnaissance."
            ),
            remediation="Implement Modbus/TCP Security (TLS encapsulation per IEC 62351) or place SCADA controllers behind an OT firewall.",
            evidence={"register": reg_addr, "value": current_val},
        )

        # Step 2: Two-Key Safety Gate for Bounded State Change
        authorized = session.get_option("AUTHORIZED_TEST", False)
        if not authorized:
            logger.info("Safety Invariant: Modbus write test bypassed (requires --authorize).")
            return self.findings

        if not self.assert_authorized(session, f"Modbus FC 0x06 setpoint perturbation on {target}:{port}"):
            return self.findings

        # Execute bounded perturbation and auto-revert
        logger.warning(f"Executing bounded FC 0x06 setpoint perturbation ({reg_addr} -> {test_val}) for {pulse_dur}s...")
        write_success = raw_modbus_write_register(target, port, reg_addr, test_val)
        time.sleep(pulse_dur)

        # Mandatory Reversion
        revert_success = raw_modbus_write_register(target, port, reg_addr, baseline_val)
        _, final_val = raw_modbus_read_holding_register(target, port, reg_addr)

        if write_success and revert_success and final_val == baseline_val:
            logger.success("Deterministic auto-revert verified: Register restored to baseline.")
            self.add_finding(
                finding_id="MODBUS-UNAUTH-CONTROL-VALIDATED",
                target=f"{target}:{port}",
                title="Unauthenticated Modbus TCP Setpoint Modification Validated",
                spec_id="MODBUS-TCP-SPEC",
                cwe="CWE-284",
                status="CRITICAL_NON_COMPLIANT",
                details=(
                    f"Modbus controller accepted unauthenticated FC 0x06 write to Register {reg_addr} "
                    f"({baseline_val} -> {test_val}). Auto-revert restored baseline ({baseline_val}) within {pulse_dur}s."
                ),
                remediation="Disable write access on untrusted network interfaces; enforce physical key-switch interlocking for setpoint overrides.",
                evidence={
                    "register": reg_addr,
                    "test_val": test_val,
                    "restored_val": final_val,
                    "reversion_verified": True,
                },
            )
        else:
            self.add_finding(
                finding_id="MODBUS-WRITE-INCONCLUSIVE",
                target=f"{target}:{port}",
                title="Modbus Write Action Rejected or Inconclusive",
                spec_id="MODBUS-TCP-SPEC",
                cwe="CWE-284",
                status="INFORMATIONAL",
                details=f"Write attempt to register {reg_addr} did not confirm state change or was blocked.",
                remediation="Verify controller memory map and access permissions.",
            )

        return self.findings
