"""
controlled_impact_validator.py - Controlled Impact Validation Engine with Circuit Breaker
Authorized Defensive Security Validation Lab (IoTFlux)

Enforces safety boundaries, Two-Key authorization, container execution verification,
state reversion, and emergency circuit breaker trip mechanisms across both
Docker-simulated environments and physical Raspberry Pi 5 lab hardware.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import ipaddress
import json
import os
from pathlib import Path
import time
from typing import Any, Callable, Dict, List, Optional, Union

from iotflux.core.audit_log import audit_trail
from iotflux.core.logger import logger
from iotflux.core.pcap_recorder import PcapRecorder
from iotflux.core.profiles import DeviceProfile
from iotflux.core.scope_manager import (
    PHYSICAL_LAB_SUPERNET,
    PhysicalLabAuthorizationError,
    PhysicalLabMetadataError,
    ScopeManager,
)
from iotflux.core.scope_validator import ScopeViolationError, validate_target_ip
from iotflux.core.scoring import Finding


# Global Safety Circuit Breaker State
SAFETY_CIRCUIT_BREAKER_TRIPPED: bool = False
HALT_REASON: Optional[str] = None


def reset_circuit_breaker() -> None:
    """Resets the global circuit breaker latch to disarmed/nominal state."""
    global SAFETY_CIRCUIT_BREAKER_TRIPPED, HALT_REASON
    SAFETY_CIRCUIT_BREAKER_TRIPPED = False
    HALT_REASON = None
    logger.info("Safety circuit breaker reset to nominal state.")


def trip_circuit_breaker(reason: str) -> None:
    """Immediately trips the global circuit breaker, halting all validation activities."""
    global SAFETY_CIRCUIT_BREAKER_TRIPPED, HALT_REASON
    SAFETY_CIRCUIT_BREAKER_TRIPPED = True
    HALT_REASON = reason
    audit_trail.log_event(
        event_type="CIRCUIT_BREAKER_TRIP",
        action="trip_circuit_breaker",
        details={"reason": reason},
    )
    logger.error(f"CRITICAL: Safety circuit breaker TRIPPED! Reason: {reason}")


def is_running_in_kali_container() -> bool:
    """
    Deprecated: Physical lab testing runs natively on real Kali Linux OS.
    Maintained for API compatibility. Always returns True.
    """
    return True


class CircuitBreakerTrippedError(PermissionError):
    """Raised when an operation is attempted while the safety circuit breaker is tripped."""


class ExecutionContextError(PermissionError):
    """Deprecated: Physical lab operations execute natively on real Kali Linux OS."""


class StateRestorationFailureError(RuntimeError):
    """Raised when baseline state restoration fails to return a device to its safe pre-test state."""


@dataclass
class ValidationArtifact:
    """Forensic evidence package generated from a controlled impact validation execution."""
    experiment_id: str
    target_ip: str
    target_port: int
    status: str
    reverted_cleanly: bool
    start_time_utc: str
    end_time_utc: str
    pre_state: Dict[str, Any] = field(default_factory=dict)
    post_state: Dict[str, Any] = field(default_factory=dict)
    power_draw_watts: Optional[float] = None
    actuator_response_time_ms: Optional[float] = None
    rf_rssi_dbm: Optional[float] = None
    pcap_path: Optional[str] = None
    evidence_json_path: Optional[str] = None
    finding: Optional[Finding] = None
    audit_trail: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "status": self.status,
            "reverted_cleanly": self.reverted_cleanly,
            "start_time_utc": self.start_time_utc,
            "end_time_utc": self.end_time_utc,
            "hardware_telemetry": {
                "power_draw_watts": self.power_draw_watts,
                "actuator_response_time_ms": self.actuator_response_time_ms,
                "rf_rssi_dbm": self.rf_rssi_dbm,
            },
            "pcap_path": self.pcap_path,
            "evidence_json_path": self.evidence_json_path,
            "pre_state": self.pre_state,
            "post_state": self.post_state,
            "audit_trail": self.audit_trail,
        }


class ControlledImpactValidator(ABC):
    """
    Abstract base class providing bounded, reversible validation workflows
    with strict Two-Key authorization, pre-flight routing/container verification,
    telemetry capture, and fail-safe circuit breaker protection.
    """

    SAFETY_CIRCUIT_BREAKER_TRIPPED: bool = False
    HALT_REASON: Optional[str] = None

    @classmethod
    def reset_circuit_breaker(cls) -> None:
        reset_circuit_breaker()
        ControlledImpactValidator.SAFETY_CIRCUIT_BREAKER_TRIPPED = False
        ControlledImpactValidator.HALT_REASON = None
        for sub in ControlledImpactValidator.__subclasses__():
            sub.SAFETY_CIRCUIT_BREAKER_TRIPPED = False
            sub.HALT_REASON = None

    @classmethod
    def trip_circuit_breaker(cls, reason: str) -> None:
        trip_circuit_breaker(reason)
        ControlledImpactValidator.SAFETY_CIRCUIT_BREAKER_TRIPPED = True
        ControlledImpactValidator.HALT_REASON = reason
        for sub in ControlledImpactValidator.__subclasses__():
            sub.SAFETY_CIRCUIT_BREAKER_TRIPPED = True
            sub.HALT_REASON = reason

    def __init__(
        self,
        experiment_id: str,
        target_ip: str,
        target_port: int,
        authorized: bool = False,
        evidence_dir: Union[str, Path] = "evidence/validation",
        profile: Optional[DeviceProfile] = None,
        scope_manager: Optional[ScopeManager] = None,
    ) -> None:
        self.experiment_id = experiment_id.strip().upper()
        self.target_ip = target_ip.strip()
        self.target_port = int(target_port)
        self.authorized = bool(authorized)
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.profile = profile
        self.scope_manager = scope_manager or ScopeManager()
        self.pcap = PcapRecorder(output_target=self.evidence_dir / f"{self.experiment_id.lower()}_trace.pcap")
        self._audit_log: List[str] = []

        # 1. Circuit Breaker Pre-Flight Check
        if SAFETY_CIRCUIT_BREAKER_TRIPPED or ControlledImpactValidator.SAFETY_CIRCUIT_BREAKER_TRIPPED:
            active_reason = ControlledImpactValidator.HALT_REASON or HALT_REASON or "Safety circuit breaker tripped"
            raise CircuitBreakerTrippedError(f"Validation aborted: {active_reason}")

        # 2. Scope & Physical Subnet Pre-Flight Check
        self._verify_preflight_scope()

    def _is_target_in_physical_lab(self) -> bool:
        try:
            return ipaddress.ip_address(self.target_ip) in PHYSICAL_LAB_SUPERNET
        except ValueError:
            return False

    def _verify_preflight_scope(self) -> None:
        """Enforces network scope and Two-Key authorization."""
        is_physical = self._is_target_in_physical_lab()

        # Two-Key Authorization Gate: physical targets mandate runtime confirmation
        if is_physical and not self.authorized:
            msg = (
                f"Two-Key authorization violation: Target {self.target_ip} requires explicit "
                f"runtime operator confirmation (--authorize flag required for physical lab operations)."
            )
            self._log(f"REJECTED: {msg}")
            raise PhysicalLabAuthorizationError(msg)

        # Standard Scope Policy Validation
        self.scope_manager.validate_target(self.target_ip, authorize=self.authorized)
        self._log(f"Pre-flight scope verified for {self.target_ip}:{self.target_port} (physical={is_physical})")

    def _log(self, message: str) -> None:
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        entry = f"[{ts}] [{self.experiment_id}] {message}"
        self._audit_log.append(entry)
        logger.info(entry)

    def capture_state(self) -> Dict[str, Any]:
        """Captures device operational state before perturbation. Default empty baseline."""
        return {"captured": True, "baseline": "default"}

    @abstractmethod
    def execute_validation(self) -> Dict[str, Any]:
        """
        Executes controlled, bounded perturbation against target device.
        Must return execution telemetry dict (may include power_draw_watts, response times, etc.).
        """
        raise NotImplementedError

    def revert_state(self, pre_state: Dict[str, Any]) -> bool:
        """
        Reverts device to baseline operational state captured before execution.
        Must return True if state restored successfully, False otherwise.
        """
        return True

    def emergency_revert(self, pre_state: Dict[str, Any]) -> bool:
        """Secondary fallback reversion if primary revert fails."""
        return False

    def verify_safe_baseline(self, pre_state: Dict[str, Any], post_state: Dict[str, Any]) -> bool:
        """Verifies that post_state matches safe pre_state baseline."""
        return True

    def run(self) -> ValidationArtifact:
        """
        Executes complete controlled impact validation lifecycle:
        1. Circuit breaker gate
        2. Pre-state capture
        3. Controlled perturbation execution
        4. State restoration & verification
        5. Emergency revert on failure -> trip circuit breaker
        6. Forensic evidence package generation (PCAP + JSON telemetry)
        """
        if SAFETY_CIRCUIT_BREAKER_TRIPPED or ControlledImpactValidator.SAFETY_CIRCUIT_BREAKER_TRIPPED:
            active_reason = ControlledImpactValidator.HALT_REASON or HALT_REASON or "Safety circuit breaker tripped"
            raise CircuitBreakerTrippedError(f"Validation aborted: {active_reason}")

        start_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._log(f"Beginning controlled validation run against {self.target_ip}:{self.target_port}")

        # Capture pre-execution state baseline
        pre_state = self.capture_state()
        self._log(f"Pre-execution state baseline captured: {json.dumps(pre_state, sort_keys=True)}")

        # Execute perturbation
        exec_telemetry: Dict[str, Any] = {}
        try:
            exec_telemetry = self.execute_validation() or {}
            self._log("Perturbation execution completed.")
        except Exception as ex:
            self._log(f"Perturbation execution encountered exception: {ex}")
            # Continue to mandatory state reversion

        # State Reversion
        reverted_cleanly = False
        revert_ok = self.revert_state(pre_state)
        post_state = self.capture_state()

        if revert_ok and self.verify_safe_baseline(pre_state, post_state):
            reverted_cleanly = True
            self._log("Verified post-execution state matches safe baseline.")
        else:
            self._log("Primary state restoration failed. Attempting emergency fallback reversion...")
            emergency_ok = self.emergency_revert(pre_state)
            post_state_emergency = self.capture_state()

            if emergency_ok and self.verify_safe_baseline(pre_state, post_state_emergency):
                reverted_cleanly = True
                post_state = post_state_emergency
                self._log("Emergency fallback reversion succeeded.")
            else:
                fail_msg = (
                    f"CRITICAL: Failed to restore device {self.target_ip}:{self.target_port} to safe baseline! "
                    f"Tripping circuit breaker."
                )
                self._log(fail_msg)
                self.__class__.trip_circuit_breaker(fail_msg)
                raise StateRestorationFailureError(fail_msg)

        end_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Physical telemetry extraction
        power_draw = exec_telemetry.get("power_draw_watts")
        response_time = exec_telemetry.get("actuator_response_time_ms")
        rf_rssi = exec_telemetry.get("rf_rssi_dbm")

        # Record forensic trace entry
        self.pcap.record_with_telemetry(
            src_ip="10.10.10.1" if self._is_target_in_physical_lab() else "172.28.0.1",
            dst_ip=self.target_ip,
            dst_port=self.target_port,
            protocol=exec_telemetry.get("protocol", "TCP"),
            summary=f"{self.experiment_id} impact validation trace",
            payload=exec_telemetry.get("raw_payload", b""),
            power_draw_watts=power_draw,
            actuator_response_time_ms=response_time,
            rf_rssi_dbm=rf_rssi,
        )

        pcap_path = self.pcap.write_pcap()
        json_path = self.pcap.export_evidence_json(self.evidence_dir / f"{self.experiment_id.lower()}_telemetry.json")

        artifact = ValidationArtifact(
            experiment_id=self.experiment_id,
            target_ip=self.target_ip,
            target_port=self.target_port,
            status="SUCCESS" if reverted_cleanly else "FAILED",
            reverted_cleanly=reverted_cleanly,
            start_time_utc=start_time,
            end_time_utc=end_time,
            pre_state=pre_state,
            post_state=post_state,
            power_draw_watts=power_draw,
            actuator_response_time_ms=response_time,
            rf_rssi_dbm=rf_rssi,
            pcap_path=pcap_path,
            evidence_json_path=json_path,
            audit_trail=list(self._audit_log),
        )

        # Build Finding if defined
        if hasattr(self, "build_finding"):
            try:
                artifact.finding = self.build_finding(artifact)
            except Exception:
                pass

        audit_trail.log_event(
            event_type="VALIDATION_RUN",
            action="execute_controlled_impact",
            details={
                "experiment_id": self.experiment_id,
                "target_ip": self.target_ip,
                "status": artifact.status,
                "reverted_cleanly": artifact.reverted_cleanly,
                "power_draw_watts": artifact.power_draw_watts,
                "actuator_response_time_ms": artifact.actuator_response_time_ms,
            },
        )

        return artifact
