#!/usr/bin/env python3
"""
test_safety_boundary_and_revert_reliability.py

Self-Documenting Safety Boundary, Two-Key Authorization, Circuit Breaker,
and Physical Raspberry Pi 5 Telemetry Test Suite for IoTFlux v4.0.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any, Dict
import unittest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from iotflux.core.controlled_impact_validator import (
    CircuitBreakerTrippedError,
    ControlledImpactValidator,
    ExecutionContextError,
    StateRestorationFailureError,
    ValidationArtifact,
    reset_circuit_breaker,
)
from iotflux.core.pcap_recorder import PcapRecorder
from iotflux.core.profile_generator import (
    DynamicProfileGenerator,
    SafetyLimitValidationError,
    validate_device_safety_limits,
)
from iotflux.core.profiles import DeviceProfile, load_profile
from iotflux.core.scope_manager import (
    NetworkBoundaryRule,
    PhysicalLabAuthorizationError,
    PhysicalLabMetadataError,
    ScopeManager,
)
from iotflux.core.scope_validator import ScopeViolationError, validate_target_ip


class MockFlakyPhysicalValidator(ControlledImpactValidator):
    """Test double for verifying circuit breaker trip behavior on failed state restoration."""

    def __init__(self, *args, should_fail_revert: bool = False, telemetry: Dict[str, Any] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.should_fail_revert = should_fail_revert
        self.telemetry = telemetry or {
            "power_draw_watts": 48.5,
            "actuator_response_time_ms": 115.0,
            "rf_rssi_dbm": -62.0,
            "protocol": "HTTP",
        }
        self.state_counter = 0

    def capture_state(self) -> Dict[str, Any]:
        return {"relay_state": "ON" if self.state_counter > 0 else "OFF"}

    def execute_validation(self) -> Dict[str, Any]:
        self.state_counter = 1
        return self.telemetry

    def revert_state(self, pre_state: Dict[str, Any]) -> bool:
        if self.should_fail_revert:
            return False
        self.state_counter = 0
        return True

    def emergency_revert(self, pre_state: Dict[str, Any]) -> bool:
        if self.should_fail_revert:
            return False
        self.state_counter = 0
        return True

    def verify_safe_baseline(self, pre_state: Dict[str, Any], post_state: Dict[str, Any]) -> bool:
        return post_state.get("relay_state") == "OFF"


class TestSafetyBoundaryAndRevertReliability(unittest.TestCase):
    """Validates the non-negotiable safety constraints for the physical Pi 5 lab."""

    def setUp(self) -> None:
        ControlledImpactValidator.reset_circuit_breaker()
        self._orig_context = os.environ.get("IOTFLUX_EXECUTION_CONTEXT")

    def tearDown(self) -> None:
        ControlledImpactValidator.reset_circuit_breaker()
        if self._orig_context is not None:
            os.environ["IOTFLUX_EXECUTION_CONTEXT"] = self._orig_context
        else:
            os.environ.pop("IOTFLUX_EXECUTION_CONTEXT", None)

    # --------------------------------------------------------------------------
    # Test 1: Scope validator accepts 10.10.0.0/16 ONLY when physical_lab: true
    # --------------------------------------------------------------------------
    def test_1_scope_validator_accepts_physical_subnet_only_with_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            # 1a. Scope configuration with physical_lab: true
            valid_scope_yaml = Path(tmpdir) / "valid_scope.yaml"
            valid_scope_yaml.write_text(
                """allowed_networks:
  - cidr: "10.10.0.0/16"
    description: "Physical Pi 5 Lab"
    physical_lab: true
denied_networks:
  - cidr: "0.0.0.0/0"
    description: "Default Deny"
validation_mode: enforce
""",
                encoding="utf-8",
            )
            sm_valid = ScopeManager(config_path=valid_scope_yaml)
            self.assertTrue(sm_valid.validate_target("10.10.20.30", authorize=True))

            # 1b. Scope configuration with physical_lab: false (missing true metadata)
            invalid_scope_yaml = Path(tmpdir) / "invalid_scope.yaml"
            invalid_scope_yaml.write_text(
                """allowed_networks:
  - cidr: "10.10.0.0/16"
    description: "Physical Pi 5 Lab Without Required Metadata"
    physical_lab: false
denied_networks:
  - cidr: "0.0.0.0/0"
    description: "Default Deny"
validation_mode: enforce
""",
                encoding="utf-8",
            )
            sm_invalid = ScopeManager(config_path=invalid_scope_yaml)
            with self.assertRaises(PhysicalLabMetadataError):
                sm_invalid.validate_target("10.10.20.30", authorize=True)

    # --------------------------------------------------------------------------
    # Test 2: Operations on physical subnet fail without --authorize flag
    # --------------------------------------------------------------------------
    def test_2_operations_on_physical_subnet_fail_without_authorize_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            scope_yaml = Path(tmpdir) / "assessment_scope.yaml"
            scope_yaml.write_text(
                """allowed_networks:
  - cidr: "10.10.0.0/16"
    description: "Physical Pi 5 Lab"
    physical_lab: true
denied_networks:
  - cidr: "0.0.0.0/0"
    description: "Default Deny"
validation_mode: enforce
""",
                encoding="utf-8",
            )
            sm = ScopeManager(config_path=scope_yaml)

            # Failure without --authorize (Two-Key authorization violation)
            with self.assertRaises(PhysicalLabAuthorizationError):
                sm.validate_target("10.10.20.30", authorize=False)

            # Success with --authorize
            self.assertTrue(sm.validate_target("10.10.20.30", authorize=True))

    # --------------------------------------------------------------------------
    # Test 3: Circuit breaker trips identically on physical vs. Docker hardware
    # --------------------------------------------------------------------------
    def test_3_circuit_breaker_trips_identically_on_physical_vs_docker(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            # 3a. Trip on Docker target (172.28.0.30)
            ControlledImpactValidator.reset_circuit_breaker()
            self.assertFalse(ControlledImpactValidator.SAFETY_CIRCUIT_BREAKER_TRIPPED)

            docker_val = MockFlakyPhysicalValidator(
                experiment_id="EXP-DOCKER-FAIL",
                target_ip="172.28.0.30",
                target_port=80,
                authorized=True,
                evidence_dir=tmpdir,
                should_fail_revert=True,
            )
            with self.assertRaises(StateRestorationFailureError):
                docker_val.run()

            self.assertTrue(ControlledImpactValidator.SAFETY_CIRCUIT_BREAKER_TRIPPED)

            # Subsequent attempts blocked by tripped breaker
            with self.assertRaises(CircuitBreakerTrippedError):
                MockFlakyPhysicalValidator(
                    experiment_id="EXP-SUBSEQUENT",
                    target_ip="172.28.0.30",
                    target_port=80,
                    authorized=True,
                    evidence_dir=tmpdir,
                )

            # 3b. Reset and verify identical trip behavior on physical target (10.10.20.30)
            ControlledImpactValidator.reset_circuit_breaker()
            self.assertFalse(ControlledImpactValidator.SAFETY_CIRCUIT_BREAKER_TRIPPED)

            pi5_val = MockFlakyPhysicalValidator(
                experiment_id="EXP-PI5-FAIL",
                target_ip="10.10.20.30",
                target_port=80,
                authorized=True,
                evidence_dir=tmpdir,
                should_fail_revert=True,
            )
            with self.assertRaises(StateRestorationFailureError):
                pi5_val.run()

            self.assertTrue(ControlledImpactValidator.SAFETY_CIRCUIT_BREAKER_TRIPPED)

    # --------------------------------------------------------------------------
    # Test 4: Physical lab operation runs natively on real Kali Linux OS
    # --------------------------------------------------------------------------
    def test_4_physical_operation_runs_natively_without_container_requirement(self) -> None:
        os.environ.pop("IOTFLUX_EXECUTION_CONTEXT", None)

        with tempfile.TemporaryDirectory() as tmpdir:
            validator = MockFlakyPhysicalValidator(
                experiment_id="EXP-PI5-NATIVE",
                target_ip="10.10.20.30",
                target_port=80,
                authorized=True,
                evidence_dir=tmpdir,
                should_fail_revert=False,
            )
            artifact = validator.run()
            self.assertTrue(artifact.reverted_cleanly)
            self.assertEqual(artifact.target_ip, "10.10.20.30")

    # --------------------------------------------------------------------------
    # Test 5: DynamicProfileGenerator validates safety_limits before authorization
    # --------------------------------------------------------------------------
    def test_5_dynamic_profile_generator_validates_safety_limits(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generator = DynamicProfileGenerator(output_dir=tmpdir)

            # 5a. Excess pulse duration (> 2.0s) MUST raise SafetyLimitValidationError
            invalid_pulse_dev = {
                "ip_address": "10.10.20.30",
                "device_id": "dev_shelly_test",
                "authorized": True,
                "safety_limits": {"max_pulse": "3.5s", "auto_revert": "relay_off"},
            }
            with self.assertRaises(SafetyLimitValidationError):
                generator.build_profile_dict(invalid_pulse_dev, whitelist={"10.10.20.30"})

            # 5b. Missing auto_revert mechanism MUST raise SafetyLimitValidationError
            missing_revert_dev = {
                "ip_address": "10.10.20.30",
                "device_id": "dev_shelly_test",
                "authorized": True,
                "safety_limits": {"max_pulse": "2.0s", "auto_revert": ""},
            }
            with self.assertRaises(SafetyLimitValidationError):
                generator.build_profile_dict(missing_revert_dev, whitelist={"10.10.20.30"})

            # 5c. Physical lab device attempting authorization without safety limits MUST be rejected
            unbounded_physical_dev = {
                "ip_address": "10.10.99.99",
                "device_id": "dev_shelly_test",
                "authorized": True,
            }
            with self.assertRaises(SafetyLimitValidationError):
                generator.build_profile_dict(unbounded_physical_dev, whitelist={"10.10.99.99"})

            # 5d. Valid datasheet safety limits succeed and embed into profile
            valid_dev = {
                "ip_address": "10.10.20.30",
                "device_id": "dev_shelly_test",
                "open_ports": [80],
                "safety_limits": {"max_pulse": "2.0s", "auto_revert": "relay_off", "max_power_watts": 2500.0},
            }
            prof_dict = generator.build_profile_dict(valid_dev, whitelist={"10.10.20.30"})
            self.assertTrue(prof_dict["authorized"])
            self.assertEqual(prof_dict["safety_limits"]["max_pulse"], "2.0s")
            self.assertEqual(prof_dict["safety_limits"]["auto_revert"], "relay_off")

    # --------------------------------------------------------------------------
    # Test 6: Evidence pipeline captures hardware telemetry in validation artifact
    # --------------------------------------------------------------------------
    def test_6_evidence_pipeline_captures_hardware_telemetry(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            validator = MockFlakyPhysicalValidator(
                experiment_id="EXP-PI5-TELEMETRY",
                target_ip="10.10.20.30",
                target_port=80,
                authorized=True,
                evidence_dir=tmpdir,
                should_fail_revert=False,
                telemetry={
                    "power_draw_watts": 12.8,
                    "actuator_response_time_ms": 78.4,
                    "rf_rssi_dbm": -55.0,
                    "protocol": "HTTP",
                },
            )
            artifact = validator.run()

            # Verify artifact fields
            self.assertTrue(artifact.reverted_cleanly)
            self.assertEqual(artifact.power_draw_watts, 12.8)
            self.assertEqual(artifact.actuator_response_time_ms, 78.4)
            self.assertEqual(artifact.rf_rssi_dbm, -55.0)

            # Verify exported evidence JSON
            self.assertTrue(Path(artifact.evidence_json_path).exists())
            evidence_data = json.loads(Path(artifact.evidence_json_path).read_text(encoding="utf-8"))
            self.assertGreater(evidence_data["trace_count"], 0)

            first_trace = evidence_data["traces"][0]
            self.assertEqual(first_trace["hardware_telemetry"]["power_draw_watts"], 12.8)
            self.assertEqual(first_trace["hardware_telemetry"]["actuator_response_time_ms"], 78.4)
            self.assertEqual(first_trace["hardware_telemetry"]["rf_rssi_dbm"], -55.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
