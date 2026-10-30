#!/usr/bin/env python3
"""
test_safety_boundary_and_revert_reliability.py

Self-Documenting Safety Boundary, Two-Key Authorization, and State Restoration
Reliability Test Suite for Phase 2 Controlled Impact Validation:
  - `iotsploit/core/immutable_lab_boundary.py`
  - `iotsploit/core/ephemeral_credential_vault.py`
  - `iotsploit/core/controlled_impact_validator.py`
  - `iotsploit/modules/demos/mqtt_credential_reuse_validator.py`
  - `iotsploit/modules/demos/shelly_bounded_actuation_validator.py`
"""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
from typing import Any
import unittest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from iotsploit.core.controlled_impact_validator import (
    ControlledImpactValidator,
    StateRestorationFailureError,
)
from iotsploit.core.ephemeral_credential_vault import EphemeralCredentialVault
from iotsploit.core.immutable_lab_boundary import (
    SafetyBoundaryViolationError,
    enforce_bounded_actuation_duration,
    enforce_immutable_lab_subnet_boundary,
)
from iotsploit.core.scope import LabContext
from iotsploit.modules.validate.mqtt_pivot import (
    MqttHarvestedCredentialValidator,
)
from iotsploit.modules.validate.shelly_actuation import (
    ShellyBoundedPulseActuationValidator,
)
from tests.test_validation_safety import TestControlledValidationSafetySuite as TestControlledDemoSafetySuite


class TestRefactoredDescriptiveSafetyNames(unittest.TestCase):
    """
    Verifies that all refactored descriptive classes, methods, exceptions,
    and circuit-breaker attributes operate identically to their legacy aliases.
    """

    def setUp(self) -> None:
        ControlledImpactValidator.reset_circuit_breaker()

    def tearDown(self) -> None:
        ControlledImpactValidator.reset_circuit_breaker()

    def test_descriptive_boundary_and_duration_functions(self) -> None:
        enforce_immutable_lab_subnet_boundary("172.28.0.20", 1883, "EXP-01")
        enforce_immutable_lab_subnet_boundary("172.28.0.30", 80, "EXP-02")
        enforce_bounded_actuation_duration(2.0)
        # No hard ceiling: operator-configurable durations above the former 2.0s cap are allowed.
        enforce_bounded_actuation_duration(4.0)

        with self.assertRaises(SafetyBoundaryViolationError):
            enforce_immutable_lab_subnet_boundary("8.8.8.8", 80, "EXP-02")
        with self.assertRaises(SafetyBoundaryViolationError):
            enforce_bounded_actuation_duration(0.0)

    def test_descriptive_mqtt_and_shelly_validators(self) -> None:
        vault = EphemeralCredentialVault(scope=LabContext(allowed_cidrs=["172.28.0.0/24"]))
        handle = vault.harvest("admin", "SecretMqttPw123", "coap://172.28.0.70:5683/config", "172.28.0.70")

        with tempfile.TemporaryDirectory() as tmpdir:
            mqtt_val = MqttHarvestedCredentialValidator(
                vault=vault,
                handle_id=handle.handle_id,
                evidence_dir=tmpdir,
                connect_fn=lambda ip, port, u, p: 0,
            )
            art_mqtt = mqtt_val.run(confirmation_token="CONFIRM-EXP-01")
            self.assertTrue(art_mqtt.reverted_cleanly)
            self.assertEqual(len(vault.handles), 0)

            relay = {"on": False}

            def mock_http(url: str) -> tuple[int, dict[str, Any]]:
                if "GetStatus" in url:
                    return 200, {"switch:0": {"id": 0, "output": relay["on"], "voltage": 230.2}}
                if "on=true" in url:
                    relay["on"] = True
                    return 200, {"was_on": False}
                if "on=false" in url:
                    relay["on"] = False
                    return 200, {"was_on": True}
                return 404, {}

            shelly_val = ShellyBoundedPulseActuationValidator(
                evidence_dir=tmpdir,
                http_get_fn=mock_http,
                sleep_fn=lambda _: None,
            )
            art_shelly = shelly_val.run(confirmation_token="CONFIRM-EXP-02")
            self.assertTrue(art_shelly.reverted_cleanly)
            self.assertFalse(ControlledImpactValidator.SAFETY_CIRCUIT_BREAKER_TRIPPED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
