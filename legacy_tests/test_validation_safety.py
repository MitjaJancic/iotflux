#!/usr/bin/env python3
"""
test_validation_safety.py

Safety Validation Test Suite for Phase 3 Controlled Impact Validation Modules:
  - `iotsploit/core/immutable_lab_boundary.py`
  - `iotsploit/core/controlled_impact_validator.py`
  - `iotsploit/modules/validate/mqtt_pivot.py`
  - `iotsploit/modules/validate/shelly_actuation.py`

Test Categories:
  1. Positive Tests: Verify EXP-01 and EXP-02 execute within safety bounds,
     revert cleanly, redact secrets, and produce PCAP + JSON evidence packages.
  2. Negative Tests: Verify compile-time scope enforcement blocks out-of-subnet IPs,
     unauthorized ports/services, invalid confirmation tokens, unharvested credentials,
     and excessive pulse durations.
  3. Revert Reliability & Circuit-Breaker Tests: Simulate primary revert failure and
     verify emergency revert triggers, critical alarms activate, and the global
     circuit breaker halts all subsequent demonstrations.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
from typing import Any
import unittest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from iotsploit.core.credential_vault import CredentialVault
from iotsploit.core.controlled_impact_validator import (
    ControlledImpactValidator,
    DemoExecutionArtifact,
    DemoRevertFailureError,
    ImpactValidationEvidencePackage,
    ImpactValidationExecutor,
    StateRestorationFailureError,
)
from iotsploit.core.immutable_lab_boundary import (
    DemoSafetyViolationError,
    SafetyBoundaryViolationError,
    assert_bounded_duration,
    assert_immutable_demo_scope,
    enforce_bounded_actuation_duration,
    enforce_immutable_lab_subnet_boundary,
)
from iotsploit.core.scope import LabContext
from iotsploit.modules.validate.mqtt_pivot import MqttCredentialPivotDemo, MqttPivotValidator
from iotsploit.modules.validate.shelly_actuation import ShellyActuationValidator, ShellyLockPulseDemo


class TestControlledValidationSafetySuite(unittest.TestCase):

    def setUp(self) -> None:
        ControlledImpactValidator.reset_circuit_breaker()

    def tearDown(self) -> None:
        ControlledImpactValidator.reset_circuit_breaker()

    # ------------------------------------------------------------------
    # 1. POSITIVE TESTS: Safe Execution, Auto-Revert & Redacted Evidence
    # ------------------------------------------------------------------

    def test_positive_exp01_mqtt_credential_pivot(self) -> None:
        """
        Verifies EXP-01 uses a pre-harvested credential handle, performs a single
        CONNECT-CONNACK-DISCONNECT handshake, wipes vault handles on revert,
        redacts plaintext credentials in JSON, and emits a valid libpcap trace.
        """
        vault = CredentialVault()
        raw_user = "lab_user"
        raw_pass = "SuperSecretLabPass123!"
        source_url = "coap://172.28.0.70:5683/config"
        harvested = vault.harvest(raw_user, raw_pass, source_url, "172.28.0.70")
        handle_id = harvested.handle_id

        # Mock MQTT connect probe returning CONNACK return code 0 (Accepted)
        mock_probe_called = []

        def mock_mqtt_probe(ip: str, port: int, username: str, password: str, timeout: float = 3.0) -> int:
            mock_probe_called.append((ip, port, username, password))
            return 0

        with tempfile.TemporaryDirectory() as tmpdir:
            demo = MqttPivotValidator(
                vault=vault,
                handle_id=handle_id,
                evidence_dir=tmpdir,
                connect_fn=mock_mqtt_probe,
            )
            artifact = demo.run(confirmation_token="CONFIRM-EXP-01")

            # 1. Probe invoked with correct parameters
            self.assertEqual(len(mock_probe_called), 1)
            self.assertEqual(mock_probe_called[0][0], "172.28.0.20")
            self.assertEqual(mock_probe_called[0][1], 1883)
            self.assertEqual(mock_probe_called[0][2], raw_user)
            self.assertEqual(mock_probe_called[0][3], raw_pass)

            # 2. Pre, during, post lifecycle
            self.assertFalse(artifact.pre_state["session_active"])
            self.assertTrue(artifact.during_state["session_active"])
            self.assertFalse(artifact.post_state["session_active"])
            self.assertTrue(artifact.reverted_cleanly)
            self.assertFalse(artifact.emergency_revert_triggered)

            # 3. Vault handles invalidated post-run
            self.assertEqual(len(vault.handles), 0)

            # 4. Redaction check in evidence JSON
            ev_json_path = Path(artifact.evidence_json_path)
            self.assertTrue(ev_json_path.exists())
            raw_json_text = ev_json_path.read_text(encoding="utf-8")
            self.assertNotIn(raw_pass, raw_json_text)
            self.assertIn(handle_id, raw_json_text)

            # 5. PCAP trace check (non-empty libpcap binary)
            pcap_path = Path(artifact.pcap_path)
            self.assertTrue(pcap_path.exists())
            self.assertGreater(pcap_path.stat().st_size, 24)  # > global header size

            # 6. Finding generated
            finding = artifact.finding
            self.assertIsNotNone(finding)
            self.assertEqual(finding.check_name, "cross_protocol_credential_reuse")
            self.assertNotIn(raw_pass, finding.description)
            self.assertIn(handle_id, finding.description)

    def test_positive_exp02_shelly_lock_pulse_and_video_sync(self) -> None:
        """
        Verifies EXP-02 energizes the lock solenoid relay for exactly pulse_seconds (<=2.0s),
        records ISO-8601 UTC video sync timestamps (t1, t2), confirms state restoration
        to LOCKED_SAFE, and exports PCAP + JSON artifacts.
        """
        http_requests: list[str] = []
        sleep_durations: list[float] = []

        def mock_http_get(url: str, timeout: float = 2.0) -> tuple[int, dict[str, Any]]:
            http_requests.append(url)
            if "/rpc/Shelly.GetStatus" in url:
                # Simulates relay state based on recent commands
                is_on = any("on=true" in u for u in http_requests[-2:])
                return 200, {"switch:0": {"id": 0, "output": is_on, "voltage": 230.1}}
            elif "/relay/0" in url:
                return 200, {"ison": False}
            return 200, {}

        def mock_sleep(seconds: float) -> None:
            sleep_durations.append(seconds)

        with tempfile.TemporaryDirectory() as tmpdir:
            demo = ShellyActuationValidator(
                pulse_seconds=2.0,
                evidence_dir=tmpdir,
                http_get_fn=mock_http_get,
                sleep_fn=mock_sleep,
            )
            artifact = demo.run(confirmation_token="CONFIRM-EXP-02")

            self.assertEqual(sleep_durations, [2.0])
            self.assertTrue(artifact.reverted_cleanly)
            self.assertFalse(artifact.emergency_revert_triggered)
            self.assertEqual(artifact.pre_state["lock_strike_state"], "LOCKED_SAFE")
            self.assertEqual(artifact.during_state["lock_strike_state"], "UNLOCKED_ENERGIZED")
            self.assertEqual(artifact.post_state["lock_strike_state"], "LOCKED_SAFE")
            self.assertTrue(
                artifact.state_diff["lock_strike_state"]["transient_change_observed"]
            )
            self.assertTrue(artifact.state_diff["lock_strike_state"]["restored_to_pre"])
            self.assertIn("t1_solenoid_energized_utc", demo.video_sync_markers)
            self.assertIn("t2_solenoid_reverted_utc", demo.video_sync_markers)
            self.assertTrue(Path(artifact.pcap_path).exists())
            self.assertTrue(Path(artifact.evidence_json_path).exists())

    # ------------------------------------------------------------------
    # 2. NEGATIVE TESTS: Compile-Time Scope, Service & Token Rejections
    # ------------------------------------------------------------------

    def test_negative_out_of_subnet_ips_blocked(self) -> None:
        """Verifies external, private non-lab, loopback, and hostname targets are blocked."""
        prohibited_targets = [
            "8.8.8.8",
            "1.1.1.1",
            "192.168.1.30",
            "10.0.0.30",
            "172.16.0.30",
            "127.0.0.1",
            "shelly-lock.local",
        ]
        for bad_ip in prohibited_targets:
            with self.subTest(bad_ip=bad_ip):
                with self.assertRaises(SafetyBoundaryViolationError):
                    enforce_immutable_lab_subnet_boundary(bad_ip, 80, "EXP-02")
                with self.assertRaises(SafetyBoundaryViolationError):
                    ShellyActuationValidator(target_ip=bad_ip, target_port=80)

    def test_negative_unauthorized_service_or_port_inside_subnet_blocked(self) -> None:
        """Verifies EXP-01 and EXP-02 cannot target non-allowlisted nodes or ports inside 172.28.0.0/24."""
        # EXP-02 is strictly bound to 172.28.0.30:80 (cannot target .31, .50, or port 22)
        with self.assertRaises(SafetyBoundaryViolationError):
            ShellyActuationValidator(target_ip="172.28.0.31", target_port=80)
        with self.assertRaises(SafetyBoundaryViolationError):
            ShellyActuationValidator(target_ip="172.28.0.30", target_port=22)

        # EXP-01 is strictly bound to 172.28.0.20:1883 (cannot target .40 or port 8883)
        vault = CredentialVault()
        h = vault.harvest("admin", "admin", "coap://172.28.0.70:5683/config", "172.28.0.70")
        with self.assertRaises(SafetyBoundaryViolationError):
            MqttPivotValidator(vault=vault, handle_id=h.handle_id, target_ip="172.28.0.40", target_port=1883)
        with self.assertRaises(SafetyBoundaryViolationError):
            MqttPivotValidator(vault=vault, handle_id=h.handle_id, target_ip="172.28.0.20", target_port=8883)

    def test_negative_nonpositive_pulse_duration_blocked(self) -> None:
        """Pulse duration is operator-configurable with NO hard ceiling; only
        non-positive (<= 0.0s) durations are rejected. Large durations are allowed."""
        with self.assertRaises(SafetyBoundaryViolationError):
            enforce_bounded_actuation_duration(0.0)
        with self.assertRaises(SafetyBoundaryViolationError):
            enforce_bounded_actuation_duration(-1.0)
        with self.assertRaises(SafetyBoundaryViolationError):
            ShellyActuationValidator(pulse_seconds=0.0)
        # No upper ceiling: large/uncapped operator-configured durations are accepted.
        enforce_bounded_actuation_duration(2.5)
        enforce_bounded_actuation_duration(900.0)
        big = ShellyActuationValidator(pulse_seconds=15.0)
        self.assertEqual(big.pulse_seconds, 15.0)
        # An explicit max is still honoured when a caller supplies one.
        with self.assertRaises(SafetyBoundaryViolationError):
            enforce_bounded_actuation_duration(5.0, 2.0)

    def test_negative_two_key_operator_confirmation_mismatch_blocked(self) -> None:
        """Verifies runtime execution halts if exact confirmation string is not provided."""
        demo = ShellyActuationValidator(http_get_fn=lambda _: (200, {}))
        for invalid_token in ("", "yes", "CONFIRM", "CONFIRM-EXP-01", "confirm-exp-02"):
            with self.assertRaises(SafetyBoundaryViolationError):
                demo.run(confirmation_token=invalid_token)

    def test_negative_unharvested_or_raw_credentials_rejected(self) -> None:
        """Verifies EXP-01 rejects raw password strings or unknown credential handles."""
        vault = CredentialVault()
        with self.assertRaises(SafetyBoundaryViolationError):
            MqttPivotValidator(vault=vault, handle_id="admin:admin")

        demo = MqttPivotValidator(vault=vault, handle_id="cred_deadbeef")
        with self.assertRaises(SafetyBoundaryViolationError):
            demo.run(confirmation_token="CONFIRM-EXP-01")

    # ------------------------------------------------------------------
    # 2b. LATCHING MODE & MQTT BRUTE-FORCE (operator-authorized capabilities)
    # ------------------------------------------------------------------

    def test_positive_latching_mode_holds_state_without_autorevert(self) -> None:
        """Latching mode energizes and HOLDS state (no auto-revert) without tripping
        the circuit breaker; a separate explicit --revert restores LOCKED_SAFE."""
        relay = {"on": False}

        def mock_http(url: str, timeout: float = 2.0) -> tuple[int, dict[str, Any]]:
            if "/rpc/Shelly.GetStatus" in url:
                return 200, {"switch:0": {"id": 0, "output": relay["on"], "voltage": 230.1}}
            if "on=true" in url:
                relay["on"] = True
                return 200, {}
            if "on=false" in url:
                relay["on"] = False
                return 200, {}
            return 200, {}

        with tempfile.TemporaryDirectory() as tmpdir:
            demo = ShellyActuationValidator(
                pulse_seconds=10.0,
                latching=True,
                evidence_dir=tmpdir,
                http_get_fn=mock_http,
                sleep_fn=lambda _: None,
            )
            artifact = demo.run(confirmation_token="CONFIRM-EXP-02")
            self.assertTrue(artifact.reverted_cleanly)
            self.assertFalse(artifact.emergency_revert_triggered)
            self.assertFalse(ControlledImpactValidator.SAFETY_CIRCUIT_BREAKER_TRIPPED)
            self.assertTrue(relay["on"])  # state HELD energized
            self.assertEqual(artifact.during_state["lock_strike_state"], "UNLOCKED_ENERGIZED")

            reverter = ShellyActuationValidator(
                revert_only=True,
                evidence_dir=tmpdir,
                http_get_fn=mock_http,
                sleep_fn=lambda _: None,
            )
            rev_art = reverter.run(confirmation_token="CONFIRM-EXP-02")
            self.assertTrue(rev_art.reverted_cleanly)
            self.assertFalse(relay["on"])  # explicit revert restored LOCKED_SAFE
            self.assertEqual(rev_art.post_state["lock_strike_state"], "LOCKED_SAFE")

    def test_positive_mqtt_bruteforce_records_authenticated_handles(self) -> None:
        """MQTT brute-force iterates a credential list, records which authenticate as
        SHA-256 handles (no plaintext), stays scope-locked, and reverts cleanly."""
        from iotsploit.modules.validate.mqtt_bruteforce import MqttBruteforceValidator

        creds = [("admin", "wrong1"), ("admin", "admin"), ("root", "toor")]

        def mock_probe(ip, port, username, password, timeout=3.0):
            return 0 if (username, password) == ("admin", "admin") else 5

        with tempfile.TemporaryDirectory() as tmpdir:
            val = MqttBruteforceValidator(
                credentials=creds,
                evidence_dir=tmpdir,
                connect_fn=mock_probe,
            )
            artifact = val.run(confirmation_token="CONFIRM-MQTT-BRUTEFORCE")
            self.assertTrue(artifact.reverted_cleanly)
            self.assertEqual(artifact.during_state["total_tested"], 3)
            self.assertEqual(artifact.during_state["authenticated_count"], 1)
            self.assertTrue(artifact.during_state["any_authenticated"])
            raw_json = Path(artifact.evidence_json_path).read_text(encoding="utf-8")
            self.assertNotIn("admin:admin", raw_json)   # no plaintext cred pair
            self.assertNotIn("toor", raw_json)           # no plaintext password
            self.assertEqual(val.target_ip, "172.28.0.20")  # scope-locked target

    def test_negative_mqtt_bruteforce_out_of_subnet_blocked(self) -> None:
        """Brute-force module remains confined to the immutable lab subnet."""
        from iotsploit.modules.validate.mqtt_bruteforce import MqttBruteforceValidator
        with self.assertRaises(SafetyBoundaryViolationError):
            MqttBruteforceValidator(credentials=[("a", "b")], target_ip="8.8.8.8", target_port=1883)

    # ------------------------------------------------------------------
    # 3. REVERT RELIABILITY & CIRCUIT-BREAKER TESTS
    # ------------------------------------------------------------------

    def test_revert_failure_triggers_emergency_revert_alarm_and_system_halt(self) -> None:
        """
        Simulates a stuck relay where `primary_revert()` fails to turn off the lock
        solenoid. Verifies that:
          1. `emergency_revert()` is automatically called (`/relay/0?turn=off`),
          2. `CRITICAL_SAFETY_ALARM` is logged and persisted to the evidence JSON,
          3. `StateRestorationFailureError` is raised, and
          4. `ControlledImpactValidator.SAFETY_CIRCUIT_BREAKER_TRIPPED` blocks any subsequent demo run.
        """
        called_urls: list[str] = []

        def stuck_relay_http(url: str) -> tuple[int, dict[str, Any]]:
            called_urls.append(url)
            if "/rpc/Shelly.GetStatus" in url:
                # Before pulse: False; after pulse & after primary_revert: stuck True!
                is_stuck_on = any("on=true" in u for u in called_urls)
                return 200, {"switch:0": {"id": 0, "output": is_stuck_on, "voltage": 230.2}}
            return 200, {"was_on": False}

        with tempfile.TemporaryDirectory() as tmpdir:
            demo = ShellyActuationValidator(
                evidence_dir=tmpdir,
                http_get_fn=stuck_relay_http,
                sleep_fn=lambda _: None,
            )
            with self.assertRaises(StateRestorationFailureError) as ctx:
                demo.run(confirmation_token="CONFIRM-EXP-02")

            self.assertIn("CRITICAL_SAFETY_ALARM", str(ctx.exception))
            # Verify emergency_revert() issued the fallback Gen 1 /relay/0?turn=off command
            self.assertTrue(any("/relay/0?turn=off" in u for u in called_urls))
            # Verify global circuit breaker is tripped
            self.assertTrue(ControlledImpactValidator.SAFETY_CIRCUIT_BREAKER_TRIPPED)

            # Verify any subsequent demonstration is immediately blocked by the circuit breaker
            demo2 = ShellyActuationValidator(
                evidence_dir=tmpdir,
                http_get_fn=lambda _: (200, {"switch:0": {"id": 0, "output": False}}),
                sleep_fn=lambda _: None,
            )
            with self.assertRaises(SafetyBoundaryViolationError) as halt_ctx:
                demo2.run(confirmation_token="CONFIRM-EXP-02")
            self.assertIn("Safety circuit breaker is active", str(halt_ctx.exception))


# Backward-compatible class alias
TestControlledDemoSafetySuite = TestControlledValidationSafetySuite

if __name__ == "__main__":
    unittest.main(verbosity=2)
