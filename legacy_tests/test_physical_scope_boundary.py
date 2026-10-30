#!/usr/bin/env python3
"""
test_physical_scope_boundary.py

Phase 2 physical scope-model split — fail-closed unit verification:
  (a) empty AUTHORIZED_PHYSICAL_ENDPOINTS => enforce_physical_endpoint_boundary raises
  (b) latching / uncapped pulse refused on a hypothetical physical target
  (c) UPnP / mDNS / RTSP active modes refuse non-172.28 and physical-allowlisted IPs
  (d) sim Key A path unchanged for 172.28.0.0/24 endpoints
  (e) missing lab_context.yaml fails closed to sim subnet + loopback (not all RFC1918)
  (f) scope guard still refuses 8.8.8.8
"""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from iotsploit.core.immutable_lab_boundary import (
    AUTHORIZED_PHYSICAL_ENDPOINTS,
    AUTHORIZED_VALIDATION_ENDPOINTS,
    IMMUTABLE_LAB_SUBNET,
    MAX_RELAY_PULSE_SECONDS,
    SafetyBoundaryViolationError,
    assert_active_mode_not_physical,
    enforce_bounded_actuation_duration,
    enforce_immutable_lab_subnet_boundary,
    enforce_key_a_boundary,
    enforce_physical_actuation_constraints,
    enforce_physical_endpoint_boundary,
    is_physical_allowlisted_endpoint,
)
from iotsploit.core.scope import DEFAULT_LAB_CIDRS, LabContext, ScopeViolationError
from iotsploit.checks.upnp_scpd_audit import ActiveModeScopeError, _assert_active_upnp_endpoint
from iotsploit.checks.mdns_checks import ActiveMdnsScopeError, _assert_active_lab_ipv4
from iotsploit.checks.camera_checks import ActiveRtspScopeError, _assert_active_rtsp_endpoint


class TestPhysicalScopeBoundary(unittest.TestCase):
    def tearDown(self) -> None:
        # Fail-closed invariant: tests must leave the physical allowlist EMPTY.
        AUTHORIZED_PHYSICAL_ENDPOINTS.clear()

    def test_a_empty_allowlist_raises(self) -> None:
        self.assertEqual(len(AUTHORIZED_PHYSICAL_ENDPOINTS), 0)
        with self.assertRaises(SafetyBoundaryViolationError) as ctx:
            enforce_physical_endpoint_boundary("192.168.50.10", 80, "SHELLY-ACTUATION-PHYS-1")
        self.assertIn("EMPTY", str(ctx.exception).upper())

        with self.assertRaises(SafetyBoundaryViolationError):
            enforce_key_a_boundary("192.168.50.10", 80, "SHELLY-ACTUATION-PHYS-1")

        with self.assertRaises(SafetyBoundaryViolationError):
            enforce_key_a_boundary("192.168.50.10", 80, "EXP-02")

    def test_b_latching_and_uncapped_refused_on_physical(self) -> None:
        # Hypothetical physical entry — cleared in tearDown.
        AUTHORIZED_PHYSICAL_ENDPOINTS["SHELLY-ACTUATION-PHYS-1"] = (
            "192.168.50.10",
            80,
            "Hypothetical thesis Shelly (unit-test only)",
        )
        try:
            enforce_physical_endpoint_boundary(
                "192.168.50.10", 80, "SHELLY-ACTUATION-PHYS-1"
            )
            with self.assertRaises(SafetyBoundaryViolationError) as ctx:
                enforce_physical_actuation_constraints(
                    latching=True,
                    pulse_seconds=1.0,
                    experiment_id="SHELLY-ACTUATION-PHYS-1",
                )
            self.assertIn("latching", str(ctx.exception).lower())

            with self.assertRaises(SafetyBoundaryViolationError) as ctx2:
                enforce_physical_actuation_constraints(
                    latching=False,
                    pulse_seconds=5.0,
                    experiment_id="SHELLY-ACTUATION-PHYS-1",
                )
            self.assertIn(str(MAX_RELAY_PULSE_SECONDS), str(ctx2.exception))

            # Bounded 2.0s non-latching is permitted by the constraint helper.
            enforce_physical_actuation_constraints(
                latching=False,
                pulse_seconds=MAX_RELAY_PULSE_SECONDS,
                experiment_id="SHELLY-ACTUATION-PHYS-1",
            )
        finally:
            AUTHORIZED_PHYSICAL_ENDPOINTS.clear()

    def test_c_active_modes_refuse_non_lab_and_physical(self) -> None:
        with self.assertRaises(ActiveModeScopeError):
            _assert_active_upnp_endpoint("8.8.8.8", 5000)
        with self.assertRaises(ActiveModeScopeError):
            _assert_active_upnp_endpoint("192.168.33.1", 5000)
        with self.assertRaises(ActiveModeScopeError):
            _assert_active_upnp_endpoint("192.168.50.10", 5000)
        with self.assertRaises(ActiveModeScopeError):
            _assert_active_upnp_endpoint("172.28.0.50", 5000)  # wrong endpoint pair

        with self.assertRaises(ActiveMdnsScopeError):
            _assert_active_lab_ipv4("8.8.8.8")
        with self.assertRaises(ActiveMdnsScopeError):
            _assert_active_lab_ipv4("192.168.50.10")

        with self.assertRaises(ActiveRtspScopeError):
            _assert_active_rtsp_endpoint("8.8.8.8", 554)
        with self.assertRaises(ActiveRtspScopeError):
            _assert_active_rtsp_endpoint("192.168.50.10", 554)

        # Explicit physical-allowlist guard (belt-and-suspenders)
        AUTHORIZED_PHYSICAL_ENDPOINTS["SHELLY-ACTUATION-PHYS-1"] = (
            "192.168.50.10",
            80,
            "Hypothetical",
        )
        try:
            self.assertTrue(is_physical_allowlisted_endpoint("192.168.50.10"))
            with self.assertRaises(SafetyBoundaryViolationError):
                assert_active_mode_not_physical("192.168.50.10", mode="UPNP-AddPortMapping")
            with self.assertRaises(ActiveModeScopeError):
                _assert_active_upnp_endpoint("192.168.50.10", 5000)
            with self.assertRaises(ActiveMdnsScopeError):
                _assert_active_lab_ipv4("192.168.50.10")
            with self.assertRaises(ActiveRtspScopeError):
                _assert_active_rtsp_endpoint("192.168.50.10", 554)
        finally:
            AUTHORIZED_PHYSICAL_ENDPOINTS.clear()

        # In-lab authorized endpoints still accepted by active asserts
        self.assertEqual(_assert_active_upnp_endpoint("172.28.0.40", 5000), "172.28.0.40")
        self.assertEqual(_assert_active_lab_ipv4("172.28.0.10"), "172.28.0.10")
        self.assertEqual(_assert_active_rtsp_endpoint("172.28.0.50", 554), "172.28.0.50")

    def test_d_sim_behavior_unchanged(self) -> None:
        self.assertEqual(str(IMMUTABLE_LAB_SUBNET), "172.28.0.0/24")
        self.assertIn("EXP-02", AUTHORIZED_VALIDATION_ENDPOINTS)
        enforce_immutable_lab_subnet_boundary("172.28.0.30", 80, "EXP-02")
        enforce_immutable_lab_subnet_boundary("172.28.0.20", 1883, "EXP-01")
        enforce_key_a_boundary("172.28.0.30", 80, "EXP-02")
        enforce_bounded_actuation_duration(2.0)
        enforce_bounded_actuation_duration(4.0)  # sim uncapped still allowed when no max
        with self.assertRaises(SafetyBoundaryViolationError):
            enforce_immutable_lab_subnet_boundary("8.8.8.8", 80, "EXP-02")

    def test_e_missing_yaml_fails_closed(self) -> None:
        self.assertEqual(
            set(DEFAULT_LAB_CIDRS),
            {"172.28.0.0/24", "127.0.0.0/8"},
        )
        self.assertNotIn("192.168.0.0/16", DEFAULT_LAB_CIDRS)
        self.assertNotIn("10.0.0.0/8", DEFAULT_LAB_CIDRS)
        self.assertNotIn("172.16.0.0/12", DEFAULT_LAB_CIDRS)

        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "does_not_exist.yaml"
            ctx = LabContext.load(missing)
            allowed = {str(n) for n in ctx.allowed_networks}
            self.assertIn("172.28.0.0/24", allowed)
            self.assertIn("127.0.0.0/8", allowed)
            self.assertNotIn("192.168.0.0/16", allowed)
            self.assertTrue(ctx.is_in_scope("172.28.0.30"))
            self.assertTrue(ctx.is_in_scope("127.0.0.1"))
            self.assertFalse(ctx.is_in_scope("192.168.1.1"))
            self.assertFalse(ctx.is_in_scope("10.0.0.1"))
            self.assertFalse(ctx.is_in_scope("192.168.33.1"))

    def test_f_scope_refuses_public_ip(self) -> None:
        ctx = LabContext(allowed_cidrs=["172.28.0.0/24", "127.0.0.0/8"])
        self.assertFalse(ctx.is_in_scope("8.8.8.8"))
        with self.assertRaises(ScopeViolationError):
            ctx.assert_in_scope("8.8.8.8", "unit-test probe")

        # Loaded lab_context.yaml (repo root) must not reintroduce 192.168.33.0/24
        yaml_path = PROJECT_ROOT / "lab_context.yaml"
        self.assertTrue(yaml_path.exists())
        loaded = LabContext.load(yaml_path)
        allowed = {str(n) for n in loaded.allowed_networks}
        self.assertIn("172.28.0.0/24", allowed)
        self.assertNotIn("192.168.33.0/24", allowed)
        self.assertFalse(loaded.is_in_scope("192.168.33.1"))
        self.assertFalse(loaded.is_in_scope("8.8.8.8"))
        self.assertTrue(loaded.is_in_scope("172.28.0.31"))  # shelly ap-check target still in scope

    def test_physical_allowlist_ships_empty(self) -> None:
        self.assertEqual(AUTHORIZED_PHYSICAL_ENDPOINTS, {})
        self.assertFalse(is_physical_allowlisted_endpoint("172.28.0.30", 80))
        self.assertFalse(is_physical_allowlisted_endpoint("192.168.50.10"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
