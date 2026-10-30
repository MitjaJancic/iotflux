#!/usr/bin/env python3
"""
test_v2_iteration.py

Tests for the iotsploit v0.2.0 iteration:
  - new Finding fields (remediation / cve / override_unvalidated) + serialization
  - taxonomy remediation coverage + two new taxonomy keys
  - client-report executive summary + override labeling
  - new device-class profile loading / validation
  - CLI bounded-default / override-opt-in flag
  - NON-NEGOTIABLE appliance thermal hazard gate (not override-bypassable)
Keeps existing scope-lock behavior intact (negative test re-asserted).
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import unittest

from iotsploit.core.scoring import Finding, DEFAULT_WEIGHTS
from iotsploit.core import report
from iotsploit.core import taxonomy
from iotsploit.core.appliance_safety import (
    ApplianceThermalHazardError,
    enforce_appliance_thermal_safety,
    enforce_from_profile,
    is_thermal_actuation,
)
from iotsploit.core.immutable_lab_boundary import (
    SafetyBoundaryViolationError,
    enforce_immutable_lab_subnet_boundary,
)

try:
    import yaml  # noqa: F401
    from iotsploit.core.device_profile import load_profile, load_profiles_dir
    HAVE_YAML = True
except Exception:  # pragma: no cover
    HAVE_YAML = False

PROFILES_DIR = PROJECT_ROOT / "profiles"


class TestFindingNewFields(unittest.TestCase):
    def test_defaults_none(self):
        f = Finding("f", "172.28.0.30", "mqtt_anonymous", "x", None, {"privacy": 2})
        self.assertIsNone(f.cve)
        self.assertIsNone(f.remediation)
        self.assertFalse(f.override_unvalidated)

    def test_to_dict_surfaces_new_fields(self):
        f = Finding("f", "172.28.0.30", "mqtt_anonymous", "x", None, {"privacy": 2},
                    cve="CVE-TEST-0001", override_unvalidated=True)
        d = f.to_dict(DEFAULT_WEIGHTS)
        self.assertEqual(d["cve"], "CVE-TEST-0001")
        self.assertTrue(d["override_unvalidated"])
        self.assertTrue(d["remediation"])  # inherited from taxonomy

    def test_remediation_precedence(self):
        f = Finding("f", "d", "mqtt_anonymous", "x", None, {}, remediation="Custom fix")
        self.assertEqual(f.to_dict()["remediation"], "Custom fix")


class TestTaxonomy(unittest.TestCase):
    def test_all_entries_have_remediation(self):
        for key, entry in taxonomy.CHECK_TAXONOMY.items():
            self.assertIn("remediation", entry, f"{key} missing remediation")
            self.assertTrue(entry["remediation"].strip())

    def test_new_keys_present(self):
        a = taxonomy.CHECK_TAXONOMY["shelly_mqtt_auth_plane_split"]
        self.assertEqual(a["cwe"], "CWE-306")
        self.assertEqual(a["capec"], "CAPEC-115")
        b = taxonomy.CHECK_TAXONOMY["actuator_unbounded_pulse"]
        self.assertEqual(b["cwe"], "CWE-284")
        self.assertEqual(b["capec"], "CAPEC-180")

    def test_fallback_has_remediation(self):
        self.assertTrue(taxonomy.lookup_remediation("some_unknown_check", 9.5))
        self.assertTrue(taxonomy.lookup_taxonomy("some_unknown_check", 0.0)["remediation"])


class TestClientReport(unittest.TestCase):
    def _findings(self):
        return [
            Finding("a", "172.28.0.30", "shelly_auth_bypass", "unauth relay", 9.1,
                    {"physical_safety": 3, "chaining_depth": 3}),
            Finding("b", "172.28.0.30", "shelly_active_verification", "latched hold", 8.0,
                    {"physical_safety": 3}, override_unvalidated=True),
            Finding("c", "172.28.0.20", "mqtt_telemetry_exposure", "cleartext", None, {"privacy": 2}),
        ]

    def test_summary(self):
        s = report.summarize_findings(self._findings(), DEFAULT_WEIGHTS)
        self.assertEqual(s["device_count"], 2)
        self.assertEqual(s["finding_count"], 3)
        self.assertEqual(s["override_unvalidated_count"], 1)
        self.assertEqual(s["severity_counts"]["CRITICAL"], 1)
        self.assertTrue(s["top_risks"])

    def test_exec_summary_text(self):
        md = report.generate_executive_summary(self._findings(), DEFAULT_WEIGHTS, "now")
        self.assertIn("Executive Summary", md)
        self.assertIn("Highest Risks", md)
        self.assertIn("kali container", md)  # run-methodology baked in

    def test_client_report_labels_override(self):
        rep = report.generate_client_report(self._findings(), DEFAULT_WEIGHTS, "now")
        self.assertIn(report.OVERRIDE_LABEL, rep)

    def test_write_reports_emits_client_outputs(self):
        tmp = tempfile.mkdtemp()
        paths = report.write_reports(self._findings(), DEFAULT_WEIGHTS, tmp, "assessment")
        self.assertIn("client_html", paths)
        self.assertIn("client_md", paths)
        html = Path(paths["client_html"]).read_text(encoding="utf-8")
        self.assertIn("NOT LAB-VALIDATED", html)
        self.assertIn("kali container", html)

    def test_empty_report_posture_note(self):
        md = report.generate_client_report([], DEFAULT_WEIGHTS, "now")
        self.assertIn("NO FINDINGS", md.upper())


@unittest.skipUnless(HAVE_YAML, "pyyaml not available")
class TestNewProfiles(unittest.TestCase):
    EXPECTED = [
        "generic_onvif_camera", "generic_router_gateway", "generic_fire_alarm_panel",
        "generic_intrusion_alarm_panel", "generic_smarthome_hub", "generic_smart_lock",
        "generic_smart_plug", "generic_bacnet_knx_controller", "generic_smart_appliance",
    ]

    def test_all_new_profiles_load(self):
        for name in self.EXPECTED:
            p = load_profile(PROFILES_DIR / f"{name}.yaml")
            self.assertEqual(p.device_id, name)
            self.assertTrue(p.flagged_ports or p.http_endpoints)

    def test_profiles_dir_loads(self):
        profs = load_profiles_dir(PROFILES_DIR)
        ids = {p.device_id for p in profs}
        for name in self.EXPECTED:
            self.assertIn(name, ids)

    def test_appliance_defaults_production(self):
        p = load_profile(PROFILES_DIR / "generic_smart_appliance.yaml")
        appliance = p.raw.get("appliance_safety", {})
        self.assertFalse(appliance.get("simulator", False))
        self.assertFalse(appliance.get("interlock_protected", False))


class TestApplianceThermalHazardGate(unittest.TestCase):
    def test_non_thermal_passes(self):
        # Non-thermal actuation is never gated.
        enforce_appliance_thermal_safety(
            device_id="oven1", actuation_type="status_led",
            is_simulator=False, interlock_protected=False)

    def test_production_thermal_refused(self):
        with self.assertRaises(ApplianceThermalHazardError):
            enforce_appliance_thermal_safety(
                device_id="oven1", actuation_type="heating_element",
                is_simulator=False, interlock_protected=False)

    def test_simulator_allowed(self):
        enforce_appliance_thermal_safety(
            device_id="oven1", actuation_type="oven",
            is_simulator=True, interlock_protected=False)

    def test_interlock_allowed(self):
        enforce_appliance_thermal_safety(
            device_id="oven1", actuation_type="cooktop",
            is_simulator=False, interlock_protected=True)

    def test_override_does_NOT_bypass(self):
        # The operator override toggle must NOT bypass the thermal hazard gate.
        with self.assertRaises(ApplianceThermalHazardError):
            enforce_appliance_thermal_safety(
                device_id="oven1", actuation_type="heating_element",
                is_simulator=False, interlock_protected=False, override_unsafe=True)

    def test_is_thermal_actuation(self):
        self.assertTrue(is_thermal_actuation("heating_element"))
        self.assertTrue(is_thermal_actuation("Oven"))
        self.assertFalse(is_thermal_actuation("relay_toggle"))

    @unittest.skipUnless(HAVE_YAML, "pyyaml not available")
    def test_from_profile_production_refused(self):
        p = load_profile(PROFILES_DIR / "generic_smart_appliance.yaml")
        with self.assertRaises(ApplianceThermalHazardError):
            enforce_from_profile(p, "oven", override_unsafe=True)


class TestCliBoundedOverrideToggle(unittest.TestCase):
    def test_override_flag_present(self):
        from iotsploit import cli
        parser = cli.build_arg_parser()
        ns = parser.parse_args(["validate", "shelly-actuation", "--override-unsafe"])
        self.assertTrue(getattr(ns, "override_unsafe", False))

    def test_override_default_false(self):
        from iotsploit import cli
        parser = cli.build_arg_parser()
        ns = parser.parse_args(["validate", "shelly-actuation"])
        self.assertFalse(getattr(ns, "override_unsafe", False))


class TestScopeLockStillEnforced(unittest.TestCase):
    """Immutable scope lock must remain intact (8.8.8.8 rejected)."""
    def test_external_ip_rejected(self):
        with self.assertRaises(SafetyBoundaryViolationError):
            enforce_immutable_lab_subnet_boundary("8.8.8.8", 1883, "EXP-01")

    def test_in_subnet_allowed(self):
        enforce_immutable_lab_subnet_boundary("172.28.0.20", 1883, "EXP-01")


if __name__ == "__main__":
    unittest.main()
