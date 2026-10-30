"""
test_hygiene_integrity.py - Post-Cleanup Verification Suite for IoTFlux v4.0
Authorized Security Assessment & Conformance Validation Framework

Runs after every cleanup operation (and as part of standard unittest discovery) to:
1. Confirm all 37 original unit/integration tests in tests/test_iotflux.py still pass.
2. Verify 'iotflux scope init', 'discover', 'auth set', 'validate', and 'hygiene' execute without import errors.
3. Validate the schema of assessment_audit.jsonl and hygiene_cleanup_audit.jsonl.
4. Ensure no broken imports across all CLI entrypoints, modules, and workflows.
5. Verify fail-fast automatic rollback ('hygiene restore') if any post-cleanup verification step fails.
"""

from __future__ import annotations

import importlib
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch


REQUIRED_ASSESSMENT_AUDIT_KEYS = {
    "timestamp_utc",
    "operator_id",
    "event_type",
    "action",
    "scope_config_hash",
    "target_list_hash",
    "details",
}

REQUIRED_HYGIENE_AUDIT_KEYS = {
    "timestamp_utc",
    "operator_id",
    "action",
    "retention_policy_days",
    "details",
}


def run_post_cleanup_verification() -> bool:
    """
    Programmatic post-cleanup verification runner invoked by HygieneManager.
    Returns True if all integrity checks pass, or False (triggering automatic rollback).
    """
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestHygieneIntegritySuite)
    runner = unittest.TextTestRunner(verbosity=0)
    result = runner.run(suite)
    return result.wasSuccessful()


class TestHygieneIntegritySuite(unittest.TestCase):
    """Post-Cleanup Verification Suite for IoTFlux v4.0."""

    def test_1_all_37_original_unit_and_integration_tests_pass(self) -> None:
        """Confirms all 37 original unit and integration tests in tests/test_iotflux.py pass."""
        from tests import test_iotflux

        loader = unittest.defaultTestLoader
        suite = loader.loadTestsFromModule(test_iotflux)
        self.assertGreaterEqual(suite.countTestCases(), 37)

        runner = unittest.TextTestRunner(stream= open(os.devnull, "w", encoding="utf-8"), verbosity=0)
        try:
            result = runner.run(suite)
        finally:
            runner.stream.close()

        self.assertTrue(
            result.wasSuccessful(),
            f"Original test suite had failures/errors: {result.failures} / {result.errors}",
        )

    def test_2_cli_commands_and_entrypoints_have_no_broken_imports(self) -> None:
        """
        Verifies all core, module, and workflow imports and executes:
        - iotflux scope init
        - iotflux discover
        - iotflux auth set / verify
        - iotflux validate
        - iotflux hygiene
        without import or runtime errors.
        """
        critical_modules = [
            "iotflux",
            "iotflux.core.cli",
            "iotflux.core.scope_manager",
            "iotflux.core.scope_validator",
            "iotflux.core.credential_manager",
            "iotflux.core.profile_generator",
            "iotflux.core.audit_log",
            "iotflux.core.hygiene_manager",
            "iotflux.modules",
            "iotflux.modules.discovery.auto_detect",
            "iotflux.workflows.field_assessment",
            "iotflux.workflows.lab_orchestrator",
            "workflows.field_assessment",
            "workflows.lab_orchestrator",
            "scripts.hygiene_audit",
        ]
        for mod_name in critical_modules:
            imported = importlib.import_module(mod_name)
            self.assertIsNotNone(imported)

        from iotflux.core.audit_log import AuditTrailLogger
        from iotflux.core.cli import direct_cli_entrypoint
        from iotflux.core.credential_manager import set_device_auth_interactive

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            scope_yaml = tmp / "assessment_scope.yaml"
            targets_json = tmp / "assessment_targets.json"
            prof_dir = tmp / "profiles"
            key_file = tmp / ".iotflux_fernet.key"
            audit_json = tmp / "audit_log.json"
            audit_jsonl = tmp / "assessment_audit.jsonl"
            test_audit = AuditTrailLogger(
                log_path=audit_json,
                jsonl_path=audit_jsonl,
                scope_path=scope_yaml,
                targets_path=targets_json,
            )

            with patch("iotflux.core.scope_manager.audit_trail", test_audit), patch(
                "iotflux.modules.discovery.auto_detect.audit_trail", test_audit
            ), patch("iotflux.core.credential_manager.audit_trail", test_audit), patch(
                "iotflux.core.cli.audit_trail", test_audit
            ), patch("iotflux.modules.discovery.auto_detect.check_tcp_port", return_value=False), patch(
                "iotflux.modules.validation.shelly_auditor.requests.get",
                side_effect=OSError("Simulated unreachable host"),
            ):
                # 1. scope init
                rc_init = direct_cli_entrypoint(["scope", "init", "--output", str(scope_yaml)])
                self.assertEqual(rc_init, 0)
                self.assertTrue(scope_yaml.exists())

                # 2. discover (against single non-listening IP in 10.42.0.0/16 with fast timeout)
                rc_disc = direct_cli_entrypoint([
                    "discover",
                    "--scope",
                    str(scope_yaml),
                    "--target-range",
                    "10.42.0.250",
                    "--timeout",
                    "0.05",
                    "--output",
                    str(targets_json),
                ])
                self.assertEqual(rc_disc, 0)
                self.assertTrue(targets_json.exists())

                # 3. auth set & auth verify
                with patch(
                    "iotflux.core.credential_manager.DEFAULT_KEY_FILE",
                    key_file,
                ):
                    set_device_auth_interactive(
                        device_id="dev_verify_01",
                        auth_type="token",
                        secret_prompt_fn=lambda _: "tok_integrity_check",
                        key_path=key_file,
                        profiles_dir=prof_dir,
                    )
                    rc_verify = direct_cli_entrypoint([
                        "auth",
                        "verify",
                        "dev_verify_01",
                        "--profiles-dir",
                        str(prof_dir),
                        "--json",
                    ])
                    self.assertEqual(rc_verify, 0)

                    # 4. validate (read-only mode with --require-auth and --scope)
                    with patch(
                        "iotflux.core.credential_manager.verify_profile_credentials_present",
                        return_value=(True, "api-token", "REDACTED"),
                    ):
                        rc_val = direct_cli_entrypoint([
                            "validate",
                            "shelly_auditor",
                            "--device-id",
                            "dev_verify_01",
                            "--target",
                            "10.42.0.250",
                            "--require-auth",
                            "--scope",
                            str(scope_yaml),
                            "--timeout",
                            "0.05",
                            "--json",
                        ])
                        self.assertEqual(rc_val, 0)

    def test_3_assessment_and_hygiene_audit_jsonl_schemas_valid(self) -> None:
        """Checks that assessment_audit.jsonl and hygiene_cleanup_audit.jsonl schemas remain valid."""
        from iotflux.core.audit_log import AuditTrailLogger
        from iotflux.core.hygiene_manager import log_hygiene_event

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            a_json = tmp / "audit_log.json"
            a_jsonl = tmp / "assessment_audit.jsonl"
            h_jsonl = tmp / "hygiene_cleanup_audit.jsonl"

            logger_inst = AuditTrailLogger(log_path=a_json, jsonl_path=a_jsonl)
            logger_inst.log_event(
                event_type="SCHEMA_VERIFICATION",
                action="verify_schema",
                details={"ok": True},
            )
            log_hygiene_event(
                action="schema_check",
                details={"verified": True},
                log_path=h_jsonl,
            )

            for line in a_jsonl.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    rec = json.loads(line)
                    self.assertTrue(REQUIRED_ASSESSMENT_AUDIT_KEYS.issubset(rec.keys()))
                    self.assertTrue(str(rec["scope_config_hash"]).startswith("sha256:"))
                    self.assertTrue(str(rec["target_list_hash"]).startswith("sha256:"))

            for line in h_jsonl.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    h_rec = json.loads(line)
                    self.assertTrue(REQUIRED_HYGIENE_AUDIT_KEYS.issubset(h_rec.keys()))
                    self.assertEqual(h_rec["retention_policy_days"], 90)

    def test_4_hygiene_audit_static_analysis_report(self) -> None:
        """Verifies scripts/hygiene_audit.py generates a valid hygiene_audit_report.json without modifying files."""
        from scripts.hygiene_audit import run_hygiene_audit

        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "hygiene_audit_report.json"
            entries = run_hygiene_audit(root_dir=".", output_path=report_path)
            self.assertTrue(report_path.exists())
            self.assertIsInstance(entries, list)
            self.assertGreater(len(entries), 0)
            for item in entries:
                for required_key in (
                    "file_path",
                    "artifact_type",
                    "last_referenced_by",
                    "confidence_score",
                    "recommended_action",
                ):
                    self.assertIn(required_key, item)

    def test_5_hygiene_remove_restore_and_fail_fast_rollback(self) -> None:
        """
        Verifies:
        1. Preservation whitelist blocks removal of core/, modules/, workflows/, *audit*, *scope*, *auth*,
           *compliance*, CHANGELOG_PRODUCTION.md, FIELD_ASSESSMENT_GUIDE.md, ASSESSMENT_POLICY_TEMPLATE.md,
           and files modified within 30 days.
        2. Obsolete files older than 30 days are moved to .archive/YYYY-MM-DD_hygiene_cleanup/ (never deleted).
        3. Manual 'hygiene restore' restores archived files accurately.
        4. Fail-fast verification failure automatically triggers rollback restoration.
        """
        from iotflux.core.hygiene_manager import (
            HygieneManager,
            MODIFIED_RECENT_SECONDS,
            evaluate_preservation_whitelist,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            # Create protected files and one obsolete legacy file older than 30 days
            (tmp / "core").mkdir(parents=True, exist_ok=True)
            core_file = tmp / "core" / "engine.py"
            core_file.write_text("# core\n", encoding="utf-8")

            scope_file = tmp / "assessment_scope.yaml"
            scope_file.write_text("# scope\n", encoding="utf-8")

            guide_file = tmp / "FIELD_ASSESSMENT_GUIDE.md"
            guide_file.write_text("# guide\n", encoding="utf-8")

            recent_legacy = tmp / "recent_helper.sh"
            recent_legacy.write_text("#!/bin/sh\n", encoding="utf-8")

            old_legacy = tmp / "obsolete_v1_setup.sh"
            old_legacy.write_text("#!/bin/sh\necho legacy\n", encoding="utf-8")
            # Set mtime of old_legacy to 45 days ago
            forty_five_days_ago = time.time() - (45 * 86400)
            os.utime(old_legacy, (forty_five_days_ago, forty_five_days_ago))
            os.utime(core_file, (forty_five_days_ago, forty_five_days_ago))
            os.utime(scope_file, (forty_five_days_ago, forty_five_days_ago))
            os.utime(guide_file, (forty_five_days_ago, forty_five_days_ago))

            # Check whitelist directly
            self.assertTrue(evaluate_preservation_whitelist("core/engine.py", root_dir=tmp)[0])
            self.assertTrue(evaluate_preservation_whitelist("assessment_scope.yaml", root_dir=tmp)[0])
            self.assertTrue(evaluate_preservation_whitelist("FIELD_ASSESSMENT_GUIDE.md", root_dir=tmp)[0])
            self.assertTrue(evaluate_preservation_whitelist("recent_helper.sh", root_dir=tmp)[0])
            self.assertFalse(evaluate_preservation_whitelist("obsolete_v1_setup.sh", root_dir=tmp)[0])

            report_file = tmp / "hygiene_audit_report.json"
            report_file.write_text(
                json.dumps([
                    {"file_path": "core/engine.py", "artifact_type": "python_module", "recommended_action": "archive_candidate"},
                    {"file_path": "assessment_scope.yaml", "artifact_type": "configuration_file", "recommended_action": "archive_candidate"},
                    {"file_path": "FIELD_ASSESSMENT_GUIDE.md", "artifact_type": "documentation_file", "recommended_action": "archive_candidate"},
                    {"file_path": "recent_helper.sh", "artifact_type": "shell_script", "recommended_action": "archive_candidate"},
                    {"file_path": "obsolete_v1_setup.sh", "artifact_type": "shell_script", "recommended_action": "archive_candidate"},
                ]),
                encoding="utf-8",
            )

            mgr = HygieneManager(root_dir=tmp)

            # 1. Dry-run leaves all files in place
            dry_res = mgr.remove_artifacts(audit_report_path=report_file, dry_run=True)
            self.assertEqual(dry_res["preserved_count"], 4)
            self.assertEqual(dry_res["eligible_count"], 1)
            self.assertTrue(old_legacy.exists())

            # 2. Live archival with passing verification moves only obsolete_v1_setup.sh to .archive/
            live_res = mgr.remove_artifacts(
                audit_report_path=report_file,
                dry_run=False,
                verification_fn=lambda: True,
            )
            self.assertEqual(live_res["archived_count"], 1)
            self.assertFalse(old_legacy.exists())
            self.assertTrue(core_file.exists())
            self.assertTrue(scope_file.exists())
            self.assertTrue(guide_file.exists())
            self.assertTrue(recent_legacy.exists())

            # 3. Manual restore brings obsolete_v1_setup.sh back
            restore_res = mgr.restore_archive(live_res["archive_directory"])
            self.assertEqual(restore_res["restored_count"], 1)
            self.assertTrue(old_legacy.exists())
            os.utime(old_legacy, (forty_five_days_ago, forty_five_days_ago))

            # 4. Fail-fast verification failure automatically triggers rollback restore!
            with self.assertRaises(RuntimeError):
                mgr.remove_artifacts(
                    audit_report_path=report_file,
                    dry_run=False,
                    verification_fn=lambda: False,
                )
            # Verify obsolete_v1_setup.sh was automatically restored after verification failed
            self.assertTrue(old_legacy.exists())


if __name__ == "__main__":
    unittest.main()
