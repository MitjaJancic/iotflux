"""
tests/test_authorize_scope_override.py

Proves --authorize operator scope override (no justification required):
  (a) out-of-scope WITHOUT --authorize -> ScopeViolationError
  (b) WITH --authorize alone -> allowed + SCOPE_OVERRIDE_AUTHORIZED
  (c) nested/session authorize path works (plumbing)
  (d) in-scope unaffected
  (e) --authorize DOES flip AUTHORIZED_TEST (one-flag model)
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from iotflux.core.audit_log import AuditTrailLogger
from iotflux.core.scope_validator import (
    ScopeViolationError,
    expand_scoped_targets,
    load_scope_config,
    validate_target_ip,
)
from iotflux.core.session import FluxSession


FAIL_CLOSED_ENV = (
    "# fail-closed lab scope\n"
    "ALLOWED_SUBNETS=172.28.0.0/24,127.0.0.0/8\n"
    "DENIED_SUBNETS=0.0.0.0/0\n"
    "SCOPE_VALIDATION_MODE=enforce\n"
)

CAMERA_IP = "192.168.1.193"
LAB_IP = "172.28.0.32"


class TestAuthorizeScopeOverride(unittest.TestCase):
    def _env(self, tmp: Path) -> Path:
        env_file = tmp / "lab-scope.env"
        env_file.write_text(FAIL_CLOSED_ENV, encoding="utf-8")
        return env_file

    def test_a_out_of_scope_without_authorize_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            env_file = self._env(tmp)
            audit_file = tmp / "audit_log.json"
            with patch("iotflux.core.scope_validator.audit_trail", AuditTrailLogger(audit_file)):
                with self.assertRaises(ScopeViolationError):
                    validate_target_ip(CAMERA_IP, env_path=env_file)

    def test_b_authorize_alone_allows_and_audits(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            env_file = self._env(tmp)
            audit_file = tmp / "audit_log.json"
            jsonl = tmp / "assessment_audit.jsonl"
            trail = AuditTrailLogger(audit_file, jsonl_path=jsonl)
            with patch("iotflux.core.scope_validator.audit_trail", trail):
                ok = validate_target_ip(CAMERA_IP, env_path=env_file, authorize_override=True)
                self.assertTrue(ok)
                hosts = expand_scoped_targets(CAMERA_IP, env_path=env_file, authorize_override=True)
                self.assertEqual(hosts, [CAMERA_IP])
            events = json.loads(audit_file.read_text(encoding="utf-8"))
            overrides = [e for e in events if e["event_type"] == "SCOPE_OVERRIDE_AUTHORIZED"]
            self.assertGreaterEqual(len(overrides), 1)
            self.assertEqual(overrides[0]["details"]["justification"], "operator --authorize")
            self.assertIn("SCOPE_OVERRIDE_AUTHORIZED", jsonl.read_text(encoding="utf-8"))

    def test_c_nested_helper_honors_active_authorize_flag(self) -> None:
        """Module-level probe helpers must honor _ACTIVE_AUTHORIZE_OVERRIDE (the discover plumbing bug)."""
        from iotflux.modules.discovery import auto_detect as ad

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            env_file = self._env(tmp)
            audit_file = tmp / "audit_log.json"
            with patch("iotflux.core.scope_validator.audit_trail", AuditTrailLogger(audit_file)):
                ad._ACTIVE_AUTHORIZE_OVERRIDE = False
                with self.assertRaises(ScopeViolationError):
                    ad._authorized_validate_target_ip(CAMERA_IP, env_path=env_file)
                ad._ACTIVE_AUTHORIZE_OVERRIDE = True
                try:
                    self.assertTrue(ad._authorized_validate_target_ip(CAMERA_IP, env_path=env_file))
                finally:
                    ad._ACTIVE_AUTHORIZE_OVERRIDE = False

    def test_d_in_scope_target_unaffected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            env_file = self._env(tmp)
            audit_file = tmp / "audit_log.json"
            with patch("iotflux.core.scope_validator.audit_trail", AuditTrailLogger(audit_file)):
                self.assertTrue(validate_target_ip(LAB_IP, env_path=env_file))
                self.assertTrue(validate_target_ip("127.0.0.1", env_path=env_file))

    def test_e_authorize_flips_authorized_test(self) -> None:
        sess = FluxSession()
        self.assertFalse(sess.get_option("AUTHORIZED_TEST"))
        sess.set_option("AUTHORIZE", True)
        self.assertTrue(sess.get_option("AUTHORIZE"))
        self.assertTrue(sess.get_option("AUTHORIZED_TEST"))
        from iotflux.modules.base import BaseValidationModule

        class _Probe(BaseValidationModule):
            name = "probe"
            def run(self, session):
                return []

        self.assertTrue(_Probe().assert_authorized(sess, "test state change"))

    def test_e2_authorized_test_cli_alias_resolves(self) -> None:
        from types import SimpleNamespace
        from iotflux.core.cli import _resolve_authorize_flags

        a, o = _resolve_authorize_flags(SimpleNamespace(authorize=False, override_safety=False, authorized_test=True))
        self.assertTrue(a)
        self.assertTrue(o)
        a2, o2 = _resolve_authorize_flags(SimpleNamespace(authorize=True, override_safety=False, authorized_test=False))
        self.assertTrue(a2)
        self.assertTrue(o2)

    def test_fallback_defaults_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = Path(tmpdir) / "does-not-exist.env"
            cfg = load_scope_config(missing)
            allowed = {str(n) for n in cfg.allowed_subnets}
            self.assertIn("172.28.0.0/24", allowed)
            self.assertNotIn("10.42.0.0/16", allowed)

    def test_cli_help_exposes_authorize_not_justification(self) -> None:
        from iotflux.core.cli import direct_cli_entrypoint

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            with self.assertRaises(SystemExit) as cm:
                direct_cli_entrypoint(["discover", "--help"])
        self.assertEqual(cm.exception.code, 0)
        help_text = buf.getvalue()
        self.assertIn("--authorize", help_text)
        self.assertNotIn("--justification", help_text)

        buf2 = io.StringIO()
        with patch("sys.stdout", buf2):
            with self.assertRaises(SystemExit) as cm2:
                direct_cli_entrypoint(["validate", "--help"])
        val_help = buf2.getvalue()
        self.assertIn("--authorize", val_help)
        self.assertNotIn("--authorized-test", val_help)  # hidden deprecated alias
        self.assertNotIn("--justification", val_help)

    def test_discover_output_optional(self) -> None:
        from iotflux.core.cli import direct_cli_entrypoint
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            with self.assertRaises(SystemExit) as cm:
                direct_cli_entrypoint(["discover", "--help"])
        self.assertIn("Optional path", buf.getvalue())

    def test_scope_manager_authorize_alone(self) -> None:
        from iotflux.core.scope_manager import ScopeManager

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            yaml_path = tmp / "assessment_scope.yaml"
            yaml_path.write_text(
                "allowed_networks:\n"
                '  - cidr: "172.28.0.0/24"\n'
                '    description: "lab"\n'
                "denied_networks:\n"
                '  - cidr: "0.0.0.0/0"\n'
                '    description: "deny"\n'
                "validation_mode: enforce\n"
                "max_concurrent_probes: 10\n"
                "probe_timeout_seconds: 3\n",
                encoding="utf-8",
            )
            audit_file = tmp / "audit_log.json"
            with patch("iotflux.core.scope_manager.audit_trail", AuditTrailLogger(audit_file)):
                mgr = ScopeManager(config_path=yaml_path)
                with self.assertRaises(ScopeViolationError):
                    mgr.validate_target(CAMERA_IP)
                mgr2 = ScopeManager(config_path=yaml_path, authorize_override=True)
                self.assertTrue(mgr2.validate_target(CAMERA_IP))
            events = json.loads(audit_file.read_text(encoding="utf-8"))
            self.assertTrue(any(e["event_type"] == "SCOPE_OVERRIDE_AUTHORIZED" for e in events))


if __name__ == "__main__":
    unittest.main()
