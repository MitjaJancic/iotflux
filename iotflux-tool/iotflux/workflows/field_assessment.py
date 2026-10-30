"""
field_assessment.py - Portable Field Assessment Orchestrator for IoTFlux
Authorized Security Assessment & Conformance Validation Framework

Guides security assessors step-by-step through portable field assessments with:
- Context-aware operational help
- Expected outputs & success criteria
- Failure recovery instructions
- Explicit operator confirmation before every stage
- Structured, tamper-evident logging to assessment_audit.jsonl (including operator_id,
  scope_config_hash, target_list_hash, and module execution results)
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from iotflux.core.audit_log import audit_trail, compute_file_sha256
from iotflux.core.logger import Colors, logger


@dataclass(frozen=True)
class FieldAssessmentStep:
    step_id: str
    title: str
    cli_command: str
    context_help: str
    expected_outputs: List[str]
    failure_recovery: List[str]


FIELD_ASSESSMENT_STEPS: Dict[str, FieldAssessmentStep] = {
    "1": FieldAssessmentStep(
        step_id="1",
        title="Initialize & Validate Assessment Scope",
        cli_command="iotflux scope init --output assessment_scope.yaml && iotflux scope validate --config assessment_scope.yaml",
        context_help="Defines authorized CIDR boundaries (allowed_networks vs denied_networks), concurrency limits, and enforce mode.",
        expected_outputs=[
            "assessment_scope.yaml created and validated against local system network interfaces",
            "SCOPE_CONFIG_VALIDATED event logged to assessment_audit.jsonl with SHA-256 config hash",
        ],
        failure_recovery=[
            "If YAML validation fails, check CIDR syntax (e.g., 10.42.0.0/16) in assessment_scope.yaml",
            "If non-enforce mode is rejected, restore validation_mode: enforce or provide --override-safety --justification",
        ],
    ),
    "2": FieldAssessmentStep(
        step_id="2",
        title="Discover Targets Within Scope",
        cli_command="iotflux discover --scope assessment_scope.yaml --output assessment_targets.json",
        context_help="Executes strictly read-only mDNS/SSDP/UPnP, TCP port, HTTP metadata, and MQTT CONNECT probes within scope.",
        expected_outputs=[
            "assessment_targets.json containing device_id, ip_address, mac_address, open_ports, service_fingerprints, detected_protocol, network_segment",
            "DEVICE_DISCOVERY record appended to assessment_audit.jsonl",
        ],
        failure_recovery=[
            "If ScopeViolationError occurs, verify --target-range is a subnet of allowed_networks, or pass --authorize",
            "If zero devices respond, verify VLAN routing or specify --interface <interface_ip>",
        ],
    ),
    "3": FieldAssessmentStep(
        step_id="3",
        title="Generate Validation Profiles from Discovered Targets",
        cli_command="iotflux profile generate --targets assessment_targets.json --whitelist authorized_devices.txt",
        context_help="Generates schema-validated device profiles in profiles/auto_generated/ and marks whitelisted targets as authorized.",
        expected_outputs=[
            "profiles/auto_generated/<device_id>.yaml for each discovered target",
            "PROFILE_GENERATION record appended to assessment_audit.jsonl",
        ],
        failure_recovery=[
            "Ensure assessment_targets.json exists (complete Step 2 first)",
            "Add authorized device IDs or IPv4 addresses to authorized_devices.txt before re-running",
        ],
    ),
    "4": FieldAssessmentStep(
        step_id="4",
        title="Configure & Verify Credentials for Authorized Devices",
        cli_command="iotflux auth set <device_id> && iotflux auth verify <device_id>",
        context_help="Prompts for password, API token, client certificate, or OAuth2 client credentials and stores Fernet-encrypted bundle in profiles/<device_id>.yaml.enc.",
        expected_outputs=[
            "Encrypted credential bundle at profiles/<device_id>.yaml.enc",
            "Pre-flight verification confirming credentials are valid, un-expired, and sufficiently privileged",
        ],
        failure_recovery=[
            "If DECRYPTION_FAILED occurs, verify .iotflux_fernet.key matches the key used during 'iotflux auth set'",
            "If EXPIRED_CREDENTIALS or INSUFFICIENT_PRIVILEGES occurs, rotate credentials via 'iotflux auth set <device_id>'",
        ],
    ),
    "5": FieldAssessmentStep(
        step_id="5",
        title="Execute Validation with Explicit Authorization",
        cli_command="iotflux validate shelly_auditor --device-id <id> --require-auth --scope assessment_scope.yaml",
        context_help="Executes protocol conformance and security validation modules gated by assessment_scope.yaml and --require-auth.",
        expected_outputs=[
            "Structured validation findings mapped to CWE and protocol specifications",
            "VALIDATION_EXECUTION record appended to assessment_audit.jsonl with module results",
        ],
        failure_recovery=[
            "If CREDENTIAL GATE BLOCKED occurs, run 'iotflux auth verify <device_id>' to diagnose missing or expired credentials",
            "If ASSESSMENT SCOPE VIOLATION occurs, verify the device IP is in allowed_networks, or pass --authorize",
        ],
    ),
    "6": FieldAssessmentStep(
        step_id="6",
        title="Export Compliance & Audit Trail Summary",
        cli_command="Verify assessment_audit.jsonl and export consolidated engagement report",
        context_help="Consolidates scope hash, target inventory hash, and JSONL audit trail into a compliance report.",
        expected_outputs=[
            "reports/field_assessment_summary.json and verified assessment_audit.jsonl",
        ],
        failure_recovery=[
            "Verify write permissions in reports/ directory",
        ],
    ),
}


class FieldAssessmentOrchestrator:
    """
    Interactive orchestrator guiding authorized operators through the 6-stage
    portable field assessment workflow.
    """

    MENU = (
        "\n[IoTFlux Portable Field Assessment Orchestrator]\n"
        "1. Initialize & validate scope (assessment_scope.yaml)\n"
        "2. Discover targets within scope (assessment_targets.json)\n"
        "3. Generate validation profiles (authorized_devices.txt)\n"
        "4. Configure & verify device credentials (profiles/<id>.yaml.enc)\n"
        "5. Execute authorized validation module (--require-auth)\n"
        "6. Export compliance & audit summary (assessment_audit.jsonl)\n"
        "q. Quit\n"
    )

    def __init__(
        self,
        dry_run: bool = False,
        input_fn: Callable[[str], str] = input,
        scope_path: str | Path = "assessment_scope.yaml",
        targets_path: str | Path = "assessment_targets.json",
        authorize_override: bool = False,
    ) -> None:
        self.dry_run = dry_run
        self._input_fn = input_fn
        self.scope_path = Path(scope_path)
        self.targets_path = Path(targets_path)
        self.authorize_override = bool(authorize_override)

    def _authorize_cli_args(self) -> List[str]:
        """Append --authorize/--justification when the orchestrator was launched with them."""
        if not self.authorize_override:
            return []
        return ["--authorize"]

    def show_step_guidance(self, step_id: str) -> FieldAssessmentStep:
        step = FIELD_ASSESSMENT_STEPS[step_id]
        logger.header(f"FIELD ASSESSMENT STEP {step.step_id}: {step.title.upper()}")
        print(f" {Colors.BOLD}Context:{Colors.RESET}          {step.context_help}")
        print(f" {Colors.BOLD}CLI Command:{Colors.RESET}      {step.cli_command}\n")
        print(f" {Colors.BOLD}Expected Outputs:{Colors.RESET}")
        for out in step.expected_outputs:
            print(f"   + {out}")
        print(f"\n {Colors.BOLD}Failure Recovery Instructions:{Colors.RESET}")
        for rec in step.failure_recovery:
            print(f"   ! {rec}")
        print()
        return step

    def execute_step(self, step_id: str) -> int:
        if step_id not in FIELD_ASSESSMENT_STEPS:
            logger.warning(f"Unknown step '{step_id}'. Select 1-6.")
            return 1

        step = self.show_step_guidance(step_id)
        confirm = self._input_fn(f"Proceed with Step {step.step_id} ({step.title})? [y/N]: ").strip().lower()
        if confirm not in ("y", "yes"):
            logger.warning(f"Step {step.step_id} skipped by operator.")
            audit_trail.log_event(
                event_type="FIELD_WORKFLOW_STEP",
                action=f"step_{step.step_id}_skipped",
                details={"step": step.title, "status": "SKIPPED_BY_OPERATOR"},
                scope_file=self.scope_path,
                targets_file=self.targets_path,
            )
            return 0

        if self.dry_run:
            logger.info(f"[DRY-RUN] Would execute: {step.cli_command}")
            audit_trail.log_event(
                event_type="FIELD_WORKFLOW_STEP",
                action=f"step_{step.step_id}_dry_run",
                details={"step": step.title, "command": step.cli_command, "dry_run": True},
                scope_file=self.scope_path,
                targets_file=self.targets_path,
            )
            return 0

        from iotflux.core.cli import direct_cli_entrypoint

        if step_id == "1":
            out_scope = self._input_fn(f"Scope file path [{self.scope_path}]: ").strip() or str(self.scope_path)
            if not Path(out_scope).exists():
                direct_cli_entrypoint(["scope", "init", "--output", out_scope])
            return direct_cli_entrypoint(["scope", "validate", "--config", out_scope])

        elif step_id == "2":
            scope_cfg = self._input_fn(f"Scope config [{self.scope_path}]: ").strip() or str(self.scope_path)
            target_range = self._input_fn("Target CIDR range (leave blank for primary allowed network): ").strip()
            out_targets = self._input_fn(f"Output targets file [{self.targets_path}]: ").strip() or str(self.targets_path)
            cmd = ["discover", "--scope", scope_cfg, "--output", out_targets]
            if target_range:
                cmd.extend(["--target-range", target_range])
            cmd.extend(self._authorize_cli_args())
            return direct_cli_entrypoint(cmd)

        elif step_id == "3":
            in_targets = self._input_fn(f"Discovered targets JSON [{self.targets_path}]: ").strip() or str(self.targets_path)
            whitelist = self._input_fn("Authorized devices whitelist [authorized_devices.txt]: ").strip() or "authorized_devices.txt"
            return direct_cli_entrypoint(["profile", "generate", "--targets", in_targets, "--whitelist", whitelist])

        elif step_id == "4":
            dev_id = self._input_fn("Device ID to configure & verify: ").strip()
            if not dev_id:
                logger.failure("Device ID is required.")
                return 1
            rc = direct_cli_entrypoint(["auth", "set", dev_id])
            if rc != 0:
                return rc
            return direct_cli_entrypoint(["auth", "verify", dev_id])

        elif step_id == "5":
            mod_name = self._input_fn("Validation module [shelly_auditor]: ").strip() or "shelly_auditor"
            dev_id = self._input_fn("Authorized Device ID: ").strip()
            scope_cfg = self._input_fn(f"Scope config [{self.scope_path}]: ").strip() or str(self.scope_path)
            cmd = ["validate", mod_name, "--device-id", dev_id, "--require-auth", "--scope", scope_cfg]
            cmd.extend(self._authorize_cli_args())
            return direct_cli_entrypoint(cmd)

        elif step_id == "6":
            out_report = Path(
                self._input_fn("Summary report path [reports/field_assessment_summary.json]: ").strip()
                or "reports/field_assessment_summary.json"
            )
            out_report.parent.mkdir(parents=True, exist_ok=True)
            summary = {
                "scope_config_path": str(self.scope_path),
                "scope_config_hash": compute_file_sha256(self.scope_path),
                "target_list_path": str(self.targets_path),
                "target_list_hash": compute_file_sha256(self.targets_path),
                "audit_jsonl_events": len(audit_trail.read_jsonl_events()),
            }
            out_report.write_text(json.dumps(summary, indent=2), encoding="utf-8")
            audit_trail.log_event(
                event_type="FIELD_ASSESSMENT_REPORT_EXPORTED",
                action="export_summary",
                details=summary,
                scope_file=self.scope_path,
                targets_file=self.targets_path,
            )
            logger.success(f"Exported field assessment compliance summary to {out_report}.")
            return 0

        return 0

    def run_interactive_loop(self) -> int:
        logger.header("IOTFLUX PORTABLE FIELD ASSESSMENT ORCHESTRATOR")
        while True:
            print(self.MENU)
            try:
                choice = self._input_fn("Select step (1-6 or q): ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if choice in ("q", "quit", "exit"):
                break
            if not choice:
                continue
            self.execute_step(choice)
        return 0


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="field_assessment",
        description="IoTFlux Portable Field Assessment Interactive Orchestrator",
    )
    parser.add_argument("--dry-run", action="store_true", help="Preview assessment steps without executing network/file changes")
    parser.add_argument("--step", choices=list(FIELD_ASSESSMENT_STEPS.keys()), default=None, help="Execute a specific step (1-6)")
    parser.add_argument(
        "--authorize",
        action="store_true",
        help="Operator-authorize out-of-scope targets (scope-only, not state changes)",
    )
    args = parser.parse_args(argv)

    orch = FieldAssessmentOrchestrator(
        dry_run=args.dry_run,
        authorize_override=bool(getattr(args, 'authorize', False)),
    )
    if args.step:
        return orch.execute_step(args.step)
    return orch.run_interactive_loop()


if __name__ == "__main__":
    sys.exit(main())
