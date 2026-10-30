"""
lab_orchestrator.py - Operator-Guided Step-by-Step Lab Workflow Orchestrator for IoTFlux
Authorized Defensive Security Validation Lab

Replaces opaque black-box shell automation with a transparent, operator-controlled
workflow engine that:
1. Displays expected outputs, success criteria, and common failure modes before each step.
2. Requires explicit operator confirmation before executing any stage.
3. Supports --dry-run mode to preview exact CLI commands without side effects.
4. Writes structured step-by-step execution logs to /var/log/iotflux/orchestrator.log
   (falling back to logs/orchestrator.log on non-root / Windows hosts) and audit_log.json.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from iotflux.core.audit_log import audit_trail
from iotflux.core.logger import Colors, logger
from iotflux.core.scope_validator import load_scope_config


PRIMARY_ORCHESTRATOR_LOG = Path("/var/log/iotflux/orchestrator.log")
FALLBACK_ORCHESTRATOR_LOG = Path("logs/orchestrator.log")


@dataclass(frozen=True)
class WorkflowStepSpec:
    step_id: str
    title: str
    cli_command_preview: str
    expected_outputs: List[str]
    success_criteria: List[str]
    common_failure_modes: List[str]


WORKFLOW_STEPS: Dict[str, WorkflowStepSpec] = {
    "1": WorkflowStepSpec(
        step_id="1",
        title="Start infrastructure",
        cli_command_preview="python -m iotflux infra start --compose-file docker-compose.yml",
        expected_outputs=[
            "Isolated Docker lab bridge network initialized",
            "Simulated IoT zone containers running and passing health checks",
        ],
        success_criteria=[
            "docker compose ps reports all lab services in 'running' / 'healthy' state",
            "No host port conflicts on isolated bridge interfaces",
        ],
        common_failure_modes=[
            "Docker daemon not running or current user lacks docker socket permissions",
            "Subnet overlap with existing host bridge networks (adjust docker-compose.yml & lab-scope.env)",
        ],
    ),
    "2": WorkflowStepSpec(
        step_id="2",
        title="Run service discovery",
        cli_command_preview="python -m iotflux run discovery/auto_detect --target 10.42.0.0/24 --output discovered_devices.json",
        expected_outputs=[
            "discovered_devices.json containing device_id, ip_address, open_ports, and service_fingerprints",
            "DEVICE_DISCOVERY event recorded in audit_log.json",
        ],
        success_criteria=[
            "Target subnet passes runtime lab-scope.env validation",
            "At least one active lab node fingerprinted and written to discovered_devices.json",
        ],
        common_failure_modes=[
            "ScopeViolationError: Target subnet not listed in ALLOWED_SUBNETS of lab-scope.env",
            "Zero devices discovered because lab containers are still initializing",
        ],
    ),
    "3": WorkflowStepSpec(
        step_id="3",
        title="Review discovered devices",
        cli_command_preview="python -m iotflux profiles list  (inspect discovered_devices.json)",
        expected_outputs=[
            "Formatted table of discovered device IDs, IP addresses, open TCP ports, and detected protocols",
        ],
        success_criteria=[
            "Operator verifies all discovered nodes match expected physical/virtual lab topology",
        ],
        common_failure_modes=[
            "discovered_devices.json missing (run Step 2 first)",
            "Unexpected IP or missing service banner requiring container health inspection",
        ],
    ),
    "4": WorkflowStepSpec(
        step_id="4",
        title="Generate profiles",
        cli_command_preview="python -m iotflux profiles generate --input discovered_devices.json --whitelist lab_whitelist.txt",
        expected_outputs=[
            "YAML device profiles in profiles/auto_generated/<device_id>.yaml",
            "authorized: true only for device IDs/IPs present in lab_whitelist.txt",
        ],
        success_criteria=[
            "All generated YAML profiles pass strict schema validation",
            "No plaintext or default credentials written to generated files",
        ],
        common_failure_modes=[
            "discovered_devices.json not found or empty",
            "lab_whitelist.txt missing (defaults to authorized: false for all generated profiles)",
        ],
    ),
    "5": WorkflowStepSpec(
        step_id="5",
        title="Configure credentials",
        cli_command_preview="python -m iotflux profiles set-creds <device_id>",
        expected_outputs=[
            "Fernet-encrypted (AES-128-CBC + HMAC-SHA256) credential token saved to profile YAML",
            "CREDENTIAL_CONFIGURED event logged in audit_log.json (zero plaintext logged)",
        ],
        success_criteria=[
            "Encrypted credential field starts with 'ENC:FERNET:' in profile YAML",
            "Operator key saved with 0600 permissions at .iotflux_vault.key",
        ],
        common_failure_modes=[
            "Specified device_id does not exist in profiles/auto_generated/ or profiles/",
            "Empty password input rejected by interactive validator",
        ],
    ),
    "6": WorkflowStepSpec(
        step_id="6",
        title="Run validation checks",
        cli_command_preview="python -m iotflux run validation/shelly_auditor --device-id <id> --require-creds",
        expected_outputs=[
            "Structured conformance findings mapped to CWE and protocol specifications",
            "Validation evidence logged to console and session report",
        ],
        success_criteria=[
            "Target IP passes runtime scope check via core/scope_validator.py",
            "If --require-creds is active, credentials are verified present before any state-changing check",
        ],
        common_failure_modes=[
            "CREDENTIAL GATE BLOCKED (--require-creds specified but credentials unset for device_id)",
            "Target IP unreachable or rejected by lab-scope.env",
        ],
    ),
    "7": WorkflowStepSpec(
        step_id="7",
        title="Export audit report",
        cli_command_preview="Export consolidated JSON/Markdown lab validation & audit trail report",
        expected_outputs=[
            "reports/lab_validation_report.json consolidating discovered inventory, generated profiles, and audit_log.json",
        ],
        success_criteria=[
            "Report artifact written to disk with complete operator accountability chain",
        ],
        common_failure_modes=[
            "Insufficient disk permissions in output directory",
        ],
    ),
}


def resolve_orchestrator_log_path(preferred: Optional[Path] = None) -> Path:
    """
    Attempts to write to /var/log/iotflux/orchestrator.log on Linux/Pi hosts,
    and cleanly falls back to logs/orchestrator.log on Windows or unprivileged environments.
    """
    target = preferred or PRIMARY_ORCHESTRATOR_LOG
    try:
        # On Windows, '/var/log/...' resolves to current drive root '\var\log\...'.
        # Only use /var/log/iotflux automatically on POSIX when writable, or if explicitly requested.
        if preferred is None and os.name == "nt":
            raise PermissionError("Using workspace logs/orchestrator.log on Windows host")
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "a", encoding="utf-8"):
            pass
        return target
    except Exception:
        fallback = FALLBACK_ORCHESTRATOR_LOG
        fallback.parent.mkdir(parents=True, exist_ok=True)
        return fallback


def log_orchestrator_step(
    step_name: str,
    status: str,
    command: str,
    details: Optional[Dict[str, Any]] = None,
    log_path: Optional[Path] = None,
) -> Path:
    """Writes a structured JSON-line progress entry to orchestrator.log and audit_log.json."""
    resolved = resolve_orchestrator_log_path(log_path)
    entry = {
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "operator": os.environ.get("IOTFLUX_OPERATOR") or os.environ.get("USER") or os.environ.get("USERNAME") or "operator",
        "step": step_name,
        "status": status,
        "command": command,
        "details": details or {},
    }
    with open(resolved, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")

    audit_trail.log_event(
        event_type="WORKFLOW_STEP",
        action=f"orchestrator_{step_name}",
        details={
            "status": status,
            "command": command,
            "log_file": str(resolved),
            **(details or {}),
        },
    )
    return resolved


def run_infra_start(
    compose_file: str | Path = "docker-compose.yml",
    dry_run: bool = False,
    log_path: Optional[Path] = None,
) -> int:
    """
    Step 1 implementation: `python -m iotflux infra start --compose-file docker-compose.yml [--dry-run]`
    Validates compose file presence, logs step progression, and starts isolated lab containers.
    """
    cpath = Path(compose_file)
    cmd_str = f"docker compose -f {cpath} up -d"

    logger.header("STEP 1: LAB INFRASTRUCTURE STARTUP")
    print(f" Compose File : {cpath}")
    print(f" Command      : {cmd_str}")
    print(f" Mode         : {'DRY-RUN (no containers modified)' if dry_run else 'LIVE EXECUTION'}")

    if dry_run:
        logger.info(f"[DRY-RUN] Would execute: {cmd_str}")
        log_orchestrator_step(
            step_name="infra_start",
            status="DRY_RUN",
            command=cmd_str,
            details={"compose_file": str(cpath), "dry_run": True},
            log_path=log_path,
        )
        return 0

    if not cpath.exists():
        logger.failure(f"Compose file '{cpath}' not found. Verify path or run with --compose-file.")
        log_orchestrator_step(
            step_name="infra_start",
            status="FAILED_PRECONDITION",
            command=cmd_str,
            details={"error": f"Compose file {cpath} missing"},
            log_path=log_path,
        )
        return 1

    log_orchestrator_step(
        step_name="infra_start",
        status="STARTED",
        command=cmd_str,
        details={"compose_file": str(cpath)},
        log_path=log_path,
    )
    try:
        proc = subprocess.run(
            ["docker", "compose", "-f", str(cpath), "up", "-d"],
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            logger.failure(f"Docker Compose failed (exit {proc.returncode}): {proc.stderr.strip()}")
            log_orchestrator_step(
                step_name="infra_start",
                status="FAILED",
                command=cmd_str,
                details={"returncode": proc.returncode, "stderr": proc.stderr.strip()},
                log_path=log_path,
            )
            return proc.returncode

        logger.success("Isolated Docker lab infrastructure started and verified.")
        log_orchestrator_step(
            step_name="infra_start",
            status="COMPLETED",
            command=cmd_str,
            details={"returncode": 0},
            log_path=log_path,
        )
        return 0
    except FileNotFoundError:
        logger.failure("Docker CLI binary not found on PATH. Install Docker or run with --dry-run.")
        log_orchestrator_step(
            step_name="infra_start",
            status="FAILED_NO_DOCKER",
            command=cmd_str,
            details={"error": "docker binary not found"},
            log_path=log_path,
        )
        return 1


class LabOrchestrator:
    """
    Interactive, operator-controlled workflow orchestrator for IoTFlux.
    Presents pre-step operational guidance (expected outputs, success criteria,
    common failure modes) and requires explicit operator confirmation before every step.
    """

    MENU_TEXT = (
        "\n[IoTFlux Lab Orchestrator] Select operation:\n"
        "1. Start infrastructure      4. Generate profiles\n"
        "2. Run service discovery     5. Configure credentials\n"
        "3. Review discovered devices 6. Run validation checks\n"
        "7. Export audit report       q. Quit\n"
    )

    def __init__(
        self,
        dry_run: bool = False,
        input_fn: Callable[[str], str] = input,
        log_path: Optional[Path] = None,
    ) -> None:
        self.dry_run = dry_run
        self._input_fn = input_fn
        self.log_path = resolve_orchestrator_log_path(log_path)

    def display_step_briefing(self, step_id: str) -> WorkflowStepSpec:
        spec = WORKFLOW_STEPS[step_id]
        logger.header(f"WORKFLOW STEP {spec.step_id}: {spec.title.upper()}")
        print(f" {Colors.BOLD}Equivalent CLI Command:{Colors.RESET}")
        print(f"   {spec.cli_command_preview}\n")
        print(f" {Colors.BOLD}Expected Outputs:{Colors.RESET}")
        for item in spec.expected_outputs:
            print(f"   + {item}")
        print(f"\n {Colors.BOLD}Success Criteria:{Colors.RESET}")
        for item in spec.success_criteria:
            print(f"   * {item}")
        print(f"\n {Colors.BOLD}Common Failure Modes:{Colors.RESET}")
        for item in spec.common_failure_modes:
            print(f"   ! {item}")
        print()
        return spec

    def confirm_execution(self, step_spec: WorkflowStepSpec) -> bool:
        ans = self._input_fn(
            f"Confirm execution of Step {step_spec.step_id} ({step_spec.title})? [y/N]: "
        ).strip().lower()
        if ans not in ("y", "yes"):
            logger.warning(f"Step {step_spec.step_id} ({step_spec.title}) cancelled by operator.")
            log_orchestrator_step(
                step_name=f"step_{step_spec.step_id}_{step_spec.title.lower().replace(' ', '_')}",
                status="SKIPPED_BY_OPERATOR",
                command=step_spec.cli_command_preview,
                log_path=self.log_path,
            )
            return False
        return True

    def execute_step(self, step_id: str) -> int:
        if step_id not in WORKFLOW_STEPS:
            logger.warning(f"Unknown orchestrator option '{step_id}'.")
            return 1

        spec = self.display_step_briefing(step_id)
        if not self.confirm_execution(spec):
            return 0

        if step_id == "1":
            compose_file = self._input_fn("Compose file [docker-compose.yml]: ").strip() or "docker-compose.yml"
            return run_infra_start(compose_file=compose_file, dry_run=self.dry_run, log_path=self.log_path)

        elif step_id == "2":
            cfg = load_scope_config()
            default_target = f"{cfg.allowed_subnets[0].network_address}/24" if cfg.allowed_subnets else "10.42.0.0/24"
            target = self._input_fn(f"Target subnet or IP [{default_target}]: ").strip() or default_target
            out_file = self._input_fn("Output inventory file [discovered_devices.json]: ").strip() or "discovered_devices.json"
            cmd_preview = f"python -m iotflux run discovery/auto_detect --target {target} --output {out_file}"

            if self.dry_run:
                logger.info(f"[DRY-RUN] Would execute: {cmd_preview}")
                log_orchestrator_step("service_discovery", "DRY_RUN", cmd_preview, {"target": target, "output": out_file}, self.log_path)
                return 0

            from iotflux.modules.discovery.auto_detect import AutoDetectScanner

            scanner = AutoDetectScanner()
            devices = scanner.discover_network(subnet_or_ip=target, output_file=out_file)
            log_orchestrator_step(
                "service_discovery",
                "COMPLETED",
                cmd_preview,
                {"target": target, "devices_found": len(devices), "output": out_file},
                self.log_path,
            )
            return 0

        elif step_id == "3":
            inv_file = Path(self._input_fn("Inventory file to review [discovered_devices.json]: ").strip() or "discovered_devices.json")
            cmd_preview = f"review {inv_file}"
            if self.dry_run:
                logger.info(f"[DRY-RUN] Would inspect discovered inventory at {inv_file}")
                log_orchestrator_step("review_devices", "DRY_RUN", cmd_preview, {"file": str(inv_file)}, self.log_path)
                return 0

            if not inv_file.exists():
                logger.failure(f"Inventory file '{inv_file}' not found. Run Step 2 first.")
                return 1
            devices = json.loads(inv_file.read_text(encoding="utf-8"))
            logger.header(f"DISCOVERED LAB INVENTORY ({len(devices)} device(s))")
            for idx, dev in enumerate(devices, 1):
                print(
                    f" {idx}. {dev.get('device_id')} | IP: {dev.get('ip_address')} | "
                    f"Ports: {dev.get('open_ports')} | Protocols: {dev.get('protocols')}"
                )
            log_orchestrator_step("review_devices", "COMPLETED", cmd_preview, {"devices_reviewed": len(devices)}, self.log_path)
            return 0

        elif step_id == "4":
            in_file = self._input_fn("Input inventory JSON [discovered_devices.json]: ").strip() or "discovered_devices.json"
            whitelist = self._input_fn("Whitelist file [lab_whitelist.txt]: ").strip() or "lab_whitelist.txt"
            cmd_preview = f"python -m iotflux profiles generate --input {in_file} --whitelist {whitelist}"

            if self.dry_run:
                logger.info(f"[DRY-RUN] Would execute: {cmd_preview}")
                log_orchestrator_step("generate_profiles", "DRY_RUN", cmd_preview, {"input": in_file, "whitelist": whitelist}, self.log_path)
                return 0

            from iotflux.core.profile_generator import DynamicProfileGenerator
            from iotflux.core.profiles import catalog as profile_catalog

            gen = DynamicProfileGenerator(whitelist_path=whitelist)
            paths = gen.generate_from_file(in_file)
            profile_catalog.reload()
            logger.success(f"Generated {len(paths)} profile(s).")
            log_orchestrator_step("generate_profiles", "COMPLETED", cmd_preview, {"profiles_generated": len(paths)}, self.log_path)
            return 0

        elif step_id == "5":
            device_id = self._input_fn("Device ID for credential setup: ").strip()
            if not device_id:
                logger.failure("Device ID is required.")
                return 1
            cmd_preview = f"python -m iotflux profiles set-creds {device_id}"
            if self.dry_run:
                logger.info(f"[DRY-RUN] Would execute: {cmd_preview}")
                log_orchestrator_step("configure_credentials", "DRY_RUN", cmd_preview, {"device_id": device_id}, self.log_path)
                return 0

            from iotflux.core.credential_manager import set_device_credentials_interactive

            set_device_credentials_interactive(device_id, prompt_fn=self._input_fn)
            log_orchestrator_step("configure_credentials", "COMPLETED", cmd_preview, {"device_id": device_id}, self.log_path)
            return 0

        elif step_id == "6":
            mod_name = self._input_fn("Validation module [validation/shelly_auditor]: ").strip() or "validation/shelly_auditor"
            device_id = self._input_fn("Target device ID: ").strip()
            req_creds_ans = self._input_fn("Enforce --require-creds gate? [Y/n]: ").strip().lower()
            require_creds = req_creds_ans in ("", "y", "yes")
            cmd_preview = (
                f"python -m iotflux run {mod_name} --device-id {device_id}"
                + (" --require-creds" if require_creds else "")
            )

            if self.dry_run:
                logger.info(f"[DRY-RUN] Would execute: {cmd_preview}")
                log_orchestrator_step(
                    "run_validation",
                    "DRY_RUN",
                    cmd_preview,
                    {"module": mod_name, "device_id": device_id, "require_creds": require_creds},
                    self.log_path,
                )
                return 0

            from iotflux.core.cli import direct_cli_entrypoint

            cli_args = ["run", mod_name]
            if device_id:
                cli_args.extend(["--device-id", device_id])
            if require_creds:
                cli_args.append("--require-creds")
            rc = direct_cli_entrypoint(cli_args)
            log_orchestrator_step(
                "run_validation",
                "COMPLETED" if rc == 0 else "ABORTED",
                cmd_preview,
                {"returncode": rc, "module": mod_name, "device_id": device_id},
                self.log_path,
            )
            return rc

        elif step_id == "7":
            report_path = Path(
                self._input_fn("Audit report output path [reports/lab_validation_report.json]: ").strip()
                or "reports/lab_validation_report.json"
            )
            cmd_preview = f"export audit report -> {report_path}"
            if self.dry_run:
                logger.info(f"[DRY-RUN] Would export consolidated audit report to {report_path}")
                log_orchestrator_step("export_audit_report", "DRY_RUN", cmd_preview, {"report_path": str(report_path)}, self.log_path)
                return 0

            report_path.parent.mkdir(parents=True, exist_ok=True)
            discovered = []
            if Path("discovered_devices.json").exists():
                try:
                    discovered = json.loads(Path("discovered_devices.json").read_text(encoding="utf-8"))
                except Exception:
                    pass
            report_payload = {
                "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "scope_configuration": load_scope_config().to_dict(),
                "discovered_devices_count": len(discovered),
                "discovered_devices": discovered,
                "audit_trail_events": audit_trail.read_events(),
            }
            report_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")
            logger.success(f"Exported consolidated lab audit report to {report_path}.")
            log_orchestrator_step("export_audit_report", "COMPLETED", cmd_preview, {"report_path": str(report_path)}, self.log_path)
            return 0

        return 0

    def run_interactive_loop(self) -> int:
        logger.header("IOTFLUX OPERATOR-GUIDED LAB WORKFLOW ORCHESTRATOR")
        print(f" Structured Progress Log : {self.log_path}")
        print(f" Execution Mode          : {'DRY-RUN' if self.dry_run else 'INTERACTIVE OPERATOR-CONFIRMED'}")

        while True:
            print(self.MENU_TEXT)
            try:
                choice = self._input_fn("Select step (1-7 or q): ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                logger.info("Exiting IoTFlux Lab Orchestrator.")
                break

            if choice in ("q", "quit", "exit"):
                logger.info("Exiting IoTFlux Lab Orchestrator.")
                break
            if not choice:
                continue
            try:
                self.execute_step(choice)
            except Exception as exc:
                logger.failure(f"Step {choice} failed: {exc}")
                log_orchestrator_step(
                    step_name=f"step_{choice}",
                    status="ERROR",
                    command=f"interactive_step_{choice}",
                    details={"error": str(exc)},
                    log_path=self.log_path,
                )
        return 0


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="lab_orchestrator",
        description="IoTFlux Interactive Operator-Guided Lab Workflow Orchestrator",
    )
    parser.add_argument("--dry-run", action="store_true", help="Preview exact CLI commands without executing changes")
    parser.add_argument("--step", choices=list(WORKFLOW_STEPS.keys()), default=None, help="Execute a single menu step (with confirmation)")
    args = parser.parse_args(argv)

    orch = LabOrchestrator(dry_run=args.dry_run)
    if args.step:
        return orch.execute_step(args.step)
    return orch.run_interactive_loop()


if __name__ == "__main__":
    sys.exit(main())
