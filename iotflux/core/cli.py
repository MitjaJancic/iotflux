"""
cli.py - Modular high-speed CLI engine and interactive console for IoTFlux
Authorized Security Assessment & Conformance Validation Framework
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from pathlib import Path
from typing import List, Optional

from iotflux import __version__
from iotflux.core.audit_log import audit_trail
from iotflux.core.logger import Colors, logger
from iotflux.core.profiles import catalog as profile_catalog
from iotflux.core.scope_validator import show_scope_configuration
from iotflux.core.session import FluxSession, session
from iotflux.core.specification import list_specs
from iotflux.modules import BaseValidationModule, get_module, list_modules

BANNER = f"""{Colors.CYAN}
  ██╗ ██████╗ ████████╗███████╗██╗     ██╗   ██╗██╗  ██╗
  ██║██╔═══██╗╚══██╔══╝██╔════╝██║     ██║   ██║╚██╗██╔╝
  ██║██║   ██║   ██║   █████╗  ██║     ██║   ██║ ╚███╔╝ 
  ██║██║   ██║   ██║   ██╔══╝  ██║     ██║   ██║ ██╔██╗ 
  ██║╚██████╔╝   ██║   ██║     ███████╗╚██████╔╝██╔╝ ██╗
  ╚═╝ ╚═════╝    ╚═╝   ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝
{Colors.RESET}
  {Colors.BOLD}IoTFlux v{__version__} - Portable IoT Exploitation & Assessment Framework{Colors.RESET}
  {Colors.GRAY}Active exploitation by default: state changes run without a gate{Colors.RESET}
  {Colors.YELLOW}[!] Scope is advisory. Auto-revert is off unless AUTO_REVERT=true{Colors.RESET}
"""



AUTHORIZE_HELP = (
    "Legacy unlock flag. State changes already run by default; --authorize is kept "
    "for compatibility and is a no-op. --override-safety is an alias."
)


def _resolve_authorize_flags(args) -> tuple[bool, bool]:
    """
    Returns (authorize_override, override_safety).
    --authorize unlocks BOTH out-of-scope assessment and bounded state changes.
    --override-safety and --authorized-test are aliases that map to the same unlock
    (--authorized-test is hidden/deprecated; help advertises --authorize only).
    """
    authorize = bool(
        getattr(args, "authorize", False)
        or getattr(args, "override_safety", False)
        or getattr(args, "authorized_test", False)
    )
    override_safety = authorize
    return authorize, override_safety


class FluxConsole:
    """Metasploit-style interactive console for IoTFlux."""

    def __init__(self, sess: Optional[FluxSession] = None) -> None:
        self.session = sess or session
        self.active_module: Optional[BaseValidationModule] = None

    def print_banner(self) -> None:
        print(BANNER)

    def print_help(self) -> None:
        logger.header("IOTFLUX CONSOLE COMMAND REFERENCE")
        commands = [
            ("use <module>", "Select and activate a validation or conformance module"),
            ("show modules", "List all registered modules by security tier"),
            ("show profiles", "List all hardware and virtual device profiles in catalog"),
            ("show scope", "Display active runtime network scope rules"),
            ("show options", "Display global session parameters and active module options"),
            ("set <option> <val>", "Set a parameter value (e.g., 'set target 10.42.0.30')"),
            ("run / audit", "Execute the active validation module"),
            ("info [module]", "Display technical details, references, and options for module"),
            ("creds", "List credentials harvested into the plaintext store"),
            ("profile <device_id>", "Display details of a specific device profile"),
            ("specs", "Display catalog of referenced public standards (Shelly, MQTT, NIST)"),
            ("back", "Deselect active module and return to global context"),
            ("help / ?", "Show this command reference guide"),
            ("exit / quit", "Exit the IoTFlux validation console"),
        ]
        for cmd, desc in commands:
            print(f"  {Colors.BOLD}{cmd:<24}{Colors.RESET} {desc}")
        print()

    def show_modules(self) -> None:
        logger.header("REGISTERED VALIDATION & CONFORMANCE MODULES")
        mods = list_modules()
        print(f" {'#':<3} {'Module Path':<40} {'Security Tier':<25} {'Description'}")
        print(f" {'-'*3} {'-'*40} {'-'*25} {'-'*26}")
        for idx, (path, cls) in enumerate(sorted(mods.items()), 1):
            inst = cls()
            print(f" {idx:<3} {path:<40} {inst.tier:<25} {inst.description}")
        print()

    def show_profiles(self) -> None:
        logger.header("DEVICE PROFILE CATALOG")
        profs = profile_catalog.list_profiles()
        print(f" {'#':<3} {'Device ID':<30} {'Vendor':<16} {'Model':<20} {'Protocols'}")
        print(f" {'-'*3} {'-'*30} {'-'*16} {'-'*20} {'-'*25}")
        for idx, p in enumerate(profs, 1):
            proto_str = ", ".join(p.protocols)
            print(f" {idx:<3} {p.device_id:<30} {p.vendor:<16} {p.model:<20} {proto_str}")
        print(f"\n Total Profiles Loaded: {len(profs)}\n")

    def show_profile_detail(self, device_id: str) -> None:
        p = profile_catalog.get_profile(device_id)
        if not p:
            logger.failure(f"Device profile '{device_id}' not found in catalog.")
            return
        logger.header(f"PROFILE: {p.device_id}")
        print(f" Vendor:          {p.vendor}")
        print(f" Model:           {p.model}")
        print(f" Protocols:       {', '.join(p.protocols)}")
        print(f" Authorized Mode: {p.authorized}")
        if p.http_base_url:
            print(f" HTTP Base URL:   {p.http_base_url}")
        if p.http_endpoints:
            print(" HTTP Endpoints:")
            for ep in p.http_endpoints:
                print(f"   [{ep.method}] {ep.path} (Auth: {ep.expect_auth}) - {ep.description}")
        if p.coap_endpoints:
            print(" CoAP Endpoints:")
            for cep in p.coap_endpoints:
                print(f"   [{cep.method}] {cep.path} (Auth: {cep.expect_auth})")
        if p.known_cves:
            print(" Known Vulnerabilities:")
            for cve in p.known_cves:
                print(f"   * {cve.id} (CVSS: {cve.cvss}) - {cve.description}")
        print()

    def show_specs(self) -> None:
        logger.header("PUBLIC SPECIFICATION & STANDARD REFERENCES")
        for sp in list_specs():
            print(f" * {Colors.BOLD}{sp.spec_id:<18}{Colors.RESET} {sp.title}")
            print(f"   Org: {sp.organization} | URL: {sp.reference_url}")
            print(f"   Defensive Guidance: {sp.defensive_guidance}\n")

    def run_active_module(self) -> None:
        if not self.active_module:
            logger.failure("No module selected. Use 'use <module>' first.")
            return

        target_val = self.session.get_option("TARGET")
        logger.info(f"Executing {self.active_module.name} against target {target_val}...")
        findings = self.active_module.run(self.session)

        audit_trail.log_event(
            event_type="VALIDATION_EXECUTION",
            action=self.active_module.name,
            details={
                "module": self.active_module.name,
                "target": target_val,
                "device_id": self.session.get_option("DEVICE_ID", ""),
                "findings_count": len(findings),
                "findings": [f.to_dict() for f in findings],
            },
        )

        # Output formatting
        fmt = self.session.get_option("OUTPUT_FORMAT", "text")
        if fmt == "json":
            out_data = {
                "module": self.active_module.name,
                "findings": [f.to_dict() for f in findings],
            }
            print(json.dumps(out_data, indent=2))
        else:
            logger.header(f"VALIDATION REPORT: {self.active_module.name}")
            if not findings:
                logger.info("No findings reported for this module run.")
            for f in findings:
                status_color = Colors.GREEN if "COMPLIANT" in f.status and "NON_COMPLIANT" not in f.status else Colors.RED
                print(f" [{f.finding_id}] {f.title}")
                print(f"   Target:      {f.target}")
                print(f"   Status:      {status_color}{f.status}{Colors.RESET}")
                print(f"   Standard:    {f.spec_id} ({f.cwe})")
                print(f"   Observation: {f.details}")
                print(f"   Remediation: {f.remediation}\n")

    def cmdloop(self) -> None:
        self.print_banner()
        while True:
            try:
                mod_prompt = f" ({Colors.RED}{self.active_module.name}{Colors.RESET})" if self.active_module else ""
                prompt = f"{Colors.BOLD}iotflux{Colors.RESET}{mod_prompt} > "
                raw = input(prompt).strip()
                if not raw:
                    continue

                parts = shlex.split(raw)
                cmd = parts[0].lower()
                args = parts[1:]

                if cmd in ("exit", "quit"):
                    logger.info("Exiting IoTFlux validation session.")
                    break
                elif cmd in ("help", "?"):
                    self.print_help()
                elif cmd == "show":
                    sub = args[0].lower() if args else "options"
                    if sub == "modules":
                        self.show_modules()
                    elif sub == "profiles":
                        self.show_profiles()
                    elif sub == "scope":
                        show_scope_configuration()
                    elif sub == "options":
                        self.session.show_options()
                        if self.active_module:
                            self.active_module.show_info()
                    elif sub == "specs":
                        self.show_specs()
                    else:
                        logger.warning("Usage: show [options|modules|profiles|scope|specs]")
                elif cmd == "profiles":
                    self.show_profiles()
                elif cmd == "profile":
                    if args:
                        self.show_profile_detail(args[0])
                    else:
                        logger.warning("Usage: profile <device_id>")
                elif cmd == "options":
                    self.session.show_options()
                    if self.active_module:
                        self.active_module.show_info()
                elif cmd == "specs":
                    self.show_specs()
                elif cmd == "use":
                    if not args:
                        logger.warning("Usage: use <module_name>")
                        continue
                    try:
                        self.active_module = get_module(args[0])
                        logger.success(f"Loaded module: {self.active_module.name}")
                    except KeyError as ex:
                        logger.failure(str(ex))
                elif cmd == "set":
                    if len(args) < 2:
                        logger.warning("Usage: set <option> <value>")
                        continue
                    opt, val = args[0], " ".join(args[1:])
                    if self.active_module and opt.upper() in self.active_module.module_options:
                        self.active_module.set_option(opt, val)
                    else:
                        self.session.set_option(opt, val)
                elif cmd == "info":
                    if args:
                        try:
                            m = get_module(args[0])
                            m.show_info()
                        except KeyError as ex:
                            logger.failure(str(ex))
                    elif self.active_module:
                        self.active_module.show_info()
                    else:
                        logger.warning("Usage: info <module_name> or select a module first with 'use'")
                elif cmd in ("run", "audit", "validate", "exploit"):
                    self.run_active_module()
                elif cmd == "creds":
                    from iotflux.core import creds_store

                    entries = creds_store.all_credentials()
                    if not entries:
                        logger.info(f"No credentials stored in {creds_store.creds_path()}.")
                    for e in entries:
                        mark = "*" if e.get("verified") else " "
                        print(f" {mark} {e.get('host')}:{e.get('port')} [{e.get('protocol')}] {e.get('username')}:{e.get('password')}")
                elif cmd == "back":
                    self.active_module = None
                else:
                    logger.warning(f"Unknown command '{cmd}'. Type 'help' for available commands.")

            except (KeyboardInterrupt, EOFError):
                print()
                logger.info("Session terminated by operator.")
                break
            except Exception as ex:
                logger.failure(f"Command execution error: {ex}")


def direct_cli_entrypoint(argv: Optional[List[str]] = None) -> int:
    from iotflux.core.commands import reorder as _reorder

    if argv is None:
        argv = sys.argv[1:]
    argv = _reorder(list(argv))

    parser = argparse.ArgumentParser(
        prog="iotflux",
        description="IoTFlux - Portable IoT Exploitation & Assessment Framework",
    )
    subparsers = parser.add_subparsers(dest="command", help="Operational mode")

    # Console mode
    subparsers.add_parser("console", help="Launch interactive Metasploit-style validation shell")

    # 1. Dynamic Scope Management (`iotflux scope init` / `iotflux scope validate`)
    scope_parser = subparsers.add_parser("scope", help="Manage and validate assessment_scope.yaml boundaries")
    scope_parser.add_argument("action", choices=["init", "validate"], help="Scope operation (init, validate)")
    scope_parser.add_argument("--output", default="assessment_scope.yaml", help="Output path for 'scope init'")
    scope_parser.add_argument("--config", default="assessment_scope.yaml", help="Config path for 'scope validate'")
    scope_parser.add_argument(
        "--override-safety",
        action="store_true",
        help="Required safety gate override when validation_mode is 'warn' or 'dry-run'",
    )
    scope_parser.add_argument(
        "--authorize",
        action="store_true",
        help="Alias of --override-safety for warn/dry-run mode unlock (scope config validate)",
    )
    scope_parser.add_argument("--json", action="store_true", help="Output scope validation report in JSON format")

    # 2. Environment-Agnostic Discovery (`iotflux discover`)
    disc_parser = subparsers.add_parser("discover", help="Run read-only protocol discovery within assessment scope")
    disc_parser.add_argument("--scope", default="assessment_scope.yaml", help="Path to assessment_scope.yaml")
    disc_parser.add_argument("--target-range", default=None, help="Target CIDR or IP range within allowed_networks")
    disc_parser.add_argument("--interface", default="default", help="Network interface IP for mDNS/SSDP/UPnP binding")
    disc_parser.add_argument("--output", "-o", default=None, help="Optional path to write inventory JSON (prints to stdout if omitted)")
    disc_parser.add_argument("--timeout", type=float, default=None, help="Override per-probe timeout in seconds")
    disc_parser.add_argument(
        "--authorize",
        action="store_true",
        help=AUTHORIZE_HELP,
    )
    disc_parser.add_argument(
        "--override-safety",
        action="store_true",
        help="Allow warn/dry-run scope modes; also accepted as alias of --authorize",
    )

    # 3. Portable Profile Generation (`iotflux profile ...` & `iotflux profiles ...`)
    prof_singular = subparsers.add_parser("profile", help="Generate and manage target validation profiles")
    prof_singular.add_argument(
        "action",
        choices=["generate", "list", "show", "edit"],
        help="Profile action (generate, list, show, edit)",
    )
    prof_singular.add_argument("device_id", nargs="?", default=None, help="Device ID for 'show' or 'edit'")
    prof_singular.add_argument("--targets", "--input", dest="targets", default="assessment_targets.json", help="Input discovered targets JSON")
    prof_singular.add_argument("--whitelist", default="authorized_devices.txt", help="Authorized devices whitelist file")
    prof_singular.add_argument("--output-dir", default="profiles/auto_generated", help="Output directory for generated profiles")

    # 4. Portable Credential & Authorization Workflow (`iotflux auth set` / `iotflux auth verify`)
    auth_parser = subparsers.add_parser("auth", help="Manage and verify encrypted device credentials")
    auth_parser.add_argument("action", choices=["set", "verify"], help="Credential operation (set, verify)")
    auth_parser.add_argument("device_id", help="Target device profile identifier")
    auth_parser.add_argument(
        "--type",
        dest="auth_type",
        choices=["password", "token", "cert", "oauth2"],
        default=None,
        help="Authentication scheme (password, token, cert, oauth2)",
    )
    auth_parser.add_argument("--profiles-dir", default="profiles", help="Directory for encrypted .yaml.enc storage")
    auth_parser.add_argument("--json", action="store_true", help="Output pre-flight verification result in JSON")

    # 4b. Plaintext credential store (`iotflux creds list|get|export|delete|import`)
    creds_parser = subparsers.add_parser("creds", help="Inspect the plaintext credential store (creds.json)")
    creds_parser.add_argument("action", choices=["list", "get", "export", "delete", "import"], help="Credential store operation")
    creds_parser.add_argument("host", nargs="?", default=None, help="Host filter (get/export/delete)")
    creds_parser.add_argument("--protocol", default=None, help="Protocol filter")
    creds_parser.add_argument("--file", default=None, help="Override store path (or source file for 'import')")
    creds_parser.add_argument("--json", action="store_true", help="Output JSON")

    # 5. Field Validation Execution (`iotflux validate <module> --device-id <id> --require-auth --scope ...`)
    val_parser = subparsers.add_parser("validate", help="Execute validation module with scope and authorization gates")
    val_parser.add_argument("module", help="Module name (e.g. shelly_auditor or validation/shelly_auditor)")
    val_parser.add_argument("--device-id", default=None, help="Authorized device profile ID")
    val_parser.add_argument("--target", "-t", default=None, help="Target IP or CIDR")
    val_parser.add_argument("--port", "-p", type=int, default=None, help="Target port")
    val_parser.add_argument("--scope", default="assessment_scope.yaml", help="Assessment scope YAML configuration")
    val_parser.add_argument("--require-auth", action="store_true", help="Enforce valid, non-expired, privileged credentials")
    val_parser.add_argument("--require-creds", action="store_true", help="Alias for --require-auth")
    val_parser.add_argument(
        "--authorized-test",
        action="store_true",
        help=argparse.SUPPRESS,  # deprecated alias of --authorize
    )
    val_parser.add_argument("--authorize", action="store_true", help=AUTHORIZE_HELP)
    val_parser.add_argument(
        "--override-safety",
        action="store_true",
        help="Allow warn/dry-run scope modes; also accepted as alias of --authorize",
    )
    val_parser.add_argument("--json", action="store_true", help="Output findings in JSON format")
    val_parser.add_argument("--timeout", type=float, default=3.0, help="Socket timeout in seconds")
    val_parser.add_argument("--auto-revert", action="store_true", help="Restore pre-change state after perturbation")
    val_parser.add_argument(
        "--opt",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Set a module option (repeatable), e.g. --opt ACTION=set --opt CHANNEL=1",
    )

    # 6. Interactive Field Assessment Orchestrator (`iotflux field-assess`)
    fa_parser = subparsers.add_parser("field-assess", help="Launch interactive Portable Field Assessment Orchestrator")
    fa_parser.add_argument("--dry-run", action="store_true", help="Preview workflow steps without executing changes")
    fa_parser.add_argument("--step", default=None, help="Execute a specific step (1-6)")
    fa_parser.add_argument("--authorize", action="store_true", help=AUTHORIZE_HELP)

    # Legacy/Lab Config subcommand (`iotflux config show-scope`)
    cfg_parser = subparsers.add_parser("config", help="Inspect runtime configuration and network scope rules")
    cfg_parser.add_argument(
        "action",
        nargs="?",
        default="show-scope",
        choices=["show-scope"],
        help="Configuration action (show-scope)",
    )
    cfg_parser.add_argument("--env-file", default="lab-scope.env", help="Path to lab-scope.env file")
    cfg_parser.add_argument("--json", action="store_true", help="Output scope configuration in JSON format")

    # Infra subcommand (`iotflux infra start --compose-file docker-compose.yml`)
    infra_parser = subparsers.add_parser("infra", help="Manage isolated Docker lab infrastructure")
    infra_parser.add_argument("action", choices=["start"], help="Infrastructure operation (start)")
    infra_parser.add_argument("--compose-file", default="docker-compose.yml", help="Path to Docker Compose file")
    infra_parser.add_argument("--dry-run", action="store_true", help="Print exact infrastructure commands without executing")

    # Orchestrate subcommand (interactive guided lab workflow menu)
    orch_parser = subparsers.add_parser("orchestrate", help="Launch interactive operator-guided lab workflow orchestrator")
    orch_parser.add_argument("--dry-run", action="store_true", help="Preview exact workflow commands without side effects")
    orch_parser.add_argument("--step", default=None, help="Execute a specific workflow step (1-7)")

    # Run single module
    run_parser = subparsers.add_parser("run", help="Execute a specific validation module directly")
    run_parser.add_argument("module", help="Module identifier (e.g. validation/shelly_auditor)")
    run_parser.add_argument("--target", "-t", default=None, help="Target host IP or CIDR")
    run_parser.add_argument("--port", "-p", type=int, default=None, help="Target port")
    run_parser.add_argument("--output", "-o", default=None, help="Output file path (e.g. discovered_devices.json)")
    run_parser.add_argument("--device-id", default=None, help="Device profile ID for credential & authorization checks")
    run_parser.add_argument("--scope", default=None, help="Optional assessment_scope.yaml path")
    run_parser.add_argument(
        "--authorized-test",
        action="store_true",
        help=argparse.SUPPRESS,  # deprecated alias of --authorize
    )
    run_parser.add_argument("--authorize", action="store_true", help=AUTHORIZE_HELP)
    run_parser.add_argument(
        "--override-safety",
        action="store_true",
        help="Allow warn/dry-run scope modes; also accepted as alias of --authorize",
    )
    run_parser.add_argument("--require-creds", action="store_true", help="Fail gracefully on state-changing checks if profile credentials are unset")
    run_parser.add_argument("--require-auth", action="store_true", help="Enforce valid, non-expired, privileged credentials")
    run_parser.add_argument("--dry-run", action="store_true", help="Validate scope and preview module execution without live socket modifications")

    # Human-facing family/verb surface: `iotflux <family> <address> <verb>`.
    # `run` above stays as the compatibility path.
    from iotflux.core import commands as _commands

    _commands.build(subparsers)
    run_parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    run_parser.add_argument("--timeout", type=float, default=3.0, help="Socket timeout in seconds")
    run_parser.add_argument("--auto-revert", action="store_true", help="Restore pre-change state after perturbation")
    run_parser.add_argument(
        "--opt",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Set a module option (repeatable), e.g. --opt ACTION=set --opt CHANNEL=1",
    )

    # Modules list
    subparsers.add_parser("modules", help="List all available validation modules")

    # Specs list
    subparsers.add_parser("specs", help="List all referenced public specifications & security standards")

    # Profiles management (list / show / generate / set-creds / edit)
    prof_parser = subparsers.add_parser("profiles", help="Hardware & dynamic device profile management")
    prof_parser.add_argument(
        "action",
        nargs="?",
        default="list",
        choices=["list", "show", "generate", "set-creds", "edit"],
        help="Action (list, show, generate, set-creds, edit)",
    )
    prof_parser.add_argument("device_id", nargs="?", default=None, help="Device ID for 'show', 'set-creds', or 'edit'")
    prof_parser.add_argument("--input", "--targets", dest="input", default="discovered_devices.json", help="Input inventory JSON for 'generate'")
    prof_parser.add_argument("--output-dir", default="profiles/auto_generated", help="Output directory for 'generate'")
    prof_parser.add_argument("--whitelist", default="lab_whitelist.txt", help="Whitelist file for 'generate'")

    # Audit all
    audit_parser = subparsers.add_parser("audit-all", help="Execute comprehensive multi-zone audit across cyber range")
    audit_parser.add_argument("--subnet", default="172.28.0.0/24", help="Target cyber range subnet")
    audit_parser.add_argument("--authorize", action="store_true", help=AUTHORIZE_HELP)
    audit_parser.add_argument("--json", action="store_true", help="Output summary in JSON format")

    # Nmap ingest -> module direction (iotflux nmap-import)
    nmap_parser = subparsers.add_parser(
        "nmap-import",
        help="Parse nmap -oX/-oG/-oN output and suggest IoTFlux validation modules (read-only)",
    )
    nmap_parser.add_argument(
        "file",
        nargs="?",
        default=None,
        help="Path to nmap output file (-oX XML preferred; -oG/-oN accepted). Use - for stdin.",
    )
    nmap_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON plan instead of the text report",
    )

    # 7. Safe Codebase Hygiene Protocol (`iotflux hygiene audit | remove | restore`)
    hyg_parser = subparsers.add_parser("hygiene", help="Safe codebase hygiene audit, reversible archival, and restoration")
    hyg_parser.add_argument("action", choices=["audit", "remove", "restore"], help="Hygiene action (audit, remove, restore)")
    hyg_parser.add_argument(
        "--audit-report",
        default="hygiene_audit_report.json",
        help="Path to hygiene_audit_report.json for 'audit' or 'remove'",
    )
    hyg_parser.add_argument(
        "--archive-path",
        default=None,
        help="Archive directory path (e.g. .archive/YYYY-MM-DD_hygiene_cleanup/) for 'restore'",
    )
    hyg_parser.add_argument("--dry-run", action="store_true", help="Preview archival decisions without modifying files")
    hyg_parser.add_argument("--json", action="store_true", help="Output hygiene summary in JSON format")

    args = parser.parse_args(argv)

    if not args.command or args.command == "console":
        console = FluxConsole()
        console.cmdloop()
        return 0

    elif args.command == "nmap-import":
        from iotflux.core.nmap_import import run_nmap_import

        return run_nmap_import(path=args.file, as_json=args.json)

    elif args.command == "hygiene":
        from iotflux.core.hygiene_manager import HygieneManager

        mgr = HygieneManager()
        if args.action == "audit":
            from scripts.hygiene_audit import run_hygiene_audit

            entries = run_hygiene_audit(output_path=args.audit_report)
            if args.json:
                print(json.dumps(entries, indent=2))
            else:
                logger.success(f"Hygiene audit complete: {len(entries)} item(s) written to {args.audit_report}.")
            return 0
        elif args.action == "remove":
            try:
                res = mgr.remove_artifacts(
                    audit_report_path=args.audit_report,
                    dry_run=args.dry_run,
                )
                if args.json:
                    print(json.dumps(res, indent=2))
                return 0
            except Exception as exc:
                logger.failure(f"Hygiene remove failed: {exc}")
                return 1
        elif args.action == "restore":
            if not args.archive_path:
                logger.failure("Usage: iotflux hygiene restore --archive-path .archive/YYYY-MM-DD_hygiene_cleanup/")
                return 1
            try:
                res = mgr.restore_archive(archive_path=args.archive_path)
                if args.json:
                    print(json.dumps(res, indent=2))
                return 0
            except Exception as exc:
                logger.failure(f"Hygiene restore failed: {exc}")
                return 1

    elif args.command == "scope":
        from iotflux.core.scope_manager import (
            ScopeConfigurationError,
            ScopeSafetyGateError,
            init_scope_config,
            validate_scope_config_cli,
        )

        try:
            if args.action == "init":
                init_scope_config(output_path=args.output, overwrite=True)
                return 0
            elif args.action == "validate":
                authorize, override_safety = _resolve_authorize_flags(args)
                validate_scope_config_cli(
                    config_path=args.config,
                    override_safety=override_safety,
                    as_json=args.json,
                    authorize_override=authorize,
                )
                return 0
        except (ScopeConfigurationError, ScopeSafetyGateError) as exc:
            logger.failure(str(exc))
            return 1

    elif args.command == "discover":
        from iotflux.modules.discovery.auto_detect import AutoDetectScanner

        authorize, override_safety = _resolve_authorize_flags(args)
        if authorize:
            session.set_option("AUTHORIZE", True)

        try:
            scanner = AutoDetectScanner(scope_yaml_path=args.scope)
            scanner.discover_network(
                subnet_or_ip=args.target_range,
                timeout=args.timeout,
                output_file=args.output,
                scope_yaml_path=args.scope,
                interface_ip=args.interface,
                override_safety=override_safety,
                authorize_override=authorize,
            )
            return 0
        except Exception as exc:
            logger.failure(f"Discovery failed: {exc}")
            return 1

    elif args.command == "profile":
        console = FluxConsole()
        if args.action == "show" and args.device_id:
            console.show_profile_detail(args.device_id)
        elif args.action == "generate":
            from iotflux.core.profile_generator import DynamicProfileGenerator

            try:
                gen = DynamicProfileGenerator(output_dir=args.output_dir, whitelist_path=args.whitelist)
                paths = gen.generate_from_file(args.targets)
                profile_catalog.reload()
                logger.success(f"Generated {len(paths)} profile(s) in {args.output_dir}.")
                return 0
            except Exception as ex:
                logger.failure(f"Profile generation failed: {ex}")
                return 1
        elif args.action == "edit" and args.device_id:
            from iotflux.core.credential_manager import edit_device_profile_interactive

            try:
                edit_device_profile_interactive(args.device_id)
                return 0
            except Exception as ex:
                logger.failure(f"Profile edit failed: {ex}")
                return 1
        else:
            console.show_profiles()
        return 0

    elif args.command == "auth":
        from iotflux.core.credential_manager import (
            set_device_auth_interactive,
            verify_device_auth_preflight,
        )

        if args.action == "set":
            try:
                set_device_auth_interactive(
                    device_id=args.device_id,
                    auth_type=args.auth_type,
                    profiles_dir=args.profiles_dir,
                )
                return 0
            except Exception as exc:
                logger.failure(f"Auth setup failed: {exc}")
                return 1
        elif args.action == "verify":
            ok, status_code, details = verify_device_auth_preflight(
                args.device_id,
                profiles_dir=args.profiles_dir,
            )
            if args.json:
                print(json.dumps({"valid": ok, "status": status_code, "details": details}, indent=2))
            elif ok:
                logger.success(
                    f"PRE-FLIGHT AUTH VERIFIED [{status_code}]: Device '{args.device_id}' "
                    f"(scheme={details.get('auth_type')}, privilege={details.get('privilege_level')})"
                )
            else:
                logger.failure(
                    f"PRE-FLIGHT AUTH FAILED [{status_code}] for '{args.device_id}': {details.get('reason')}"
                )
            return 0 if ok else 2

    elif args.command == "creds":
        from iotflux.core import creds_store

        store = args.file
        if args.action == "list":
            entries = creds_store.all_credentials(store)
            if args.host:
                entries = [e for e in entries if e.get("host") == args.host]
            if args.protocol:
                entries = [e for e in entries if e.get("protocol") == args.protocol]
            if args.json:
                print(json.dumps(entries, indent=2))
            else:
                if not entries:
                    logger.info(f"No credentials in {creds_store.creds_path(store)}.")
                for e in entries:
                    mark = "*" if e.get("verified") else " "
                    print(f" {mark} {e.get('host')}:{e.get('port')} [{e.get('protocol')}] {e.get('username')}:{e.get('password')}")
            return 0
        if args.action == "get":
            if not args.host:
                logger.failure("creds get requires a host.")
                return 1
            entries = creds_store.get(args.host, protocol=args.protocol, path=store)
            if args.json:
                print(json.dumps(entries, indent=2))
            else:
                for e in entries:
                    print(f"{e.get('username')}:{e.get('password')} [{e.get('protocol')}]")
            return 0 if entries else 2
        if args.action == "export":
            if not args.host:
                logger.failure("creds export requires a host.")
                return 1
            for pair in creds_store.export_pairs(args.host, protocol=args.protocol, path=store):
                print(pair)
            return 0
        if args.action == "delete":
            if not args.host:
                logger.failure("creds delete requires a host.")
                return 1
            removed = creds_store.delete(args.host, protocol=args.protocol, path=store)
            logger.success(f"Removed {removed} credential(s) for {args.host}.")
            return 0
        if args.action == "import":
            if not args.file:
                logger.failure("creds import requires --file <user:pass list> and a host.")
                return 1
            if not args.host:
                logger.failure("creds import requires a host.")
                return 1
            pairs = creds_store.read_wordlist(args.file)
            for user, pwd in pairs:
                creds_store.add(args.host, args.protocol or "http-basic", user, pwd, source="import")
            logger.success(f"Imported {len(pairs)} pair(s) for {args.host}.")
            return 0
        return 0

    elif args.command == "field-assess":
        from iotflux.workflows.field_assessment import FieldAssessmentOrchestrator
        authorize, _ = _resolve_authorize_flags(args)

        orch = FieldAssessmentOrchestrator(
            dry_run=args.dry_run,
            authorize_override=authorize,
        )
        if args.step:
            return orch.execute_step(args.step)
        return orch.run_interactive_loop()

    elif args.command == "config":
        show_scope_configuration(env_path=args.env_file, as_json=args.json)
        return 0

    elif args.command == "infra":
        from iotflux.workflows.lab_orchestrator import run_infra_start

        return run_infra_start(compose_file=args.compose_file, dry_run=args.dry_run)

    elif args.command == "orchestrate":
        from iotflux.workflows.lab_orchestrator import LabOrchestrator

        orch = LabOrchestrator(dry_run=args.dry_run)
        if args.step:
            return orch.execute_step(args.step)
        return orch.run_interactive_loop()

    elif args.command == "modules":
        console = FluxConsole()
        console.show_modules()
        return 0

    elif args.command == "profiles":
        console = FluxConsole()
        if args.action == "show" and args.device_id:
            console.show_profile_detail(args.device_id)
        elif args.action == "generate":
            from iotflux.core.profile_generator import DynamicProfileGenerator

            try:
                gen = DynamicProfileGenerator(output_dir=args.output_dir, whitelist_path=args.whitelist)
                paths = gen.generate_from_file(args.input)
                profile_catalog.reload()
                logger.success(f"Generated {len(paths)} profile(s) in {args.output_dir}.")
                return 0
            except Exception as ex:
                logger.failure(f"Profile generation failed: {ex}")
                return 1
        elif args.action == "set-creds":
            if not args.device_id:
                logger.failure("Usage: iotflux profiles set-creds <device_id>")
                return 1
            from iotflux.core.credential_manager import set_device_credentials_interactive

            try:
                set_device_credentials_interactive(args.device_id)
                return 0
            except Exception as ex:
                logger.failure(f"Credential configuration failed: {ex}")
                return 1
        elif args.action == "edit":
            if not args.device_id:
                logger.failure("Usage: iotflux profiles edit <device_id>")
                return 1
            from iotflux.core.credential_manager import edit_device_profile_interactive

            try:
                edit_device_profile_interactive(args.device_id)
                return 0
            except Exception as ex:
                logger.failure(f"Profile edit failed: {ex}")
                return 1
        else:
            console.show_profiles()
        return 0

    elif args.command == "specs":
        console = FluxConsole()
        console.show_specs()
        return 0

    elif args.command in ("run", "validate"):
        authorize, override_safety = _resolve_authorize_flags(args)

        try:
            mod = get_module(args.module)
        except KeyError as ex:
            logger.failure(str(ex))
            return 1

        require_auth = bool(getattr(args, "require_auth", False) or getattr(args, "require_creds", False))
        scope_file = getattr(args, "scope", None)

        if authorize:
            session.set_option("AUTHORIZE", True)

        if args.target:
            session.set_option("TARGET", args.target)
            if "SUBNET" in mod.module_options:
                mod.set_option("SUBNET", args.target)
            if "TARGET" in mod.module_options:
                mod.set_option("TARGET", args.target)
        if args.port:
            session.set_option("PORT", args.port)
            if "PORT" in mod.module_options:
                mod.set_option("PORT", args.port)
        if getattr(args, "output", None):
            if "OUTPUT_FILE" in mod.module_options:
                mod.set_option("OUTPUT_FILE", args.output)
        if args.device_id:
            session.set_option("DEVICE_ID", args.device_id)
            mod.set_option("DEVICE_ID", args.device_id)
            prof = profile_catalog.get_profile(args.device_id)
            if prof and prof.ip_address and not args.target:
                session.set_option("TARGET", prof.ip_address)
                mod.set_option("TARGET", prof.ip_address)
        # --authorize (and hidden --authorized-test alias) already folded into authorize
        # via _resolve_authorize_flags; session.AUTHORIZE also sets AUTHORIZED_TEST.
        if require_auth:
            session.set_option("REQUIRE_CREDS", True)
            session.set_option("REQUIRE_AUTH", True)
            mod.set_option("REQUIRE_CREDS", True)
            mod.set_option("REQUIRE_AUTH", True)
        if args.json:
            session.set_option("OUTPUT_FORMAT", "json")
        session.set_option("TIMEOUT", args.timeout)
        if getattr(args, "auto_revert", False):
            session.set_option("AUTO_REVERT", True)

        # --opt KEY=VALUE module options
        for assignment in getattr(args, "opt", []) or []:
            if "=" not in assignment:
                logger.warning(f"Ignoring malformed --opt '{assignment}' (expected KEY=VALUE).")
                continue
            key, _, val = assignment.partition("=")
            key = key.strip().upper()
            if key in mod.module_options:
                mod.set_option(key, val)
            elif key in session.options:
                session.set_option(key, val)
            else:
                logger.warning(f"Unknown option '{key}' for module {args.module}.")

        # Advisory scope check: never blocks.
        target_ip = args.target or session.get_option("TARGET")
        if target_ip and target_ip != "127.0.0.1":
            from iotflux.core.scope_validator import validate_target_ip

            try:
                validate_target_ip(str(target_ip), authorize_override=authorize)
            except Exception as exc:
                logger.warning(f"Scope check skipped: {exc}")

        if getattr(args, "dry_run", False):
            target_str = args.target or args.device_id or session.get_option("TARGET")
            logger.info(f"[DRY-RUN] Module '{args.module}' would run against '{target_str}'.")
            return 0

        if require_auth:
            from iotflux.core.credential_manager import (
                verify_device_auth_preflight,
                verify_profile_credentials_present,
            )

            lookup = args.device_id or args.target or session.get_option("TARGET")
            has_creds, _, _ = verify_profile_credentials_present(str(lookup))
            if not has_creds:
                ok_pre, status_code, info = verify_device_auth_preflight(str(lookup))
                if not ok_pre:
                    logger.failure(
                        f"GRACEFUL ABORT (--require-auth/--require-creds) [{status_code}]: "
                        f"{info.get('reason', 'Credentials missing, expired, or insufficiently privileged')} "
                        f"Configure credentials via 'iotflux auth set {lookup}'."
                    )
                    return 2

        console = FluxConsole(sess=session)
        console.active_module = mod
        console.run_active_module()
        return 0

    elif args.command == "audit-all":
        authorize, _ = _resolve_authorize_flags(args)

        from iotflux.core.scope_validator import validate_target_ip

        try:
            validate_target_ip(
                args.subnet,
                authorize_override=authorize,
            )
        except Exception as exc:
            logger.failure(f"Scope validation gate blocked audit-all: {exc}")
            return 1

        if authorize:
            session.set_option("AUTHORIZE", True)
        session.set_option("SUBNET", args.subnet)
        session.set_option("TARGET", args.subnet)

        logger.header("IOTFLUX COMPREHENSIVE CYBER RANGE AUDIT")
        all_mods = [
            "discovery/subnet_mapper",
            "validation/shelly_auditor",
            "validation/mqtt_telemetry_checker",
            "validation/pin_entropy_analyzer",
            "conformance/protocol_boundary_tester",
            "correlation/cross_zone_correlator",
        ]
        all_findings = []
        for m_name in all_mods:
            try:
                mod_inst = get_module(m_name)
                f_list = mod_inst.run(session)
                all_findings.extend(f_list)
            except Exception as ex:
                logger.warning(f"Module {m_name} encountered notice: {ex}")

        if args.json:
            print(json.dumps([f.to_dict() for f in all_findings], indent=2))
        else:
            logger.header("COMPREHENSIVE AUDIT SUMMARY")
            print(f" Total Findings Evaluated: {len(all_findings)}")
            non_comp = sum(1 for f in all_findings if "NON_COMPLIANT" in f.status)
            print(f" Non-Compliant Items:      {non_comp}")
        return 0

    elif args.command == "ls":
        print("Device families (iotflux <family> <address> <verb>):")
        print()
        print(_commands.list_families())
        return 0

    elif args.command == "completion":
        print(_commands.completion_script())
        return 0

    elif args.command in _commands.FAMILIES:
        if not getattr(args, "verb", None):
            fam = _commands.FAMILIES[args.command]
            print(f"iotflux {args.command} <address> <verb>")
            print()
            print(fam["help"])
            print()
            for verb, spec in fam["verbs"].items():
                print(f"  {verb:<12} {spec.get('help', '')}")
            return 0
        args.family = args.command
        return _commands.run(args, session)

    return 0


def main() -> None:
    sys.exit(direct_cli_entrypoint(sys.argv[1:]))


if __name__ == "__main__":
    main()
