# Changelog — Phase 3: Environment-Adaptive Scoping & Operator-Controlled Workflows

**Release**: IoTFlux v3.0.0 (Phase 3)  
**Date**: 2026-10-29  
**Focus**: Runtime Network Scope Configuration, Operator-Guided Workflow Orchestration, and Transparent Script Replacement

---

## 1. Runtime Network Scope Configuration (Replaces Compile-Time Subnet Locks)

- **Added [`lab-scope.env`](file:///C:/Users/mitja/Downloads/iotsploit/lab-scope.env)**:
  - Defines operator-configurable `ALLOWED_SUBNETS`, `DENIED_SUBNETS`, and `SCOPE_VALIDATION_MODE` (`enforce`, `warn`, `dry-run`).
- **Added [`iotflux/core/scope_validator.py`](file:///C:/Users/mitja/Downloads/iotsploit/iotflux/core/scope_validator.py)**:
  - Implemented `validate_target_ip(target_ip: str) -> bool`, `evaluate_target_against_config()`, `load_scope_config()`, `expand_scoped_targets()`, and `ScopeViolationError`.
  - Uses **Longest-Prefix Match (LPM)** precedence so authorized lab subnets (e.g., `10.42.0.0/16`) cleanly override broad catch-all blocks (`10.0.0.0/8`, `0.0.0.0/0`) while still honoring more-specific `/24` or `/32` exclusions in `DENIED_SUBNETS`.
  - Records every scope inspection, warning, dry-run check, and violation in `audit_log.json`.
- **Refactored [`iotflux/modules/discovery/auto_detect.py`](file:///C:/Users/mitja/Downloads/iotsploit/iotflux/modules/discovery/auto_detect.py)**:
  - Removed all hardcoded compile-time subnet literals (`ALLOWED_DOCKER_LAB_NETWORKS`).
  - Integrated `validate_target_ip()` prior to every UDP SSDP probe, TCP port check, and HTTP metadata request, and suppressed live socket operations when `SCOPE_VALIDATION_MODE=dry-run`.
- **Added `iotflux config show-scope` in [`iotflux/core/cli.py`](file:///C:/Users/mitja/Downloads/iotsploit/iotflux/core/cli.py)**:
  - Displays active allowed/denied CIDRs, validation mode, and configuration file path in human-readable or `--json` format (also accessible via `show scope` inside the interactive console).

---

## 2. Operator-Controlled Workflow Orchestration (Replaces Black-Box Automation)

- **Decomposed `lab_setup.sh` into 4 Discrete CLI Commands in [`iotflux/core/cli.py`](file:///C:/Users/mitja/Downloads/iotsploit/iotflux/core/cli.py)**:
  1. `python -m iotflux infra start --compose-file docker-compose.yml [--dry-run]`
  2. `python -m iotflux run discovery/auto_detect --target 10.42.0.0/24 --output discovered_devices.json`
  3. `python -m iotflux profiles generate --input discovered_devices.json --whitelist lab_whitelist.txt`
  4. `python -m iotflux run validation/shelly_auditor --device-id <id> --require-creds`
- **Added [`iotflux/workflows/lab_orchestrator.py`](file:///C:/Users/mitja/Downloads/iotsploit/iotflux/workflows/lab_orchestrator.py) & [`workflows/lab_orchestrator.py`](file:///C:/Users/mitja/Downloads/iotsploit/workflows/lab_orchestrator.py)**:
  - Interactive 7-step operator menu (`1. Start infrastructure` through `7. Export audit report`, `q. Quit`).
  - Displays pre-step briefings covering **Equivalent CLI Command**, **Expected Outputs**, **Success Criteria**, and **Common Failure Modes**.
  - Requires explicit operator confirmation (`[y/N]`) before executing any stage.

---

## 3. Transparent Script Replacement Framework

- **Added [`scripts/README.md`](file:///C:/Users/mitja/Downloads/iotsploit/scripts/README.md) & [`scripts/script_registry.json`](file:///C:/Users/mitja/Downloads/iotsploit/scripts/script_registry.json)**:
  - Machine-readable and human-readable inventory of all orchestration scripts, their preconditions, expected artifacts, failure modes, and manual CLI fallback procedures.
- **Refactored [`lab_setup.sh`](file:///C:/Users/mitja/Downloads/iotsploit/lab_setup.sh)**:
  - Added `--dry-run` flag support to preview exact commands without side effects.
  - Added step-by-step confirmation prompts and structured JSONL progress logging to `/var/log/iotflux/orchestrator.log` (with automatic fallback to `logs/orchestrator.log` on unprivileged/Windows hosts).

---

## 4. Environment Adaptation Documentation

- **Added [`docs/ENVIRONMENT_ADAPTATION.md`](file:///C:/Users/mitja/Downloads/iotsploit/docs/ENVIRONMENT_ADAPTATION.md)**:
  - Complete guide for configuring `lab-scope.env`, Mermaid troubleshooting flowchart for scope validation failures, reference configurations for single-bridge, multi-VLAN, and hybrid Docker/physical labs, and a 7-point operator verification checklist.
