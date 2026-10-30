# IoTFlux Transparent Orchestration Script Reference (`scripts/`)

This directory documents and indexes all orchestration scripts and workflow entrypoints in **IoTFlux**. To maintain full academic reproducibility and operator visibility, **no script performs hidden state modifications, silent credential injection, or unlogged network operations**.

All scripts are registered in [`script_registry.json`](file:///C:/Users/mitja/Downloads/iotsploit/scripts/script_registry.json) with machine-readable preconditions, expected artifacts, and manual fallback procedures.

---

## 1. Design Principles

1. **Step-by-Step Operator Visibility**: Every orchestration workflow is decomposed into discrete, independently runnable CLI commands.
2. **Dry-Run Verification (`--dry-run`)**: Every script and CLI workflow stage supports `--dry-run`, printing the exact commands and validating scope rules without starting containers or transmitting packets.
3. **Structured Progress Logging**: All workflow steps write JSON Lines (`.jsonl`) progress records to `/var/log/iotflux/orchestrator.log` (automatically falling back to `logs/orchestrator.log` on Windows or non-root environments) and append accountability events to `audit_log.json`.

---

## 2. Registered Scripts & Workflows

### 2.1 `workflows/lab_orchestrator.py` (`python -m iotflux orchestrate`)
- **Purpose**: Interactive, menu-driven operator workflow orchestrator covering all 7 lab lifecycle stages.
- **Inputs**:
  - `lab-scope.env` (runtime network scope configuration)
  - `docker-compose.yml` (isolated lab container topology)
  - `lab_whitelist.txt` (authorized device IDs / IPs)
  - `--dry-run` (optional flag to preview commands without execution)
  - `--step <1..7>` (optional flag to run a single step with operator confirmation)
- **Outputs / Artifacts**:
  - `discovered_devices.json`
  - `profiles/auto_generated/<device_id>.yaml`
  - `reports/lab_validation_report.json`
  - `/var/log/iotflux/orchestrator.log` (or `logs/orchestrator.log`)
  - `audit_log.json`
- **Failure Modes & Manual Fallbacks**:
  - *Docker daemon unavailable*: Run with `--dry-run` or start Docker manually (`docker compose -f docker-compose.yml up -d`).
  - *ScopeViolationError*: Run `python -m iotflux config show-scope` and verify `ALLOWED_SUBNETS` in `lab-scope.env`.
  - *Credential Gate Blocked*: Run `python -m iotflux profiles set-creds <device_id>` before executing state-changing checks with `--require-creds`.

---

### 2.2 `lab_setup.sh`
- **Purpose**: Transparent POSIX shell wrapper that guides the operator through the 4 core validation preparation steps with explicit `[y/N]` confirmation prompts at each stage.
- **Usage**:
  ```bash
  # Interactive step-by-step mode (prompts before each stage)
  ./lab_setup.sh 10.42.0.0/24

  # Dry-run mode (prints exact commands and logs preview without making changes)
  ./lab_setup.sh --dry-run 10.42.0.0/24
  ```
- **Inputs**:
  - Optional `--dry-run` flag
  - Target subnet argument (defaults to `10.42.0.0/24` or `IOTFLUX_TARGET_SUBNET`)
  - `lab-scope.env`, `docker-compose.yml`, `lab_whitelist.txt`
- **Outputs / Artifacts**:
  - `discovered_devices.json`
  - `profiles/auto_generated/*.yaml`
  - Structured step logs in `/var/log/iotflux/orchestrator.log` (or `logs/orchestrator.log`)
- **Failure Modes**:
  - Exits immediately with non-zero status if `lab-scope.env` rejects the target subnet or if a required precondition file is missing.

---

## 3. Manual Four-Step CLI Equivalent

Operators can bypass all wrapper scripts at any time and execute the four discrete CLI commands directly:

```bash
# Step 1: Start isolated lab containers and verify health
python -m iotflux infra start --compose-file docker-compose.yml

# Step 2: Run read-only service discovery (requires operator confirmation of target subnet in lab-scope.env)
python -m iotflux run discovery/auto_detect --target 10.42.0.0/24 --output discovered_devices.json

# Step 3: Generate baseline YAML profiles from discovery output (requires review of discovered_devices.json)
python -m iotflux profiles generate --input discovered_devices.json --whitelist lab_whitelist.txt

# Step 4: Execute validation modules (requires manual credential setup via `iotflux profiles set-creds <id>` first)
python -m iotflux run validation/shelly_auditor --device-id <id> --require-creds
```
