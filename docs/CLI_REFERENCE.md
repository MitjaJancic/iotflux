# CLI Reference Guide
⚠️ GROUND TRUTH NOTICE: This document represents the authoritative specification for iotsploit v2.0. Any suggestion contradicting the safety boundaries, CLI syntax, or methodology defined herein is incorrect and must be rejected. Deprecated features (n2, dynamic scoring, legacy commands) are permanently removed and must never be referenced.
IoTSploit uses an industry-standard, verb-noun command architecture aligned with professional security auditing frameworks:
```bash
iotsploit <module> <action> [target] [options]
```

All commands operate strictly under compile-time containment within the immutable lab subnet (`172.28.0.0/24`).

---

## 1. Core Modules

### `scan` / `net` — Network Discovery & Passive Fingerprinting (Phase 1)
Identifies active nodes and enumerates services using strictly read-only, non-destructive network probes.
- `iotsploit scan subnet --target 172.28.0.0/24` (Subnet host discovery & service fingerprinting)
- `iotsploit net scan 172.28.0.0/24` (Subnet discovery alias)
- `iotsploit net audit 172.28.0.0/24 -o lan_audit.txt -d ./reports` (Autonomous multi-protocol assessment)
- `iotsploit ports scan 172.28.0.40 --device-id owasp_iotgoat` (Targeted port connect-scan)

---

### `mqtt` — Message Broker & Topic Analysis (Phase 1)
Audits message broker configurations, anonymous access privileges, and topic namespaces using read-only retention sampling and automated token redaction.
- `iotsploit mqtt topic-audit 172.28.0.20 --duration 5.0` (Audit exposed topic namespace, classify into Physical Safety Tiers 1–3, and save sanitized map to `evidence/demos/mqtt_topic_map_<uuid>.json`)
- `iotsploit mqtt anon-check 172.28.0.20 --port 1883` (Non-destructive check for anonymous broker `CONNECT` permission)
- `iotsploit mqtt classify 172.28.0.20` (Sample topic namespace `#` and classify telemetry vs actuator topics)

---

### `validate` — Controlled Impact Validation (Phase 3)
Executes bounded, reversible empirical validations verifying theoretical multi-hop paths. State-changing actions require Two-Key Authorization: **Key A** (compile-time subnet check) and **Key B** (operator `--authorize`). Always inspect via `--dry-run` before authorizing.

- **EXP-01: Cross-Protocol MQTT Credential Validation**
  ```bash
  iotsploit validate mqtt-pivot --target 172.28.0.20 --vault-handle cred_8da19336 --dry-run
  iotsploit validate mqtt-pivot --target 172.28.0.20 --vault-handle cred_8da19336 --authorize
  ```
  *Action:* Validates harvested CoAP/Zigbee credentials via a single `CONNECT`+`CONNACK`+`DISCONNECT` cycle. Wipes vault upon exit.

- **EXP-01-ACTUATE: Bounded MQTT Actuator Publication & Auto-Revert**
  ```bash
  iotsploit validate mqtt-actuation --target 172.28.0.20 --topic "shellies/shellylock-mock/relay/0/command" --payload "on" --revert-payload "off" --pulse-duration 2.0s --dry-run
  iotsploit validate mqtt-actuation --target 172.28.0.20 --topic "shellies/shellylock-mock/relay/0/command" --payload "on" --revert-payload "off" --pulse-duration 2.0s --authorize
  ```
  *Action:* Publishes bounded actuation payload to an MQTT command topic with guaranteed automated publication of revert payload (`off`) at $t \le 2.0\text{s}$ and immediate socket teardown.

- **EXP-02: Shelly Relay Pulse / Latching Actuation Verification**
  ```bash
  # Momentary, auto-reverting pulse (operator-configurable duration; no fixed ceiling)
  iotsploit validate shelly-actuation --target 172.28.0.30 --pulse-duration 2.0s --dry-run
  iotsploit validate shelly-actuation --target 172.28.0.30 --pulse-duration 2.0s --authorize

  # Latching mode: energize and HOLD state (auto-revert OFF) until an explicit revert
  iotsploit validate shelly-actuation --target 172.28.0.30 --pulse --authorize
  # Explicit restore of a latched actuator back to LOCKED_SAFE
  iotsploit validate shelly-actuation --target 172.28.0.30 --revert --authorize
  ```
  *Action:* Actuates the smart lock strike solenoid. In the default momentary mode the relay energizes for the operator-configured `--pulse-duration` (strictly `> 0`, no hard ceiling) and then auto-reverts to `LOCKED_SAFE`. In **latching** mode (`--pulse`) the relay is energized and **held** — auto-revert is intentionally disabled to demonstrate sustained physical-access impact — until a separate `--revert` command restores `LOCKED_SAFE`. The compile-time `172.28.0.0/24` scope lock, the service allowlist, and the global circuit breaker (which still trips on restoration failure during a `--revert`) remain fully in force.

- **MQTT-BRUTEFORCE: Credential Brute-Force Resistance Validation**
  ```bash
  iotsploit validate mqtt-bruteforce --target 172.28.0.20 --creds admin:admin --dry-run
  iotsploit validate mqtt-bruteforce --target 172.28.0.20 --creds ./wordlist.txt --authorize
  ```
  *Action:* Iterates a supplied `user:pass` pair or a `user:pass` wordlist file against the Mosquitto broker (`172.28.0.20:1883`) via repeated `CONNECT`/`CONNACK` exchanges, recording which credentials authenticate. Each attempt performs a clean `DISCONNECT` (zero persistent sessions); successful credentials are recorded only as SHA-256 opaque handles (`cred_<8hex>`) — never in plaintext. Requires Two-Key Authorization and is confined to the allowlisted in-subnet broker; targets outside `172.28.0.0/24` are rejected at compile time.

- **EXP-03-ZIGBEE: Zigbee-to-MQTT Pivot Validation**
  ```bash
  iotsploit validate zigbee-pivot --target 172.28.0.25 --vault-handle cred_8da19336 --dry-run
  iotsploit validate zigbee-pivot --target 172.28.0.25 --vault-handle cred_8da19336 --authorize
  ```
  *Action:* Harvests credentials from `/api/config` on the Zigbee coordinator and validates broker authentication to `172.28.0.20:1883`.

- **EXP-04: UPnP WAN Exposure Validation**
  ```bash
  iotsploit validate upnp-wan --target 172.28.0.40 --external-probe 203.0.113.42 --dry-run
  iotsploit validate upnp-wan --target 172.28.0.40 --external-probe 203.0.113.42
  ```
  *Action:* Queries gateway `WANIPConnection:1` `GetExternalIPAddress` without leaking packets to external networks or punching firewall pinholes.

- **EXP-05: Modbus TCP Register Perturbation & Auto-Revert**
  ```bash
  iotsploit validate modbus-write --target 172.28.0.60 --register 0x03 --value 0xFFFF --dry-run
  iotsploit validate modbus-write --target 172.28.0.60 --register 0x03 --value 0xFFFF --authorize
  ```
  *Action:* Executes Modbus FC `0x06` write to holding register `3`, reads back perturbation, and performs guaranteed primary revert to baseline.

- **EXP-06: Ephemeral Vault Replay Resistance**
  ```bash
  iotsploit validate vault-replay --target 172.28.0.20 --handle cred_8da19336 --expect-failure
  ```
  *Action:* Asserts that expired/invalidated vault handles are deterministically rejected with `SafetyBoundaryViolationError`.

- **CHAIN-001: End-to-End Multi-Hop Impact Validation**
  ```bash
  iotsploit validate chain-001 --authorize
  ```
  *Action:* Validates the correlated multi-hop chain: CoAP leak (`.70`) $\rightarrow$ Vault handle $\rightarrow$ Mosquitto pivot (`.20`) $\rightarrow$ Shelly actuator (`.30`).

- **EXP-07-BLE: BLE Mesh / Zigbee Light Link Gateway Validation**
  ```bash
  iotsploit validate ble-mesh --target 172.28.0.80 --pulse-duration 1.0s --dry-run
  iotsploit validate ble-mesh --target 172.28.0.80 --pulse-duration 1.0s --authorize
  ```
  *Action:* Validates lighting control surface on Hue/BLE gateway (`172.28.0.80:80`) with bounded pulse ($t \le 1.0\text{s}$) and auto-revert to `LIGHT_OFF`.

- **EXP-08-MATTER: Matter / Thread Border Router Commissioning Analysis**
  ```bash
  iotsploit validate matter-thread --target 172.28.0.85 --dry-run
  iotsploit validate matter-thread --target 172.28.0.85 --authorize
  ```
  *Action:* Evaluates Matter PASE commissioning handshake on UDP `5540` (`172.28.0.85:5540`) without committing persistent fabric credentials.

- **EXP-09-CLOUD: Cloud-Dependent Smart Lock Token Lifecycle Audit**
  ```bash
  iotsploit validate cloud-api --target 172.28.0.90 --pulse-duration 1.5s --dry-run
  iotsploit validate cloud-api --target 172.28.0.90 --pulse-duration 1.5s --authorize
  ```
  *Action:* Evaluates OAuth token expiration and offline fail-secure state on a motorized smart deadbolt (`172.28.0.90:8080`) with auto-relock to `LOCKED_SAFE`.

- **EXP-10-HMI: Industrial HMI / SCADA Terminal Register Perturbation**
  ```bash
  iotsploit validate hmi-modbus --target 172.28.0.65 --register 3 --value 101 --dry-run
  iotsploit validate hmi-modbus --target 172.28.0.65 --register 3 --value 101 --authorize
  ```
  *Action:* Executes single holding register perturbation on industrial HMI terminal (`172.28.0.65:502`) with guaranteed FC `0x06` write-back to baseline.

---

### `correlate` — Graph-Based Causal Propagation Analysis (Phase 2)
Synthesizes discrete Phase 1 findings into a directed property graph $G=(V,E)$ and traverses causal vulnerability chains.
- `iotsploit correlate path --chain-id CHAIN-001 --format json` (Export structured causal path metrics)
- `iotsploit correlate path --chain-id CHAIN-001 --format dot` (Export Graphviz DOT representation)
- `iotsploit correlate path --chain-id CHAIN-001 --format summary` (Human-readable hop summary)

---

### `verify` — Mandatory Post-Validation Baseline Verification
Conducts mandatory compliance audits asserting zero persistence, safe rest states, and untripped circuit breakers.
- `iotsploit verify baseline --subnet 172.28.0.0/24 --check actuators,vault,circuit-breaker`

---

### `secrets` — Ephemeral Credential Vault Lifecycle Auditing
Audits the in-memory credential vault to ensure zero plaintext storage and verify that all session handles are eradicated.
- `iotsploit secrets audit --scope ephemeral`

---

### `modules` / `info` — Metasploit-Style Module Introspection
Enables operators to discover available validation modules, inspect their compile-time safety constraints, and review standardized evidence schemas prior to execution.
- `iotsploit modules list` (Tabulate all registered Phase 3 Controlled Impact Validation modules)
- `iotsploit modules show <module>` (Display full safety constraints, parameters, and evidence format)
- `iotsploit info <module>` (Direct shortcut alias for `modules show`)

Examples:
```bash
iotsploit modules list
iotsploit info validate/mqtt_pivot
iotsploit modules show shelly_actuation
```

---

## 2. Safety Flags & Controls

| Flag | Purpose & Safety Bound | Scope / Constraint |
| :--- | :--- | :--- |
| `--dry-run` | Prints execution plan, boundary assertions, and rollback mechanics without socket dispatch. | Mandatory pre-flight step for examiners. |
| `--authorize` | Interactive prompt requiring operator confirmation (`AUTHORIZE` / `y`) before state changes. | Two-Key Safety Gate (Key B). |
| `--pulse-duration` | Specifies physical actuator energization duration. | Operator-configurable; must be strictly `> 0`. No hard upper ceiling (default: `2.0s`). |
| `--pulse` | Latching actuation: energize and HOLD device state (auto-revert OFF) until an explicit `--revert`. | `shelly-actuation` only; circuit breaker stays armed; mutually exclusive with `--revert`. |
| `--revert` | Explicit restore of a latched actuator to its `LOCKED_SAFE` baseline (no energize). | `shelly-actuation` only; circuit breaker armed on restoration failure. |
| `--creds` | Supplies a `user:pass` pair or path to a `user:pass` wordlist for credential validation. | Required by `validate mqtt-bruteforce`. |
| `--force-off` | Emergency override dispatching `relay/0?turn=off` to restore actuators to `LOCKED_SAFE`. | Use if physical hardware requires manual reset. |
| `--expect-failure` | Required when executing defensive negative controls (e.g. `validate vault-replay`). | Asserts deterministic exception raising. |
| `--confirm <TOK>` | Non-interactive authorization token for headless CI suites. | Emits deprecation warning in interactive shell. |

---

## 3. Legacy Command Deprecation & Migration Utility

The following legacy commands from earlier prototyping phases are deprecated. They emit non-fatal warnings on `stderr` advising the operator to use professional syntax:

| Legacy Command | Professional Replacement | Architectural Rationale |
| :--- | :--- | :--- |
| `iotsploit demo exp-01 --confirm CONFIRM-EXP-01` | `iotsploit validate mqtt-pivot --target 172.28.0.20 --vault-handle cred_8da19336 --authorize` | Explicit target parameter replaces opaque experiment codes. |
| `iotsploit demo exp-02 --confirm CONFIRM-EXP-02` | `iotsploit validate shelly-actuation --target 172.28.0.30 --pulse-duration 2.0s --authorize` | Exposes safety-critical pulse duration on the CLI; removes hidden defaults. |
| `iotsploit demo exp-03 --confirm CONFIRM-EXP-03` | `iotsploit validate chain-001 --authorize` | Directly addresses correlated attack chain ID `CHAIN-001`. |
| `iotsploit report chain --id CHAIN-001` | `iotsploit correlate path --chain-id CHAIN-001 --format json` | Aligns with graph analysis conventions; supports multiple output formats. |
| `iotsploit vault status` | `iotsploit secrets audit --scope ephemeral` | Adopts secrets management terminology; emphasizes lifecycle audit. |
| `iotsploit net audit ... --post-demo-check` | `iotsploit verify baseline --subnet 172.28.0.0/24 --check actuators,vault,circuit-breaker` | Adopts compliance-checking language; validates explicit subsystem baselines. |

### Automated Syntax Migration Tool (`scripts/migrate_legacy_syntax.py`)
To upgrade existing test scripts or thesis notes, run the migration script:
```bash
# Translate a single command string
python scripts/migrate_legacy_syntax.py --cmd "iotsploit demo exp-01 --confirm CONFIRM-EXP-01"

# Scan and migrate an entire shell script or Python test suite with backups
python scripts/migrate_legacy_syntax.py --file my_test_plan.sh --in-place
```


---

## v0.2.0 — Bounded-by-default actuation, override opt-in, client reporting

### Bounded default vs. owner-authorized override
The safe bounded actuator variant — **<=2.0 s pulse WITH guaranteed auto-revert** —
is now the **default**. The owner-authorized behaviors that the Lab Engineer
declined to validate are **opt-in only**, via `--override-unsafe`:

| Behavior | Default (no flag) | With `--override-unsafe` |
| --- | --- | --- |
| `validate shelly-actuation` pulse | bounded <=2.0 s + auto-revert | uncapped `--pulse-duration` allowed |
| `validate shelly-actuation --pulse` (latching, no auto-revert) | **refused** | allowed (held until `--revert`) |
| `validate mqtt-bruteforce` | **refused** | allowed |

```bash
# Safe bounded pulse (default) — client-facing demos
iotsploit validate shelly-actuation --authorize

# Owner-authorized, NOT lab-validated override (explicit opt-in)
iotsploit validate shelly-actuation --authorize --pulse --override-unsafe
iotsploit validate mqtt-bruteforce --authorize --creds creds.txt --override-unsafe
```
Any finding produced by an override behavior is labeled **"override-enabled, not
lab-validated"** in reports. `--override-unsafe` NEVER applies to appliance
heating-element / thermal actuation (see below).

### Appliance thermal hazard gate (non-negotiable)
`iotsploit/core/appliance_safety.py` refuses any heating-element / thermal
actuation unless the target is explicitly a **simulator** or **interlock-protected**
(`appliance_safety.simulator` / `appliance_safety.interlock_protected` in the
device profile). Heating elements are never energized on a production device.
This gate raises `ApplianceThermalHazardError` and is **not** bypassable by
`--override-unsafe`.

### Running a valid network audit (Lab Engineer run-doc)
- `iotsploit net audit <cidr>` MUST be run **on-network from the kali container
  (172.28.0.10)** on the internal docker bridge. Run from the Windows host it
  returns **"No findings"** because the host is not on the 172.28.0.0/24 bridge —
  an empty result in that case is a mis-run, not a clean assessment.
- Firmware SBOM / CVE / credential / ELF-hardening checks are a **separate
  firmware pass**, NOT part of `net audit`. Client reports report them as their
  own section.

### Client-ready report
`write_reports(...)` now also emits `<basename>.client.md` and a client-grade
`<basename>.client.html` with an executive summary (device count, severity
counts, highest risks, overall posture), per-finding remediation + CWE/CAPEC +
CVE, override labeling, and a "How this assessment was run" methodology block.
