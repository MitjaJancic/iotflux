# Operational Methodology & Safety Gates
⚠️ GROUND TRUTH NOTICE: This document represents the authoritative specification for iotsploit v2.0. Any suggestion contradicting the safety boundaries, CLI syntax, or methodology defined herein is incorrect and must be rejected. Deprecated features (n2, dynamic scoring, legacy commands) are permanently removed and must never be referenced.
This document details the three-phase empirical security assessment and validation methodology implemented in `iotsploit`. All state-changing operations are strictly governed by the formal safety boundaries defined in [`operational_methodology.svg`](../docker-lab/operational_methodology.svg), the threat model in [`THREAT_MODEL.md`](THREAT_MODEL.md), and physical laboratory protocols in [`PHYSICAL_LAB_PREPARATION.md`](PHYSICAL_LAB_PREPARATION.md).

---

## 1. Phase 1: Multi-Protocol Assessment (Read-Only)

Phase 1 provides passive network discovery, service identification, and configuration exposure auditing without altering the operational state of any target device.

- **Scope & Containment:** Confined strictly to the immutable lab subnet (`172.28.0.0/24`). Any request targeting external networks or unapproved IP addresses is rejected at compile time.
- **Safety Invariant:** Exclusively GET-only HTTP requests, read-only CoAP queries (`/.well-known/core`), read-holding-register Modbus queries (FC `0x03`), and passive mDNS/UPnP/WS-Discovery broadcasts. Active state manipulation is strictly prohibited.
- **Multi-Vector Ingress Surface Enumeration:**
  Identifies potential access surfaces across heterogeneous transport layers without disruptive exploitation:
  1. *Exposed Management APIs (CWE-306)*: Unauthenticated Gen 2 JSON-RPC (`/rpc/Shelly.GetDeviceInfo`) and Gen 1 endpoints (`/status`, `/settings`).
  2. *Cleartext Configuration Disclosures (CWE-522)*: CoAP link-format declarations and unencrypted Zigbee coordinator configuration dumps (`/api/config`).
  3. *Perimeter Gateway Boundaries (CWE-284)*: UPnP IGD XML descriptors (`/rootDesc.xml`) and WAN IP disclosure interfaces.
  4. *Persistent Setup Access Point Flaws (CWE-1188)*: Unencrypted ad-hoc Wi-Fi management SSIDs active concurrently with station interfaces.
- **Firmware & State-Retention Surface Auditing:**
  `capability_checks.py` inspects device capability trees and profile signatures to identify non-volatile configuration partitions, missing firmware update signature verification, and unauthenticated reboot interfaces—evaluating theoretical persistence vectors analytically without injecting code.
- **Assessment Modules:**
  - `net_auditor.py`: Subnet-wide ARP/TCP port discovery and multi-protocol dispatch.
  - `discovery.py` & `port_scan.py`: Passive mDNS reflection and TCP/UDP connect scans.
  - `capability_checks.py`: Profile-driven capability checks (HTTP auth, MQTT TLS, BLE advertising).
  - `book_checks.py`: Standardized protocol audits (UPnP WAN IP probe, WS-Discovery, Modbus read-only).
  - `shelly_checks.py`: Shelly Gen 2 RPC device info inspection (`/rpc/Shelly.GetDeviceInfo`).

---

## 2. Phase 2: Correlation & Risk Quantification

Phase 2 aggregates discrete Phase 1 findings into a coherent causal graph, derives potential multi-hop paths, and assigns standardized risk classifications without performing active exploitation.

### A. Directed Property Graph Model
Findings are modeled as a directed property graph:
$$G = (V_{svc} \cup V_{cred} \cup V_{topic} \cup V_{act}, E)$$
where vertices represent discrete services ($V_{svc}$), harvested credentials ($V_{cred}$), MQTT topic channels ($V_{topic}$), and physical actuators ($V_{act}$). Edges ($E$) represent causal transitions, such as `EXPOSES_CONFIG`, `AUTHENTICATES_SERVICE`, and `ACTUATES_DEVICE`.

### B. Algorithmic Chaining Depth & Physical Impact Tiers
A breadth-first search (BFS) traversal evaluates multi-hop causality:
- **Algorithmic Chaining Depth ($d$):** Calculated as $d = \min(3, |E|)$, capping depth at 3 hops to represent realistic adversarial pivot horizons.
- **Physical Safety Impact Tier ($s \in \{1, 2, 3\}$):** Evaluated objectively from actuator categories:
  - **Tier 1 (Informational / Auxiliary):** Smart indicator bulbs, ambient lighting, display status LEDs.
  - **Tier 2 (Operational / Appliance):** Smart metering plugs, non-safety HVAC fan relays, environmental sensors.
  - **Tier 3 (Kinetic / Physical Access / Grid):** Solenoid door strike locks, motorized deadbolts, industrial DIN circuit breakers.
- **Taxonomy Mapping (`taxonomy.py`):** Correlates paths to standardized CWE/CAPEC classifications (e.g., CWE-306 Missing Authentication, CWE-522 Protected Information, CAPEC-180 Actuator Manipulation, CAPEC-560 Cross-Protocol Reuse).

### C. Standardized Empirical Risk Formulation
Empirical severity is quantified using a non-arbitrary mathematical formulation:
$$R = \min\left(10.0, \; \text{CVSS}_{\text{base}} \times \left(1.0 + \frac{s - 1}{2}\right) \times \left(1.0 - \frac{d - 1}{4}\right)\right)$$
This formula objectively scales standard CVSS base metrics upward when high-consequence physical actuators ($s=3$) are impacted, and discounts risk when longer traversal paths ($d=3$) reduce operational likelihood.

### D. Ephemeral Credential Vault (`ephemeral_credential_vault.py`)
- **Opaque Handle Generation:** Harvests credentials disclosed in cleartext configuration leaks (e.g., `.70` CoAP, `.25` Zigbee `/api/config`) and stores them strictly in volatile process memory under SHA-256 opaque handles (`cred_<8hex>`).
- **Credential Validation Modes:** Graph-driven validation defaults to pre-harvested lab secrets (vault handles) rather than guessing. An explicit, operator-authorized brute-force resistance module (`validate mqtt-bruteforce`, Phase 3) is additionally provided: it iterates an operator-supplied `user:pass` list against the allowlisted in-subnet Mosquitto broker to empirically measure authentication resistance. It requires Two-Key Authorization (`--authorize`), stays confined to `172.28.0.0/24`, records only SHA-256 opaque handles (`cred_<8hex>`) for any credential that authenticates, and never persists plaintext.
- **Zero Disk Persistence:** Plaintext credentials are never written to disk or recorded in logs, and all handles are invalidated upon session termination.

---

## 3. Phase 3: Controlled Impact Validation

Phase 3 replaces unconstrained penetration testing with bounded, reversible state-change verification. It empirically validates whether a theoretical attack path predicted in Phase 2 can produce physical impact, under strict safety guarantees.

### A. Mandatory Two-Key Safety Gate
Every validation experiment requires two independent keys:
1. **Key A (Compile-Time Scope Enforcement):** Codified in `immutable_lab_boundary.py`. Asserts that target endpoints belong to `172.28.0.0/24` and match pre-registered service endpoints. Runtime flags cannot bypass this boundary.
2. **Key B (Operator Authorization):** Requires explicit operator confirmation (`--authorize` prompt in interactive mode, or `--confirm TOKEN` for headless CI). Prevents unintended execution from shell history or automated scripts.

### B. Pre-Flight Lockfile Synchronization
To prevent cross-contamination between the host environment and automated validation, `ControlledImpactValidator` checks that `config/shelly_bridge.lock` is absent. If the host mDNS bridge is running, validation aborts immediately.

### C. Control Surface Validation Modules
The framework implements eleven constrained validation modules targeting specific control surfaces across simulated and physical lab hardware:

1. **EXP-01: Cross-Protocol MQTT Credential Validation (`mqtt_credential_reuse_validator.py`)**  
   Validates logical credential reuse against Mosquitto broker (`172.28.0.20:1883`) via a single `CONNECT`+`CONNACK`+`DISCONNECT` cycle. Wipes vault handles upon exit.
2. **EXP-02: Shelly Relay Pulse / Latching Actuation Verification (`shelly_actuation.py`)**  
   Energizes the physical lock strike relay on `172.28.0.30:80` for an operator-configurable pulse duration (strictly `> 0`; no fixed ceiling) and auto-reverts to `LOCKED_SAFE`. A **latching** mode (`--pulse`) instead energizes and holds the relay — auto-revert intentionally disabled — to demonstrate sustained physical-access impact, until a separate explicit `--revert` restores `LOCKED_SAFE`. The compile-time scope lock and the global circuit breaker (which still trips on restoration failure during a `--revert`) remain in force.
3. **EXP-03-ZIGBEE: Zigbee-to-MQTT Pivot Validation (`zigbee_pivot_validator.py`)**  
   Harvests MQTT credentials from `/api/config` on the Zigbee coordinator (`172.28.0.25:8080`) and validates broker authentication to `172.28.0.20:1883`.
4. **EXP-04: UPnP WAN Exposure Validation (`upnp_wan_validator.py`)**  
   Validates unauthenticated external IP disclosure on gateway router (`172.28.0.40:5000`) via SOAP `GetExternalIPAddress` without leaking packets to the internet or punching firewall holes.
5. **EXP-05: Modbus TCP Register Perturbation & Auto-Revert (`modbus_write_validator.py`)**  
   Performs a Modbus FC `0x06` write to holding register `3` on PLC (`172.28.0.60:502`), reads back the perturbed state, and executes an immediate primary write-back to baseline.
6. **EXP-06: Vault Replay Resistance Validation (`vault_replay_validator.py`)**  
   Demonstrates defensive resilience by attempting replay of an invalidated vault handle against Mosquitto, deterministically asserting rejection (`SafetyBoundaryViolationError`).
7. **EXP-07-BLE: BLE Mesh / Zigbee Light Link Gateway Validation (`ble_mesh_validator.py`)**  
   Validates non-IP mesh protocol risks and lighting control surface reachability on `172.28.0.80:80` under a bounded 1.0s light pulse and auto-revert to `LIGHT_OFF`.
8. **EXP-08-MATTER: Matter / Thread Border Router Commissioning Analysis (`matter_thread_auditor.py`)**  
   Evaluates Matter PASE commissioning handshake on UDP port `5540` (`172.28.0.85:5540`), confirming protocol security without committing persistent fabric credentials.
9. **EXP-09-CLOUD: Cloud-Dependent Smart Lock Token Lifecycle Audit (`cloud_api_validator.py`)**  
   Audits OAuth2 token expiration and offline fail-secure state on a motorized smart deadbolt (`172.28.0.90:8080`) under a bounded 1.5s pulse with immediate token purge and re-lock to `LOCKED_SAFE`.
10. **EXP-10-HMI: Industrial HMI / SCADA Terminal Register Perturbation (`hmi_modbus_validator.py`)**  
    Validates industrial operator touch panel register exposure on `172.28.0.65:502`, executing a single holding register perturbation (Register 3 $\to$ 101) with immediate write-back to baseline.

11. **MQTT-BRUTEFORCE: Credential Brute-Force Resistance Validation (`mqtt_bruteforce.py`)**  
    An explicit, operator-authorized module that iterates an operator-supplied `user:pass` credential list against the allowlisted Mosquitto broker (`172.28.0.20:1883`) via repeated `CONNECT`/`CONNACK` exchanges, recording which credentials authenticate. Each attempt performs a clean `DISCONNECT` (zero persistent sessions); authenticated credentials are recorded only as SHA-256 opaque handles (`cred_<8hex>`), never in plaintext. Confined to `172.28.0.0/24`; out-of-subnet targets are rejected at compile time.

### D. Auto-Revert Engine & Global Circuit Breaker
Every validation action follows a strict 5-stage lifecycle:
1. **Pre-State Capture:** Records baseline device state and telemetry.
2. **Bounded Perturbation:** Dispatches the constrained validation action (operator-configurable actuation duration, or single register write). In latching actuation the state is intentionally held and restored later by an explicit `--revert` command rather than auto-reverted inline.
3. **During-State Capture:** Verifies physical actuation or authentication success.
4. **Primary Revert:** Actively executes restoration command (relay de-energize, Modbus baseline rewrite, MQTT session disconnect).
5. **Post-State Verification:** Audits final state against pre-state snapshot.
   - If post-state matches baseline: Validation marked successful.
   - In operator-authorized **latching** actuation, the held (energized) state is the intended outcome and is recorded as such rather than treated as a restoration failure; baseline is restored later by the explicit `--revert` command, whose own post-state verification remains circuit-breaker protected.
   - If post-state deviates unexpectedly: Invokes **Emergency State Rollback** (e.g., fallback `/relay/0?turn=off`) and trips the **Global Safety Circuit Breaker**, halting all further operations.

### E. Evidence Capture Pipeline & Anti-Forensic Resilience
Recognizing that embedded IoT target devices frequently utilize volatile circular RAM buffers (`syslogd -C`, `tmpfs`) that are susceptible to intentional erasure, truncation, or power-cycle loss, `iotsploit` establishes an **Independent Out-of-Band Evidence Pipeline**:
- **Raw Network PCAP Observer:** Captures Layer 2 through Layer 4 packets independently (`evidence/demos/<exp>_<uuid>_validation_capture.pcap`), providing non-repudiable proof of all packet transmissions and acknowledgments.
- **Tri-State Cryptographic Diffs:** Preserves exact pre-, during-, and post-perturbation JSON state snapshots (`evidence/demos/<exp>_<uuid>_validation_evidence.json`).
- **ISO-8601 UTC Video Synchronization:** Records high-precision markers (`t1`, `t2`) to align network events deterministically with external physical laboratory video feeds.
- **Credential Sanitization:** All persisted evidence dossiers replace sensitive credentials with SHA-256 opaque handles (`cred_<8hex>`).

### F. Zero Persistence Design Philosophy
`iotsploit` maintains zero persistence across all operations:
- No executable binaries, shell scripts, crontabs, or modified files are ever written to target device filesystems or flash partitions.
- All credential handles exist strictly in transient RAM and are purged upon exit.
- Device state is restored to its verified baseline (`LOCKED_SAFE`), leaving zero operational residue.

---

## 4. Physical Laboratory Validation & Comparative Methodology

### A. Pre-Flight Physical Isolation Protocol
Before dispatching validation packets to physical hardware in the university testbed, operators must verify physical network isolation:
```bash
python scripts/verify_physical_isolation.py
```
Asserts workstation subnet containment (`172.28.0.0/24`), gateway reachability (`172.28.0.1`), bridge mutex absence (`config/shelly_bridge.lock`), zero rogue DHCP servers, and complete public WAN air-gap.

### B. Hardware Profiling & Mechanical Calibration
All physical appliances must be profiled in `profiles/<device>.yaml` incorporating actuator mass, stroke length, return spring force, and thermal limits as defined in [`profiles/_physical_template.yaml`](../profiles/_physical_template.yaml). Actuator pulse durations must be calibrated using an oscilloscope and DC current probe following [`PHYSICAL_LAB_PREPARATION.md`](PHYSICAL_LAB_PREPARATION.md).

### C. Pre-Validation Baseline Reference Snapshot
```bash
python scripts/capture_physical_baseline.py --output evidence/baselines/reference_baseline.json
```
Creates an immutable reference dossier containing cryptographic SHA-256 hashes of pre-validation contact positions, Modbus register blocks, and coordinator channels.

### D. Comparative Evaluation Methodology (Simulation vs. Hardware)
Chapter 5 of the thesis benchmarks Docker simulation against physical hardware across four key dimensions documented in [`COMPARATIVE_ANALYSIS_FRAMEWORK.md`](COMPARATIVE_ANALYSIS_FRAMEWORK.md):
1. **Protocol Fidelity:** Measuring response latency and scheduler jitter ($\Delta t_{\text{RPC}} \approx +24.4\text{ms}$ on physical Wi-Fi).
2. **Safety Boundary Robustness:** Validating that primary and secondary auto-revert routines restore baseline across real-world packet drops.
3. **Attack Surface Divergence:** Discovering undocumented vendor debug endpoints and RF beacon behaviors absent from synthetic simulators.
4. **Evidence Completeness:** Evaluating packet retransmissions and RF channel dynamics in forensic PCAP records.

---

## 5. Safety & Ethical Considerations

`iotsploit` is engineered exclusively as a defensive security assessment framework for academic research and empirical verification:

1. **Reversible-by-Design Invariant:** Actuation duration is operator-configurable (strictly `> 0`) rather than fixed at a 2.0s ceiling, and latching mode can deliberately hold state; in every mode a restore path exists (inline auto-revert for momentary pulses, or the explicit `--revert` for latching) and the circuit breaker guards restoration. Because the former hard cap no longer enforces this automatically, operators must calibrate durations to each actuator's datasheet thermal/mechanical limits (see [`PHYSICAL_HARDWARE_RISK_MEMO.md`](PHYSICAL_HARDWARE_RISK_MEMO.md)) to avoid coil burnout.
2. **Boundary Containment:** All state perturbations are locked at compile time to the isolated research testbed (`172.28.0.0/24`). Dispatch to production or external subnets is programmatically impossible.
3. **Constrained Primitives:** The framework contains zero memory-corruption exploit payloads and no anti-forensic log-scrubbing scripts, and verifies security posture via documented vendor protocols and standard administrative control surfaces. Credential brute-force resistance testing is available only as an explicit, operator-authorized module (`validate mqtt-bruteforce`) that is confined to the allowlisted in-subnet broker, records only SHA-256 handles, and persists no plaintext.
4. **Hardware Hazard Mitigation:** All electrical, thermal, and mechanical hazards are formally evaluated in [`PHYSICAL_HARDWARE_RISK_MEMO.md`](PHYSICAL_HARDWARE_RISK_MEMO.md).

---

## 6. Decommissioned & Archived Components

To maintain thesis auditability, obsolete components from earlier development iterations have been archived:

| Component | Historical Role | Reason for Deprecation | Approved Active Replacement |
| :--- | :--- | :--- | :--- |
| **"n2" Feature Module** | Early network mapper prototype. | Superseded by Phase 3 `ControlledImpactValidator` and `net_auditor.py`. | [`iotsploit/core/controlled_impact_validator.py`](../iotsploit/core/controlled_impact_validator.py) |
| **`test_live_lab.py`** | Monolithic integration test runner. | Replaced by modular, safety-bounded unit and regression suites. | [`tests/test_validation_safety.py`](../tests/test_validation_safety.py) & [`tests/test_cli_and_gap_validators.py`](../tests/test_cli_and_gap_validators.py) |
| **Dynamic Scoring Weights** | Arbitrary penalty scoring. | Replaced by standardized CWE/CAPEC impact mappings and BFS depth. | [`iotsploit/core/taxonomy.py`](../iotsploit/core/taxonomy.py) |

All decommissioned files are preserved in `/archive/deprecated_YYYYMMDD/` and recorded in [`DEPRECATION_LOG.md`](../DEPRECATION_LOG.md).

### Approved Active Test Suite
The following 6 test suites represent the complete, authorized regression suite (76 passing tests):
1. `tests/test_validation_safety.py`: Compile-time scope enforcement, operator authorization tokens, and circuit-breaker tripping.
2. `tests/test_safety_boundary_and_revert_reliability.py`: Revert reliability, timeout bounds, and state restoration.
3. `tests/test_cli_and_gap_validators.py`: Refactored CLI parser, dry-run mode, and gap validation modules.
4. `tests/test_baseline_matrix.py`: Negative control matrix and false-positive benchmark (FPR = 0.0%).
5. `tests/test_checks.py`: Discrete capability checks and protocol probes.
6. `tests/test_comparative_validators.py`: Bounded execution, dry-run safety, and boundary rejection for the 4 comparative modules.
