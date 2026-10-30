# Override Validation Run — Results

**Run:** 2026-10-27 (Europe/Ljubljana)  **Branch:** testbed-expansion  **Lab:** isolated Docker 172.28.0.0/24
**Authorization:** M J direct owner approval of the override behaviours; two-key `--authorize` + explicit
`--override-unsafe` opt-in on every override command. All targets are simulated containers inside the
immutable `172.28.0.0/24` scope lock. No real hardware, no external target.

> These are **OVERRIDE-ENABLED FINDINGS** — produced with owner-authorized, NOT-lab-validated override
> behaviours (`--override-unsafe`). They are labelled distinctly from safe-baseline (bounded <=2.0s +
> auto-revert, no brute-force) findings and must be reported as such in any client-facing output.

## capability_checks.py conflict (prior run)
Per instruction, the merged tree uses **master's committed `capability_checks.py`** (authoritative; imports
and baseline pass with it). The earlier uncommitted read-only change remains preserved **as-is** and was
**not re-applied**: `stash@{0}` + backup `C:\Users\mitja\capability_checks.py.premerge.bak` +
diff `C:\Users\mitja\capability_checks_premerge.diff`. Not committed, not discarded.

## Pre / Post baseline integrity
| Signal | PRE | POST |
|--------|-----|------|
| `.30` lock (override target) | LOCKED_SAFE (output:false) | **LOCKED_SAFE (output:false)** |
| `.32` | LOCKED_SAFE | LOCKED_SAFE |
| `.31` shelly-ap-flaw (deliberate-misconfig device, NOT touched) | UNLOCKED_ENERGIZED | UNLOCKED_ENERGIZED (unchanged) |
| vault ephemeral handles | 0 | 0 |
| vault persisted secrets | 0 | 0 |
| circuit breaker | not tripped (NORMAL_OPERATION) | not tripped (NORMAL_OPERATION) |

> `verify baseline` returns **FAIL** both pre and post — **solely** because `.31` (shelly-ap-flaw) defaults to
> `UNLOCKED_ENERGIZED` as a deliberate misconfiguration device. This state is **pre-existing and identical
> before and after** the run; this run never actuated `.31`. The override target `.30` returned to
> LOCKED_SAFE, the vault is clean (`cred_8da19336` destroyed on process exit, `zero_persistence_verified:true`),
> and the circuit breaker never tripped. Integrity on everything the overrides touched is intact.

---

## OVERRIDE-ENABLED FINDING 1 — Latching pulse (auto-revert OFF)
- **Command:** `iotsploit validate shelly-actuation --target 172.28.0.30 --pulse --authorize --override-unsafe`
- **Before:** `.30` = LOCKED_SAFE (output:false, 0 W)
- **Actuated/held:** relay energized and **HELD** — output:true, 8.4 W (auto-revert disabled)
- **Explicit restore:** `iotsploit validate shelly-actuation --target 172.28.0.30 --revert --authorize` → `.30` = LOCKED_SAFE (output:false)
- **Before→After:** LOCKED_SAFE → (held) UNLOCKED_ENERGIZED → (explicit revert) LOCKED_SAFE
- **Result:** **PASS** — latching holds without auto-revert; explicit `--revert` restores LOCKED_SAFE. Finding score 8.0 [CWE-306 | CAPEC-180]. Evidence PCAP: `evidence/demos/exp-02_f5ddc6e4_*` (hold) + `exp-02_62b771fc_*` (revert).

## OVERRIDE-ENABLED FINDING 2 — Uncapped pulse > 2.0s
- **Command:** `iotsploit validate shelly-actuation --target 172.28.0.30 --pulse-duration 5.0s --authorize --override-unsafe`
- **Before:** `.30` = LOCKED_SAFE
- **Actuated:** energized for **5.0s** then **auto-reverted** (pre=LOCKED_SAFE → during=UNLOCKED_ENERGIZED @17:22:43Z → post=LOCKED_SAFE @17:22:48Z, exactly 5s)
- **Before→After:** LOCKED_SAFE → (5s energized) → LOCKED_SAFE
- **Result:** **PASS** — uncapped duration honored (exceeds 2.0s ceiling via override), bounded auto-revert still fired at t=5s; final LOCKED_SAFE. Simulated relay container — no physical/thermal hazard. Score 8.0. PCAP: `evidence/demos/exp-02_c2c1d96d_*`.

## OVERRIDE-ENABLED FINDING 3 — MQTT credential brute-force
- **Command:** `iotsploit validate mqtt-bruteforce --target 172.28.0.20 --creds admin:admin --authorize --override-unsafe`
- **Result/enumerated:** iterated 1 credential via repeated CONNECT/CONNACK against `172.28.0.20:1883`; **1 authenticated** (`admin:admin`) → recorded as SHA-256 handle `cred_8da19336` only (no plaintext). All sessions disconnected; zero persistent sessions.
- **Result:** **PASS** — brute-force path executed against allowlisted lab broker; credential succeeded; handle wiped on process exit (post-run vault = 0 handles). Score 4.0 [CWE-307 | CAPEC-49].

---

## Negative control — scope-lock rejection (safety boundary holds)
- **Command:** `iotsploit validate shelly-actuation --target 192.0.2.10 --pulse --authorize --override-unsafe`
- **Result:** **REFUSED**, exit code 1:
  `[!] Safety Boundary Violation: [EXP-02] Safety Boundary Rejection: Target IP '192.0.2.10' is outside the immutable lab subnet '172.28.0.0/24'. No CLI flag or config can override this boundary.`
- **Proves:** the immutable `172.28.0.0/24` scope lock blocks out-of-subnet targets **even with `--override-unsafe` present**.

## Scope lock file
`git diff` on `iotsploit/core/immutable_lab_boundary.py` is **empty** (working tree and vs pre-merge). Line 32 unchanged: `IMMUTABLE_LAB_SUBNET = IPv4Network("172.28.0.0/24")`. Allowlist and safety ceilings not modified.

## Final lab state
All actuators restored to LOCKED_SAFE (`.30`/`.32`; `.31` remains in its pre-existing deliberate-misconfig default). Device room torn down after the run; **core left up**.
