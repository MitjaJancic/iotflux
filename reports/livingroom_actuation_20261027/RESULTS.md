# Living Room Bounded-Default Actuation — Results

**Run:** 2026-10-27 (Europe/Ljubljana)  **Branch:** testbed-expansion  **Lab:** isolated Docker 172.28.0.0/24
**Authorization:** M J direct owner approval ("i allow it") to add .32/.33/.34 to the actuation allowlist
and actuate them. Merge of master `713eaa5`.

> These are **BOUNDED-DEFAULT (SAFE) FINDINGS** — produced with the default safe mode:
> <=2.0s pulse WITH guaranteed auto-revert, two-key `--authorize`, and **NO `--override-unsafe`**.
> They are distinct from the earlier OVERRIDE-ENABLED findings (latching / uncapped / brute-force).

## Allowlist change (master 713eaa5) — PURE ADDITION verified
`git show 713eaa5` = +15 / -0, single file `iotsploit/core/immutable_lab_boundary.py`. Adds only three
in-subnet actuation endpoints to `AUTHORIZED_VALIDATION_ENDPOINTS` (3 aliases each):
`172.28.0.32:80`, `172.28.0.33:80`, `172.28.0.34:80`. Subnet boundary line (`172.28.0.0/24`), enforce
logic, circuit breaker, bounded <=2.0s + auto-revert default, and `--override-unsafe` gating are all
byte-unchanged. Import `iotsploit.cli` rc=0.

## .34 serving port
Verified real: `.34` (shelly-trv) serves **HTTP :80** — `curl http://172.28.0.34/rpc/Switch.GetStatus?id=0`
returns `http_code=200`; `Shelly.GetStatus` responds. Compose maps container `80/tcp` -> host 8034.
Matches the allowlist entry; no mismatch, so `.34` was actuated.

## Per-target bounded actuation (command: `iotsploit validate shelly-actuation --target <ip> [--relay 0] --authorize`)
| Target | Device | Before | During | After | Pulse | Result |
|--------|--------|--------|--------|-------|-------|--------|
| 172.28.0.32 | Shelly Plus Plug S | UNLOCKED_ENERGIZED (default-on plug) | UNLOCKED_ENERGIZED | **LOCKED_SAFE** | 2.0s | **PASS** |
| 172.28.0.33 | Shelly Pro 4PM (relay 0) | LOCKED_SAFE | UNLOCKED_ENERGIZED | **LOCKED_SAFE** | 2.0s | **PASS** |
| 172.28.0.34 | Shelly TRV (:80 verified) | LOCKED_SAFE | UNLOCKED_ENERGIZED | **LOCKED_SAFE** | 2.0s | **PASS** |

All three: allowlist accepted the target (no boundary rejection), energized for the bounded 2.0s window,
then **auto-reverted to LOCKED_SAFE**. Each finding `shelly_active_verification` score 8.0 [CWE-306 | CAPEC-180];
PCAPs under `evidence/demos/exp-02_*`. Raw before/cmd/after in `32.txt`, `33.txt`, `34.txt`.

## Baseline integrity (before vs after)
| Signal | PRE | POST |
|--------|-----|------|
| baseline verdict | FAIL (only because `.32` default-energized) | **PASS** |
| .30 / .31 / .32 | LOCKED_SAFE / LOCKED_SAFE / UNLOCKED_ENERGIZED | LOCKED_SAFE / LOCKED_SAFE / **LOCKED_SAFE** |
| vault handles / persisted | 0 / 0 | 0 / 0 (`zero_persistence_verified: true`) |
| circuit breaker | not tripped | **not tripped** (NORMAL_OPERATION throughout) |

Note: the pre-run `FAIL` was solely `.32`'s default-on smart-plug state; the bounded actuation's auto-revert
left `.32` at LOCKED_SAFE, so the post-run baseline is a clean PASS. The circuit breaker never tripped.

## Scope lock
`git diff iotsploit/core/immutable_lab_boundary.py` (working tree) empty; line 32 unchanged:
`IMMUTABLE_LAB_SUBNET = IPv4Network("172.28.0.0/24")`. No safety ceiling / gating modified.

## capability_checks.py
Merged tree continues to use master's committed version; earlier uncommitted change left untouched
(`stash@{0}` + backup), not re-applied.

## Final lab state
All actuators LOCKED_SAFE; living-room torn down; core left up.
