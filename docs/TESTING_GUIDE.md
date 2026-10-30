# iotsploit Lab — Full Testing Guide (Theory + Practice)

> **Scope of this guide.** A standalone, start-to-finish teaching document for testing the isolated
> Docker IoT lab on subnet `172.28.0.0/24` with `iotsploit`. Every command and flag below is grounded in
> the real source: `docs/CLI_REFERENCE.md`, `docs/METHODOLOGY.md`, `docker-lab/ROOMS.md`,
> `docker-lab/RUNBOOK.md`, `iotsploit/cli.py` (`build_arg_parser()` + `MODULES`), the validator modules
> under `iotsploit/modules/validate/`, and `iotsploit/core/immutable_lab_boundary.py`.
>
> **Authoritative-source note:** where `METHODOLOGY.md` prose says the actuation pulse has "no fixed
> ceiling", the shipping CLI (`cli.py`) is authoritative and enforces a **bounded `<=2.0s` default with
> guaranteed auto-revert**; durations `>2.0s` and latching are **refused unless `--override-unsafe`** is
> passed. This guide documents the CLI's real, enforced behavior.

---

## 1. Overview & Safety Model (theory)

### 1.1 Three-phase methodology
`iotsploit` separates assessment from impact:

1. **Phase 1 — Multi-protocol assessment (read-only).** Passive/GET-only discovery and configuration
   auditing. No device state is changed. Covers HTTP/RPC auth exposure, MQTT broker posture, UPnP/WS-Discovery,
   Modbus read-holding-register (FC `0x03`), CoAP `/.well-known/core`, camera/ONVIF, firmware fixtures.
2. **Phase 2 — Correlation & risk quantification.** Phase-1 findings become a directed property graph
   `G = (V_svc ∪ V_cred ∪ V_topic ∪ V_act, E)`. A BFS traversal (depth capped at 3 hops) derives multi-hop
   causal chains; risk is scored from CVSS base × physical-impact tier × traversal discount, mapped to
   CWE/CAPEC. No active exploitation.
3. **Phase 3 — Controlled impact validation.** Bounded, reversible state-change experiments that empirically
   prove whether a Phase-2 path yields physical impact, under a strict 5-stage lifecycle
   (pre-state → bounded perturbation → during-state → primary revert → post-state verify).

### 1.2 Two-key authorization gate
Every state-changing (Phase 3) action needs two independent keys:

- **Key A — compile-time scope lock.** `iotsploit/core/immutable_lab_boundary.py` hardcodes
  `IMMUTABLE_LAB_SUBNET = IPv4Network("172.28.0.0/24")` and an `AUTHORIZED_VALIDATION_ENDPOINTS` allowlist.
  Any target outside the subnet is rejected at compile time. Its own message: *"No CLI flag or config can
  override this boundary."* **This key cannot be bypassed by any runtime flag.**
- **Key B — operator authorization.** `--authorize` (interactive confirm) or `--confirm <TOKEN>` (headless).
  Prevents accidental execution from shell history or scripts.

### 1.3 Ephemeral SHA-256 credential vault
Harvested credentials live **only in volatile process RAM** under opaque handles `cred_<8hex>` (e.g.
`cred_8da19336`). Plaintext is never written to disk or logs; handles are invalidated on process exit
(**zero persistence**). Verified at runtime by `iotsploit secrets audit --scope ephemeral`
(`zero_persistence_verified: true`).

### 1.4 Bounded-by-default actuation + circuit breaker
The default actuation is a **momentary pulse `<=2.0s` with guaranteed auto-revert** to `LOCKED_SAFE`.
Every action records pre/during/post state. If the post-state deviates from baseline unexpectedly, an
**Emergency State Rollback** fires (`/relay/0?turn=off`) and the **global circuit breaker** trips, halting
further operations. `verify baseline` reports `circuit_breaker_tripped` and `halt_reason`.

### 1.5 The `--override-unsafe` opt-in — what it does and does NOT bypass
`--override-unsafe` (cli.py, `dest=override_unsafe`) opts in to three **owner-authorized, NOT-lab-validated**
behaviors, each still requiring `--authorize`:
- uncapped `--pulse-duration` (`>2.0s`),
- latching `--pulse` (auto-revert disabled until explicit `--revert`),
- `validate mqtt-bruteforce`.

It **never** bypasses:
- **the `172.28.0.0/24` compile-time scope lock (Key A)** — out-of-subnet is still refused (proven in §6.4);
- **appliance thermal/heating-element gating** (`iotsploit/core/appliance_safety.py`) — refuses
  heating-element actuation unless a simulator/interlock is present, and is **not** override-bypassable.

### 1.6 Terminology convention
Use defensive/academic language: **validate** (not "exploit"), **actuation / perturbation** (the bounded
state change), **ingress vector** (access surface), **controlled impact validation** (not "attack"). This is
a defensive assessment framework.

---

## 2. Lab topology & rooms (theory + practice)

### 2.1 Rooms map (room → devices → IPs → what it tests)

| Room | Service | Container | IP | Tests |
|------|---------|-----------|----|-------|
| **core** | kali | iotsploit-kali | 172.28.0.10 | Auditor workstation (run the tool here) |
| **core** | mqtt-broker | iotsploit-broker | 172.28.0.20 | Central Mosquitto broker |
| **core** | mqtt-broker-anon | iotsploit-broker-anon | 172.28.0.21 | Anonymous / no-ACL MQTT listener |
| **core** | mqtt-topic-seeder | iotsploit-mqtt-seeder | 172.28.0.22 | Seeds retained topics on .21 |
| **core** | gateway-router | iotsploit-gateway | 172.28.0.40 | Perimeter gateway/router (UPnP, backdoor) |
| **core** | gateway-admin | iotsploit-gateway-admin | 172.28.0.41 | Gateway admin panel (default creds) |
| **living-room** | shelly-app | iotsploit-shelly-app | 172.28.0.15 | Shelly companion dashboard |
| **living-room** | shelly-plug | iotsploit-shelly-plug | 172.28.0.32 | Shelly Plus Plug S metering relay |
| **living-room** | shelly-pro4pm | iotsploit-shelly-pro4pm | 172.28.0.33 | Shelly Pro 4PM 4-ch relay |
| **living-room** | shelly-trv | iotsploit-shelly-trv | 172.28.0.34 | Shelly TRV (Gen2 RPC, auth_en=false) |
| **entry-security** | shelly-lock | iotsploit-shelly-lock | 172.28.0.30 | Smart lock / solenoid strike |
| **entry-security** | shelly-ap-flaw | iotsploit-shelly-ap | 172.28.0.31 | Persistent setup-AP flaw |
| **surveillance** | ip-camera | iotsploit-ip-camera | 172.28.0.50 | Front-porch camera (RTSP/ONVIF) |
| **surveillance** | ip-camera-side-gate | iotsploit-ip-camera-2 | 172.28.0.51 | Side-gate camera (default admin/admin) |
| **surveillance** | nvr-dvr | iotsploit-nvr-dvr | 172.28.0.52 | NVR/DVR (telnet:23, weak auth) |
| **hub-zigbee** | zigbee-hub | iotsploit-zigbee-hub | 172.28.0.25 | Zigbee2MQTT coordinator |
| **hub-zigbee** | zigbee-hub-secondary | iotsploit-zigbee-hub-2 | 172.28.0.26 | Zigbee2MQTT secondary (/api/config leak) |
| **utility** | modbus-plc | iotsploit-modbus-plc | 172.28.0.60 | Smart-grid Modbus PLC (:502) |
| **utility** | coap-sensor | iotsploit-coap-sensor | 172.28.0.70 | CoAP sensor (:5683/udp) |

19 nodes = 6 core + 13 across 5 device rooms. All IPs stay inside `172.28.0.0/24`.

### 2.2 Why core is always-on, and the memory rationale
`core` holds the shared infrastructure every device room depends on (MQTT brokers, topic seeder, gateways,
and the kali auditor). Device rooms publish to the broker and route via the gateway, so `core` must stay up
while any room runs. Bringing up **all 19 nodes at once risks exhausting memory**, so the design is: keep
`core` up, and cycle **one device room at a time**.

### 2.3 docker compose commands — every flag explained
```powershell
# Bring up CORE only. -p = project name (groups containers/network as "iotsploit");
# --profile core selects the service group tagged profiles:[core]; up = create+start; -d = detached (background).
docker compose -p iotsploit --profile core up -d

# Bring up CORE + ONE device room (repeat --profile to union the groups).
docker compose -p iotsploit --profile core --profile living-room up -d
```
```powershell
# TEAR DOWN ONE ROOM — by SERVICE NAME, not --profile.
docker compose -p iotsploit stop  shelly-app shelly-plug shelly-pro4pm shelly-trv
docker compose -p iotsploit rm -f shelly-app shelly-plug shelly-pro4pm shelly-trv   # -f = no confirm prompt
```
> **The `--profile down` gotcha (verified):** `docker compose --profile <room> stop|rm|down` acts on the
> **whole running project and stops `core` too** — not just the room. Always tear a room down by naming its
> services (as above), which scopes the teardown precisely and leaves `core` and other rooms running.

Per-room teardown service lists: living-room `shelly-app shelly-plug shelly-pro4pm shelly-trv`;
entry-security `shelly-lock shelly-ap-flaw`; surveillance `ip-camera ip-camera-side-gate nvr-dvr`;
hub-zigbee `zigbee-hub zigbee-hub-secondary`; utility `modbus-plc coap-sensor`.

### 2.4 Entry pattern — run checks FROM the kali container
Checks must run from the on-network auditor at `172.28.0.10`. **Host-run checks return "No findings"**
because the host is not on the `iot_lab` bridge network.
```powershell
docker exec -it iotsploit-kali bash          # interactive shell inside the auditor (working dir /root/iotsploit)
#   then: iotsploit <module> <action> <target> [options]
docker exec iotsploit-kali iotsploit <...>    # one-shot, non-interactive
```
Entrypoints that work (verified): `iotsploit` is on PATH (`/usr/local/bin/iotsploit`); `python -m iotsploit`
also works.

---

## 3. Phase 1 — read-only assessment (practice)

General command grammar: `iotsploit <module> <action> [target] [options]`. None of these change device state.

Common flags: `target` (positional device IP, or `--target <ip>`); `-o/--output <file>` (save report file);
`-d/--output-dir <dir>` (directory for output); `--port <n>` (override default port, e.g. mqtt 1883 / modbus
502); `--ports a,b,c` (extra ports to probe); `--device-id <id>` (match a `profiles/*.yaml`); `--json`
(JSON instead of table); `-v/--verbose`.

```bash
# Whole-subnet autonomous multi-protocol audit -> saved report
iotsploit net audit 172.28.0.0/24 -o lan_audit.txt -d ./reports
#   net audit = autonomous LAN discovery+fingerprint+multi-protocol; -o file; -d dir.
iotsploit scan subnet --target 172.28.0.0/24     # host discovery + service fingerprint
iotsploit net scan 172.28.0.0/24                 # discovery alias

# MQTT (brokers .20 / .21) — all read-only
iotsploit mqtt anon-check 172.28.0.20 --port 1883   # anonymous CONNECT permitted?
iotsploit mqtt auth-check  172.28.0.20              # anon + profile-declared creds (CONNECT-only)
iotsploit mqtt classify    172.28.0.20              # sample topic tree '#', classify actuator/telemetry/bridge
iotsploit mqtt topic-audit 172.28.0.20 --duration 5.0   # map topic namespace to safety tiers; --duration = seconds sampled
iotsploit mqtt test        172.28.0.20              # plaintext accepted where TLS expected?

# Shelly HTTP/RPC (lock .30, plugs/relays .32/.33/.34, TRV .34) — missing-auth audit
iotsploit shelly check    172.28.0.30
iotsploit shelly ap-check 172.28.0.31               # persistent unencrypted setup-AP flaw

# Cameras / NVR (.50/.51/.52)
iotsploit camera check 172.28.0.50                  # RTSP :554 + HTTP snapshot + ONVIF/config
iotsploit wsd scan                                  # WS-Discovery (ONVIF-style), passive
iotsploit ports scan 172.28.0.52 --ports 23,80,554  # banner grab incl. NVR telnet:23
iotsploit cve list --device-id nvr_dvr_0804         # known_cves from the profile

# Gateway (.40/.41)
iotsploit upnp enum      172.28.0.40                # SSDP discover + description XML
iotsploit upnp wan-check 172.28.0.40                # read-only WANIPConnection probe
iotsploit http audit     172.28.0.41                # security headers / cookie flags / clickjacking (read-only)

# Zigbee bridges (.25/.26) — config credential leak
iotsploit http audit  172.28.0.25
iotsploit http check  172.28.0.26 --authorized      # /api/config credential-leak probe (see note on --authorized)

# Modbus PLC (.60) and CoAP sensor (.70)
iotsploit modbus check 172.28.0.60 --port 502 --unit 1   # read-holding-register (FC 0x03); --unit = Modbus unit/device ID
iotsploit coap check   172.28.0.70 --port 5683           # CoAP auth enforcement + /.well-known/core (RFC 6690)
```
> **`--authorized` vs `--authorize`.** `--authorized` (and `--dev`) is a Phase-1 flag asserting you own/are
> authorized to test a target for state-touching HTTP probes (`http check`, `http injection-check`). It is
> distinct from `--authorize` (the Phase-3 Key-B gate). Most Phase-1 reads need neither.

---

## 4. Phase 2 — correlation (theory + practice)

The risk graph turns discrete Phase-1 findings into causal chains: e.g. *CoAP config leak (.70) → vault
handle → Mosquitto pivot (.20) → Shelly lock actuation (.30)*. Vertices are services / credentials / MQTT
topics / actuators; edges are `EXPOSES_CONFIG`, `AUTHENTICATES_SERVICE`, `ACTUATES_DEVICE`.
```bash
iotsploit correlate path --chain-id CHAIN-001 --format summary   # human-readable hop summary
iotsploit correlate path --chain-id CHAIN-001 --format json      # structured metrics
iotsploit correlate path --chain-id CHAIN-001 --format dot       # Graphviz DOT
#   --chain-id (alias --id) selects the chain; --format one of json|text|summary|dot.
iotsploit chain verify 172.28.0.40     # multi-stage reuse across SSH/LuCI/MQTT/backdoors
```
`validate chain-001` (Phase 3, needs `--authorize`) executes the end-to-end chain empirically.

---

## 5. Phase 3 — bounded actuation (the SAFE default) (practice)

This is the default, bounded, reversible mode — **no `--override-unsafe`**.
```bash
# Bounded <=2.0s pulse with guaranteed auto-revert to LOCKED_SAFE. Dry-run first to see the plan.
iotsploit validate shelly-actuation --target 172.28.0.30 --dry-run
iotsploit validate shelly-actuation --target 172.28.0.30 --authorize
# Living-room relays (allowlisted): .32 plug, .33 Pro 4PM, .34 TRV
iotsploit validate shelly-actuation --target 172.28.0.32 --authorize
iotsploit validate shelly-actuation --target 172.28.0.33 --relay 0 --authorize
iotsploit validate shelly-actuation --target 172.28.0.34 --authorize
```
Flag meanings (from cli.py):
- `--target <ip>` — device to actuate (must be in-subnet AND allowlisted, else Key A refuses).
- `--authorize` — Key B operator gate.
- `--pulse-duration` — defaults to `2.0s`; omitting it uses the bounded 2.0s pulse. `>2.0s` is refused unless
  `--override-unsafe` (see §6).
- `--relay <n>` — relay/switch index for multi-relay devices (default `0`; Pro 4PM has 0–3).
- `--dry-run` — prints the action plan, boundary assertions, and revert mechanics **without opening sockets**.

**Reading before/during/after.** The finding line reports `pre=... -> during=... -> post=...` with ISO-8601
UTC markers `t1`/`t2`. For a bounded run you expect `pre=LOCKED_SAFE -> during=UNLOCKED_ENERGIZED -> post=
LOCKED_SAFE`. You can independently read device state from kali:
```bash
curl -s 'http://172.28.0.30/rpc/Switch.GetStatus?id=0'    # output:false = LOCKED_SAFE; output:true = ENERGIZED
```

**Integrity checks — run before AND after any actuation:**
```bash
iotsploit verify baseline --subnet 172.28.0.0/24 --check actuators,vault,circuit-breaker
#   --subnet = CIDR to verify (default 172.28.0.0/24); --check = comma list of subsystems.
iotsploit secrets audit --scope ephemeral     # vault handles=0, persisted=0, zero_persistence_verified:true
```

---

## 6. Override validations (M J-approved, lab-only) — OVERRIDE, not default (theory + practice)

> These require explicit owner authorization. They are **owner-authorized, NOT lab-validated** and must be
> labelled distinctly from safe-baseline findings. Each needs `--authorize` **and** `--override-unsafe`.
> Headless confirm tokens: `CONFIRM-EXP-02` (shelly-actuation), `CONFIRM-MQTT-BRUTEFORCE` (mqtt-bruteforce)
> — note `--confirm` emits a deprecation warning in interactive mode; `--authorize` is preferred.

### 6.1 Latching pulse (auto-revert OFF)
```bash
iotsploit validate shelly-actuation --target 172.28.0.30 --pulse --authorize --override-unsafe
# ...device stays HELD/energized... then restore explicitly:
iotsploit validate shelly-actuation --target 172.28.0.30 --revert --authorize
```
- `--pulse` — latching mode: energize and **HOLD** (auto-revert disabled) until an explicit `--revert`.
- `--revert` — explicit restore to `LOCKED_SAFE` (no energize); does NOT require `--override-unsafe`;
  circuit breaker remains armed for restoration failure. `--pulse` and `--revert` are mutually exclusive.
- **vs safe default:** the default auto-reverts within `<=2.0s`; latching deliberately does not, to
  demonstrate sustained physical-access impact. **Healthy result:** after `--pulse`, status `output:true`
  (held); after `--revert`, `output:false` (LOCKED_SAFE).

### 6.2 Uncapped pulse > 2.0s
```bash
iotsploit validate shelly-actuation --target 172.28.0.30 --pulse-duration 5.0s --authorize --override-unsafe
```
- `--pulse-duration 5.0s` — energization time; `>2.0s` requires `--override-unsafe` (the default ceiling is
  2.0s). **This is still a bounded, auto-reverting pulse** — just longer. **Healthy result:**
  `pre=LOCKED_SAFE -> during=UNLOCKED_ENERGIZED -> post=LOCKED_SAFE`, energized ~5s then auto-reverted.

### 6.3 MQTT credential brute-force
```bash
iotsploit validate mqtt-bruteforce --target 172.28.0.20 --creds admin:admin --authorize --override-unsafe
iotsploit validate mqtt-bruteforce --target 172.28.0.20 --creds ./wordlist.txt --authorize --override-unsafe
```
- `--creds` — either a single `user:pass` pair or a path to a `user:pass` wordlist file.
- Iterates credentials against the allowlisted broker `172.28.0.20:1883` via repeated CONNECT/CONNACK;
  each attempt does a clean DISCONNECT (zero persistent sessions); any authenticating credential is recorded
  **only** as a SHA-256 handle `cred_<8hex>` — never plaintext. **Healthy result:** reports how many
  authenticated and the handle(s); post-run vault audit shows 0 handles (destroyed on process exit).

### 6.4 Scope-lock negative control (REQUIRED safety check)
```bash
iotsploit validate shelly-actuation --target 192.0.2.10 --pulse --authorize --override-unsafe
```
This **MUST be refused** with a non-zero exit and:
`Safety Boundary Violation ... Target IP '192.0.2.10' is outside the immutable lab subnet '172.28.0.0/24'.
No CLI flag or config can override this boundary.`
**Why it matters:** it proves Key A (the compile-time scope lock) holds **even with `--override-unsafe`
present** — the override opt-in changes actuation semantics but can never widen the network boundary.

> **Note on `--no-scope-check`.** cli.py defines `--no-scope-check` ("Disable lab network scope validation
> boundaries"). This toggles a softer scope-policy layer; the **immutable compile-time boundary in
> immutable_lab_boundary.py still rejects out-of-subnet targets regardless** (that file states no flag can
> override it). I did not exercise `--no-scope-check` at runtime, so treat its exact interaction as
> **unverified-by-this-guide** and do not rely on it to reach any target outside `172.28.0.0/24`.

---

## 7. Reproducing our actual run (copy-paste, in order)

All commands run inside kali (prefix `docker exec iotsploit-kali bash -lc "cd /root/iotsploit && <cmd>"` or
from an interactive `docker exec -it iotsploit-kali bash`). Evidence from our run:
`reports/override_run_20261027/` and `reports/livingroom_actuation_20261027/`.

```powershell
# A) Core up + pre-state baseline (read-only)
docker compose -p iotsploit --profile core --profile entry-security up -d
docker exec iotsploit-kali iotsploit verify baseline --subnet 172.28.0.0/24 --check actuators,vault,circuit-breaker
```
```bash
# B) The three OVERRIDE validations on .30 / .20 (before/after via curl Switch.GetStatus)
#   1 latching + explicit revert
iotsploit validate shelly-actuation --target 172.28.0.30 --pulse --authorize --override-unsafe
iotsploit validate shelly-actuation --target 172.28.0.30 --revert --authorize
#   2 uncapped 5.0s (simulated relay -> no thermal hazard)
iotsploit validate shelly-actuation --target 172.28.0.30 --pulse-duration 5.0s --authorize --override-unsafe
#   3 mqtt brute-force
iotsploit validate mqtt-bruteforce --target 172.28.0.20 --creds admin:admin --authorize --override-unsafe
#   4 REQUIRED negative control (must be refused)
iotsploit validate shelly-actuation --target 192.0.2.10 --pulse --authorize --override-unsafe
```
```powershell
# C) Swap entry-security for living-room, run SAFE bounded actuation on .32/.33/.34
docker compose -p iotsploit stop shelly-lock shelly-ap-flaw
docker compose -p iotsploit rm -f shelly-lock shelly-ap-flaw
docker compose -p iotsploit --profile core --profile living-room up -d
```
```bash
iotsploit validate shelly-actuation --target 172.28.0.32 --authorize
iotsploit validate shelly-actuation --target 172.28.0.33 --relay 0 --authorize
iotsploit validate shelly-actuation --target 172.28.0.34 --authorize
```
```powershell
# D) Post baseline + integrity, then teardown (core stays up)
docker exec iotsploit-kali iotsploit verify baseline --subnet 172.28.0.0/24 --check actuators,vault,circuit-breaker
docker exec iotsploit-kali iotsploit secrets audit --scope ephemeral
docker compose -p iotsploit stop shelly-app shelly-plug shelly-pro4pm shelly-trv
docker compose -p iotsploit rm -f shelly-app shelly-plug shelly-pro4pm shelly-trv
```

---

## 8. Interpreting results & troubleshooting

- **PASS/FAIL on `verify baseline`.** `actuator_integrity` is `PASS` only when every sampled actuator
  (`.30/.31/.32`) is `LOCKED_SAFE`. `vault_integrity` PASS = 0 handles / 0 persisted. `safety_circuit_breaker`
  shows `circuit_breaker_tripped` + `halt_reason`.
- **Known benign FAIL.** Some deliberate-misconfig devices default to `UNLOCKED_ENERGIZED` at rest — e.g.
  `.31` (shelly-ap-flaw) and `.32` (default-on smart plug). When such a device is up, `verify baseline`
  reports `FAIL_ENERGIZED_RELAYS`. If this state is **identical before and after** your run, it is a property
  of the simulated device, **not a regression** caused by your test. (In our run the bounded actuation's
  auto-revert actually left `.32` at `LOCKED_SAFE`, flipping the post-run baseline to PASS.)
- **LOCKED_SAFE vs UNLOCKED_ENERGIZED.** Read `output` from `Switch.GetStatus`: `false`+`apower 0` =
  LOCKED_SAFE; `true`+nonzero power = energized/held.
- **Vault zero-persistence.** `secrets audit` → `status: INVALIDATED_EMPTY`, `zero_persistence_verified:true`.
  Handles created during a run (e.g. `cred_8da19336`) are destroyed on process exit, so post-run audit = 0.
- **"No findings" gotcha.** If a scan returns "No findings", you almost certainly ran it from the host, not
  from kali. Re-run from the on-network `iotsploit-kali` container (`172.28.0.10`).
- **Circuit breaker tripped.** Indicates a restoration/post-state anomaly during an actuation; investigate the
  device, run `shelly ... --force-off` (emergency `relay/0?turn=off`) if needed, and re-verify baseline.

---

## 9. Safety boundaries recap

- **Can NEVER be overridden:** the `172.28.0.0/24` compile-time scope lock (Key A) and appliance
  thermal/heating-element gating. No flag — including `--override-unsafe` — bypasses either.
- **Two keys always required** for Phase-3 state changes: in-subnet+allowlisted target (A) and `--authorize`
  (B). Always `--dry-run` first and `verify baseline` after.
- **Physical-hardware rule:** uncapped (`--pulse-duration >2.0s`) and latching (`--pulse`) overrides must
  **never** run on real physical hardware without a calibrated hardware duty-cycle / thermal limit
  (coil-burnout / fire hazard). They are safe on the simulated relay containers; on real actuators, calibrate
  per the device datasheet first.
