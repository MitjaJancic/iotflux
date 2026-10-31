# Changelog

All notable changes to iotsploit are documented here. This project uses a
single version source in `pyproject.toml`, mirrored by `iotsploit.__version__`.

## v0.8.0 — Human-friendly command surface

`iotflux <family> <address> <verb> [flags]` replaces
`iotflux run exploit/<module> -t <host> --port <port> --opt ACTION=<verb>`.
The module layer is unchanged; `run` and `--opt` still work.

### Added
- Family/verb registry (`core/commands.py`) covering every exploit module.
- Address syntax `host[:port]` with a per-family default port.
- Typed flags: durations (`--in 30s`), validated addresses, `--on`/`--off`
  pairs, real integers, positional arguments where they read better
  (`modbus … write-coil 0 1`).
- `iotflux ls`, per-family help, per-verb help with defaults.
- `iotflux completion bash` for shell completion.
- `--json`, `--quiet`, `--dry-run` on every verb.
- `.iotflux.toml` for standing defaults (timeout, threads).
- A one-line verdict after each run, plus an undo hint on state changes.

### Changed
- Bare `iotflux` opens the console (was already the behaviour; now documented).
- `--opt KEY=VALUE` is the escape hatch, not the primary interface.

## v0.7.0 — Real-world readiness

Everything here exists because the tool was only correct against the lab. The
lab has been extended to match, but the changes are driven by what real devices
actually do.

### Added — device families
- `exploit/tasmota_control` — Tasmota `/cm?cmnd=` command API: state, toggle,
  OTA URL, MQTT and Wi-Fi redirection.
- `exploit/esphome_control` — ESPHome `web_server`: entity inventory, toggle,
  press, sensor read.
- `exploit/ha_control` — Home Assistant REST API: token check, entity dump,
  service calls.
- `exploit/tuya_discover` — Tuya UDP discovery and TCP 6668 handshake.

### Added — Shelly Gen1
- `exploit/shelly_common` — generation-aware transport. Detects Gen1 vs Gen2
  from `/shelly` or `/rpc/Shelly.GetDeviceInfo`, then maps every action to REST
  (Gen1, Basic auth) or JSON-RPC (Gen2, Digest).
- `shelly_control` and `shelly_persist` now drive both generations. Gen1
  persistence uses `/settings` and `/ota?url=`; actions that do not exist on
  Gen1 (`schedule`, `kvs`, `profile`) report `SHELLY-UNSUPPORTED-GEN1`.

### Changed
- **Cloud redirection sends a WebSocket RPC endpoint** (`host:6022/jrpc`), not
  an HTTP URL — real firmware never reconnects to the old shape.
- **MQTT redirection sends `topic_prefix`**, which real firmware requires.
- **Schedules accept a cron `TIMESPEC`**; `@now+Ns` is only the fallback.
- **Spray defaults are embedded-safe**: `THREADS=1`, `DELAY=0.3`. Four threads
  wedge a Shelly's HTTP server and produce false 401s.
- **Reboot and Wi-Fi changes poll for the device to come back** (`WAIT_BACK`)
  instead of reporting success and moving on.
- `fw_upload` gained `MODE=url` (device fetches) and separates accepted from
  rejected from unclear, instead of treating HTTP 200 as proof.

### Fixed
- Matter probe sent a 16-byte blob; it now sends a real PASE
  `PBKDFParamRequest` (MRP header + exchange header + TLV) and reads the reply
  opcode. A real device drops anything it cannot parse.
- MRP header length was wrong (8 bytes, actually 6) in both the probe and the
  simulator.

## v0.6.0 — Protocol breadth, radio, and Shelly

Adds 16 modules across the management plane, legacy transfer, embedded web,
cloud API, radio and smart-relay surfaces, plus a Shelly persistence module and
mDNS discovery. No new Python dependencies: SNMP, BACnet and OPC UA are raw
sockets with hand-rolled encoders.

### Added — management plane and OT
- `exploit/snmp_enum` — community spray, GetNext walk, single get (minimal BER).
- `exploit/bacnet_write` — Who-Is, ReadProperty, WriteProperty (BVLC framing).
- `exploit/opcua_browse` — GetEndpoints, anonymous CreateSession + Browse
  (minimal binary client, SecurityPolicy None).

### Added — legacy transfer
- `exploit/tftp_pull` — anonymous config/firmware retrieval.
- `exploit/ftp_anon` — anonymous login, listing, retrieval.

### Added — embedded web and cloud
- `exploit/cgi_inject` — shell injection in CGI handlers.
- `exploit/fw_upload` — unsigned firmware upload.
- `exploit/jwt_forge` — `alg:none` and bad-signature JWT.
- `exploit/ws_hijack` — WebSocket with no origin validation.
- `exploit/dns_rebind` — Host-header trust.
- `exploit/matter_commission` — commissioning window probe.

### Added — radio
- `exploit/ble_scan`, `exploit/zigbee_sniff`, `exploit/subghz_replay`,
  `exploit/wifi_attack`.

### Added — Shelly
- `discovery/shelly_mdns` — `_shelly._tcp` inventory with unicast fallback.
- `exploit/shelly_persist` — schedules, KVS, MQTT/cloud redirection, Wi-Fi
  move, unsigned OTA, auth lockout/removal, reboot, neighbour scan. Reuses
  `creds.json` automatically.
- `docs/SHELLY.md` — vulnerability classes, coverage matrix, open gaps.

### Changed
- `default_creds.for_protocol()` now returns the full vendor corpus instead of
  generics only, so a spray without `VENDOR` still reaches vendor defaults.
- Shelly vendor list extended with plausible operator passwords.

### Fixed
- BACnet APDU offset skipped only the BVLC header, not BVLC + NPDU.
- OPC UA TwoByte NodeId was encoded with a redundant namespace byte; the
  FourByte form used a 4-byte body instead of 1+2.
- OPC UA `OpenSecureChannel` field order and the missing `TokenId` in the
  symmetric security header.
- `dns_rebind` compared bodies verbatim, so an echoed Host always looked like a
  difference.

## v0.5.0 — Exploitation posture

Turns IoTFlux from a read-only conformance auditor into an active exploitation
framework. All safety gates that blocked real-world use are removed or inverted.

### Changed (breaking)
- **Exploit-by-default.** `AUTHORIZED_TEST` and `AUTHORIZE` default to `True`.
  `assert_authorized()` always passes unless the operator explicitly sets
  `AUTHORIZED_TEST false`. `--authorize` / `--override-safety` /
  `--authorized-test` still parse and are no-ops.
- **Scope gate is advisory.** `validate_target_ip()` never raises. Out-of-boundary
  targets log a `SCOPE_ADVISORY` line and a `SCOPE_ADVISORY` audit event, then run.
  The physical-lab `10.10.0.0/16` two-key gate and its `assessment_scope.yaml`
  metadata requirement are gone.
- **Auto-revert is off.** `shelly_auditor`, `modbus_auditor` and
  `ble_mesh_auditor` apply their change and leave it. `--auto-revert` /
  `AUTO_REVERT=true` restores inline.
- **Credentials persist in plaintext** to `creds.json` (`chmod 600`), replacing
  the RAM-only vault for cross-invocation reuse.
- `iotflux.core` resolves `FluxConsole`/`main` lazily, fixing an import cycle that
  broke `import iotflux.modules`.

### Added
- `exploit/` module package: `cred_spray`, `mqtt_publish`, `coap_write`,
  `upnp_portmap`, `tr069_exploit`, `firmware_extract`, `camera_capture`,
  `modbus_write`, `shelly_control`.
- `iotflux/core/creds_store.py` plus `iotflux creds list|get|export|delete|import`.
- `--opt KEY=VALUE` (repeatable) and `--auto-revert` on `run`/`validate`.
- `docs/EXPLOITATION.md`, `tests/test_exploit_modules.py` (31 tests).
- `creds.json` and `evidence/captures/` added to `.gitignore`.

## v0.2.0

Second iteration. Hardens iotsploit into a tool whose single read-only Phase-1
scan plus firmware pass can back a client-ready assessment report, while keeping
the compile-time lab safety boundary fully intact.

### Added
- **Versioning + changelog.** `__version__ = "0.2.0"` in `iotsploit/__init__.py`;
  `pyproject.toml` bumped 0.1.0 -> 0.2.0; this `CHANGELOG.md`.
- **Finding schema** (`iotsploit/core/scoring.py`): two optional fields
  `remediation: str | None` and `cve: str | None` (both default `None`, nothing
  breaks), plus an optional `override_unvalidated: bool` flag. All surfaced in
  `Finding.to_dict()`.
- **Taxonomy remediation** (`iotsploit/core/taxonomy.py`): concrete per-check
  remediation guidance added to every `CHECK_TAXONOMY` entry and to the
  score-based fallback. Two new keys: `shelly_mqtt_auth_plane_split`
  (CWE-306 / CAPEC-115) and `actuator_unbounded_pulse` (CWE-284 / CAPEC-180).
  Findings inherit the taxonomy remediation when a per-finding one is not set.
- **Client-ready report** (`iotsploit/core/report.py`): a client-assessment mode
  with an Executive Summary (device count, findings by severity, highest risks,
  overall posture) plus per-finding detail now carrying severity label, evidence
  path, CWE/CAPEC, CVE (if any) and remediation. A clean client-grade HTML is
  emitted as `<basename>.client.html`. JSON/HTML/MD/text are retained.
- **New device profiles** (`profiles/`): `generic_onvif_camera.yaml`,
  `generic_router_gateway.yaml`, `generic_fire_alarm_panel.yaml`, following the
  exact `_template.yaml` schema. `known_cves` are intentionally empty stubs
  (no CVE IDs are fabricated). Addresses stay inside 172.28.0.0/24.
- **Bounded-vs-override toggle** (CLI): the safe bounded actuation variant
  (<=2.0s pulse WITH guaranteed auto-revert) is now the DEFAULT. The owner-
  authorized override behaviors are opt-in via the new `--override-unsafe` flag.
- **Tests** (`tests/test_v2_iteration.py`): cover new Finding fields, new
  taxonomy keys, client exec-summary generation, new-profile loading, and the
  bounded-default / override-opt-in gate.

### Core validator architecture (foundational commit)
- Landed the core validator architecture that prior commits referenced but
  which was present on disk yet untracked: `iotsploit/modules/base.py`
  (`BaseValidationModule`, `AuthorizationLevel`, `SAFETY_CONSTRAINTS`),
  `iotsploit/__main__.py`, and the eight `iotsploit/modules/validate/*`
  validators (zigbee_pivot, upnp_wan, modbus_write, vault_replay, chain_001,
  matter_thread_auditor, cloud_api_validator, hmi_modbus_validator). This
  resolves the `import iotsploit.cli` ModuleNotFoundError on master.

### Changed
- Client/report and CLI help now document two Lab-Engineer run facts:
  (1) `net audit` must be run ON-NETWORK from the kali container (172.28.0.10)
  on the internal docker bridge; run from the Windows host it returns "No
  findings" because the host is not on the 172.28.0.0/24 bridge; and
  (2) firmware SBOM/CVE checks are a SEPARATE firmware pass, not part of
  `net audit`.

### OWNER-AUTHORIZED OVERRIDE BEHAVIORS - NOT LAB-VALIDATED
The following three behaviors are retained from the previous change at the
explicit direction of the owner (M J), who accepted the risk as owner. They are
**NOT lab-validated**: the Lab Engineer declined to validate them. They are now
**opt-in only** (bounded-with-auto-revert is the default), and any finding they
produce is clearly labeled "override-enabled, not lab-validated" in reports:
- **Configurable / uncapped `--pulse-duration`** - the 2.0s actuation ceiling is
  not enforced for operator-supplied durations (only strictly-positive is).
- **Latching `--pulse` mode** - energizes and HOLDS device state with auto-revert
  intentionally disabled until an explicit `--revert`.
- **MQTT brute-force validator** (`validate mqtt-bruteforce`) - iterates a
  supplied credential list against the lab Mosquitto broker.

### Safety (unchanged / immutable)
- The compile-time `172.28.0.0/24` scope lock, the `AUTHORIZED_VALIDATION_ENDPOINTS`
  allowlist, and the circuit breaker in `iotsploit/core/immutable_lab_boundary.py`
  remain **immutable** and were not modified in this iteration. Out-of-scope
  targets (e.g. 8.8.8.8) still raise `SafetyBoundaryViolationError`.

## v0.1.0
- Initial config-driven IoT security / damage audit tool: three-phase methodology
  (read-only multi-protocol assessment, correlation graph + weighted damage score,
  controlled impact validation), profile system, CWE/CAPEC taxonomy, JSON/HTML/MD/
  text reporting.
