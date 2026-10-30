# Changelog

All notable changes to iotsploit are documented here. This project uses a
single version source in `pyproject.toml`, mirrored by `iotsploit.__version__`.

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
