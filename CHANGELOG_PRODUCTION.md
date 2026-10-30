# Changelog — Production Generalization Architecture (v4.0.0)

**Release**: IoTFlux v4.0.0 (Portable Assessment Toolkit)  
**Date**: 2026-10-29  
**Summary**: Architectural evolution from a fixed Docker lab simulation into a portable, environment-agnostic authorized IoT security assessment and compliance validation framework.

---

## 1. Environment-Agnostic Discovery Engine ([`iotflux/modules/discovery/auto_detect.py`](file:///C:/Users/mitja/Downloads/iotsploit/iotflux/modules/discovery/auto_detect.py))

- **Universal Physical & Virtual Hardware Discovery**:
  - Replaced Docker-coupled assumptions with interface-aware (`--interface`) mDNS/SSDP/UPnP discovery and rate-limited TCP port probing (`--target-range`) governed by `max_concurrent_probes` and `probe_timeout_seconds`.
  - Expanded read-only HTTP banner extraction to cover `/rpc/Shelly.GetInfo`, `/rpc/Shelly.GetDeviceInfo`, `/api/version`, `/rootDesc.xml`, and `/device/info`.
  - Added [`probe_mqtt_connect_readonly()`](file:///C:/Users/mitja/Downloads/iotsploit/iotflux/modules/discovery/auto_detect.py#L140-L176), performing a strictly read-only MQTT v3.1.1 anonymous `CONNECT`/`CONNACK` header inspection followed immediately by `DISCONNECT` (no topic subscriptions or state changes).
  - Exports structured inventories to `assessment_targets.json` with `{device_id, ip_address, mac_address, open_ports, service_fingerprints, detected_protocol, network_segment}`.

---

## 2. Dynamic Scope Management System ([`iotflux/core/scope_manager.py`](file:///C:/Users/mitja/Downloads/iotsploit/iotflux/core/scope_manager.py) & [`assessment_scope.yaml`](file:///C:/Users/mitja/Downloads/iotsploit/assessment_scope.yaml))

- **Structured YAML Scope Boundaries**:
  - Added [`assessment_scope.yaml`](file:///C:/Users/mitja/Downloads/iotsploit/assessment_scope.yaml) supporting named `allowed_networks`, `denied_networks`, `validation_mode`, `max_concurrent_probes`, and `probe_timeout_seconds`.
  - Implemented [`ScopeManager`](file:///C:/Users/mitja/Downloads/iotsploit/iotflux/core/scope_manager.py#L100-L315) with strict startup YAML schema validation and Longest-Prefix Match (LPM) CIDR evaluation.
- **Immutable `enforce` Default & Audited Safety Override Gate**:
  - Enforces `validation_mode: enforce` by default. Using `warn` or `dry-run` requires `--override-safety` and a mandatory `--justification "<reason>"` logged to `assessment_audit.jsonl`.
- **Scope CLI Commands**:
  - Added `iotflux scope init --output assessment_scope.yaml` and `iotflux scope validate --config assessment_scope.yaml`.

---

## 3. Portable Credential & Authorization Workflow ([`iotflux/core/credential_manager.py`](file:///C:/Users/mitja/Downloads/iotsploit/iotflux/core/credential_manager.py))

- **Multi-Scheme Physical Device Authentication**:
  - Added `iotflux auth set <device_id>` ([`set_device_auth_interactive()`](file:///C:/Users/mitja/Downloads/iotsploit/iotflux/core/credential_manager.py#L146-L279)) supporting `password` (username/password), `token` (API bearer token), `cert` (mTLS client certificate path), and `oauth2` (RFC 6749 OAuth2 Client Credentials flow).
  - Encrypts credential bundles with Fernet (`AES-128-CBC + HMAC-SHA256`) and stores them in `profiles/<device_id>.yaml.enc`.
- **Pre-Flight Verification & `--require-auth` Gate**:
  - Added `iotflux auth verify <device_id>` ([`verify_device_auth_preflight()`](file:///C:/Users/mitja/Downloads/iotsploit/iotflux/core/credential_manager.py#L313-L418)) to verify decryption integrity, credential expiration (`expires_at_epoch`), privilege level, and certificate existence without executing validation checks.
  - Updated [`BaseValidationModule.assert_authorized()`](file:///C:/Users/mitja/Downloads/iotsploit/iotflux/modules/base.py#L89-L152) to enforce `--require-auth` across all state-changing modules.

---

## 4. Field Assessment Orchestration & Tamper-Evident Audit Logging

- **Modular CLI Workflow ([`iotflux/core/cli.py`](file:///C:/Users/mitja/Downloads/iotsploit/iotflux/core/cli.py))**:
  - Added `iotflux scope`, `iotflux discover`, `iotflux profile`, `iotflux auth`, `iotflux validate`, and `iotflux field-assess`.
- **Interactive Field Assessment Orchestrator ([`iotflux/workflows/field_assessment.py`](file:///C:/Users/mitja/Downloads/iotsploit/iotflux/workflows/field_assessment.py) & [`workflows/field_assessment.py`](file:///C:/Users/mitja/Downloads/iotsploit/workflows/field_assessment.py))**:
  - Guides operators step-by-step with context-aware help, expected outputs, and failure recovery instructions.
- **Cryptographic Audit Trail ([`iotflux/core/audit_log.py`](file:///C:/Users/mitja/Downloads/iotsploit/iotflux/core/audit_log.py))**:
  - Writes structured JSONL records to `assessment_audit.jsonl` containing `operator_id`, `scope_config_hash` (SHA-256 of `assessment_scope.yaml`), `target_list_hash` (SHA-256 of `assessment_targets.json`), and module execution results.

---

## 5. Production Documentation & Compliance Package

- Added [`docs/FIELD_ASSESSMENT_GUIDE.md`](file:///C:/Users/mitja/Downloads/iotsploit/docs/FIELD_ASSESSMENT_GUIDE.md) and [`compliance/ASSESSMENT_POLICY_TEMPLATE.md`](file:///C:/Users/mitja/Downloads/iotsploit/compliance/ASSESSMENT_POLICY_TEMPLATE.md).
