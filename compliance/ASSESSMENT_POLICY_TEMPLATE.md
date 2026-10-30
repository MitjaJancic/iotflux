# Organizational IoT Security Assessment & Validation Policy Template

**Organization Name**: `[INSERT ORGANIZATION NAME]`  
**Policy Identifier**: `POL-IOT-VAL-001`  
**Effective Date**: `[INSERT DATE]`  
**Approved By**: `[INSERT CISO / AUTHORIZING OFFICIAL]`

---

## 1. Purpose and Scope

This policy establishes mandatory governance, operational boundaries, and technical controls for conducting **authorized security assessments** and **compliance-driven validation** of Internet of Things (IoT), smart building, and Industrial IoT (IIoT) assets using the **IoTFlux** validation framework.

This policy applies to all internal security personnel, authorized third-party assessors, and academic researchers operating within `[INSERT ORGANIZATION NAME]` network segments.

---

## 2. Authorization-by-Design Requirements

1. **Written Engagement Authorization**:
   No discovery or validation activity may commence without a signed Rules of Engagement (RoE) specifying the authorized assessment window, points of contact, and target network segments.
2. **Dual-Control Execution (`--require-auth` & `authorized_devices.txt`)**:
   - Only devices explicitly listed by `device_id` or IPv4 address in `authorized_devices.txt` may receive `authorized: true` in generated validation profiles.
   - All state-changing conformance checks require both `--authorized-test` and `--require-auth` with verified, non-expired credentials.

---

## 3. Network Scope Boundaries (`assessment_scope.yaml`)

1. **Mandatory `enforce` Mode**:
   All assessments must operate with `validation_mode: enforce` in `assessment_scope.yaml`.
2. **Explicit Exclusions (`denied_networks`)**:
   Safety-critical controllers, medical devices, upstream production routers, and out-of-scope subnets must be explicitly listed in `denied_networks` (in addition to the catch-all `0.0.0.0/0` default deny rule).
3. **Safety Override Governance**:
   Transitioning `validation_mode` to `warn` or `dry-run` requires explicit management approval and must be invoked with `--override-safety --justification "<ticket_id and reason>"` so the justification is permanently recorded in `assessment_audit.jsonl`.
4. **Rate Limiting**:
   Assessors must configure `max_concurrent_probes` and `probe_timeout_seconds` appropriate to the target environment (e.g., `max_concurrent_probes <= 4` for embedded RTOS/OT segments).

---

## 4. Credential Handling & Cryptographic Protection

1. **Prohibition of Plaintext Credentials**:
   Assessment credentials (passwords, API bearer tokens, mTLS certificates, and OAuth2 client secrets) must never be stored in plaintext YAML/JSON files or passed via CLI arguments.
2. **Fernet Encryption at Rest**:
   All device credentials must be provisioned interactively via `iotflux auth set <device_id>` and stored encrypted (`AES-128-CBC + HMAC-SHA256`) in `profiles/<device_id>.yaml.enc`.
3. **Post-Engagement Sanitization**:
   Within `[24/48]` hours of engagement completion, temporary assessment accounts must be revoked on physical devices and the engagement `.iotflux_fernet.key` and `profiles/*.yaml.enc` files must be securely destroyed.

---

## 5. Incident Response & Safe Abort Procedures

1. **Immediate Halt Condition**:
   If any physical IoT device exhibits unexpected latency degradation (`conformance/resilience_monitor` HTTP 5xx or connection drop rate > 0%) or anomalous physical behavior:
   - Immediately terminate active validation runs (`Ctrl+C`).
   - Verify that bounded auto-revert routines have restored baseline device state.
   - Notify the facility/network owner POC listed below within **15 minutes**.
2. **Evidence Preservation**:
   Preserve `assessment_audit.jsonl`, `audit_log.json`, `assessment_scope.yaml`, and `assessment_targets.json` unedited for post-incident review.

---

## 6. Sign-Off & Emergency Contacts

| Role | Name | Contact Phone / Email | Signature & Date |
| :--- | :--- | :--- | :--- |
| **Authorizing Official / CISO** | `[Name]` | `[Contact]` | `____________________` |
| **Lead Security Assessor** | `[Name]` | `[Contact]` | `____________________` |
| **Facility / OT Network Owner** | `[Name]` | `[Contact]` | `____________________` |
