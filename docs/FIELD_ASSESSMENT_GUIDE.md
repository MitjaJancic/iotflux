# IoTFlux Portable Field Assessment Guide

**Document Version**: 4.0.0  
**Framework**: IoTFlux Portable Security Conformance & Assessment Toolkit  
**Governance Model**: Authorization-by-Design, Immutable `enforce` Scope Default, and Tamper-Evident Audit Logging (`assessment_audit.jsonl`)

---

## 1. End-to-End Field Assessment Workflow

IoTFlux decomposes authorized security assessments into five explicit, operator-verified CLI commands (or via the interactive [`workflows/field_assessment.py`](file:///C:/Users/mitja/Downloads/iotsploit/workflows/field_assessment.py) orchestrator):

```bash
# 1. Define and validate assessment scope
python -m iotflux scope init --output assessment_scope.yaml
python -m iotflux scope validate --config assessment_scope.yaml

# 2. Discover targets within authorized scope (strictly read-only)
python -m iotflux discover --scope assessment_scope.yaml --output assessment_targets.json

# 3. Generate validation profiles from discovered targets
python -m iotflux profile generate --targets assessment_targets.json --whitelist authorized_devices.txt

# 4. Configure & pre-flight verify encrypted credentials for authorized devices
python -m iotflux auth set <device_id>
python -m iotflux auth verify <device_id>

# 5. Execute validation with explicit authorization and scope gates
python -m iotflux validate shelly_auditor --device-id <id> --require-auth --scope assessment_scope.yaml
```

---

## 2. Scope Configuration for Common Operational Environments

All scope definitions are managed via [`assessment_scope.yaml`](file:///C:/Users/mitja/Downloads/iotsploit/assessment_scope.yaml) and evaluated at runtime by [`iotflux/core/scope_manager.py`](file:///C:/Users/mitja/Downloads/iotsploit/iotflux/core/scope_manager.py) using **Longest-Prefix Match (LPM)** CIDR rules.

> [!IMPORTANT]
> `validation_mode: enforce` is the immutable default. Using `warn` or `dry-run` requires passing `--override-safety --justification "<documented reason>"`, which is immediately recorded in `assessment_audit.jsonl`.

### 2.1 Corporate Enterprise IoT VLANs
Use when conducting validated testing across segmented building-automation, smart lighting, or conference-room VLANs while excluding core infrastructure gateways:

```yaml
allowed_networks:
  - cidr: "10.42.10.0/24"
    description: "Corporate Building Automation VLAN 10"
  - cidr: "10.42.20.0/24"
    description: "Corporate AV & Smart Lighting VLAN 20"
denied_networks:
  - cidr: "10.42.10.1/32"
    description: "VLAN 10 Core Switch Gateway (Excluded)"
  - cidr: "10.42.20.1/32"
    description: "VLAN 20 Core Switch Gateway (Excluded)"
  - cidr: "0.0.0.0/0"
    description: "Default deny all external"
validation_mode: enforce
max_concurrent_probes: 10
probe_timeout_seconds: 2
```

### 2.2 Residential Smart Home Test Segments
Use when assessing consumer IoT gateways, relays, and cameras on a dedicated residential subnet:

```yaml
allowed_networks:
  - cidr: "192.168.50.0/24"
    description: "Residential IoT Assessment Segment"
denied_networks:
  - cidr: "192.168.50.1/32"
    description: "Upstream Residential ISP Router (Excluded)"
  - cidr: "0.0.0.0/0"
    description: "Default deny all external"
validation_mode: enforce
max_concurrent_probes: 5
probe_timeout_seconds: 3
```

### 2.3 Industrial OT / IIoT Zones
Use conservative concurrency (`max_concurrent_probes: 2`) and extended timeouts (`probe_timeout_seconds: 5`) when validating programmable logic controllers (PLCs), Modbus gateways, and telemetry brokers in isolated OT segments:

```yaml
allowed_networks:
  - cidr: "172.16.100.0/24"
    description: "Industrial OT Supervisory Cell"
denied_networks:
  - cidr: "172.16.100.250/32"
    description: "Safety Instrumented System (SIS) Controller - Strictly Excluded"
  - cidr: "0.0.0.0/0"
    description: "Default deny all external"
validation_mode: enforce
max_concurrent_probes: 2
probe_timeout_seconds: 5
```

---

## 3. Credential Management Best Practices for Physical Devices

IoTFlux manages credentials through [`iotflux/core/credential_manager.py`](file:///C:/Users/mitja/Downloads/iotsploit/iotflux/core/credential_manager.py), storing Fernet-encrypted (`AES-128-CBC + HMAC-SHA256`) credential bundles in `profiles/<device_id>.yaml.enc`.

1. **Zero Plaintext Persistence**:
   Never pass passwords or API tokens on the command line where shell history can record them. Always use `python -m iotflux auth set <device_id>` to enter secrets via hidden `stdin`.
2. **Supported Authentication Schemes (`--type`)**:
   - `password`: Local device HTTP Basic/Digest or RPC username and password.
   - `token`: Bearer API token for REST/RPC interfaces.
   - `cert`: Mutual TLS (mTLS) X.509 client certificate and private key paths for industrial/matter nodes.
   - `oauth2`: RFC 6749 OAuth2 Client Credentials flow (`token_url`, `client_id`, `client_secret`, `scope`) for cloud-managed IoT controllers.
3. **Mandatory Pre-Flight Verification**:
   Always run `python -m iotflux auth verify <device_id>` before executing validation modules. This confirms decryption integrity, token expiration (`expires_at_epoch`), certificate file presence, and privilege level without modifying device state.
4. **Key Custody & Rotation**:
   Protect `.iotflux_fernet.key` with `0600` file permissions, store it separately from assessment artifacts during transport, and shred the key upon engagement completion per organizational policy.

---

## 4. Troubleshooting Discovery Failures Across Network Types

| Symptom | Root Cause | Resolution |
| :--- | :--- | :--- |
| `ASSESSMENT SCOPE VIOLATION` during `iotflux discover` | `--target-range` falls outside `allowed_networks` or overlaps a more-specific `denied_networks` entry. | Run `python -m iotflux scope validate --config assessment_scope.yaml` and verify LPM CIDR rules. |
| `SAFETY GATE BLOCKED` when loading `assessment_scope.yaml` | `validation_mode` is set to `warn` or `dry-run` without safety override. | Set `validation_mode: enforce` or pass `--override-safety --justification "<reason>"`. |
| mDNS / SSDP / UPnP returns empty fingerprints on multi-NIC laptop | UDP multicast/unicast probes routed out default interface instead of assessment NIC. | Pass `--interface <assessment_nic_ipv4>` to `iotflux discover`. |
| Physical devices drop TCP connections or time out | High probe concurrency overwhelming embedded TCP/IP stacks (e.g., ESP32/RTOS nodes). | Lower `max_concurrent_probes` (e.g., `2`–`4`) and increase `probe_timeout_seconds` in `assessment_scope.yaml`. |
| `PRE-FLIGHT AUTH FAILED [EXPIRED_CREDENTIALS]` | OAuth2 token or temporary assessment credential has passed `expires_at_epoch`. | Re-run `python -m iotflux auth set <device_id>` to refresh the encrypted bundle. |

---

## 5. Audit Log Interpretation & Compliance Reporting

Every operation appends a tamper-evident JSON Lines record to `assessment_audit.jsonl` (and `audit_log.json`). Each record contains:

```json
{
  "timestamp_utc": "2026-10-29T12:15:00Z",
  "operator_id": "assessor_01",
  "event_type": "VALIDATION_EXECUTION",
  "action": "validation/shelly_auditor",
  "scope_config_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "target_list_hash": "sha256:4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
  "details": {
    "module": "validation/shelly_auditor",
    "target": "10.42.0.30",
    "device_id": "dev_552d952b0d",
    "findings_count": 1
  }
}
```

- **`scope_config_hash`**: Cryptographic SHA-256 hash of `assessment_scope.yaml` at the exact moment of execution, proving that scope boundaries were not altered mid-engagement.
- **`target_list_hash`**: Cryptographic SHA-256 hash of `assessment_targets.json`, linking validation checks directly to the authorized discovery inventory.
- **`operator_id`**: Attributable operator identity for every scope check, credential setup, and module run.
