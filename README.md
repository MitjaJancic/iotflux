# IoTFlux: Authorized Residential IoT Protocol Conformance & Hardening Framework

**IoTFlux** is a modular, high-speed, specification-driven security assessment and protocol conformance framework for residential and industrial Internet of Things (IoT) ecosystems. Developed for academic security research, IoTFlux evaluates device vulnerability to misconfiguration, telemetry exposure, and cross-zone privilege escalation within authorized lab environments and cyber ranges.

---

## 1. Key Architectural Principles

1. **Non-Destructive & Read-Only Default Verification:**
   All discovery, inspection, and conformance modules operate under a strict read-only invariant. State-modifying operations (such as relay actuation or Modbus register overrides) require explicit **Two-Key Operator Authorization** (`AUTHORIZED_TEST=true`).

2. **Bounded Perturbations & Deterministic Auto-Revert:**
   When state changes are authorized, all actuation signals are strictly bounded by pulse duration limits ($t \le 2.0\text{s}$) and automatically restored to verified baselines.

3. **Ephemeral In-Memory Credential Vaulting:**
   Secrets harvested from configuration leaks (e.g. CoAP `/.well-known/core`, Zigbee REST configs, or firmware root filesystems) are stored strictly in volatile RAM. They are referenced using deterministic SHA-256 opaque handles (`cred_<8hex>`) to prevent disk leakage and report disclosure.

4. **Profile-Driven Architecture:**
   Device knowledge and endpoint semantics are decoupled from code. Device profiles are declared in YAML (`iotflux/profiles/*.yaml`) covering relays, locks, thermostats, IP cameras, gateways, industrial PLCs, and smart lighting hubs.

5. **5-Dimensional Formulaic Damage Quantification:**
   Findings are quantified across five distinct physical and network impact dimensions:
   - **Physical Safety:** Actuator, perimeter lock, and equipment hazards (0–3).
   - **Privacy:** Telemetry, metadata, and surveillance video disclosure (0–3).
   - **Financial:** Energy consumption anomalies and metering fraud (0–3).
   - **Availability:** Service denial, daemon crash, and lockout risks (0–3).
   - **Chaining Depth:** Lateral traversal distance across segmented security zones (0–3).

---

## 2. Framework Structure

```text
iotflux/
├── core/
│   ├── cli.py             # Metasploit-style interactive shell & direct CLI
│   ├── logger.py          # ANSI colorized and structured JSON logger
│   ├── pcap_recorder.py   # Synchronized libpcap 2.4 binary packet recorder
│   ├── profiles.py        # YAML device profile catalog and search engine
│   ├── scoring.py         # 5D damage scoring and risk quantification engine
│   ├── session.py         # Global session state & Two-Key safety gates
│   ├── specification.py   # Standards catalog (Shelly, MQTT, NIST, Modbus, CSA)
│   └── vault.py           # Ephemeral RAM-only credential vault
├── modules/
│   ├── base.py            # BaseValidationModule abstraction & findings dataclass
│   ├── discovery/
│   │   ├── coap_scanner.py     # RFC 7252 / RFC 6690 CoAP resource discovery
│   │   ├── mdns_scanner.py     # Multicast DNS & UPnP XML descriptor discovery
│   │   ├── subnet_mapper.py    # Multi-zone active subnet & port scanner
│   │   └── upnp_scanner.py     # UPnP IGD WAN exposure & AddPortMapping auditor
│   ├── validation/
│   │   ├── ble_mesh_auditor.py          # BLE Mesh & Zigbee lighting gateway auditor
│   │   ├── camera_auditor.py            # IP camera RTSP (RFC 2326) & ONVIF auditor
│   │   ├── credential_pivot_auditor.py  # Cross-protocol credential reuse auditor
│   │   ├── firmware_auditor.py          # Extracted firmware ELF (NX/PIE/Canary) & SBOM
│   │   ├── modbus_auditor.py            # Modbus TCP (FC 0x03/0x06) SCADA auditor
│   │   ├── mqtt_telemetry_checker.py    # Anonymous MQTT broker & cleartext telemetry
│   │   ├── pin_entropy_analyzer.py      # Smart lock PIN entropy auditor (NIST SP 800-63B)
│   │   ├── shelly_auditor.py            # Shelly Gen 2 local RPC authentication auditor
│   │   └── web_cloud_auditor.py         # Web security headers, admin exposure, CORS
│   ├── conformance/
│   │   ├── matter_auditor.py            # Matter/Thread PASE commissioning auditor
│   │   ├── protocol_boundary_tester.py  # JSON-RPC specification boundary conformance
│   │   └── resilience_monitor.py        # Target service stability & crash monitor
│   └── correlation/
│       └── cross_zone_correlator.py     # Multi-zone risk propagation causality graph
└── profiles/                            # 25 hardware & virtual device YAML profiles
```

---

## 3. Registered Validation & Conformance Modules

| # | Module Path | Security Tier | Description |
|---|---|---|---|
| 1 | `conformance/matter_auditor` | Smart Home Fabrics & Thread Mesh | Audits Matter/Thread border routers (UDP 5540) for open commissioning windows and PASE resilience. |
| 2 | `conformance/protocol_boundary_tester` | General Conformance & Resilience | Evaluates embedded webserver JSON-RPC parser resilience against specification boundary inputs. |
| 3 | `conformance/resilience_monitor` | General Conformance & Resilience | Monitors target service stability, logs HTTP 500 exceptions, and detects daemon restarts. |
| 4 | `correlation/cross_zone_correlator` | Multi-Zone Architecture & Governance | Traces multi-zone risk propagation paths to document defense-in-depth and segmentation requirements. |
| 5 | `discovery/coap_scanner` | Constrained IoT & Sensor Mesh | Discovers CoAP nodes (UDP 5683), queries `/.well-known/core`, and audits unauthenticated resources. |
| 6 | `discovery/mdns_scanner` | Tier 1 - Edge & Multi-Zone Discovery | Read-only enumeration of mDNS advertisements and UPnP XML device descriptions. |
| 7 | `discovery/subnet_mapper` | Multi-Zone Discovery & Inventory | Room-by-room subnet mapper parsing HTTP (80/8080), MQTT (1883), and RTSP (554). |
| 8 | `discovery/upnp_scanner` | Perimeter Gateways & Routers | Audits UPnP IGD gateways for SCPD AddPortMapping exposure and WAN management leakage. |
| 9 | `validation/ble_mesh_auditor` | Wireless Mesh & Lighting Gateways | Audits smart lighting gateway control surfaces (BLE Mesh / Zigbee) and bounded actuation auto-revert. |
| 10 | `validation/camera_auditor` | Tier 3 - Perimeter Video & Surveillance | Audits IP cameras for unauthenticated RTSP stream exposure, SDP leakage, and snapshot endpoints. |
| 11 | `validation/credential_pivot_auditor` | Cross-Protocol & Identity Governance | Audits cross-protocol credential reuse (vault handles against HTTP/MQTT) without online dictionary spraying. |
| 12 | `validation/firmware_auditor` | Extracted Firmware & Binary Security | Inspects extracted firmware for compiler mitigations, hardcoded secrets, and SBOM vulnerabilities. |
| 13 | `validation/modbus_auditor` | Industrial & Operational Technology (OT) | Audits Modbus TCP supervisory control exposure (FC 0x03) and bounded register auto-revert (FC 0x06). |
| 14 | `validation/mqtt_telemetry_checker` | Tier 2 - Operational Core & Telemetry Backbone | Checks anonymous MQTT broker access, maps wildcard (`#`) topic namespaces, and flags cleartext telemetry. |
| 15 | `validation/pin_entropy_analyzer` | Tier 3 - Perimeter Access & Authentication | Evaluates smart lock temporary guest PIN generation entropy and predictability against NIST SP 800-63B. |
| 16 | `validation/shelly_auditor` | Tier 1 & Tier 2 Relay Systems | Audits Shelly Gen 2 local RPC authentication enforcement, schemas, and parameter validation. |
| 17 | `validation/web_cloud_auditor` | Embedded Web & Cloud Gateways | Audits embedded web consoles for missing security headers, unauthenticated admin endpoints, and CORS. |

---

## 4. Quick Start

### Installation

```bash
git clone https://github.com/academic-iot/iotflux.git
cd iotflux
pip install -e .
```

### Interactive Console Mode

Launch the Metasploit-style operator shell:

```bash
python -m iotflux console
```

Inside the console:
```text
iotflux > show modules
iotflux > show profiles
iotflux > use validation/shelly_auditor
iotflux (validation/shelly_auditor) > set TARGET 172.30.1.30
iotflux (validation/shelly_auditor) > run
```

### Direct CLI Mode

Run individual validation modules directly:

```bash
# Audit an unauthenticated Shelly Gen 2 relay
python -m iotflux run validation/shelly_auditor --target 172.30.1.30

# Audit an industrial Modbus controller (read-only default)
python -m iotflux run validation/modbus_auditor --target 172.30.2.65 --port 502

# Authorize bounded setpoint perturbation with auto-revert (Two-Key Gate)
python -m iotflux run validation/modbus_auditor --target 172.30.2.65 --port 502 --authorized-test

# Audit an IP camera RTSP stream
python -m iotflux run validation/camera_auditor --target 172.30.4.10

# Inspect extracted firmware filesystem
python -m iotflux run validation/firmware_auditor --target /path/to/extracted/rootfs

# List device profile catalog
python -m iotflux profiles list
python -m iotflux profiles show shelly_1pm
```

### Running Test Suite

```bash
python -m unittest discover tests
```

---

## 5. Lab Infrastructure Separation

The Docker virtual cyber ranges are decoupled from the tool and located in:
- **Pi 5 Multi-Room Cyber Range:** `Downloads/lab/` (ready for transfer and execution on headless Raspberry Pi 5 ARM64).
- **19-Node Residential Range:** `Downloads/lab/docker-lab-19node/` (complete Docker Compose simulation with all 19 virtual nodes).

See [`Downloads/lab/README.md`](file:///C:/Users/mitja/Downloads/lab/README.md) for lab topology, room subnets, and deployment instructions.
