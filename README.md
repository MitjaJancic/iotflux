# IoTFlux: IoT Exploitation & Protocol Assessment Framework

**IoTFlux** is a modular, high-speed, specification-driven exploitation and security assessment framework for residential and industrial Internet of Things (IoT) ecosystems. It discovers devices, breaks their authentication, drives their actuators, and dumps their configuration — then reports the result against public standards.

See [`docs/EXPLOITATION.md`](docs/EXPLOITATION.md) for the exploitation workflow.

---

## 1. Key Architectural Principles

1. **Exploit-by-default:**
   State-changing operations run without a gate. A read-only run is one `set AUTHORIZED_TEST false` away. `--authorize` is retained as a no-op compatibility flag.

2. **Advisory scope, not a lock:**
   `lab-scope.env` is still parsed and every out-of-boundary target is logged, but nothing is blocked. Any reachable target is fair game.

3. **No automatic revert:**
   Perturbations stay applied. Modules print the exact restore command, and `--auto-revert` restores inline when you want it.

4. **Plaintext credential store:**
   Harvested and validated credentials persist to `creds.json` so later modules reuse them without re-spraying. `iotflux creds` manages the file.

5. **Profile-Driven Architecture:**
   Device knowledge and endpoint semantics are decoupled from code. Device profiles are declared in YAML (`iotflux/profiles/*.yaml`) covering relays, locks, thermostats, IP cameras, gateways, industrial PLCs, and smart lighting hubs.

6. **5-Dimensional Formulaic Damage Quantification:**
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
│   ├── vault.py           # Ephemeral RAM-only credential vault
│   └── creds_store.py     # Plaintext on-disk credential store (creds.json)
├── modules/
│   ├── base.py            # BaseValidationModule abstraction & findings dataclass
│   ├── exploit/
│   │   ├── cred_spray.py       # Default/vendor credential spraying (HTTP/RTSP/MQTT/ONVIF/TR-069)
│   │   ├── mqtt_publish.py     # Topic capture and payload/retained injection
│   │   ├── coap_write.py       # CoAP PUT/POST/DELETE
│   │   ├── upnp_portmap.py     # IGD AddPortMapping / DeletePortMapping
│   │   ├── tr069_exploit.py    # CWMP parameter dump and set
│   │   ├── firmware_extract.py # Image extraction and secret harvesting
│   │   ├── camera_capture.py   # Snapshot, RTSP record, ONVIF profiles
│   │   ├── modbus_write.py     # FC 01/03/05/06/0F/10 read/write
│   │   └── shelly_control.py   # Shelly RPC control, config dump, reboot
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

## 3. Registered Modules

### 3a. Exploitation modules (`exploit/`)

| # | Module Path | Description |
|---|---|---|
| 1 | `exploit/cred_spray` | Default/vendor credential spraying over HTTP Basic/Digest/form, RTSP, MQTT, ONVIF, TR-069. Persists hits to `creds.json`. |
| 2 | `exploit/mqtt_publish` | Topic capture, payload injection, retained-message planting. |
| 3 | `exploit/coap_write` | CoAP PUT/POST/DELETE with readback. |
| 4 | `exploit/upnp_portmap` | SSDP IGD discovery, `AddPortMapping` / `DeletePortMapping`, WAN IP disclosure. |
| 5 | `exploit/tr069_exploit` | CWMP parameter dump, name enumeration, `SetParameterValues`. |
| 6 | `exploit/firmware_extract` | Image extraction, hardcoded-secret harvesting, ELF hardening report. |
| 7 | `exploit/camera_capture` | Snapshot pull, RTSP recording, ONVIF profile enumeration. |
| 8 | `exploit/modbus_write` | FC 01/03/05/06/0F/10 read/write, register scan. |
| 9 | `exploit/shelly_control` | Shelly RPC control, config dump, reboot, `SetAuth`. |
| 10 | `exploit/shelly_persist` | Shelly persistence: schedules, KVS, MQTT/cloud redirection, Wi-Fi move, unsigned OTA, auth lockout, neighbour scan. |
| 11 | `exploit/snmp_enum` | SNMP community spray, GetNext walk, single get. |
| 12 | `exploit/bacnet_write` | BACnet Who-Is, ReadProperty, WriteProperty. |
| 13 | `exploit/opcua_browse` | OPC UA endpoint enumeration, anonymous session and browse. |
| 14 | `exploit/tftp_pull` | Anonymous TFTP config/firmware retrieval. |
| 15 | `exploit/ftp_anon` | Anonymous FTP login, listing, retrieval. |
| 16 | `exploit/cgi_inject` | Shell injection in embedded CGI handlers. |
| 17 | `exploit/fw_upload` | Unsigned firmware upload. |
| 18 | `exploit/jwt_forge` | `alg:none` / bad-signature JWT against cloud APIs. |
| 19 | `exploit/ws_hijack` | WebSocket control channel with no origin check. |
| 20 | `exploit/dns_rebind` | Admin panels that trust an arbitrary Host header. |
| 21 | `exploit/matter_commission` | Matter commissioning window probe. |
| 22 | `exploit/ble_scan` | BLE advertisement scan and GATT enumeration. |
| 23 | `exploit/zigbee_sniff` | Zigbee coordinator API: network map, devices, permit-join. |
| 24 | `exploit/subghz_replay` | Sub-GHz capture and replay. |
| 25 | `exploit/wifi_attack` | Wi-Fi survey, deauth, PMKID capture. |
| 26 | `exploit/tasmota_control` | Tasmota command API: state, toggle, OTA, MQTT/Wi-Fi redirection. |
| 27 | `exploit/esphome_control` | ESPHome web server: entity inventory, toggle, press. |
| 28 | `exploit/ha_control` | Home Assistant REST: token check, entity dump, service calls. |
| 29 | `exploit/tuya_discover` | Tuya UDP discovery and 6668 handshake. |

Shelly modules handle **both generations**: `shelly_common` detects Gen1 vs Gen2
and maps each action to REST (Gen1, Basic) or JSON-RPC (Gen2, Digest).

### 3b. Validation & conformance modules

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
git clone https://github.com/MitjaJancic/iotflux.git
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

Run individual modules directly. State changes apply by default.

```bash
# Spray default credentials at a camera, then reuse the hit
python -m iotflux run exploit/cred_spray --target 192.168.1.40 --port 80 \
    --opt PROTOCOL=http-basic --opt VENDOR=hikvision
python -m iotflux run exploit/camera_capture --target 192.168.1.40 --port 80 \
    --opt ACTION=snapshot

# Drive a Shelly relay and leave it off
python -m iotflux run exploit/shelly_control --target 172.30.1.30 \
    --opt ACTION=set --opt CHANNEL=0 --opt ON=false

# Write a Modbus setpoint (no revert), then restore it yourself
python -m iotflux run exploit/modbus_write --target 172.30.2.65 --port 502 \
    --opt ACTION=write_reg --opt ADDRESS=3 --opt VALUE=101

# Punch a router port forward
python -m iotflux run exploit/upnp_portmap --target 192.168.1.1 \
    --opt ACTION=add --opt EXTERNAL_PORT=8080 --opt INTERNAL_PORT=80

# Dump a TR-069 CPE configuration
python -m iotflux run exploit/tr069_exploit --target 192.168.1.1 --opt ACTION=dump

# Harvest secrets out of a firmware image
python -m iotflux run exploit/firmware_extract --target firmware.bin

# Read-only run of the legacy auditor, with inline restore
python -m iotflux run validation/modbus_auditor --target 172.30.2.65 --auto-revert

# Inspect the credential store
python -m iotflux creds list
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
