# Physical Lab Setup & Routing Verification Guide
**IoTFlux v4.0 - Authorized Defensive Security Validation Lab**

This document details the configuration, network zone isolation, and operator execution requirements for extending IoTFlux validation capabilities from Docker environments (`172.28.0.0/24`) to the physical **Raspberry Pi 5 Smart Home Lab (`10.10.0.0/16`)**.

---

## 1. Network Topology & OpenWrt Zone Isolation

The physical testbed is segmented via an OpenWrt gateway router (`10.10.10.1`) running on a dedicated Raspberry Pi 5. Traffic between physical segments is strictly controlled by OpenWrt firewall zones (`iptables`/`nftables` rules) to prevent lateral spillover:

```
                          +-------------------------------+
                          |   OpenWrt Gateway / Router    |
                          |          10.10.10.1           |
                          +---------------+---------------+
                                          |
        +------------------+--------------+--------------+------------------+
        |                  |                             |                  |
+-------v--------+ +-------v--------+             +------v-------+   +------v-------+
|  VLAN 10: Core | | VLAN 20: Relays|             | VLAN 30: Env |   | VLAN 40: OT  |
| 10.10.10.0/24  | | 10.10.20.0/24  |             | 10.10.30.0/24|   | 10.10.40.0/24|
+----------------+ +----------------+             +--------------+   +--------------+
| MQTT Broker    | | Shelly Plug S  |             | Smoke Alarm  |   | Smart Lock   |
| 10.10.10.20    | | 10.10.20.30    |             | 10.10.30.40  |   | 10.10.40.50  |
|                | | Shelly 2PM     |             | Air Purifier |   | RTSP Cam     |
|                | | 10.10.20.31    |             | 10.10.30.45  |   | 10.10.40.55  |
|                | |                |             |              |   | Modbus PLC   |
|                | |                |             |              |   | 10.10.40.60  |
+----------------+ +----------------+             +--------------+   +--------------+
```

### Zone Definitions & Firewall Rules:
1. **Tier 2 - Operational Core (`10.10.10.0/24`)**:
   - Hosts MQTT broker (`10.10.10.20:1883`) and gateway management (`10.10.10.1:80/443`).
   - Forwarding to other subnets requires stateful established/related tracking.
2. **Tier 1 - Edge Smart Relays (`10.10.20.0/24`)**:
   - Hosts smart switches and plugs (`10.10.20.30`, `10.10.20.31`).
   - Isolated from direct OT control interfaces.
3. **Tier 2 - Safety & Environmental (`10.10.30.0/24`)**:
   - Hosts smoke sensors (`10.10.30.40`) and air filtration systems (`10.10.30.45`).
   - Blocked from receiving unauthenticated broadcast floods.
4. **Tier 3 - Perimeter & Supervisory (`10.10.40.0/24`)**:
   - Hosts physical access locks (`10.10.40.50`), RTSP cameras (`10.10.40.55`), and Modbus PLCs (`10.10.40.60`).
   - Highest security boundary; ingress tightly limited.

---

## 2. Operating System & Execution Context (Kali Linux)

> [!NOTE]
> Physical lab validation runs natively on **Kali Linux OS** (physical machine or Kali VM bridged to the physical lab switch / OpenWrt router). Container-mock wrappers are not required.

IoTFlux executes natively within Kali Linux:
- Physical hardware targeting is governed strictly by the **Two-Key Authorization Model** (`--authorize` flag) and compile-time scope allowlisting in `assessment_scope.yaml`.
- All socket interactions bind directly to the assigned Kali network interface routing to the OpenWrt router.

---

## 3. Pre-Flight Verification Commands

Before launching validation modules against `10.10.0.0/16`, execute the following manual checks:

### Step 1: Routing Table Verification
Ensure Kali routes forward `10.10.0.0/16` through the OpenWrt router interface (`10.10.10.1`):
```bash
ip route show to match 10.10.10.1

# Output should show:
# 10.10.0.0/16 via 10.10.10.1 dev eth0 (or wlan0)
```
```

### Step 3: Scope Policy Validation
Verify that IoTFlux recognizes the physical lab boundaries:
```bash
python -m iotflux.core.cli scope show
```
Expected output:
- `10.10.0.0/16` (Physical Raspberry Pi 5 Smart Home Lab) [physical_lab=True]
- `0.0.0.0/0` [DENIED]
- Validation Mode: `enforce`

---

## 4. Two-Key Authorization Workflow

To execute validation against any physical device in `10.10.0.0/16`, the Two-Key Authorization model requires:
1. **Compile-Time Policy Key**: The subnet `10.10.0.0/16` must be present in `assessment_scope.yaml` with `physical_lab: true`.
2. **Runtime Operator Confirmation Key**: The operator MUST supply the `--authorize` flag on every command invocation.

Example CLI invocation:
```bash
python -m iotflux.core.cli run-validation \
  --target 10.10.20.30 \
  --port 80 \
  --experiment EXP-02 \
  --authorize
```
If `--authorize` is omitted, the execution is blocked with `PhysicalLabAuthorizationError`.
