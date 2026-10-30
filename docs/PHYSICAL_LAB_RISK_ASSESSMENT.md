# Physical Lab Risk Assessment & Hazard Mitigation Memo
**IoTFlux v4.0 - Authorized Defensive Security Validation Lab**

**Target Environment:** Raspberry Pi 5 Smart Home Physical Lab (`10.10.0.0/16`)  
**Assessment Scope:** Defensive Security Posture Validation  
**Author:** IoTFlux Safety & Assurance Committee  
**Status:** Approved for Controlled Physical Operations  

---

## 1. Executive Summary

Transitioning security validation from Docker software containers (`172.28.0.0/24`) to physical hardware (`10.10.0.0/16`) introduces physical hazards not present in virtual testbeds. Physical actuators, mains relays, battery-powered locks, and radio transceivers can cause equipment wear, thermal overload, electrical shock, or unintended perimeter state changes if improperly actuated.

This memo assesses the electrical, mechanical, and radio frequency (RF) hazards associated with physical lab validation and defines mandatory defensive engineering mitigations enforced by the IoTFlux framework.

---

## 2. Hazard Identification & Risk Matrix

| Risk ID | Hazard Category | Target Devices | Threat / Failure Mode | Unmitigated Severity | Mitigated Severity |
|---|---|---|---|---|---|
| **HAZ-01** | Electrical | Shelly Plug S (`10.10.20.30`), Shelly Plus 2PM (`10.10.20.31`) | High-frequency relay cycling causing contact welding, arcing, or thermal overload | **HIGH** | **NEGLIGIBLE** |
| **HAZ-02** | Electrical | Power Supplies & Sensors (`10.10.30.40`) | Overvoltage or sustained power draw exceeding circuit rating | **MEDIUM** | **LOW** |
| **HAZ-03** | Mechanical | Smart Door Lock (`10.10.40.50`) | Solenoid latch overheating, deadbolt jam, or permanent unlocked state | **HIGH** | **NEGLIGIBLE** |
| **HAZ-04** | Mechanical | Smart Air Purifier (`10.10.30.45`) | Motor driver stall, unintended high-RPM actuation | **MEDIUM** | **LOW** |
| **HAZ-05** | RF / Wireless | Zigbee/BLE Bridges & WiFi APs | Broadcast channel flooding leading to denial of environmental telemetry | **MEDIUM** | **LOW** |
| **HAZ-06** | Operational | OpenWrt Gateway (`10.10.10.1`), MQTT Broker (`10.10.10.20`) | State desynchronization or accidental routing leak to corporate/public networks | **CRITICAL** | **NEGLIGIBLE** |

---

## 3. Detailed Hazard Analysis

### 3.1 Electrical Hazards
- **Relay Arcing & Contact Degradation**: Smart plugs switching inductive or resistive loads (up to 2500W) experience electrical arcing during rapid state transitions. Rapid toggling can fuse internal relay contacts.
- **Overcurrent & Thermal Dissipation**: Actuating multiple high-draw loads simultaneously can trip lab branch breakers or cause localized heating.

**Enforced Mitigations**:
1. **Pulse Duration Cap**: `max_pulse` is strictly capped at $\le 2.0\text{s}$ across all actuation profiles. Continuous pulsing is prohibited.
2. **Deterministic Auto-Revert**: Every actuation profile defines an explicit `auto_revert` mechanism (e.g., `"relay_off"`, `"dual_relay_restore"`).
3. **Power Draw Telemetry**: IoTFlux records `power_draw_watts` before and after each pulse; operations exceeding `max_power_watts` trigger circuit breaker shutdown.

### 3.2 Mechanical Hazards
- **Actuator Solenoid Strain**: The smart deadbolt lock (`10.10.40.50`) utilizes a 12V DC solenoid. Continuous duty beyond 3 seconds causes coil overheating and spring fatigue.
- **Physical Entrapment**: Leaving a perimeter door lock in an indeterminate state compromises physical building security.

**Enforced Mitigations**:
1. **Bounded Actuation Limit**: Solenoid actuation is hard-capped at $1.5\text{s}$ (`max_pulse: "1.5s"`).
2. **Immediate Re-Lock Policy**: The auto-revert routine enforces `bolt_relock_immediate` and verifies deadbolt engagement through post-state readback.

### 3.3 RF & Environmental Sensor Hazards
- **RF Channel Saturation**: High-volume packet generation over 2.4 GHz (802.11b/g/n / 802.15.4) can cause packet loss for the smart smoke alarm (`10.10.30.40`).
- **Nuisance Alarms**: Tampering with audible smoke sensor annunciators creates an occupational safety hazard.

**Enforced Mitigations**:
1. **Zone Isolation**: Smoke alarm telemetry is segmented into VLAN 30 (`10.10.30.0/24`) with strict ingress rate limits.
2. **RF Signal Monitoring**: `rf_rssi_dbm` telemetry is logged to detect packet loss or interference.
3. **Mute State Guard**: Safety smoke sensor validation is restricted to read-only status queries; audible alarm triggering is capped at $\le 1.0\text{s}$ with immediate `unmute_state_reset`.

---

## 4. Architectural Safety Controls

The IoTFlux framework enforces defense-in-depth safety controls prior to any packet transmission:

```
[ Operator Command ]
         │
         ▼
[ Circuit Breaker Check ] ──(Tripped?)──► [ ABORT: CircuitBreakerTrippedError ]
         │
         ▼
[ Subnet Scope Check ] ────(Out of Scope?)──► [ ABORT: ScopeViolationError ]
         │
         ▼
[ Physical Subnet Gate ] ──(No --authorize?)──► [ ABORT: PhysicalLabAuthorizationError ]
         │
         ▼
[ Profile Safety Limits ] ──(max_pulse > 2s?)──► [ ABORT: SafetyLimitValidationError ]
         │
         ▼
[ Execute Controlled Pulse ]
         │
         ▼
[ Mandatory Baseline Revert ] ──(Revert Failed?)──► [ TRIP CIRCUIT BREAKER & HALT ]
         │
         ▼
[ Generate Telemetry Artifact (PCAP + JSON) ]
```

### Circuit Breaker Fail-Safe:
If at any point during validation a target fails to return to its verified pre-test baseline within 500ms of the revert signal:
1. `emergency_revert()` is triggered.
2. If the emergency restore also fails, `trip_circuit_breaker()` activates.
3. `ControlledImpactValidator.SAFETY_CIRCUIT_BREAKER_TRIPPED` is latched to `True`.
4. All subsequent validations across all targets are blocked until an operator manually inspects the hardware and runs `reset_circuit_breaker()`.

---

## 5. Conclusion & Operational Authorization

With the implementation of Two-Key authorization, container isolation, datasheet-derived `safety_limits`, real-time telemetry capture, and the automatic circuit breaker, the risk profile of testing against the physical Raspberry Pi 5 lab is reduced to acceptable academic research thresholds.
