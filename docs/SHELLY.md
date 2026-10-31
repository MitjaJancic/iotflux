# Shelly — attack surface, known weaknesses, and tool coverage

Shelly (Allterco / Shelly Group) Gen1–Gen4 relays, plugs, TRVs, dimmers and
sensors are the most common "prosumer" IoT target in Europe. They are also a
useful teaching target because the *same* device exposes almost every class of
IoT weakness at once: an unauthenticated local RPC, a cloud tunnel, MQTT
telemetry, BLE provisioning, mDNS advertisement, and OTA.

This document records what is actually exploitable, what IoTFlux covers, and
what is still missing.

---

## 1. Why Shelly is a realistic target

- **Local RPC with auth off by default.** Gen2+ firmware ships with
  `auth_en: false`. `http://<ip>/rpc/Shelly.GetConfig` returns the full config
  — including the **Wi-Fi PSK**, the **cloud token**, and any **MQTT
  username/password** — to anyone on the LAN with no credentials.
- **`/rpc` is a full control plane, not just a status page.** The same
  unauthenticated endpoint accepts `Switch.Set`, `Shelly.SetAuth`,
  `Shelly.Update`, `Mqtt.SetConfig`, `WiFi.SetConfig`, `Schedule.Create` and
  `KVS.Set`.
- **Gen1 devices** expose `/settings`, `/status`, `/relay/0?turn=toggle` and
  `/ota?url=` with the same posture, plus HTTP Basic where auth is enabled.
- **Cloud tunnel.** With the cloud enabled the device dials out to
  `*.shelly.cloud`; the token in the config is enough to drive the device
  through the vendor API from anywhere.
- **BLE provisioning (Gen2+).** BLE is used for first-time setup and stays on.
  A device in provisioning mode accepts a new Wi-Fi config and a new owner.
- **mDNS.** Devices advertise `_shelly._tcp.local` with their id and
  generation — free inventory for an attacker and no auth.
- **OTA from an arbitrary URL.** `Shelly.Update` takes a URL and does not
  require a signature on stock firmware, so an attacker-hosted image is
  accepted.

## 2. Vulnerability classes that matter

| Class | Where | Impact |
|---|---|---|
| Missing auth on the control plane | `/rpc`, `/relay/0` | Full relay control, config read/write |
| Secret disclosure in config | `Shelly.GetConfig` | Wi-Fi PSK, cloud token, MQTT creds |
| Auth downgrade / lockout | `Shelly.SetAuth` with empty password | Owner locked out, attacker keeps access |
| Persistence via schedules | `Schedule.Create` | Timed actions survive reboot |
| Persistence via KVS | `KVS.Set` | Arbitrary stored state |
| Telemetry redirection | `Mqtt.SetConfig`, `Cloud.SetConfig` | Attacker sees all sensor data |
| Network move | `WiFi.SetConfig` | Device joins an attacker AP |
| Unsigned OTA | `Shelly.Update` | Code execution as root on the device |
| Reboot / DoS | `Shelly.Reboot` | Physical consequence (heating, gates) |
| Neighbour disclosure | `WiFi.Scan` | Aids rogue-AP planning |
| BLE provisioning hijack | BLE GATT | Take ownership during setup |
| mDNS inventory leak | `_shelly._tcp` | Target list without scanning |

Known public research in this space covers exactly these: unauthenticated
Gen1 RPC, the `Shelly.SetAuth` lockout, cleartext cloud tokens, and OTA
without signature verification. None of it needs a memory-corruption bug —
the design is the weakness.

## 3. What IoTFlux now covers

| Capability | Module | Notes |
|---|---|---|
| mDNS inventory | `discovery/shelly_mdns` | Unicast fallback so it works across bridges |
| Config dump (secrets) | `exploit/shelly_control` `ACTION=config` | Wi-Fi PSK, cloud token, MQTT creds |
| Relay control | `exploit/shelly_control` `ACTION=set/toggle` | State change, no gate |
| Digest credential spray | `exploit/cred_spray` `PROTOCOL=http-digest` | Hits persist to `creds.json` |
| Schedule persistence | `exploit/shelly_persist` `ACTION=schedule` | Survives reboot |
| KVS persistence | `exploit/shelly_persist` `ACTION=kvs` | |
| MQTT redirection | `exploit/shelly_persist` `ACTION=mqtt` | |
| Cloud redirection | `exploit/shelly_persist` `ACTION=cloud` | |
| Wi-Fi move | `exploit/shelly_persist` `ACTION=wifi` | |
| Unsigned OTA | `exploit/shelly_persist` `ACTION=ota` | |
| Auth lockout / removal | `exploit/shelly_persist` `ACTION=setauth/clearauth` | |
| Reboot | `exploit/shelly_persist` `ACTION=reboot` | |
| Neighbour SSIDs | `exploit/shelly_persist` `ACTION=wifiscan` | |
| BLE advertisement scan | `exploit/ble_scan` | Needs an adapter |
| BLE GATT enumeration | `exploit/ble_scan` `ACTION=gatt` | Needs an adapter |

`exploit/shelly_persist` reuses credentials from `creds.json` automatically, so
the chain is: spray → stored creds → authenticated persistence, with no manual
copying.

## 4. Gaps still open

- **BLE provisioning hijack.** `ble_scan` enumerates GATT but does not yet
  push a Wi-Fi config or a new owner through the provisioning service.
- **Cloud API replay.** `jwt_forge` covers JWT confusion on a generic cloud
  API; the Shelly cloud token flow (device id + token → `shelly.cloud`
  endpoint) is not modelled.
- **Firmware signature check.** `fw_upload` separates accepted from rejected,
  but a signed-image control case would prove whether the device actually
  verifies a signature rather than just the image format.
- **Rolling-code / TRV valve position.** `shelly_trv` is present in the lab but
  no module drives valve position as a physical consequence.
- **Scripting (Gen3/Gen4 `Script.*`).** mJS scripting can be used for
  persistence that survives a config reset; not implemented.

## 4a. Generation coverage

Both generations are handled. `shelly_common.ShellyDevice` detects the
generation from `/rpc/Shelly.GetDeviceInfo` (Gen2) or `/shelly` (Gen1) and maps
every action to the right API — Digest + JSON-RPC on Gen2, Basic + REST on Gen1.

Actions that genuinely do not exist on Gen1 (`schedule`, `kvs`, `profile`)
report `SHELLY-UNSUPPORTED-GEN1` instead of failing obscurely. Gen1 persistence
goes through `/settings` (MQTT, cloud, Wi-Fi, auth) and `/ota?url=` instead.

## 5. Lab targets

| Address | Role | Posture |
|---|---|---|
| `10.10.20.30` | `shelly-plug` | Auth off — full chain works unauthenticated |
| `10.10.20.35` | `hardened-shelly` | Digest auth on, `admin` / `shelly-Secret-1` — spray then persist |
| `10.10.50.31` | `shelly-ap` | Provisioning/AP mode |

Both advertise `_shelly._tcp` over mDNS and both leak secrets through
`Shelly.GetConfig` once authenticated.
