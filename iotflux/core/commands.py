"""
commands.py - the human-facing command surface.

`iotflux <family> <address> <verb> [flags]` instead of
`iotflux run exploit/<module> -t <host> --port <port> --opt ACTION=<verb>`.

The module layer is untouched: every verb resolves to a module plus a set of
fixed options, so `run`/`--opt` keeps working as the compatibility path.

Design rules:
  - the target is an address (`host[:port]`), port defaults per family
  - verbs are subcommands with real, typed flags
  - every option is declared, so --help and completion work
  - `--opt KEY=VALUE` still reaches any option the registry does not declare
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any, Dict, List, Optional

from iotflux.core.logger import logger

CFG: Dict[str, Any] = {}

# ---------------------------------------------------------------------------
# argument types
# ---------------------------------------------------------------------------

_DURATION = re.compile(r"^(\d+)\s*([smh]?)$")


def duration(text: str) -> int:
    """'30s' -> 30, '5m' -> 300, '2h' -> 7200, '30' -> 30."""
    m = _DURATION.match(text.strip())
    if not m:
        raise ValueError(f"not a duration: {text!r} (use 30s, 5m, 2h)")
    n, unit = int(m.group(1)), m.group(2)
    return n * {"": 1, "s": 1, "m": 60, "h": 3600}[unit]


def address(text: str) -> str:
    """Validates host[:port] and returns it unchanged."""
    host, sep, port = text.partition(":")
    if not host:
        raise ValueError(f"not an address: {text!r}")
    if sep and not port.isdigit():
        raise ValueError(f"bad port in {text!r}")
    return text


def split_address(text: str, default_port: int) -> tuple:
    host, sep, port = text.partition(":")
    return host, int(port) if sep else default_port


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------
# verb spec keys:
#   module   module name (defaults to the family's module)
#   set      fixed module options
#   args     extra argparse arguments
#   undo     hint printed after a successful state change
#   help     one line

def _on_off() -> List[dict]:
    return [
        {"name": "--on", "dest": "ON", "type": "true", "help": "target state on"},
        {"name": "--off", "dest": "ON", "type": "false", "help": "target state off"},
    ]


FAMILIES: Dict[str, dict] = {
    "shelly": {
        "module": "exploit/shelly_control",
        "port": 80,
        "help": "Shelly relays and plugs (Gen1 REST and Gen2+ RPC, auto-detected)",
        "verbs": {
            "status": {"set": {"ACTION": "status"}, "help": "read device state"},
            "info": {"set": {"ACTION": "info"}, "help": "read device identity"},
            "config": {"set": {"ACTION": "config"}, "help": "dump config, including Wi-Fi PSK and cloud token"},
            "on": {"set": {"ACTION": "set"}, "args": [{"name": "--channel", "dest": "CHANNEL", "type": int, "default": 0, "help": "channel index"}],
                   "set_extra": {"ON": True}, "help": "switch a channel on", "undo": "off"},
            "off": {"set": {"ACTION": "set"}, "args": [{"name": "--channel", "dest": "CHANNEL", "type": int, "default": 0, "help": "channel index"}],
                    "set_extra": {"ON": False}, "help": "switch a channel off", "undo": "on"},
            "toggle": {"set": {"ACTION": "toggle"}, "help": "toggle a channel"},
            "reboot": {"set": {"ACTION": "reboot"}, "help": "reboot the device and wait for it to return"},
            "schedule": {
                "module": "exploit/shelly_persist",
                "set": {"ACTION": "schedule"},
                "args": [
                    {"name": "--in", "dest": "DELAY", "type": "duration", "default": 60, "help": "delay before it fires (30s, 5m)"},
                    {"name": "--timespec", "dest": "TIMESPEC", "default": "", "help": "cron timespec instead of --in"},
                    {"name": "--channel", "dest": "CHANNEL", "type": int, "default": 0, "help": "channel index"},
                ] + _on_off(),
                "help": "schedule a timed switch action (Gen2 only)",
            },
            "kvs": {"module": "exploit/shelly_persist", "set": {"ACTION": "kvs"},
                    "args": [{"name": "--key", "dest": "KEY", "default": "iotflux", "help": "key"},
                             {"name": "--value", "dest": "VALUE", "default": "pwned", "help": "value"}],
                    "help": "write a persistent key/value pair (Gen2 only)"},
            "mqtt": {"module": "exploit/shelly_persist", "set": {"ACTION": "mqtt"},
                     "args": [{"name": "--broker", "dest": "BROKER", "type": address, "default": "", "help": "attacker broker host:port"},
                              {"name": "--prefix", "dest": "TOPIC_PREFIX", "default": "shelly", "help": "MQTT topic prefix"}],
                     "help": "repoint telemetry at your broker"},
            "cloud": {"module": "exploit/shelly_persist", "set": {"ACTION": "cloud"},
                      "args": [{"name": "--server", "dest": "CLOUD_SERVER", "default": "", "help": "cloud RPC endpoint host:port"}],
                      "help": "repoint the cloud endpoint"},
            "wifi": {"module": "exploit/shelly_persist", "set": {"ACTION": "wifi"},
                     "args": [{"name": "--ssid", "dest": "SSID", "default": "attacker-ap", "help": "SSID"},
                              {"name": "--psk", "dest": "PSK", "default": "attackerpass", "help": "PSK"}],
                     "help": "move the device to another network"},
            "flash": {"module": "exploit/shelly_persist", "set": {"ACTION": "ota"},
                      "args": [{"name": "--url", "dest": "FW_URL", "default": "", "help": "firmware URL"}],
                      "help": "flash firmware from a URL"},
            "lock": {"module": "exploit/shelly_persist", "set": {"ACTION": "setauth"},
                     "args": [{"name": "--user", "dest": "NEW_USER", "default": "admin", "help": "username"},
                              {"name": "--pass", "dest": "NEW_PASS", "default": "pwned123", "help": "password"}],
                     "help": "set a password (locks the owner out)", "undo": "unlock"},
            "unlock": {"module": "exploit/shelly_persist", "set": {"ACTION": "clearauth"},
                       "help": "remove the password entirely"},
            "wifiscan": {"module": "exploit/shelly_persist", "set": {"ACTION": "wifiscan"},
                         "help": "list neighbouring SSIDs"},
            "raw": {"args": [{"name": "--method", "dest": "METHOD", "default": "Shelly.GetStatus", "help": "RPC method or REST path"},
                             {"name": "--params", "dest": "PARAMS", "default": "", "help": "JSON params"}],
                    "set": {"ACTION": "raw"}, "help": "call an arbitrary method"},
        },
    },
    "tasmota": {
        "module": "exploit/tasmota_control",
        "port": 80,
        "help": "Tasmota devices (/cm?cmnd= command API)",
        "verbs": {
            "status": {"set": {"ACTION": "status"}, "help": "read state"},
            "info": {"set": {"ACTION": "info"}, "help": "read firmware and network details"},
            "toggle": {"set": {"ACTION": "toggle"}, "help": "toggle the relay"},
            "on": {"set": {"ACTION": "set"}, "set_extra": {"ON": True}, "help": "relay on", "undo": "off"},
            "off": {"set": {"ACTION": "set"}, "set_extra": {"ON": False}, "help": "relay off", "undo": "on"},
            "reboot": {"set": {"ACTION": "reboot"}, "help": "restart the device"},
            "flash": {"set": {"ACTION": "ota"}, "args": [{"name": "--url", "dest": "FW_URL", "default": "", "help": "firmware URL"}],
                      "help": "set OTA URL and upgrade"},
            "mqtt": {"set": {"ACTION": "mqtt"}, "args": [{"name": "--broker", "dest": "BROKER", "default": "", "help": "broker host"}],
                     "help": "repoint MQTT"},
            "wifi": {"set": {"ACTION": "wifi"}, "args": [{"name": "--ssid", "dest": "SSID", "default": "attacker-ap", "help": "SSID"},
                                                         {"name": "--psk", "dest": "PSK", "default": "attackerpass", "help": "PSK"}],
                     "help": "move the device to another network"},
            "raw": {"set": {"ACTION": "raw"}, "args": [{"name": "command", "nargs": "?", "default": "Status", "dest": "COMMAND", "help": "Tasmota command"}],
                    "help": "send an arbitrary command"},
        },
    },
    "esphome": {
        "module": "exploit/esphome_control",
        "port": 80,
        "help": "ESPHome web servers",
        "verbs": {
            "status": {"set": {"ACTION": "status"}, "help": "list controllable entities"},
            "toggle": {"args": [{"name": "--entity", "dest": "ENTITY", "default": "", "help": "entity id"},
                                {"name": "--domain", "dest": "DOMAIN", "default": "switch", "help": "entity domain"}],
                       "help": "toggle an entity"},
            "press": {"set": {"ACTION": "press"}, "args": [{"name": "--entity", "dest": "ENTITY", "default": "", "help": "button id"}],
                      "help": "press a button"},
            "sensor": {"set": {"ACTION": "sensor"}, "args": [{"name": "--entity", "dest": "ENTITY", "default": "", "help": "sensor id"}],
                       "help": "read a sensor"},
        },
    },
    "ha": {
        "module": "exploit/ha_control",
        "port": 8123,
        "help": "Home Assistant REST API",
        "verbs": {
            "probe": {"help": "check whether the API needs a token"},
            "states": {"args": [{"name": "--token", "dest": "TOKEN", "default": "", "help": "long-lived token"}],
                       "help": "dump every entity"},
            "call": {"set": {"ACTION": "services"},
                     "args": [{"name": "--token", "dest": "TOKEN", "default": "", "help": "long-lived token"},
                              {"name": "--domain", "dest": "DOMAIN", "default": "switch", "help": "service domain"},
                              {"name": "--service", "dest": "SERVICE", "default": "toggle", "help": "service name"},
                              {"name": "--entity", "dest": "ENTITY", "default": "", "help": "entity id"}],
                     "help": "call a service"},
        },
    },
    "tuya": {
        "module": "exploit/tuya_discover",
        "port": 6668,
        "help": "Tuya local protocol",
        "verbs": {
            "handshake": {"help": "read the device id over TCP 6668"},
            "broadcast": {"args": [{"name": "--seconds", "dest": "SECONDS", "type": float, "default": 6.0, "help": "listen window"}],
                          "help": "discover devices by UDP broadcast"},
        },
    },
    "zigbee": {
        "module": "exploit/zigbee_sniff",
        "port": 8080,
        "help": "Zigbee coordinators (Zigbee2MQTT API)",
        "verbs": {
            "api": {"set": {"ACTION": "api"}, "help": "read the network map and device inventory"},
            "permit": {"set": {"ACTION": "permit"}, "help": "open permit-join"},
        },
    },
    "matter": {
        "module": "exploit/matter_commission",
        "port": 5540,
        "help": "Matter commissioning",
        "verbs": {
            "probe": {"args": [{"name": "--mdns-timeout", "dest": "MDNS_TIMEOUT", "type": float, "default": 2.0, "help": "mDNS window"}],
                      "help": "probe for an open commissioning window"},
        },
    },
    "mqtt": {
        "module": "exploit/mqtt_publish",
        "port": 1883,
        "help": "MQTT brokers",
        "verbs": {
            "listen": {"args": [{"name": "--topic", "dest": "TOPIC", "default": "#", "help": "topic filter"},
                                {"name": "--seconds", "dest": "CAPTURE_SECONDS", "type": float, "default": 8.0, "help": "capture window"}],
                       "help": "subscribe and capture traffic"},
            "publish": {"args": [{"name": "--topic", "dest": "PUBLISH_TOPIC", "default": "", "help": "topic"},
                                 {"name": "--payload", "dest": "PAYLOAD", "default": "", "help": "payload"},
                                 {"name": "--retain", "dest": "RETAIN", "type": "true", "help": "set the retain flag"}],
                        "help": "publish a message"},
        },
    },
    "coap": {
        "module": "exploit/coap_write",
        "port": 5683,
        "help": "CoAP devices",
        "verbs": {
            "write": {"args": [{"name": "--path", "dest": "PATH", "default": "/actuators/relay", "help": "resource path"},
                               {"name": "--payload", "dest": "PAYLOAD", "default": "1", "help": "payload"}],
                      "help": "PUT a resource"},
        },
    },
    "modbus": {
        "module": "exploit/modbus_write",
        "port": 502,
        "help": "Modbus/TCP PLCs",
        "verbs": {
            "read": {"args": [{"name": "--address", "dest": "ADDRESS", "type": int, "default": 0, "help": "start address"},
                              {"name": "--count", "dest": "COUNT", "type": int, "default": 10, "help": "count"}],
                     "help": "read holding registers"},
            "write-coil": {"set": {"ACTION": "write_coil"},
                           "args": [{"name": "address", "type": int, "help": "coil address"},
                                    {"name": "value", "type": int, "help": "0 or 1"}],
                           "help": "write one coil", "undo": "write-coil back"},
            "write-reg": {"set": {"ACTION": "write_reg"},
                          "args": [{"name": "address", "type": int, "help": "register address"},
                                   {"name": "value", "type": int, "help": "value"}],
                          "help": "write one holding register"},
        },
    },
    "bacnet": {
        "module": "exploit/bacnet_write",
        "port": 47808,
        "help": "BACnet/IP devices",
        "verbs": {
            "discover": {"help": "Who-Is the segment"},
            "read": {"set": {"ACTION": "read"}, "args": [{"name": "--object", "dest": "OBJECT", "default": "1,1003", "help": "type,instance"}],
                     "help": "read a property"},
            "write": {"set": {"ACTION": "write"},
                      "args": [{"name": "--object", "dest": "OBJECT", "default": "1,1003", "help": "type,instance"},
                               {"name": "--value", "dest": "VALUE", "default": "0", "help": "value"}],
                      "help": "write a property", "undo": "write the previous value"},
        },
    },
    "snmp": {
        "module": "exploit/snmp_enum",
        "port": 161,
        "help": "SNMP agents",
        "verbs": {
            "spray": {"set": {"ACTION": "spray"}, "help": "try common community strings"},
            "walk": {"set": {"ACTION": "walk"}, "args": [{"name": "--community", "dest": "COMMUNITY", "default": "public", "help": "community"}],
                     "help": "walk the OID tree"},
        },
    },
    "switch": {
        "module": "exploit/switch_audit",
        "port": 80,
        "help": "Managed switches (info leak, default logins, port control)",
        "verbs": {
            "info": {"set": {"ACTION": "info"},
                     "args": [{"name": "--http-port", "dest": "PORT", "type": int, "default": 80, "help": "HTTP port"}],
                     "help": "unauthenticated identity + firmware"},
            "ports": {"set": {"ACTION": "ports"},
                      "args": [{"name": "--http-port", "dest": "PORT", "type": int, "default": 80, "help": "HTTP port"}],
                      "help": "port state and counters without auth"},
            "login": {"set": {"ACTION": "login"},
                      "args": [{"name": "--user", "dest": "USER", "default": "", "help": "username"},
                               {"name": "--password", "dest": "PASSWORD", "default": "", "help": "password"}],
                      "help": "try default credentials"},
            "set": {"set": {"ACTION": "set"},
                    "args": [{"name": "port_id", "type": int, "help": "port number"},
                             {"name": "--state", "dest": "PORT_STATE", "default": "off", "choices": ["on", "off"],
                              "help": "port state"},
                             {"name": "--user", "dest": "USER", "default": "", "help": "username"},
                             {"name": "--password", "dest": "PASSWORD", "default": "", "help": "password"}],
                    "help": "enable or disable a port"},
        },
    },
    "opcua": {
        "module": "exploit/opcua_browse",
        "port": 4840,
        "help": "OPC UA servers",
        "verbs": {
            "endpoints": {"help": "list endpoints and security policies"},
            "browse": {"set": {"ACTION": "browse"}, "args": [{"name": "--node", "dest": "NODE", "default": "0,85", "help": "ns,id"}],
                       "help": "browse a node anonymously"},
            "read": {"set": {"ACTION": "read"}, "args": [{"name": "--node", "dest": "NODE", "default": "0,85", "help": "ns,id"}],
                     "help": "read a node anonymously"},
        },
    },
    "tftp": {
        "module": "exploit/tftp_pull",
        "port": 69,
        "help": "TFTP servers",
        "verbs": {
            "list": {"help": "try common config and firmware filenames"},
            "pull": {"set": {"ACTION": "pull"}, "args": [{"name": "--file", "dest": "FILE", "default": "", "help": "filename"}],
                     "help": "fetch one file"},
        },
    },
    "ftp": {
        "module": "exploit/ftp_anon",
        "port": 21,
        "help": "FTP servers",
        "verbs": {
            "login": {"help": "try anonymous login"},
            "list": {"set": {"ACTION": "list"}, "args": [{"name": "--pasv-port", "dest": "PASV_PORT", "type": int, "default": 0, "help": "relay port for the data channel"}],
                     "help": "list the directory"},
            "pull": {"set": {"ACTION": "pull"},
                     "args": [{"name": "--file", "dest": "FILE", "default": "", "help": "filename"},
                              {"name": "--pasv-port", "dest": "PASV_PORT", "type": int, "default": 0, "help": "relay port for the data channel"}],
                     "help": "fetch a file"},
        },
    },
    "camera": {
        "module": "exploit/camera_capture",
        "port": 80,
        "help": "IP cameras (snapshot, RTSP, ONVIF)",
        "verbs": {
            "snapshot": {"set": {"ACTION": "snapshot"},
                         "args": [{"name": "--http-port", "dest": "HTTP_PORT", "type": int, "default": 80, "help": "HTTP port"}],
                         "help": "pull a JPEG"},
            "profiles": {"set": {"ACTION": "profiles"},
                         "args": [{"name": "--http-port", "dest": "HTTP_PORT", "type": int, "default": 80, "help": "HTTP port"}],
                         "help": "enumerate ONVIF profiles"},
            "describe": {"set": {"ACTION": "describe"},
                         "args": [{"name": "--rtsp-port", "dest": "RTSP_PORT", "type": int, "default": 554, "help": "RTSP port"}],
                         "help": "RTSP DESCRIBE"},
            "record": {"set": {"ACTION": "stream"},
                       "args": [{"name": "--rtsp-port", "dest": "RTSP_PORT", "type": int, "default": 554, "help": "RTSP port"},
                                {"name": "--seconds", "dest": "SECONDS", "type": int, "default": 10, "help": "duration"}],
                       "help": "record the stream"},
            "ptz": {"set": {"ACTION": "ptz"},
                    "args": [{"name": "command", "dest": "PTZ_COMMAND", "help": "up, down, left, right, stop"},
                             {"name": "--speed", "dest": "PTZ_SPEED", "default": "6", "help": "1-10"},
                             {"name": "--seconds", "dest": "PTZ_SECONDS", "default": "1.5", "help": "hold time"},
                             {"name": "--onvif-port", "dest": "ONVIF_PORT", "default": "", "help": "ONVIF port (blank = probe)"}],
                    "help": "move it (ONVIF PTZ)"},
        },
    },
    "jooan": {
        "module": "exploit/goform_camera",
        "port": 443,
        "help": "goform-API cameras (JOOAN/QAIOT): md5 login oracle, stream, PTZ",
        "verbs": {
            "info": {"set": {"ACTION": "info"},
                     "args": [{"name": "--scheme", "dest": "SCHEME", "default": "https", "choices": ["https", "http"],
                               "help": "https first, the http CGI wedges"},
                              {"name": "--http-port", "dest": "HTTP_PORT", "type": int, "default": 443, "help": "CGI port"}],
                     "help": "device identity and firmware"},
            "login": {"set": {"ACTION": "login"},
                      "args": [{"name": "--user", "dest": "USER", "default": "", "help": "username"},
                               {"name": "--password", "dest": "PASSWORD", "default": "", "help": "password"}],
                      "help": "spray the md5 login oracle"},
            "snapshot": {"set": {"ACTION": "snapshot"},
                         "args": [{"name": "--rtsp-port", "dest": "RTSP_PORT", "type": int, "default": 554, "help": "RTSP port"},
                                  {"name": "--rtsp-path", "dest": "RTSP_PATH", "default": "", "help": "stream path (blank = probe)"}],
                         "help": "pull a JPEG off the stream"},
            "ptz": {"set": {"ACTION": "ptz"},
                    "args": [{"name": "command", "dest": "PTZ_COMMAND", "help": "up, down, left, right, stop"},
                             {"name": "--speed", "dest": "PTZ_SPEED", "default": "5", "help": "speed"},
                             {"name": "--endpoint", "dest": "PTZ_ENDPOINT", "default": "", "help": "endpoint name (blank = discover)"}],
                    "help": "move the camera"},
        },
    },
    "upnp": {
        "module": "exploit/upnp_portmap",
        "port": 5000,
        "help": "UPnP IGD routers",
        "verbs": {
            "scan": {"set": {"ACTION": "ip"}, "args": [{"name": "--control-url", "dest": "CONTROL_URL", "default": "", "help": "descriptor URL (skips SSDP, needed behind a relay)"}],
                     "help": "find the IGD and read the WAN address"},
            "list": {"set": {"ACTION": "list"}, "help": "list existing port mappings"},
            "add": {"set": {"ACTION": "add"}, "help": "add a port mapping", "undo": "delete"},
            "delete": {"set": {"ACTION": "delete"}, "help": "delete a port mapping"},
        },
    },
    "tr069": {
        "module": "exploit/tr069_exploit",
        "port": 7547,
        "help": "TR-069/CWMP CPEs",
        "verbs": {
            "dump": {"set": {"ACTION": "dump"}, "help": "dump parameters, including secrets"},
            "set": {"set": {"ACTION": "set"}, "help": "SetParameterValues"},
        },
    },
    "jwt": {
        "module": "exploit/jwt_forge",
        "port": 8080,
        "help": "JWT-protected cloud APIs",
        "verbs": {
            "forge": {"args": [{"name": "--path", "dest": "PATH", "default": "/api/v1/device", "help": "protected path"},
                               {"name": "--subject", "dest": "SUBJECT", "default": "admin@lab", "help": "subject to claim"}],
                      "help": "try alg:none and a bad signature"},
        },
    },
    "ws": {
        "module": "exploit/ws_hijack",
        "port": 8080,
        "help": "WebSocket control channels",
        "verbs": {
            "hijack": {"args": [{"name": "--path", "dest": "PATH", "default": "/ws", "help": "WebSocket path"},
                                {"name": "--origin", "dest": "ORIGIN", "default": "http://evil.example", "help": "foreign origin"}],
                       "help": "handshake from a foreign origin"},
        },
    },
    "dns": {
        "module": "exploit/dns_rebind",
        "port": 80,
        "help": "Admin panels and DNS rebinding",
        "verbs": {
            "rebind": {"args": [{"name": "--path", "dest": "PATH", "default": "/admin", "help": "admin path"},
                                {"name": "--host", "dest": "HOST", "default": "rebind.evil.example", "help": "spoofed Host"}],
                       "help": "test Host-header trust"},
        },
    },
    "cgi": {
        "module": "exploit/cgi_inject",
        "port": 80,
        "help": "Embedded CGI handlers",
        "verbs": {
            "inject": {"args": [{"name": "--path", "dest": "PATH", "default": "/cgi-bin/status.cgi", "help": "CGI path"},
                                {"name": "--param", "dest": "PARAM", "default": "host", "help": "parameter to inject"}],
                       "help": "test shell injection"},
        },
    },
    "fw": {
        "module": "exploit/fw_upload",
        "port": 80,
        "help": "Firmware update endpoints",
        "verbs": {
            "upload": {"args": [{"name": "--path", "dest": "PATH", "default": "/upload", "help": "endpoint"},
                                {"name": "--file", "dest": "FILE", "default": "", "help": "image file"}],
                       "help": "upload an image"},
            "fetch": {"set": {"MODE": "url"}, "args": [{"name": "--url", "dest": "FW_URL", "default": "", "help": "firmware URL"}],
                      "help": "make the device fetch a URL"},
        },
    },
    "spray": {
        "module": "exploit/cred_spray",
        "port": 80,
        "help": "Credential spraying",
        "verbs": {
            "run": {"args": [
                {"name": "--basic", "dest": "PROTOCOL", "type": "const", "const": "http-basic", "help": "HTTP Basic"},
                {"name": "--digest", "dest": "PROTOCOL", "type": "const", "const": "http-digest", "help": "HTTP Digest"},
                {"name": "--form", "dest": "PROTOCOL", "type": "const", "const": "http-form", "help": "HTML form"},
                {"name": "--rtsp", "dest": "PROTOCOL", "type": "const", "const": "rtsp", "help": "RTSP"},
                {"name": "--mqtt", "dest": "PROTOCOL", "type": "const", "const": "mqtt", "help": "MQTT"},
                {"name": "--onvif", "dest": "PROTOCOL", "type": "const", "const": "onvif", "help": "ONVIF"},
                {"name": "--tr069", "dest": "PROTOCOL", "type": "const", "const": "tr069", "help": "TR-069"},
                {"name": "--path", "dest": "PATH", "default": "", "help": "protected path"},
                {"name": "--max", "dest": "MAX_ATTEMPTS", "type": int, "default": 60, "help": "attempt cap"},
                {"name": "--threads", "dest": "THREADS", "type": int, "default": CFG.get("threads", 1), "help": "parallel attempts"},
            ], "help": "spray a service"},
        },
    },
    "scan": {
        "module": "discovery/auto_detect",
        "port": 0,
        "help": "Discovery",
        "verbs": {
            "run": {"help": "sweep a subnet (address is a CIDR)"},
        },
    },
}


# ---------------------------------------------------------------------------
# builder
# ---------------------------------------------------------------------------

def _add_arg(parser, spec: dict) -> None:
    name = spec["name"]
    optional = name.startswith("-")
    kwargs: Dict[str, Any] = {"help": spec.get("help", "")}
    if optional and "dest" in spec:
        kwargs["dest"] = spec["dest"]
    elif not optional and name == "command":
        # argparse derives a positional's dest from its name, and "command" is
        # already taken by the top-level subparser dest - it would be clobbered.
        name = "command_value"
        kwargs["metavar"] = "command"
    if "nargs" in spec:
        kwargs["nargs"] = spec["nargs"]
    if "default" in spec:
        kwargs["default"] = spec["default"]

    kind = spec.get("type")
    if kind == "true":
        kwargs["action"] = "store_true"
        kwargs["default"] = False
    elif kind == "false":
        kwargs["action"] = "store_false"
        kwargs["default"] = True
    elif kind == "duration":
        kwargs["type"] = duration
    elif kind == "const":
        kwargs["action"] = "store_const"
        kwargs["const"] = spec["const"]
    elif kind == "address":
        kwargs["type"] = address
    elif kind in (int, float):
        kwargs["type"] = kind
    parser.add_argument(name, **kwargs)


def load_config() -> Dict[str, Any]:
    """Reads .iotflux.toml from the working directory, if present."""
    import pathlib
    path = pathlib.Path(".iotflux.toml")
    if not path.exists():
        return {}
    try:
        import tomllib
    except ImportError:
        return {}
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except Exception as exc:
        logger.warning(f"Could not read .iotflux.toml: {exc}")
        return {}


def build(subparsers) -> None:
    """Registers every family and verb on the top-level subparser set."""
    global CFG
    CFG = load_config()
    subparsers.add_parser("ls", help="List device families and their verbs")

    comp = subparsers.add_parser("completion", help="Print a bash completion script")
    comp.add_argument("shell", nargs="?", default="bash", choices=["bash"])

    for family, spec in FAMILIES.items():
        fam = subparsers.add_parser(family, help=spec["help"], description=spec["help"])
        verbs = fam.add_subparsers(dest="verb", metavar="<verb>")
        for verb, vspec in spec["verbs"].items():
            vp = verbs.add_parser(verb, help=vspec.get("help", ""), description=vspec.get("help", ""))
            vp.add_argument("target", nargs="?", help="host[:port]")
            vp.add_argument("--json", action="store_true", help="machine-readable output")
            vp.add_argument("--quiet", "-q", action="store_true", help="verdict line only")
            vp.add_argument("--dry-run", action="store_true", help="resolve and print, do not run")
            vp.add_argument("--timeout", type=float, default=CFG.get("timeout"), help="socket timeout")
            vp.add_argument("--opt", action="append", default=[], metavar="KEY=VALUE",
                            help="raw module option (escape hatch)")
            for arg in vspec.get("args", []):
                _add_arg(vp, arg)


def reorder(argv: List[str]) -> List[str]:
    """`<family> <address> <verb> ...` -> `<family> <verb> <address> ...`.

    argparse cannot take a positional before a subparser, so the address is
    moved behind the verb before parsing.
    """
    if len(argv) < 3 or argv[0] not in FAMILIES:
        return argv
    family, maybe_addr = argv[0], argv[1]
    verbs = FAMILIES[family]["verbs"]
    if maybe_addr.startswith("-") or maybe_addr in verbs:
        return argv
    if len(verbs) == 1:
        # single-verb family: `spray <addr> --digest` -> `spray run <addr> --digest`
        verb = next(iter(verbs))
        rest = argv[2:]
        if rest and rest[0] == verb:
            return [family, verb, maybe_addr] + rest[1:]
        return [family, verb, maybe_addr] + rest
    if argv[2] not in verbs:
        return argv
    return [family, argv[2], maybe_addr] + argv[3:]


def list_families() -> str:
    out = []
    for family, spec in FAMILIES.items():
        verbs = ", ".join(spec["verbs"])
        out.append(f"  {family:<10} {spec['help']}\n             verbs: {verbs}")
    return "\n".join(out)


def completion_script() -> str:
    words = " ".join(FAMILIES)
    lines = [f"complete -W '{words} ls completion creds run validate' iotflux"]
    for family, spec in FAMILIES.items():
        verbs = " ".join(spec["verbs"])
        lines.append(f"complete -W '{verbs}' 'iotflux {family}'")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------

def resolve(args) -> tuple:
    """Returns (module_name, options dict, target, port)."""
    spec = FAMILIES[args.family]
    vspec = spec["verbs"][args.verb]
    module = vspec.get("module", spec["module"])

    options: Dict[str, Any] = {}
    options.update(vspec.get("set", {}))
    options.update(vspec.get("set_extra", {}))

    for arg in vspec.get("args", []):
        dest = arg.get("dest") or arg["name"].lstrip("-").replace("-", "_")
        attr = dest
        if not arg["name"].startswith("-") and arg["name"] == "command":
            attr = "command_value"
        if not hasattr(args, attr):
            continue
        value = getattr(args, attr)
        if value is None or value == "":
            continue
        options[dest.upper()] = value

    target = getattr(args, "target", "") or ""
    port = spec["port"]
    if target:
        host, port = split_address(target, spec["port"])
        target = host
    return module, options, target, port


def run(args, session) -> int:
    """Executes a family/verb command. Returns a process exit code."""
    import contextlib
    import io

    from iotflux.core.cli import FluxConsole
    from iotflux.modules import get_module

    module, options, target, port = resolve(args)

    if getattr(args, "dry_run", False):
        print(f"[dry-run] {args.family} {args.verb} -> module={module} target={target or '-'} port={port} opts={options}")
        return 0

    quiet = bool(getattr(args, "quiet", False) or getattr(args, "json", False))
    sink = contextlib.redirect_stdout(io.StringIO()) if quiet else contextlib.nullcontext()

    with sink:
        try:
            mod = get_module(module)
        except KeyError as exc:
            logger.failure(str(exc))
            return 1

        if target:
            session.set_option("TARGET", target)
            if "TARGET" in mod.module_options:
                mod.set_option("TARGET", target)
            if "SUBNET" in mod.module_options:
                mod.set_option("SUBNET", target)
        if port:
            session.set_option("PORT", port)
            if "PORT" in mod.module_options:
                mod.set_option("PORT", port)

        for key, value in options.items():
            if key in mod.module_options:
                mod.set_option(key, value)
            elif key in session.options:
                session.set_option(key, value)
            else:
                logger.warning(f"'{key}' is not an option of {module}")

        for assignment in getattr(args, "opt", []) or []:
            if "=" not in assignment:
                logger.warning(f"Ignoring malformed --opt '{assignment}'")
                continue
            key, _, val = assignment.partition("=")
            key = key.strip().upper()
            if key in mod.module_options:
                mod.set_option(key, val)
            elif key in session.options:
                session.set_option(key, val)
            else:
                logger.warning(f"Unknown option '{key}' for {module}")

        if getattr(args, "timeout", None):
            session.set_option("TIMEOUT", args.timeout)

        console = FluxConsole(sess=session)
        console.active_module = mod
        console.run_active_module()

    findings = getattr(mod, "findings", []) or []
    if getattr(args, "json", False):
        print(json.dumps([f.to_dict() for f in findings], indent=2, default=str))
    else:
        mark = "x" if findings and all("FAIL" in f.finding_id or "NO-" in f.finding_id for f in findings) else "+"
        ids = ", ".join(f.finding_id for f in findings[:4]) or "no findings"
        print(f"[{mark}] {args.family} {args.verb} {target or '-'}:{port} -> {ids}")

    undo = FAMILIES[args.family]["verbs"][args.verb].get("undo")
    if undo and not quiet:
        print(f"    undo: iotflux {args.family} {args.target or ''} {undo}".replace("  ", " "))

    return 0
