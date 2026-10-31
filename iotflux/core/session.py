"""
session.py - Global session management and options configuration for IoTFlux

Real-world posture: state-changing operations are enabled by default. The
`--authorize` flag is retained as a compatibility switch and only additionally
relaxes the (now advisory) scope gate.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from .logger import Colors, logger


class FluxSession:
    """Manages active session context, target parameters, and execution options."""

    def __init__(self) -> None:
        self.options: Dict[str, Any] = {
            "TARGET": "127.0.0.1",
            "PORT": 80,
            "SUBNET": "172.30.0.0/16",
            "TIMEOUT": 3.0,
            # Exploit-by-default: state changes are always permitted.
            "AUTHORIZED_TEST": True,
            "AUTHORIZE": True,
            "REQUIRE_CREDS": False,
            "DEVICE_ID": "",
            "OUTPUT_FORMAT": "text",
            "EVIDENCE_DIR": "evidence/iotflux",
            "MQTT_BROKER": "172.30.2.10",
            "MQTT_PORT": 1883,
            # Revert behaviour: no automatic restoration unless requested.
            "AUTO_REVERT": False,
            "PULSE_DURATION": 1.0,
        }
        self.active_module_name: Optional[str] = None
        self.history: list[str] = []

    def set_option(self, key: str, value: Any) -> None:
        k = key.upper()
        if k in ("PORT", "MQTT_PORT"):
            try:
                self.options[k] = int(value)
            except ValueError:
                logger.failure(f"Invalid integer value for {k}: {value}")
                return
        elif k in ("TIMEOUT", "PULSE_DURATION"):
            try:
                self.options[k] = float(value)
            except ValueError:
                logger.failure(f"Invalid float value for {k}: {value}")
                return
        elif k in ("AUTHORIZED_TEST", "AUTHORIZE", "REQUIRE_CREDS", "AUTO_REVERT"):
            v = str(value).strip().lower()
            self.options[k] = v in ("true", "1", "yes", "on")
        else:
            self.options[k] = value
        logger.success(f"{k} => {self.options[k]}")

    def get_option(self, key: str, default: Any = None) -> Any:
        return self.options.get(key.upper(), default)

    def show_options(self) -> None:
        logger.header("GLOBAL CONFIGURATION")
        print(f" {'Option':<20} {'Current Value':<30} {'Description'}")
        print(f" {'-'*20} {'-'*30} {'-'*24}")
        descriptions = {
            "TARGET": "Target host IP or domain for single-endpoint modules",
            "PORT": "Primary destination service port",
            "SUBNET": "Subnet range for network mapping and multi-zone discovery",
            "TIMEOUT": "Socket and HTTP probe network timeout (seconds)",
            "AUTHORIZED_TEST": "State-change gate (always on; kept for compatibility)",
            "AUTHORIZE": "Legacy operator unlock (scope is advisory)",
            "OUTPUT_FORMAT": "Console report format ('text' or 'json')",
            "EVIDENCE_DIR": "Directory path where audit evidence is persisted",
            "MQTT_BROKER": "Central Mosquitto broker IP for telemetry modules",
            "MQTT_PORT": "Central Mosquitto broker port",
            "AUTO_REVERT": "Restore pre-change state after perturbation (default: off)",
            "PULSE_DURATION": "Seconds to hold a perturbation before returning",
        }
        for k, v in sorted(self.options.items()):
            desc = descriptions.get(k, "Configuration parameter")
            print(f" {k:<20} {str(v):<30} {desc}")
        print()


# Global singleton session instance
session = FluxSession()
