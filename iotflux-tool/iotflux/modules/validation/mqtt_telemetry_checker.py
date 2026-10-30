"""
mqtt_telemetry_checker.py - MQTT telemetry integrity and cleartext exposure auditor
Authorized Defensive Security Validation Lab (IoTFlux)
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None

from iotflux.core.logger import logger
from iotflux.core.session import FluxSession
from iotflux.modules.base import BaseValidationModule, ValidationFinding


class MqttTelemetryChecker(BaseValidationModule):
    name = "validation/mqtt_telemetry_checker"
    description = "Checks anonymous MQTT broker access, maps wildcard (#) topic namespaces, and flags cleartext telemetry."
    tier = "Tier 2 - Operational Core & Telemetry Backbone"
    references = ["MQTT-5.0-SEC", "CWE-306", "CWE-319", "CAPEC-116"]

    SENSITIVE_FIELD_NAMES = {
        "password", "secret", "token", "key", "door_open", "lock_state",
        "smoke_detected", "pin", "alert", "cleartext_flag", "user",
    }

    def __init__(self) -> None:
        super().__init__()
        self.register_option("BROKER", "172.30.2.10", "MQTT message broker IP address")
        self.register_option("PORT", 1883, "MQTT message broker port")
        self.register_option("DURATION", 3.0, "Wildcard sampling duration in seconds")

    def run(self, session: FluxSession) -> List[ValidationFinding]:
        self.findings.clear()
        if mqtt is None:
            logger.failure("paho-mqtt library is not installed. Module cannot proceed.")
            return self.findings

        broker = self.get_option("BROKER", session) or "172.30.2.10"
        port = int(self.get_option("PORT", session) or 1883)
        sample_duration = float(self.get_option("DURATION") or 3.0)

        logger.info(f"Auditing MQTT broker access posture on {broker}:{port}...")

        captured_messages: List[Dict[str, Any]] = []
        connection_status = {"connected": False, "connack_rc": -1}

        def on_connect(client, userdata, flags, rc):
            connection_status["connected"] = (rc == 0)
            connection_status["connack_rc"] = rc
            if rc == 0:
                client.subscribe("#", qos=0)
                client.subscribe("$SYS/#", qos=0)

        def on_message(client, userdata, msg):
            try:
                payload_str = msg.payload.decode("utf-8", errors="replace")
                try:
                    payload_json = json.loads(payload_str)
                except Exception:
                    payload_json = None
                captured_messages.append({
                    "topic": msg.topic,
                    "payload_raw": payload_str[:128],
                    "payload_json": payload_json,
                    "retained": msg.retain,
                })
            except Exception:
                pass

        try:
            try:
                client = mqtt.Client(
                    callback_api_version=mqtt.CallbackAPIVersion.VERSION1,
                    client_id="iotflux_telemetry_auditor",
                )
            except AttributeError:
                client = mqtt.Client(client_id="iotflux_telemetry_auditor")

            client.on_connect = on_connect
            client.on_message = on_message
            client.connect(broker, port, keepalive=10)
            client.loop_start()

            # Sample for configured duration
            time.sleep(sample_duration)
            client.loop_stop()
            client.disconnect()
        except Exception as ex:
            logger.warning(f"Could not connect to MQTT broker {broker}:{port}: {ex}")
            return self.findings

        # 1. Anonymous Access Finding
        if connection_status["connected"]:
            self.add_finding(
                finding_id="MQTT-ANONYMOUS-ACCESS",
                target=f"{broker}:{port}",
                title="Anonymous MQTT Broker Authentication Permitted",
                spec_id="MQTT-5.0-SEC",
                cwe="CWE-306",
                status="NON_COMPLIANT",
                details=(
                    f"Broker accepted unauthenticated CONNECT packet without credentials (CONNACK rc=0). "
                    "All connected residential clients share an unpartitioned message bus."
                ),
                remediation="Configure 'allow_anonymous false' and require per-client username/password or X.509 client certificate authentication.",
                evidence={"connack_rc": connection_status["connack_rc"], "broker": broker},
            )
        else:
            self.add_finding(
                finding_id="MQTT-AUTH-REQUIRED",
                target=f"{broker}:{port}",
                title="MQTT Broker Authentication Enforced",
                spec_id="MQTT-5.0-SEC",
                cwe="CWE-306",
                status="COMPLIANT",
                details="Broker rejected anonymous connection attempt.",
                remediation="Maintain credential rotation policies.",
            )

        # 2. Wildcard Topic Exposure & Cleartext Telemetry Analysis
        if captured_messages:
            sensitive_topics: List[str] = []
            flagged_keys: List[str] = []

            for m in captured_messages:
                pj = m.get("payload_json")
                if isinstance(pj, dict):
                    for k in pj.keys():
                        if k.lower() in self.SENSITIVE_FIELD_NAMES:
                            flagged_keys.append(k)
                            sensitive_topics.append(m["topic"])

            distinct_topics = list(set(m["topic"] for m in captured_messages))
            logger.info(f"Captured {len(captured_messages)} message(s) across {len(distinct_topics)} unique topic(s).")

            if sensitive_topics:
                self.add_finding(
                    finding_id="MQTT-CLEARTEXT-TELEMETRY",
                    target=f"{broker}:{port}",
                    title="Cleartext Sensor & State Telemetry Disclosed Over Wildcard (#)",
                    spec_id="MQTT-5.0-SEC",
                    cwe="CWE-319",
                    status="NON_COMPLIANT",
                    details=(
                        f"Subscribed wildcard (#) captured {len(distinct_topics)} topics. "
                        f"Identified cleartext operational keys: {list(set(flagged_keys))} "
                        f"across sensitive topics: {list(set(sensitive_topics))}."
                    ),
                    remediation="Encrypt telemetry payloads at application layer or mandate TLS encryption (MQTTS port 8883) with topic-level ACL restrictions.",
                    evidence={
                        "total_captured": len(captured_messages),
                        "unique_topics": distinct_topics,
                        "flagged_keys": list(set(flagged_keys)),
                    },
                )
            else:
                self.add_finding(
                    finding_id="MQTT-TOPIC-EXPOSURE",
                    target=f"{broker}:{port}",
                    title="MQTT Wildcard Topic Mapping Completed",
                    spec_id="MQTT-5.0-SEC",
                    cwe="CWE-200",
                    status="INFORMATIONAL",
                    details=f"Captured {len(distinct_topics)} topics via wildcard enumeration.",
                    remediation="Apply topic-level Access Control Lists (ACLs) to prevent wildcard subscription across security zones.",
                    evidence={"topics": distinct_topics},
                )

        return self.findings
