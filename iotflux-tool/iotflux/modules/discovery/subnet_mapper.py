"""
subnet_mapper.py - Multi-zone subnet mapper and service correlator
Authorized Defensive Security Validation Lab (IoTFlux)
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any, Dict, List
from iotflux.core.logger import logger
from iotflux.core.session import FluxSession
from iotflux.modules.base import BaseValidationModule, ValidationFinding


class SubnetMapper(BaseValidationModule):
    name = "discovery/subnet_mapper"
    description = "Room-by-room subnet mapper parsing HTTP (80/8080), MQTT (1883), and RTSP (554)."
    tier = "Multi-Zone Discovery & Inventory"
    references = ["CWE-200", "CAPEC-118"]

    AUDITED_PORTS = [80, 554, 1883, 8080]

    KNOWN_PROFILES = {
        (80,): "Shelly Gen 2 Relay / Smart Controller",
        (8080,): "Media Streamer / Smart Appliance / Camera Portal",
        (1883,): "Mosquitto Central MQTT Message Broker",
        (554, 8080): "Video Doorbell (RTSP Media Stream + HTTP Portal)",
        (80, 1883): "Shelly Relay with MQTT Bridge",
    }

    def __init__(self) -> None:
        super().__init__()
        self.register_option("SUBNET", "172.30.1.0/24", "Target subnet CIDR or IP list to scan")
        self.register_option("MAX_HOSTS", 32, "Maximum number of hosts to probe in range")

    def _check_port(self, host: str, port: int, timeout: float) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            res = sock.connect_ex((host, port))
            return res == 0
        except Exception:
            return False
        finally:
            sock.close()

    def run(self, session: FluxSession) -> List[ValidationFinding]:
        self.findings.clear()
        subnet_val = self.get_option("SUBNET", session)
        timeout = float(session.get_option("TIMEOUT", 1.0))
        max_hosts = int(self.get_option("MAX_HOSTS") or 32)

        # Parse hosts
        hosts: List[str] = []
        try:
            if "/" in str(subnet_val):
                net = ipaddress.ip_network(subnet_val, strict=False)
                for h in net.hosts():
                    hosts.append(str(h))
                    if len(hosts) >= max_hosts:
                        break
            else:
                hosts = [h.strip() for h in str(subnet_val).split(",") if h.strip()]
        except Exception as ex:
            logger.failure(f"Invalid SUBNET parameter '{subnet_val}': {ex}")
            return self.findings

        logger.info(f"Scanning {len(hosts)} host(s) across ports {self.AUDITED_PORTS}...")

        discovered_count = 0
        for host in hosts:
            open_ports: List[int] = []
            for p in self.AUDITED_PORTS:
                if self._check_port(host, p, timeout=timeout):
                    open_ports.append(p)

            if open_ports:
                discovered_count += 1
                ports_tuple = tuple(sorted(open_ports))
                profile = self.KNOWN_PROFILES.get(ports_tuple, "Generic Network IoT Node")

                # Infer zone tier from IP subnet
                tier_label = "Unassigned"
                if host.startswith("172.30.1."):
                    tier_label = "Tier 1: Living Room (Edge)"
                elif host.startswith("172.30.2."):
                    tier_label = "Tier 2: Kitchen & Utility (Operational Core)"
                elif host.startswith("172.30.3."):
                    tier_label = "Tier 2: Hallway & Bedrooms (Safety Systems)"
                elif host.startswith("172.30.4."):
                    tier_label = "Tier 3: Garage & Perimeter (Perimeter Access)"

                self.add_finding(
                    finding_id="DISC-NODE-ACTIVE",
                    target=host,
                    title=f"Active IoT Device Identified: {profile}",
                    spec_id="CWE-200",
                    cwe="CWE-200",
                    status="INFORMATIONAL",
                    details=f"Host is active in {tier_label}. Open ports: {open_ports}. Correlated profile: {profile}",
                    remediation="Apply network segmentation and access control lists (ACLs) per security tier.",
                    evidence={"host": host, "open_ports": open_ports, "tier": tier_label, "profile": profile},
                )

        logger.success(f"Subnet mapping complete. Discovered {discovered_count} active device(s).")
        return self.findings
