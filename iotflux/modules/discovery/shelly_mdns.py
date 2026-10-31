"""
shelly_mdns.py - Discover Shelly devices over mDNS.

Shelly Gen2+ devices advertise `_shelly._tcp.local`. The advertisement carries
the device id and generation, which is enough to inventory a segment and to
target the right RPC family without touching a port scanner.
"""

from __future__ import annotations

import socket
import struct
import time
from typing import Dict, List

from iotflux.core.logger import logger
from iotflux.core.session import FluxSession
from iotflux.modules.base import BaseValidationModule, ValidationFinding


def _query(timeout: float, target: str = "", port: int = 5353) -> Dict[str, Dict[str, str]]:
    pkt = (b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
           b"\x06_shelly\x04_tcp\x05local\x00\x00\x0c\x00\x01")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    found: Dict[str, Dict[str, str]] = {}
    dests = [("224.0.0.251", port)]
    if target:
        dests.insert(0, (target, port))   # unicast mDNS works across bridges
    try:
        for dest in dests:
            sock.sendto(pkt, dest)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            txt = {}
            for key in (b"id=", b"gen=", b"app=", b"ver=", b"model="):
                i = data.find(key)
                if i == -1:
                    continue
                j = i + len(key)
                while j < len(data) and 0x20 <= data[j] < 0x7F:
                    j += 1
                txt[key[:-1].decode()] = data[i + len(key) : j].decode("utf-8", "replace")
            found.setdefault(addr[0], {}).update(txt)
    except Exception:
        pass
    finally:
        sock.close()
    return found


class ShellyMdns(BaseValidationModule):
    name = "discovery/shelly_mdns"
    description = "Discovers Shelly devices over mDNS (_shelly._tcp) with id and generation."
    tier = "Discovery - Smart Relay"
    references = ["RFC-6762", "CWE-200"]

    def __init__(self) -> None:
        super().__init__()
        self.register_option("SECONDS", 5.0, "mDNS listen window")
        self.register_option("MDNS_PORT", 5353, "mDNS UDP port (change when relaying)")

    def run(self, session: FluxSession) -> List[ValidationFinding]:
        self.findings.clear()
        secs = float(self.get_option("SECONDS") or 5.0)
        target = str(self.get_option("TARGET", session) or "")
        found = _query(secs, target, int(self.get_option("MDNS_PORT") or 5353))

        if not found:
            logger.info(f"No _shelly._tcp responders in {secs}s.")
            self.add_finding(
                finding_id="SHELLY-MDNS-NONE",
                target="224.0.0.251",
                title="No Shelly device advertised over mDNS",
                spec_id="RFC-6762",
                cwe="CWE-200",
                status="INFORMATIONAL",
                details=f"{secs}s listen produced no response.",
                remediation="Confirm mDNS is not filtered and devices are on this segment.",
            )
            return self.findings

        for ip, txt in found.items():
            logger.success(f"{ip} id={txt.get('id', '?')} gen={txt.get('gen', '?')} app={txt.get('app', '?')}")

        self.add_finding(
            finding_id="SHELLY-MDNS-FOUND",
            target=", ".join(found),
            title="Shelly devices discovered over mDNS",
            spec_id="RFC-6762",
            cwe="CWE-200",
            status="NON_COMPLIANT",
            details=f"{len(found)} device(s) advertising id and generation with no authentication.",
            remediation="Disable mDNS if unused; otherwise accept the inventory leak and secure the RPC.",
            evidence={"devices": [{"ip": ip, **txt} for ip, txt in found.items()]},
        )
        return self.findings
