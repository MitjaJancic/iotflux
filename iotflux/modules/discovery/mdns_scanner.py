"""
mdns_scanner.py - Read-only mDNS and UPnP service discovery module
Authorized Defensive Security Validation Lab (IoTFlux)
"""

from __future__ import annotations

import socket
import xml.etree.ElementTree as ET
from typing import Any, Dict, List
import requests

from iotflux.core.logger import logger
from iotflux.core.session import FluxSession
from iotflux.modules.base import BaseValidationModule, ValidationFinding


class MdnsScanner(BaseValidationModule):
    name = "discovery/mdns_scanner"
    description = "Read-only enumeration of mDNS advertisements and UPnP XML device descriptions."
    tier = "Tier 1 - Edge & Multi-Zone Discovery"
    references = ["RFC-2326-RTSP", "CWE-200", "CAPEC-118"]

    def __init__(self) -> None:
        super().__init__()
        self.register_option("TARGET", "172.30.1.25", "Target host to inspect for UPnP / mDNS data")
        self.register_option("UPNP_PORT", 8080, "UPnP XML description service port")
        self.register_option("PATH", "/description.xml", "UPnP device description path")

    def run(self, session: FluxSession) -> List[ValidationFinding]:
        self.findings.clear()
        target = self.get_option("TARGET", session)
        port = int(self.get_option("UPNP_PORT") or 8080)
        path = self.get_option("PATH") or "/description.xml"
        timeout = float(session.get_option("TIMEOUT", 3.0))

        logger.info(f"Auditing UPnP / mDNS exposure on {target}:{port}{path}...")
        url = f"http://{target}:{port}{path}"

        try:
            res = requests.get(url, timeout=timeout)
            if res.status_code == 200 and "xml" in res.headers.get("Content-Type", ""):
                try:
                    root = ET.fromstring(res.text)
                    ns = {"ns": "urn:schemas-upnp-org:device-1-0"}
                    friendly_name = root.find(".//ns:friendlyName", ns)
                    model_name = root.find(".//ns:modelName", ns)
                    fname = friendly_name.text if friendly_name is not None else "Unknown"
                    mname = model_name.text if model_name is not None else "Unknown"

                    self.add_finding(
                        finding_id="DISC-UPNP-INFO",
                        target=f"{target}:{port}",
                        title="Exposed UPnP Root Device Description",
                        spec_id="CWE-200",
                        cwe="CWE-200",
                        status="INFORMATIONAL",
                        details=f"Discovered UPnP Media Renderer: friendly_name='{fname}', model='{mname}'",
                        remediation="Disable SSDP/UPnP broadcast on untrusted network segments if local media rendering is unused.",
                        evidence={"friendly_name": fname, "model_name": mname, "xml_len": len(res.text)},
                    )
                except ET.ParseError:
                    pass
        except Exception as ex:
            logger.info(f"UPnP endpoint query note on {target}:{port}: {ex}")

        # Also inspect .well-known mDNS simulation endpoint (e.g. ambient lights)
        mdns_url = f"http://{target}:80/.well-known/mdns-info"
        try:
            r = requests.get(mdns_url, timeout=timeout)
            if r.status_code == 200:
                data = r.json()
                self.add_finding(
                    finding_id="DISC-MDNS-LEAK",
                    target=f"{target}:80",
                    title="mDNS Service Parameter Disclosure",
                    spec_id="CWE-200",
                    cwe="CWE-200",
                    status="NON_COMPLIANT",
                    details=f"Device advertises internal TXT records: {data.get('txt_record', {})}",
                    remediation="Sanitize mDNS TXT records to omit firmware versions and default configuration tokens.",
                    evidence=data,
                )
        except Exception:
            pass

        return self.findings
