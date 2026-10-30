"""
upnp_scanner.py - UPnP SSDP & IGD WAN Exposure Auditor for IoTFlux
Authorized Defensive Security Validation Lab

Audits Universal Plug and Play (UPnP) and Internet Gateway Device (IGD) services:
1. Fetches root device descriptions (rootDesc.xml).
2. Parses Service Control Point Descriptions (SCPD) for WANIPConnection and WANPPPConnection.
3. Audits advertised state-changing actions (e.g. AddPortMapping) without altering firewall state.
"""

from __future__ import annotations

import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import urljoin
from typing import Any, Dict, List, Optional, Tuple

from iotflux.core.logger import logger
from iotflux.core.session import FluxSession
from iotflux.modules.base import BaseValidationModule, ValidationFinding


def local_tag(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def find_child_text(elem: ET.Element, name: str) -> Optional[str]:
    for child in elem:
        if local_tag(child.tag) == name:
            return (child.text or "").strip() or None
    return None


def fetch_xml(url: str, timeout: float = 3.0) -> Optional[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "IoTFlux-UpnpScanner/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None


class UpnpScanner(BaseValidationModule):
    """UPnP Internet Gateway Device (IGD) & SSDP Conformance Auditor."""

    name = "discovery/upnp_scanner"
    description = "Audits UPnP IGD gateways for SCPD AddPortMapping exposure and WAN management leakage."
    tier = "Perimeter Gateways & Routers"
    references = ["UPNP-IGD-WAN", "CWE-306", "CWE-284"]
    author = "Defensive Security Research Team"

    def __init__(self) -> None:
        super().__init__()
        self.register_option("PORT", 5000, "UPnP HTTP descriptor port (default: 5000 or 1900)")
        self.register_option("PATH", "/rootDesc.xml", "Path to root XML device description")
        self.register_option("TIMEOUT", 3.0, "Socket timeout in seconds")

    def run(self, session: FluxSession) -> List[ValidationFinding]:
        self.findings.clear()
        target = self.get_option("TARGET", session)
        if not target:
            logger.failure("No target specified. Set TARGET first.")
            return self.findings

        port = int(self.get_option("PORT", session) or 5000)
        desc_path = str(self.get_option("PATH", session) or "/rootDesc.xml")
        timeout = float(self.get_option("TIMEOUT", session) or 3.0)

        root_url = f"http://{target}:{port}{desc_path}"
        logger.info(f"Auditing UPnP gateway description at: {root_url}...")

        xml_data = fetch_xml(root_url, timeout=timeout)
        if not xml_data:
            logger.info(f"Target {target}:{port} did not provide UPnP rootDesc.xml.")
            self.add_finding(
                finding_id="UPNP-SERVICE-INACTIVE",
                target=f"{target}:{port}",
                title="UPnP IGD Service Not Detected",
                spec_id="UPNP-IGD-WAN",
                cwe="CWE-306",
                status="COMPLIANT",
                details=f"Target {target}:{port} does not expose unauthenticated UPnP XML descriptions.",
                remediation="Ensure UPnP IGD remains disabled on untrusted and WAN interfaces.",
            )
            return self.findings

        # Parse services
        services: List[Dict[str, str]] = []
        try:
            tree = ET.fromstring(xml_data)
            for elem in tree.iter():
                if local_tag(elem.tag) == "service":
                    st = find_child_text(elem, "serviceType") or ""
                    scpd = find_child_text(elem, "SCPDURL") or ""
                    ctrl = find_child_text(elem, "controlURL") or ""
                    if st:
                        services.append({"serviceType": st, "scpdURL": scpd, "controlURL": ctrl})
        except Exception as ex:
            logger.warning(f"Error parsing UPnP XML: {ex}")

        wan_services = [s for s in services if "WANIPConnection" in s["serviceType"] or "WANPPPConnection" in s["serviceType"]]
        advertised_actions: List[str] = []

        for s in wan_services:
            scpd_url = urljoin(root_url, s["scpdURL"])
            scpd_xml = fetch_xml(scpd_url, timeout=timeout)
            if scpd_xml:
                try:
                    s_tree = ET.fromstring(scpd_xml)
                    for action_elem in s_tree.iter():
                        if local_tag(action_elem.tag) == "action":
                            name = find_child_text(action_elem, "name")
                            if name:
                                advertised_actions.append(name)
                except Exception:
                    pass

        has_add_port_mapping = any("AddPortMapping" in a for a in advertised_actions)

        if has_add_port_mapping:
            logger.failure(f"UPnP IGD exposes unauthenticated AddPortMapping capability!")
            self.add_finding(
                finding_id="UPNP-ADDPORTMAPPING-EXPOSED",
                target=root_url,
                title="UPnP IGD Unauthenticated AddPortMapping Advertised",
                spec_id="UPNP-IGD-WAN",
                cwe="CWE-284",
                status="CRITICAL_NON_COMPLIANT",
                details=(
                    f"Gateway at {root_url} advertises WANIPConnection with AddPortMapping action. "
                    f"Local or adjacent unauthorized hosts can punch inbound firewall holes."
                ),
                remediation="Disable UPnP IGD in gateway firmware settings or restrict port mapping to authorized admin users.",
                evidence={"services": wan_services, "actions": advertised_actions},
            )
        else:
            self.add_finding(
                finding_id="UPNP-DESCRIPTORS-COMPLIANT",
                target=root_url,
                title="UPnP IGD Exposed Without State-Changing Actions",
                spec_id="UPNP-IGD-WAN",
                cwe="CWE-306",
                status="INFORMATIONAL",
                details=f"UPnP descriptor found with {len(services)} services, but AddPortMapping was not advertised.",
                remediation="Continue maintaining strict UPnP service hardening.",
                evidence={"services": services},
            )

        return self.findings
