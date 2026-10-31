"""
specification.py - Public specification catalog and defensive standard references
Authorized Defensive Security Validation Lab (IoTFlux)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class SpecReference:
    spec_id: str
    title: str
    organization: str
    reference_url: str
    section: str
    defensive_guidance: str


SPEC_CATALOG: Dict[str, SpecReference] = {
    "SHELLY-RPC-2.0": SpecReference(
        spec_id="SHELLY-RPC-2.0",
        title="Shelly Gen 2 RPC Protocol Specification",
        organization="Allterco Robotics / Shelly",
        reference_url="https://shelly-api-docs.shelly.cloud/gen2/General/RPCProtocol/",
        section="Authentication & Access Control",
        defensive_guidance="Enforce digest authentication or pre-shared bearer tokens on all local RPC endpoints (auth_en: true).",
    ),
    "MQTT-5.0-SEC": SpecReference(
        spec_id="MQTT-5.0-SEC",
        title="MQTT Version 5.0 OASIS Standard",
        organization="OASIS Open",
        reference_url="https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html",
        section="Chapter 5: Security Considerations",
        defensive_guidance="Disable anonymous access; require TLS 1.3 mutual authentication (port 8883) and enforce per-topic Access Control Lists (ACLs).",
    ),
    "RFC-2326-RTSP": SpecReference(
        spec_id="RFC-2326-RTSP",
        title="Real Time Streaming Protocol (RTSP)",
        organization="IETF RFC 2326 / RFC 7826",
        reference_url="https://datatracker.ietf.org/doc/html/rfc2326",
        section="Section 12: Security Considerations",
        defensive_guidance="Authenticate streaming sessions using Digest authentication; enforce strict length boundaries on all incoming header fields.",
    ),
    "NIST-SP-800-63B": SpecReference(
        spec_id="NIST-SP-800-63B",
        title="Digital Identity Guidelines: Authentication and Lifecycle Management",
        organization="National Institute of Standards and Technology (NIST)",
        reference_url="https://pages.nist.gov/800-63-3/sp800-63b.html",
        section="Section 5.1.1: Memorized Secret Authenticators & PIN Entropy",
        defensive_guidance="PINs must be generated using an approved Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) with adequate entropy and rate limiting.",
    ),
    "CWE-306": SpecReference(
        spec_id="CWE-306",
        title="Missing Authentication for Critical Function",
        organization="MITRE CWE",
        reference_url="https://cwe.mitre.org/data/definitions/306.html",
        section="Architectural Weakness",
        defensive_guidance="Verify identity credentials before executing state transitions or reading protected operational telemetry.",
    ),
    "CWE-319": SpecReference(
        spec_id="CWE-319",
        title="Cleartext Transmission of Sensitive Information",
        organization="MITRE CWE",
        reference_url="https://cwe.mitre.org/data/definitions/319.html",
        section="Cryptographic Weakness",
        defensive_guidance="Encrypt telemetry and management channels using TLS or DTLS across all network boundaries.",
    ),
    "CWE-1284": SpecReference(
        spec_id="CWE-1284",
        title="Improper Validation of Specified Quantity in Input",
        organization="MITRE CWE",
        reference_url="https://cwe.mitre.org/data/definitions/1284.html",
        section="Input Validation",
        defensive_guidance="Implement strict range validation on all integer parameters to prevent out-of-bounds behavioral anomalies.",
    ),
    "MODBUS-TCP-SPEC": SpecReference(
        spec_id="MODBUS-TCP-SPEC",
        title="Modbus Messaging on TCP/IP Implementation Guide V1.0b",
        organization="Modbus Organization",
        reference_url="https://modbus.org/docs/Modbus_Messaging_Implementation_Guide_V1_0b.pdf",
        section="Section 4: Protocol Security & Isolation",
        defensive_guidance="Enforce network micro-segmentation, deep-packet inspection firewalls, and Modbus/TCP Security (TLS encapsulation) to prevent unauthenticated register modification.",
    ),
    "RFC-7252-COAP": SpecReference(
        spec_id="RFC-7252-COAP",
        title="Constrained Application Protocol (CoAP)",
        organization="IETF RFC 7252 / RFC 6690",
        reference_url="https://datatracker.ietf.org/doc/html/rfc7252",
        section="Section 9: Security Considerations",
        defensive_guidance="Enforce DTLS with Pre-Shared Key (PSK) or Raw Public Key (RPK) cipher suites to protect CoAP resource discovery and control verbs.",
    ),
    "ONVIF-PROFILE-S": SpecReference(
        spec_id="ONVIF-PROFILE-S",
        title="ONVIF Profile S Specification for IP-Based Video Systems",
        organization="ONVIF Standard",
        reference_url="https://www.onvif.org/profiles/profile-s/",
        section="Security & User Authentication",
        defensive_guidance="Require WS-UsernameToken with password digest authentication on all media and PTZ service requests; disable unauthenticated RTSP stream playback.",
    ),
    "CSA-MATTER-1.2": SpecReference(
        spec_id="CSA-MATTER-1.2",
        title="Matter Core Specification Version 1.2",
        organization="Connectivity Standards Alliance (CSA)",
        reference_url="https://csa-iot.org/all-solutions/matter/",
        section="Chapter 4: Commissioning & Cryptographic Identity",
        defensive_guidance="Enforce Passcode-Authenticated Session Establishment (PASE) timeouts and strict rate limiting on PBKDF challenges to prevent unauthorized commissioning attempts.",
    ),
    "BLE-MESH-SPEC": SpecReference(
        spec_id="BLE-MESH-SPEC",
        title="Bluetooth Mesh Protocol Specification",
        organization="Bluetooth SIG",
        reference_url="https://www.bluetooth.com/specifications/specs/mesh-protocol/",
        section="Section 3: Mesh Security Architecture",
        defensive_guidance="Ensure network and application keys are properly encrypted and refreshed; isolate GATT proxy endpoints from unauthenticated local networks.",
    ),
    "UPNP-IGD-WAN": SpecReference(
        spec_id="UPNP-IGD-WAN",
        title="UPnP InternetGatewayDevice (IGD) Standard",
        organization="UPnP Forum / Open Connectivity Foundation",
        reference_url="https://openconnectivity.org/developer/specifications/upnp-resources/upnp/",
        section="WANIPConnection / WANPPPConnection Security",
        defensive_guidance="Disable UPnP IGD AddPortMapping on external/WAN-facing interfaces; enforce local subscriber authentication.",
    ),
    "CWE-798": SpecReference(
        spec_id="CWE-798",
        title="Use of Hard-coded Credentials",
        organization="MITRE CWE",
        reference_url="https://cwe.mitre.org/data/definitions/798.html",
        section="Cryptographic Credential Storage",
        defensive_guidance="Store secrets and private keys in dedicated hardware security modules (HSM) or encrypted storage rather than plaintext firmware images.",
    ),
    "CWE-119": SpecReference(
        spec_id="CWE-119",
        title="Improper Restriction of Operations within the Bounds of a Memory Buffer",
        organization="MITRE CWE",
        reference_url="https://cwe.mitre.org/data/definitions/119.html",
        section="Memory Safety",
        defensive_guidance="Compile all embedded binaries with modern compiler mitigations (NX/DEP, Stack Canaries, Full RELRO, PIE/ASLR).",
    ),
}


def get_spec(spec_id: str) -> Optional[SpecReference]:
    return SPEC_CATALOG.get(spec_id)


def list_specs() -> List[SpecReference]:
    return list(SPEC_CATALOG.values())
