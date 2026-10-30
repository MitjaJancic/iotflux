"""
modules package - Central Registry of IoTFlux validation, discovery, and conformance modules
Authorized Residential IoT Protocol Conformance & Hardening Framework
"""

from typing import Dict, Type
from .base import BaseValidationModule, ValidationFinding

# Discovery modules
from .discovery.mdns_scanner import MdnsScanner
from .discovery.subnet_mapper import SubnetMapper
from .discovery.coap_scanner import CoapScanner
from .discovery.upnp_scanner import UpnpScanner
from .discovery.auto_detect import AutoDetectScanner

# Validation modules
from .validation.shelly_auditor import ShellyAuditor
from .validation.pin_entropy_analyzer import PinEntropyAnalyzer
from .validation.mqtt_telemetry_checker import MqttTelemetryChecker
from .validation.firmware_auditor import FirmwareAuditor
from .validation.modbus_auditor import ModbusAuditor
from .validation.camera_auditor import CameraAuditor
from .validation.ble_mesh_auditor import BleMeshAuditor
from .validation.credential_pivot_auditor import CredentialPivotAuditor
from .validation.web_cloud_auditor import WebCloudAuditor
from .validation.tr069_auditor import TR069Auditor

# Conformance modules
from .conformance.protocol_boundary_tester import ProtocolBoundaryTester
from .conformance.resilience_monitor import ResilienceMonitor
from .conformance.matter_auditor import MatterAuditor

# Correlation modules
from .correlation.cross_zone_correlator import CrossZoneCorrelator

MODULE_REGISTRY: Dict[str, Type[BaseValidationModule]] = {
    # Discovery
    "discovery/auto_detect": AutoDetectScanner,
    "discovery/mdns_scanner": MdnsScanner,
    "discovery/subnet_mapper": SubnetMapper,
    "discovery/coap_scanner": CoapScanner,
    "discovery/upnp_scanner": UpnpScanner,
    # Validation
    "validation/shelly_auditor": ShellyAuditor,
    "validation/pin_entropy_analyzer": PinEntropyAnalyzer,
    "validation/mqtt_telemetry_checker": MqttTelemetryChecker,
    "validation/firmware_auditor": FirmwareAuditor,
    "validation/modbus_auditor": ModbusAuditor,
    "validation/camera_auditor": CameraAuditor,
    "validation/ble_mesh_auditor": BleMeshAuditor,
    "validation/credential_pivot_auditor": CredentialPivotAuditor,
    "validation/web_cloud_auditor": WebCloudAuditor,
    "validation/tr069_auditor": TR069Auditor,
    # Conformance
    "conformance/protocol_boundary_tester": ProtocolBoundaryTester,
    "conformance/resilience_monitor": ResilienceMonitor,
    "conformance/matter_auditor": MatterAuditor,
    # Correlation
    "correlation/cross_zone_correlator": CrossZoneCorrelator,
}


def get_module(name: str) -> BaseValidationModule:
    clean_name = name.strip().lower()
    if clean_name in MODULE_REGISTRY:
        return MODULE_REGISTRY[clean_name]()
    # Also support short names (e.g. 'modbus_auditor' -> 'validation/modbus_auditor')
    for full_name, cls in MODULE_REGISTRY.items():
        if full_name.endswith(clean_name) or clean_name == full_name.split("/")[-1]:
            return cls()
    raise KeyError(f"Module '{name}' not found. Use 'modules list' to see available modules.")


def list_modules() -> Dict[str, Type[BaseValidationModule]]:
    return MODULE_REGISTRY
