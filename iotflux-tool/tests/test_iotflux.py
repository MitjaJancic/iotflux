"""
test_iotflux.py - Comprehensive unit test suite for IoTFlux defensive validation framework
Authorized Defensive Security Validation Lab
"""

import io
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from iotflux.core.cli import direct_cli_entrypoint
from iotflux.core.logger import FluxLogger
from iotflux.core.pcap_recorder import PcapRecorder
from iotflux.core.profiles import ProfileCatalog, catalog, load_profile
from iotflux.core.scoring import DamageScorer, Finding
from iotflux.core.session import FluxSession
from iotflux.core.specification import get_spec, list_specs
from iotflux.core.vault import EphemeralCredentialVault, vault
from iotflux.modules import BaseValidationModule, ValidationFinding, get_module, list_modules

# Modules
from iotflux.modules.conformance.matter_auditor import MatterAuditor, raw_matter_udp_probe
from iotflux.modules.conformance.protocol_boundary_tester import ProtocolBoundaryTester
from iotflux.modules.conformance.resilience_monitor import ResilienceMonitor
from iotflux.modules.correlation.cross_zone_correlator import CrossZoneCorrelator
from iotflux.modules.discovery.coap_scanner import CoapScanner, encode_coap_get, extract_coap_payload
from iotflux.modules.discovery.mdns_scanner import MdnsScanner
from iotflux.modules.discovery.subnet_mapper import SubnetMapper
from iotflux.modules.discovery.upnp_scanner import UpnpScanner
from iotflux.modules.validation.ble_mesh_auditor import BleMeshAuditor
from iotflux.modules.validation.camera_auditor import CameraAuditor
from iotflux.modules.validation.credential_pivot_auditor import CredentialPivotAuditor
from iotflux.modules.validation.firmware_auditor import FirmwareAuditor, calculate_shannon_entropy, mask_token
from iotflux.modules.validation.modbus_auditor import ModbusAuditor
from iotflux.modules.validation.mqtt_telemetry_checker import MqttTelemetryChecker
from iotflux.modules.validation.pin_entropy_analyzer import PinEntropyAnalyzer
from iotflux.modules.validation.shelly_auditor import ShellyAuditor
from iotflux.modules.validation.web_cloud_auditor import WebCloudAuditor


class TestIoTFluxCore(unittest.TestCase):
    """Verifies session management, safety invariants, and specification catalog."""

    def setUp(self) -> None:
        self.session = FluxSession()

    def test_session_defaults_and_safety_invariant(self) -> None:
        self.assertFalse(self.session.get_option("AUTHORIZED_TEST"))
        self.assertEqual(self.session.get_option("TARGET"), "127.0.0.1")

        self.session.set_option("TARGET", "172.30.1.30")
        self.assertEqual(self.session.get_option("TARGET"), "172.30.1.30")

        self.session.set_option("PORT", "8080")
        self.assertEqual(self.session.get_option("PORT"), 8080)

        self.session.set_option("AUTHORIZED_TEST", "true")
        self.assertTrue(self.session.get_option("AUTHORIZED_TEST"))

    def test_specification_catalog(self) -> None:
        specs = list_specs()
        self.assertGreaterEqual(len(specs), 10)
        shelly_spec = get_spec("SHELLY-RPC-2.0")
        self.assertIsNotNone(shelly_spec)
        self.assertEqual(shelly_spec.organization, "Allterco Robotics / Shelly")

        nist_spec = get_spec("NIST-SP-800-63B")
        self.assertIsNotNone(nist_spec)
        self.assertIn("PIN Entropy", nist_spec.section)

        modbus_spec = get_spec("MODBUS-TCP-SPEC")
        self.assertIsNotNone(modbus_spec)

    def test_module_registry(self) -> None:
        registry = list_modules()
        self.assertGreaterEqual(len(registry), 16)
        expected_modules = [
            "discovery/mdns_scanner",
            "discovery/subnet_mapper",
            "discovery/coap_scanner",
            "discovery/upnp_scanner",
            "validation/shelly_auditor",
            "validation/pin_entropy_analyzer",
            "validation/mqtt_telemetry_checker",
            "validation/firmware_auditor",
            "validation/modbus_auditor",
            "validation/camera_auditor",
            "validation/ble_mesh_auditor",
            "validation/credential_pivot_auditor",
            "validation/web_cloud_auditor",
            "conformance/protocol_boundary_tester",
            "conformance/resilience_monitor",
            "conformance/matter_auditor",
            "correlation/cross_zone_correlator",
        ]
        for m in expected_modules:
            self.assertIn(m, registry)
            inst = get_module(m)
            self.assertIsInstance(inst, BaseValidationModule)

        # Test short name lookup
        inst_short = get_module("modbus_auditor")
        self.assertIsInstance(inst_short, ModbusAuditor)


class TestIoTFluxCoreExtensions(unittest.TestCase):
    """Verifies Vault, Pcap Recorder, Scoring, and Profile Catalog."""

    def test_ephemeral_credential_vault(self) -> None:
        v = EphemeralCredentialVault()
        h1 = v.store_credential("admin", "SuperSecret123!", metadata={"origin": "coap_leak"})
        self.assertTrue(h1.startswith("cred_"))
        self.assertEqual(len(h1), 13)

        rec = v.get_credential(h1)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.username, "admin")
        self.assertEqual(rec.secret, "SuperSecret123!")
        self.assertEqual(rec.metadata["origin"], "coap_leak")

        # Test deduplication
        h2 = v.store_credential("admin", "SuperSecret123!")
        self.assertEqual(h1, h2)

        # Test purge
        count = v.purge()
        self.assertEqual(count, 1)
        self.assertEqual(len(v.list_handles()), 0)

    def test_pcap_recorder(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_path = Path(tmpdir) / "test_session.pcap"
            recorder = PcapRecorder(pcap_path)
            self.assertEqual(recorder.packet_count, 0)

            # Write a simulated IP packet (20 bytes header + payload)
            fake_pkt = b"\x45\x00\x00\x1c\x00\x01\x00\x00\x40\x11\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01" + b"TEST"
            recorder.record_packet(fake_pkt)
            self.assertEqual(recorder.packet_count, 1)

            # Check file header
            data = pcap_path.read_bytes()
            self.assertGreaterEqual(len(data), 24 + 16 + len(fake_pkt))
            magic = struct.unpack("<I", data[:4])[0]
            self.assertEqual(magic, 0xA1B2C3D4)

    def test_damage_scorer(self) -> None:
        scorer = DamageScorer()
        f1 = Finding(
            finding_id="F1",
            device_id="shelly_1",
            check_name="test_check",
            description="Actuator exposure",
            cvss=8.0,
            damage={"physical_safety": 3, "privacy": 1, "financial": 2, "availability": 1, "chaining_depth": 2},
        )
        rubric = scorer.score_finding(f1)
        self.assertEqual(rubric.physical_safety, 3)
        self.assertEqual(rubric.composite_score, 16.8)
        self.assertIn("CRITICAL", rubric.composite_severity)

    def test_profile_catalog(self) -> None:
        profs = catalog.list_profiles()
        self.assertGreater(len(profs), 10)

        # Lookup by exact ID
        p1 = catalog.get_profile("shelly_1pm_gen4")
        self.assertIsNotNone(p1)
        self.assertEqual(p1.vendor, "Shelly")

        # Lookup by fuzzy match
        p2 = catalog.get_profile("shelly_1pm")
        self.assertIsNotNone(p2)
        self.assertEqual(p2.device_id, "shelly_1pm_gen4")

        # Filter by protocol
        mqtt_devices = catalog.find_by_protocol("mqtt")
        self.assertGreater(len(mqtt_devices), 3)


class TestIoTFluxValidationModules(unittest.TestCase):
    """Verifies functional auditing and conformance checking modules."""

    def setUp(self) -> None:
        self.session = FluxSession()

    @patch("requests.get")
    def test_shelly_auditor_read_only(self, mock_get: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "result": {
                "id": "shellyplusplugs-001",
                "model": "SNPL-00112EU",
                "auth_en": False,
            }
        }
        mock_get.return_value = mock_resp

        auditor = ShellyAuditor()
        findings = auditor.run(self.session)

        self.assertGreaterEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.finding_id, "SHELLY-NO-AUTH")
        self.assertEqual(f.status, "NON_COMPLIANT")
        self.assertEqual(f.cwe, "CWE-306")

    @patch("requests.post")
    def test_pin_entropy_analyzer(self, mock_post: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = [
            {"result": {"guest_pin": "1234"}},
            {"result": {"guest_pin": "1235"}},
            {"result": {"guest_pin": "1234"}},
            {"result": {"guest_pin": "1235"}},
            {"result": {"guest_pin": "1234"}},
        ]
        mock_post.return_value = mock_resp

        analyzer = PinEntropyAnalyzer()
        analyzer.set_option("SAMPLES", 5)
        findings = analyzer.run(self.session)

        self.assertGreaterEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.finding_id, "PIN-LOW-ENTROPY")
        self.assertEqual(f.status, "NON_COMPLIANT")
        self.assertEqual(f.spec_id, "NIST-SP-800-63B")

    @patch("requests.post")
    def test_protocol_boundary_tester(self, mock_post: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"id": 1, "result": {"conformance": "VALID"}}
        mock_post.return_value = mock_resp

        tester = ProtocolBoundaryTester()
        findings = tester.run(self.session)

        self.assertGreaterEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.status, "COMPLIANT_RESILIENT")
        self.assertEqual(f.finding_id, "CONF-GRACEFUL-HANDLING")

    @patch("requests.get")
    def test_resilience_monitor(self, mock_get: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp

        monitor = ResilienceMonitor()
        monitor.set_option("ROUNDS", 3)
        monitor.set_option("DELAY", 0.01)
        findings = monitor.run(self.session)

        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_id, "RESIL-STABLE-BASELINE")

    def test_cross_zone_correlator(self) -> None:
        correlator = CrossZoneCorrelator()
        findings = correlator.run(self.session)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.finding_id, "CORR-CROSS-ZONE-PATH")
        self.assertIn("Tier 1", f.details)
        self.assertIn("Tier 3", f.details)

    @patch("socket.socket")
    def test_subnet_mapper(self, mock_socket_cls: MagicMock) -> None:
        mock_sock = MagicMock()

        def fake_connect(addr):
            host, port = addr
            if host == "172.30.2.10" and port in (80, 1883):
                return 0
            return 111

        mock_sock.connect_ex.side_effect = fake_connect
        mock_socket_cls.return_value = mock_sock

        mapper = SubnetMapper()
        mapper.set_option("SUBNET", "172.30.2.10")
        findings = mapper.run(self.session)

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.target, "172.30.2.10")
        self.assertIn("Tier 2", f.details)


class TestIoTFluxPortedFeatures(unittest.TestCase):
    """Verifies all ported features: Firmware, Modbus, CoAP, Camera, Matter, BLE, UPnP, Credential Pivot, Web."""

    def setUp(self) -> None:
        self.session = FluxSession()

    def test_firmware_auditor(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            # Create simulated /etc/shadow
            (root / "etc").mkdir()
            (root / "etc" / "shadow").write_text("root:$1$abc$def:18000:0:99999:7:::\nbin:*:18000:0:99999:7:::\n", encoding="utf-8")

            # Create simulated config with hardcoded private key
            (root / "etc" / "device.conf").write_text("API_KEY=AKIA1234567890ABCDEF\n-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n", encoding="utf-8")

            # Create simulated OpenWrt opkg status
            (root / "usr" / "lib" / "opkg").mkdir(parents=True)
            (root / "usr" / "lib" / "opkg" / "status").write_text("Package: dnsmasq\nVersion: 2.80\n\nPackage: miniupnpd\nVersion: 2.0\n", encoding="utf-8")

            auditor = FirmwareAuditor()
            auditor.set_option("TARGET_DIR", str(root))
            findings = auditor.run(self.session)

            f_ids = [f.finding_id for f in findings]
            self.assertIn("FW-WEAK-ROOTFS-CREDENTIALS", f_ids)
            self.assertIn("FW-HARDCODED-SECRETS-IDENTIFIED", f_ids)
            self.assertIn("FW-OUTDATED-SBOM-COMPONENTS", f_ids)

    @patch("iotflux.modules.validation.modbus_auditor.raw_modbus_read_holding_register")
    @patch("iotflux.modules.validation.modbus_auditor.raw_modbus_write_register")
    def test_modbus_auditor(self, mock_write: MagicMock, mock_read: MagicMock) -> None:
        mock_read.return_value = (True, 100)
        mock_write.return_value = True

        auditor = ModbusAuditor()
        auditor.set_option("TARGET", "172.30.2.65")
        auditor.set_option("PORT", 502)

        # 1. Read-Only Default Run
        findings = auditor.run(self.session)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_id, "MODBUS-UNAUTH-READ-EXPOSED")

        # 2. Authorized Run with Auto-Revert
        self.session.set_option("AUTHORIZED_TEST", True)
        auditor.set_option("PULSE_DURATION", 0.01)
        findings_auth = auditor.run(self.session)
        f_ids = [f.finding_id for f in findings_auth]
        self.assertIn("MODBUS-UNAUTH-CONTROL-VALIDATED", f_ids)
        self.assertGreaterEqual(mock_write.call_count, 2)  # Write test value then revert

    @patch("iotflux.modules.discovery.coap_scanner.probe_coap_endpoint")
    def test_coap_scanner(self, mock_probe: MagicMock) -> None:
        def fake_coap_probe(ip, port, path, timeout=2.0):
            if path == "/.well-known/core":
                return 2, "</config>,</sensor/temp>"
            elif path == "/config":
                return 2, '{"mqtt_server": "172.30.2.10", "key": "secret123"}'
            return 2, "22.5 C"

        mock_probe.side_effect = fake_coap_probe
        scanner = CoapScanner()
        scanner.set_option("TARGET", "172.30.2.70")
        findings = scanner.run(self.session)

        f_ids = [f.finding_id for f in findings]
        self.assertIn("COAP-RESOURCE-DISCOVERY-EXPOSED", f_ids)
        self.assertTrue(any("COAP-UNAUTH-READ" in fid for fid in f_ids))

    @patch("iotflux.modules.validation.camera_auditor.probe_rtsp_describe")
    @patch("iotflux.modules.validation.camera_auditor.probe_http_path")
    def test_camera_auditor(self, mock_http: MagicMock, mock_rtsp: MagicMock) -> None:
        # RTSP stream /stream1 is exposed
        def fake_rtsp(ip, port, path, timeout=2.5):
            if path == "/stream1":
                return 200, "Hikvision-RTSP/1.0", "v=0\r\no=- 1 1 IN IP4 172.30.4.10\r\ns=Session\r\nm=video 0 RTP/AVP 96"
            return 401, "", ""

        mock_rtsp.side_effect = fake_rtsp
        mock_http.return_value = (200, "image/jpeg")

        auditor = CameraAuditor()
        auditor.set_option("TARGET", "172.30.4.10")
        findings = auditor.run(self.session)

        f_ids = [f.finding_id for f in findings]
        self.assertIn("CAMERA-RTSP-UNAUTH-STREAM", f_ids)
        self.assertIn("CAMERA-HTTP-SNAPSHOT-EXPOSED", f_ids)

    @patch("iotflux.modules.conformance.matter_auditor.raw_matter_udp_probe")
    def test_matter_auditor(self, mock_probe: MagicMock) -> None:
        # Mock active commissioning response
        mock_probe.return_value = (True, b"\x00\x21\x00\x01\x00\x00\x01\x00\x00\x00")

        auditor = MatterAuditor()
        auditor.set_option("TARGET", "172.30.3.85")
        findings = auditor.run(self.session)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_id, "MATTER-OPEN-COMMISSIONING-WINDOW")
        self.assertEqual(findings[0].status, "NON_COMPLIANT")

    @patch("iotflux.modules.validation.ble_mesh_auditor.http_json_request")
    def test_ble_mesh_auditor(self, mock_http: MagicMock) -> None:
        # Initial state: on = False
        mock_http.side_effect = [
            (200, {"on": False, "brightness": 0}),  # Initial GET
            (200, {"status": "ok"}),               # Test PUT
            (200, {"status": "ok"}),               # Revert PUT
            (200, {"on": False, "brightness": 0}),  # Verify GET
        ]

        auditor = BleMeshAuditor()
        auditor.set_option("TARGET", "172.30.2.80")
        auditor.set_option("PULSE_DURATION", 0.01)
        self.session.set_option("AUTHORIZED_TEST", True)

        findings = auditor.run(self.session)
        f_ids = [f.finding_id for f in findings]
        self.assertIn("BLE-LIGHTING-UNAUTH-READ", f_ids)
        self.assertIn("BLE-LIGHTING-ACTUATION-VALIDATED", f_ids)

    @patch("iotflux.modules.discovery.upnp_scanner.fetch_xml")
    def test_upnp_scanner(self, mock_fetch: MagicMock) -> None:
        root_desc = """<?xml version="1.0"?>
        <root xmlns="urn:schemas-upnp-org:device-1-0">
          <device>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <SCPDURL>/scpd.xml</SCPDURL>
                <controlURL>/control</controlURL>
              </service>
            </serviceList>
          </device>
        </root>"""
        scpd = """<?xml version="1.0"?>
        <scpd xmlns="urn:schemas-upnp-org:service-1-0">
          <actionList>
            <action><name>GetExternalIPAddress</name></action>
            <action><name>AddPortMapping</name></action>
          </actionList>
        </scpd>"""

        mock_fetch.side_effect = lambda url, timeout=3.0: scpd if "scpd.xml" in url else root_desc

        scanner = UpnpScanner()
        scanner.set_option("TARGET", "172.30.1.1")
        findings = scanner.run(self.session)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_id, "UPNP-ADDPORTMAPPING-EXPOSED")
        self.assertEqual(findings[0].status, "CRITICAL_NON_COMPLIANT")

    @patch("iotflux.modules.validation.credential_pivot_auditor.test_http_basic_auth")
    def test_credential_pivot_auditor(self, mock_auth: MagicMock) -> None:
        vault.purge()
        h = vault.store_credential("root", "123456", metadata={"origin": "coap_config"})
        mock_auth.return_value = True

        auditor = CredentialPivotAuditor()
        auditor.set_option("TARGET", "172.30.2.10")
        findings = auditor.run(self.session)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_id, "CRED-CROSS-PROTOCOL-REUSE")
        vault.purge()

    @patch("urllib.request.urlopen")
    def test_web_cloud_auditor(self, mock_urlopen: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.headers = {"Access-Control-Allow-Origin": "*"}
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        auditor = WebCloudAuditor()
        auditor.set_option("TARGET", "172.30.1.10")
        findings = auditor.run(self.session)

        f_ids = [f.finding_id for f in findings]
        self.assertIn("WEB-PERMISSIVE-CORS", f_ids)
        self.assertIn("WEB-MISSING-SECURITY-HEADERS", f_ids)


class TestIoTFluxCli(unittest.TestCase):
    """Verifies non-interactive command line dispatching."""

    def test_cli_modules_listing(self) -> None:
        rc = direct_cli_entrypoint(["modules"])
        self.assertEqual(rc, 0)

    def test_cli_profiles_listing(self) -> None:
        rc = direct_cli_entrypoint(["profiles", "list"])
        self.assertEqual(rc, 0)

    def test_cli_profiles_show(self) -> None:
        rc = direct_cli_entrypoint(["profiles", "show", "shelly_1pm"])
        self.assertEqual(rc, 0)

    def test_cli_specs_listing(self) -> None:
        rc = direct_cli_entrypoint(["specs"])
        self.assertEqual(rc, 0)

    def test_cli_unknown_module_fails_cleanly(self) -> None:
        rc = direct_cli_entrypoint(["run", "non_existent_module"])
        self.assertEqual(rc, 1)


class TestDynamicDeviceIntegration(unittest.TestCase):
    """
    Verifies the 4-component Dynamic Device Integration System:
    1. AutoDetectScanner (read-only enumeration, Docker 172.28.0.0/16 scope lock, discovered_devices.json)
    2. DynamicProfileGenerator (MAC hash IDs, capability templates, lab_whitelist.txt, empty creds)
    3. CredentialManager (interactive Fernet encryption, audit_log.json, --require-creds graceful fail)
    4. Docker lab compose & setup script artifacts
    """

    def setUp(self) -> None:
        self.session = FluxSession()

    def test_1_auto_detect_scope_lock_rejects_external_networks(self) -> None:
        from iotflux.modules.discovery.auto_detect import AutoDetectScanner, LabScopeViolationError, enforce_docker_lab_scope

        # External and home networks must be blocked at compile-time scope check
        for forbidden in ("192.168.1.0/24", "192.168.1.50", "10.0.0.1", "8.8.8.8", "172.16.0.1"):
            with self.assertRaises(LabScopeViolationError):
                enforce_docker_lab_scope(forbidden)

        # Authorized Docker lab subnet 172.28.0.0/16 must succeed
        allowed_hosts = enforce_docker_lab_scope("172.28.0.30")
        self.assertEqual(allowed_hosts, ["172.28.0.30"])

    def test_2_auto_detect_discovery_and_profile_generation_pipeline(self) -> None:
        import yaml
        from iotflux.core.audit_log import AuditTrailLogger
        from iotflux.core.profile_generator import DynamicProfileGenerator
        from iotflux.modules.discovery.auto_detect import AutoDetectScanner

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            discovered_json = tmp / "discovered_devices.json"
            whitelist_file = tmp / "lab_whitelist.txt"
            auto_profiles_dir = tmp / "profiles" / "auto_generated"
            audit_file = tmp / "audit_log.json"

            # Whitelist only 172.28.0.30; 172.28.0.10 must remain authorized: false
            whitelist_file.write_text("172.28.0.30 # Whitelisted Shelly Plug S\n", encoding="utf-8")

            def fake_port_check(ip: str, port: int, timeout: float = 0.4) -> bool:
                if ip == "172.28.0.30" and port == 80:
                    return True
                if ip == "172.28.0.10" and port == 1883:
                    return True
                return False

            def fake_metadata(ip: str, port: int, timeout: float = 1.0) -> dict:
                if ip == "172.28.0.30":
                    return {
                        "endpoint": "/rpc/Shelly.GetDeviceInfo",
                        "service_type": "Shelly RPC",
                        "vendor": "Shelly",
                        "model": "ShellyPlugS-Gen2",
                        "mac": "AA:BB:CC:11:22:33",
                    }
                return {}

            def fake_mdns_ssdp(ip: str, timeout: float = 0.5) -> dict:
                return {"ssdp_server": "Linux/5.15 UPnP/1.1"} if ip == "172.28.0.30" else {}

            scanner = AutoDetectScanner(
                port_check_fn=fake_port_check,
                metadata_fn=fake_metadata,
                mdns_ssdp_fn=fake_mdns_ssdp,
            )

            with patch("iotflux.modules.discovery.auto_detect.audit_trail", AuditTrailLogger(audit_file)):
                records1 = scanner.discover_network(
                    subnet_or_ip="172.28.0.30",
                    ports=(80, 1883),
                    output_file=discovered_json,
                )
                records2 = scanner.discover_network(
                    subnet_or_ip="172.28.0.10",
                    ports=(80, 1883),
                    output_file=discovered_json,
                )
                combined = records1 + records2
                discovered_json.write_text(json.dumps(combined, indent=2), encoding="utf-8")

            self.assertEqual(len(combined), 2)
            shelly_rec = combined[0]
            mqtt_rec = combined[1]
            self.assertTrue(shelly_rec["device_id"].startswith("dev_"))
            self.assertEqual(shelly_rec["ip_address"], "172.28.0.30")
            self.assertIn("Shelly RPC", shelly_rec["service_fingerprints"]["detected_services"])

            # Generate profiles from discovered_devices.json
            generator = DynamicProfileGenerator(
                output_dir=auto_profiles_dir,
                whitelist_path=whitelist_file,
                mirror_pkg_dir=auto_profiles_dir,
            )
            with patch("iotflux.core.profile_generator.audit_trail", AuditTrailLogger(audit_file)):
                written = generator.generate_from_file(discovered_json)

            self.assertEqual(len(written), 2)

            # Verify Shelly profile (whitelisted -> authorized: true, credentials empty)
            shelly_yaml = auto_profiles_dir / f"{shelly_rec['device_id']}.yaml"
            shelly_data = yaml.safe_load(shelly_yaml.read_text(encoding="utf-8"))
            self.assertTrue(shelly_data["authorized"])
            self.assertFalse(shelly_data["credentials"]["configured"])
            self.assertEqual(shelly_data["credentials"]["username"], "")
            self.assertEqual(shelly_data["credentials"]["encrypted_secret"], "")
            self.assertIn("http", shelly_data["network"])

            # Verify MQTT broker profile (not in whitelist -> authorized: false)
            mqtt_yaml = auto_profiles_dir / f"{mqtt_rec['device_id']}.yaml"
            mqtt_data = yaml.safe_load(mqtt_yaml.read_text(encoding="utf-8"))
            self.assertFalse(mqtt_data["authorized"])
            self.assertIn("mqtt", mqtt_data["network"])

    def test_3_encrypted_credential_workflow_and_require_creds_gate(self) -> None:
        import yaml
        from iotflux.core.audit_log import AuditTrailLogger
        from iotflux.core.credential_manager import (
            decrypt_secret_fernet,
            set_device_credentials_interactive,
            verify_profile_credentials_present,
        )
        from iotflux.core.profile_generator import DynamicProfileGenerator

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            key_file = tmp / ".iotflux_fernet.key"
            audit_file = tmp / "audit_log.json"
            auto_dir = tmp / "profiles" / "auto_generated"
            whitelist_file = tmp / "lab_whitelist.txt"
            whitelist_file.write_text("172.28.0.30\n", encoding="utf-8")

            gen = DynamicProfileGenerator(
                output_dir=auto_dir,
                whitelist_path=whitelist_file,
                mirror_pkg_dir=auto_dir,
            )
            sample_dev = {
                "device_id": "dev_aabbcc1122",
                "ip_address": "172.28.0.30",
                "mac_address": "AA:BB:CC:11:22:33",
                "open_ports": [80],
                "service_fingerprints": {"detected_services": ["Shelly RPC"], "vendor": "Shelly", "model": "PlugS"},
                "detected_protocol": "http",
            }
            disc_path = tmp / "discovered_devices.json"
            disc_path.write_text(json.dumps([sample_dev]), encoding="utf-8")

            with patch("iotflux.core.profile_generator.audit_trail", AuditTrailLogger(audit_file)):
                paths = gen.generate_from_file(disc_path)
            prof_path = paths[0]

            # 1. Before setting credentials, state-changing check with REQUIRE_CREDS must fail gracefully
            self.session.set_option("TARGET", "172.28.0.30")
            self.session.set_option("DEVICE_ID", "dev_aabbcc1122")
            self.session.set_option("AUTHORIZED_TEST", True)
            self.session.set_option("REQUIRE_CREDS", True)

            mod = ModbusAuditor()
            with patch("iotflux.core.credential_manager.verify_profile_credentials_present", return_value=(False, None, None)):
                allowed = mod.assert_authorized(self.session, "Test state-changing check")
                self.assertFalse(allowed)
                self.assertTrue(any(f.finding_id == "CREDENTIAL-GATE-BLOCKED" for f in mod.findings))

            # 2. Configure credentials via interactive stdin callback (Fernet encrypted)
            with patch("iotflux.core.credential_manager.audit_trail", AuditTrailLogger(audit_file)):
                set_device_credentials_interactive(
                    device_id="dev_aabbcc1122",
                    username_prompt_fn=lambda _: "lab_admin",
                    secret_prompt_fn=lambda _: "S3cureLabPass!2026",
                    key_path=key_file,
                    profile_path=prof_path,
                    operator_id="researcher_01",
                )

            saved_yaml = yaml.safe_load(prof_path.read_text(encoding="utf-8"))
            creds_block = saved_yaml["credentials"]
            self.assertTrue(creds_block["configured"])
            self.assertEqual(creds_block["username"], "lab_admin")
            # Ensure plaintext password is NEVER stored in YAML
            self.assertNotIn("S3cureLabPass!2026", prof_path.read_text(encoding="utf-8"))

            # Verify Fernet decryption round-trip
            decrypted = decrypt_secret_fernet(creds_block["encrypted_secret"], key_path=key_file)
            self.assertEqual(decrypted, "S3cureLabPass!2026")

            # Verify audit_log.json recorded the event without plaintext secret
            audit_text = audit_file.read_text(encoding="utf-8")
            self.assertNotIn("S3cureLabPass!2026", audit_text)
            audit_entries = json.loads(audit_text)
            cred_events = [e for e in audit_entries if e["event_type"] == "CREDENTIAL_CONFIGURATION"]
            self.assertEqual(len(cred_events), 1)
            self.assertEqual(cred_events[0]["operator_id"], "researcher_01")


if __name__ == "__main__":
    unittest.main()
