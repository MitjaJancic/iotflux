"""
camera_auditor.py - IP Camera, RTSP & ONVIF Stream Exposure Auditor for IoTFlux
Authorized Defensive Security Validation Lab

Audits IP Cameras and Network Video Recorders (NVRs):
1. Audits unauthenticated RTSP video streams (port 554/8554) via RFC 2326 OPTIONS & DESCRIBE.
2. Inspects SDP session descriptions for codec parameters and media topology disclosure.
3. Checks for unauthenticated HTTP still-image snapshots and camera management interfaces.
"""

from __future__ import annotations

import socket
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from iotflux.core.logger import logger
from iotflux.core.session import FluxSession
from iotflux.modules.base import BaseValidationModule, ValidationFinding

COMMON_RTSP_PATHS = [
    "/stream1",
    "/live/ch0",
    "/onvif1",
    "/h264Preview_01_main",
    "/live",
    "/video",
]

COMMON_SNAPSHOT_PATHS = [
    "/snapshot.jpg",
    "/cgi-bin/snapshot.cgi",
    "/onvif-http/snapshot",
]


def probe_rtsp_describe(ip: str, port: int, path: str, timeout: float = 2.5) -> Tuple[Optional[int], str, str]:
    """Sends RFC 2326 RTSP DESCRIBE request and parses response status, server banner, and SDP body."""
    uri = f"rtsp://{ip}:{port}{path}"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        desc_req = (
            f"DESCRIBE {uri} RTSP/1.0\r\n"
            f"CSeq: 1\r\n"
            f"Accept: application/sdp\r\n"
            f"User-Agent: IoTFlux-CameraAuditor/1.0\r\n\r\n"
        )
        sock.sendall(desc_req.encode("utf-8"))
        raw = sock.recv(4096).decode("utf-8", errors="replace")
        if not raw.startswith("RTSP/1.0"):
            return None, "", ""
        header_block, _, body = raw.partition("\r\n\r\n")
        lines = header_block.split("\r\n")
        parts = lines[0].split()
        status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
        server_banner = ""
        for l in lines[1:]:
            if l.lower().startswith("server:"):
                server_banner = l.split(":", 1)[1].strip()
        return status_code, server_banner, body.strip()
    except Exception:
        return None, "", ""
    finally:
        sock.close()


def probe_http_path(ip: str, port: int, path: str, timeout: float = 2.0) -> Tuple[Optional[int], str]:
    url = f"http://{ip}:{port}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "IoTFlux-CameraAuditor/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content_type = resp.headers.get("Content-Type", "")
            return resp.status, content_type
    except urllib.error.HTTPError as exc:
        return exc.code, ""
    except Exception:
        return None, ""


class CameraAuditor(BaseValidationModule):
    """IP Camera, RTSP Video Stream & ONVIF Security Conformance Auditor."""

    name = "validation/camera_auditor"
    description = "Audits IP cameras for unauthenticated RTSP stream exposure, SDP leakage, and snapshot endpoints."
    tier = "Tier 3 - Perimeter Video & Surveillance"
    references = ["RFC-2326-RTSP", "ONVIF-PROFILE-S", "CWE-306"]
    author = "Defensive Security Research Team"

    def __init__(self) -> None:
        super().__init__()
        self.register_option("RTSP_PORT", 554, "Target RTSP port (default: 554)")
        self.register_option("HTTP_PORT", 80, "Target HTTP web/snapshot port (default: 80)")
        self.register_option("CHECK_SNAPSHOTS", True, "Audit HTTP snapshot endpoints")

    def run(self, session: FluxSession) -> List[ValidationFinding]:
        self.findings.clear()
        target = self.get_option("TARGET", session)
        if not target:
            logger.failure("No target specified. Set TARGET first.")
            return self.findings

        rtsp_port = int(self.get_option("RTSP_PORT", session) or 554)
        http_port = int(self.get_option("HTTP_PORT", session) or 80)
        check_snaps = bool(self.get_option("CHECK_SNAPSHOTS", session))

        logger.info(f"Auditing IP camera / surveillance node on {target} (RTSP:{rtsp_port}, HTTP:{http_port})...")

        # 1. RTSP Stream Exposure Check
        exposed_streams: List[str] = []
        server_banner = ""
        sample_sdp = ""

        for path in COMMON_RTSP_PATHS:
            status, s_banner, sdp = probe_rtsp_describe(target, rtsp_port, path)
            if s_banner and not server_banner:
                server_banner = s_banner
            if status == 200:
                exposed_streams.append(path)
                if not sample_sdp:
                    sample_sdp = sdp

        if exposed_streams:
            logger.failure(f"Unauthenticated RTSP video stream exposure detected on {len(exposed_streams)} path(s)!")
            self.add_finding(
                finding_id="CAMERA-RTSP-UNAUTH-STREAM",
                target=f"{target}:{rtsp_port}",
                title="Unauthenticated RTSP Video Stream Exposure",
                spec_id="RFC-2326-RTSP",
                cwe="CWE-306",
                status="CRITICAL_NON_COMPLIANT",
                details=(
                    f"RTSP service at {target}:{rtsp_port} allows unauthenticated playback via RFC 2326 DESCRIBE "
                    f"on path(s): {exposed_streams}. Server banner: '{server_banner or 'unknown'}'. "
                    f"SDP video parameters leaked: {sample_sdp[:120]}..."
                ),
                remediation="Enable RTSP Digest Authentication (RFC 7616); disable anonymous stream access.",
                evidence={"paths": exposed_streams, "server": server_banner, "sdp_sample": sample_sdp},
            )
        else:
            self.add_finding(
                finding_id="CAMERA-RTSP-AUTHENTICATED",
                target=f"{target}:{rtsp_port}",
                title="RTSP Video Stream Authentication Enforced",
                spec_id="RFC-2326-RTSP",
                cwe="CWE-306",
                status="COMPLIANT",
                details=f"RTSP service at {target}:{rtsp_port} rejected unauthenticated stream playback requests (returned 401 or closed).",
                remediation="Maintain existing RTSP digest authentication configurations.",
            )

        # 2. HTTP Snapshot Check
        if check_snaps:
            exposed_snaps: List[str] = []
            for sp in COMMON_SNAPSHOT_PATHS:
                st, ctype = probe_http_path(target, http_port, sp)
                if st == 200 and "image" in ctype.lower():
                    exposed_snaps.append(sp)

            if exposed_snaps:
                self.add_finding(
                    finding_id="CAMERA-HTTP-SNAPSHOT-EXPOSED",
                    target=f"{target}:{http_port}",
                    title="Unauthenticated HTTP Still-Frame Snapshot Exposure",
                    spec_id="ONVIF-PROFILE-S",
                    cwe="CWE-306",
                    status="NON_COMPLIANT",
                    details=f"Camera provides unauthenticated still image captures on endpoint(s): {exposed_snaps}.",
                    remediation="Require authentication for all HTTP media capture endpoints per ONVIF Profile S guidelines.",
                    evidence={"snapshot_endpoints": exposed_snaps},
                )

        return self.findings
