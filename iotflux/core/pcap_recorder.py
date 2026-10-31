"""
pcap_recorder.py - Synchronized libpcap packet trace capture engine for IoTFlux
Authorized Defensive Security Validation Lab

Exports forensic protocol traces (.pcap) compatible with Wireshark and tcpdump
without requiring external dependencies (like tshark or tcpdump).
"""

from __future__ import annotations

import json
import os
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


@dataclass
class PacketEntry:
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    summary: str
    payload: bytes
    power_draw_watts: Optional[float] = None
    actuator_response_time_ms: Optional[float] = None
    rf_rssi_dbm: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "summary": self.summary,
            "payload_length": len(self.payload),
            "power_draw_watts": self.power_draw_watts,
            "actuator_response_time_ms": self.actuator_response_time_ms,
            "rf_rssi_dbm": self.rf_rssi_dbm,
            "hardware_telemetry": {
                "power_draw_watts": self.power_draw_watts,
                "actuator_response_time_ms": self.actuator_response_time_ms,
                "rf_rssi_dbm": self.rf_rssi_dbm,
            },
        }


class PcapRecorder:
    """Records protocol exchanges and emits standard libpcap binary files."""

    def __init__(self, output_target: Union[str, Path] = "evidence/pcap") -> None:
        target = Path(output_target)
        if target.suffix.lower() == ".pcap":
            self.file_path: Optional[Path] = target
            self.output_dir = target.parent
        else:
            self.file_path = None
            self.output_dir = target

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.traces: List[PacketEntry] = []

    @property
    def packet_count(self) -> int:
        return len(self.traces)

    def record(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        summary: str,
        payload: bytes = b"",
        power_draw_watts: Optional[float] = None,
        actuator_response_time_ms: Optional[float] = None,
        rf_rssi_dbm: Optional[float] = None,
    ) -> None:
        self.traces.append(
            PacketEntry(
                timestamp=time.time(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                summary=summary,
                payload=payload,
                power_draw_watts=power_draw_watts,
                actuator_response_time_ms=actuator_response_time_ms,
                rf_rssi_dbm=rf_rssi_dbm,
            )
        )
        if self.file_path:
            self.write_pcap(self.file_path.name)

    def record_with_telemetry(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        summary: str,
        payload: bytes = b"",
        power_draw_watts: Optional[float] = None,
        actuator_response_time_ms: Optional[float] = None,
        rf_rssi_dbm: Optional[float] = None,
    ) -> None:
        """Explicit helper for recording protocol traffic bundled with physical hardware telemetry."""
        self.record(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            summary=summary,
            payload=payload,
            power_draw_watts=power_draw_watts,
            actuator_response_time_ms=actuator_response_time_ms,
            rf_rssi_dbm=rf_rssi_dbm,
        )

    def export_evidence_json(self, filename_or_path: Optional[Union[str, Path]] = None) -> str:
        """Exports traces and hardware telemetry into an evidence JSON file."""
        if filename_or_path:
            p = Path(filename_or_path)
            if not p.is_absolute() and not str(p).startswith("evidence"):
                out_path = self.output_dir / p
            else:
                out_path = p
        else:
            out_path = self.output_dir / "evidence_telemetry.json"

        out_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "trace_count": len(self.traces),
            "generated_at": time.time(),
            "traces": [t.to_dict() for t in self.traces],
        }
        out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return str(out_path)

    def record_packet(
        self,
        raw_bytes: bytes,
        src_ip: str = "127.0.0.1",
        dst_ip: str = "127.0.0.1",
        dst_port: int = 0,
        protocol: str = "RAW",
        summary: str = "Captured Raw Packet",
    ) -> None:
        """Records raw binary bytes and immediately persists to file if bound."""
        self.record(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            summary=summary,
            payload=raw_bytes,
        )

    def write_pcap(self, filename: Optional[str] = None) -> str:
        """Writes accumulated packet traces to a standard libpcap 2.4 binary file."""
        if filename:
            if not filename.endswith(".pcap"):
                filename = f"{filename}.pcap"
            out_path = self.output_dir / filename
        elif self.file_path:
            out_path = self.file_path
        else:
            out_path = self.output_dir / "capture.pcap"

        # Global header: magic (0xa1b2c3d4), v2.4, thiszone=0, sigfigs=0, snaplen=65535, network=101 (LINKTYPE_RAW)
        global_header = struct.pack(
            "=IHHiIII",
            0xA1B2C3D4,  # magic number
            2,           # major version
            4,           # minor version
            0,           # thiszone
            0,           # sigfigs
            65535,       # snaplen
            101,         # network: LINKTYPE_RAW (raw IPv4)
        )

        with open(out_path, "wb") as f:
            f.write(global_header)
            for t in self.traces:
                sec = int(t.timestamp)
                usec = int((t.timestamp - sec) * 1_000_000)

                raw_data = t.payload if t.payload else f"{t.protocol}: {t.summary}".encode("utf-8")
                data_len = len(raw_data)

                packet_header = struct.pack(
                    "=IIII",
                    sec,
                    usec,
                    data_len,
                    data_len,
                )
                f.write(packet_header)
                f.write(raw_data)

        return str(out_path)

    def clear(self) -> None:
        self.traces.clear()
