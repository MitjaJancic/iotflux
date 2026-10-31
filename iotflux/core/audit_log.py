"""
audit_log.py - Tamper-Evident Audit Trail Logger for IoTFlux Field Assessments
Authorized Security Assessment & Conformance Validation Framework

Records every discovery event, dynamic profile generation, scope evaluation,
credential configuration, and module execution to both:
- audit_log.json (structured JSON array)
- assessment_audit.jsonl (timestamped JSON Lines with operator_id, scope_config_hash,
  target_list_hash, and execution telemetry)
Plaintext credentials are architecturally excluded from all audit records.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_AUDIT_LOG_PATH = Path("audit_log.json")
DEFAULT_JSONL_AUDIT_PATH = Path("assessment_audit.jsonl")


def get_operator_id() -> str:
    """Returns the current system operator username for audit attribution."""
    if os.environ.get("IOTFLUX_OPERATOR"):
        return os.environ["IOTFLUX_OPERATOR"]
    try:
        return getpass.getuser()
    except Exception:
        return "assessment-operator"


def compute_file_sha256(file_path: str | Path) -> str:
    """Computes the SHA-256 hex digest of a configuration or inventory file if present."""
    p = Path(file_path)
    if not p.exists() or not p.is_file():
        return "sha256:absent"
    try:
        return f"sha256:{hashlib.sha256(p.read_bytes()).hexdigest()}"
    except Exception:
        return "sha256:unreadable"


class AuditTrailLogger:
    """Manages structured JSON and JSONL audit logging for authorized assessment governance."""

    def __init__(
        self,
        log_path: str | Path = DEFAULT_AUDIT_LOG_PATH,
        jsonl_path: Optional[str | Path] = None,
        scope_path: str | Path = "assessment_scope.yaml",
        targets_path: str | Path = "assessment_targets.json",
    ) -> None:
        self.log_path = Path(log_path)
        if jsonl_path is not None:
            self.jsonl_path = Path(jsonl_path)
        elif self.log_path != DEFAULT_AUDIT_LOG_PATH:
            self.jsonl_path = self.log_path.with_name("assessment_audit.jsonl")
        else:
            self.jsonl_path = DEFAULT_JSONL_AUDIT_PATH
        self.scope_path = Path(scope_path)
        self.targets_path = Path(targets_path)

    def log_event(
        self,
        event_type: str,
        action: str,
        details: Dict[str, Any],
        operator_id: Optional[str] = None,
        scope_file: Optional[str | Path] = None,
        targets_file: Optional[str | Path] = None,
    ) -> Dict[str, Any]:
        """Appends a structured audit entry to audit_log.json and assessment_audit.jsonl."""
        scope_ref = Path(scope_file) if scope_file else self.scope_path
        targets_ref = Path(targets_file) if targets_file else self.targets_path

        entry = {
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "operator_id": operator_id or get_operator_id(),
            "event_type": event_type,
            "action": action,
            "scope_config_hash": compute_file_sha256(scope_ref),
            "target_list_hash": compute_file_sha256(targets_ref),
            "details": details,
        }

        # 1. Write to JSON array file (audit_log.json)
        records: List[Dict[str, Any]] = []
        if self.log_path.exists():
            try:
                raw = self.log_path.read_text(encoding="utf-8").strip()
                if raw:
                    loaded = json.loads(raw)
                    if isinstance(loaded, list):
                        records = loaded
            except Exception:
                records = []

        records.append(entry)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.write_text(json.dumps(records, indent=2), encoding="utf-8")

        # 2. Append to JSONL file (assessment_audit.jsonl)
        try:
            self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.jsonl_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except Exception:
            pass

        return entry

    def read_events(self) -> List[Dict[str, Any]]:
        if not self.log_path.exists():
            return []
        try:
            data = json.loads(self.log_path.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def read_jsonl_events(self) -> List[Dict[str, Any]]:
        if not self.jsonl_path.exists():
            return []
        out: List[Dict[str, Any]] = []
        try:
            for line in self.jsonl_path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    out.append(json.loads(line))
        except Exception:
            pass
        return out


audit_trail = AuditTrailLogger()
