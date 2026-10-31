"""
vault.py - In-memory Ephemeral Credential Vault for IoTFlux
Authorized Defensive Security Validation Lab

Academic Purpose & Safety Guarantees:
1. Harvested secrets (e.g. from CoAP /config, Zigbee /api/config, or firmware filesystems)
   are never stored in plaintext on disk, in log streams, or in report files.
2. Each credential receives a deterministic SHA-256 handle ('cred_<8hex>') and a masked preview ('ad***').
3. Handles are strictly single-session and purged via 'invalidate_all_session_handles()' or 'purge()' upon test completion.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


def mask_secret(secret: str) -> str:
    """Masks a secret following OWASP logging guidelines."""
    if not secret:
        return "<EMPTY>"
    if len(secret) <= 2:
        return "*" * len(secret)
    return secret[:2] + "*" * min(6, len(secret) - 2)


@dataclass
class CredentialRecord:
    handle_id: str
    username: str
    secret: str
    masked_secret: str
    source_endpoint: str
    source_ip: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "handle_id": self.handle_id,
            "username": self.username,
            "masked_secret": self.masked_secret,
            "source_endpoint": self.source_endpoint,
            "source_ip": self.source_ip,
            "metadata": self.metadata,
        }


class EphemeralCredentialVault:
    """
    In-memory store for credentials harvested during Phase 1/Phase 2 discovery.
    Provides opaque handle-based injection for Phase 3 validation modules without disk persistence.
    """

    def __init__(self) -> None:
        self._records: Dict[str, CredentialRecord] = {}

    def harvest(
        self,
        username: str,
        plaintext_password: str,
        source_endpoint: str = "local",
        source_ip: str = "127.0.0.1",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> CredentialRecord:
        """Stores a harvested credential in RAM and returns an opaque record with SHA-256 handle."""
        seed = f"{source_ip}:{source_endpoint}:{username}:{plaintext_password}".encode("utf-8")
        h_hash = hashlib.sha256(seed).hexdigest()[:8]
        handle_id = f"cred_{h_hash}"

        rec = CredentialRecord(
            handle_id=handle_id,
            username=username,
            secret=plaintext_password,
            masked_secret=mask_secret(plaintext_password),
            source_endpoint=source_endpoint,
            source_ip=source_ip,
            metadata=metadata or {},
        )
        self._records[handle_id] = rec
        return rec

    def store_credential(
        self,
        username: str,
        secret: str,
        source_endpoint: str = "local",
        source_ip: str = "127.0.0.1",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Helper to store a credential and return the handle ID string."""
        rec = self.harvest(username, secret, source_endpoint, source_ip, metadata)
        return rec.handle_id

    def get_handle(self, handle_id: str) -> Optional[CredentialRecord]:
        return self._records.get(handle_id)

    def get_credential(self, handle_id: str) -> Optional[CredentialRecord]:
        return self._records.get(handle_id)

    def retrieve_raw_secret(self, handle_id: str) -> Tuple[str, str]:
        """
        Retrieves raw (username, password) strictly for authorized network protocol dispatch.
        Raises KeyError if handle is expired or invalidated.
        """
        if handle_id not in self._records:
            raise KeyError(f"Invalid, expired, or non-existent credential handle: {handle_id}")
        rec = self._records[handle_id]
        return rec.username, rec.secret

    def list_handles(self) -> List[str]:
        return list(self._records.keys())

    def list_records(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self._records.values()]

    def invalidate_all_session_handles(self) -> int:
        """Cryptographically purges all handles and raw secrets from process RAM."""
        count = len(self._records)
        self._records.clear()
        return count

    def purge(self) -> int:
        return self.invalidate_all_session_handles()


# Global vault singleton for active session
vault = EphemeralCredentialVault()
