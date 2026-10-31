"""
creds_store.py - Plaintext credential store for real-world engagements.

The RAM-only vault is fine for a lab demo but useless across shell invocations.
This store persists harvested and validated credentials to a JSON file on disk so
later modules (MQTT publish, CoAP write, TR-069 set, camera capture) can reuse them
without re-spraying.

Location resolution order:
  1. IOTFLUX_CREDS_FILE environment variable
  2. ./creds.json

File format (version 1):
{
  "version": 1,
  "updated": "2026-10-30T12:00:00Z",
  "credentials": [
    {
      "host": "10.0.0.5", "port": 80, "protocol": "http-basic",
      "username": "admin", "password": "admin", "source": "spray",
      "verified": true, "timestamp": "..."
    }
  ]
}

Passwords are stored in clear text on purpose. `chmod 600` is applied on POSIX.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_CREDS_FILE = Path("creds.json")
ENV_CREDS_FILE = "IOTFLUX_CREDS_FILE"


def creds_path(path: Optional[str | Path] = None) -> Path:
    return Path(path or os.environ.get(ENV_CREDS_FILE, "") or DEFAULT_CREDS_FILE)


def _empty() -> Dict[str, Any]:
    return {"version": 1, "updated": _now(), "credentials": []}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load(path: Optional[str | Path] = None) -> Dict[str, Any]:
    p = creds_path(path)
    if not p.exists():
        return _empty()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return _empty()
    if not isinstance(data, dict) or "credentials" not in data:
        return _empty()
    return data


def save(data: Dict[str, Any], path: Optional[str | Path] = None) -> Path:
    p = creds_path(path)
    data["version"] = 1
    data["updated"] = _now()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, sort_keys=False), encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except Exception:
        pass
    return p


def add(
    host: str,
    protocol: str,
    username: str,
    password: str,
    port: Optional[int] = None,
    source: str = "manual",
    verified: bool = False,
    extra: Optional[Dict[str, Any]] = None,
    path: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """Adds or updates a credential (dedupe on host+port+protocol+username)."""
    data = load(path)
    entry = {
        "host": host,
        "port": port,
        "protocol": protocol,
        "username": username,
        "password": password,
        "source": source,
        "verified": verified,
        "timestamp": _now(),
    }
    if extra:
        entry.update(extra)

    for idx, existing in enumerate(data["credentials"]):
        if (
            existing.get("host") == host
            and existing.get("port") == port
            and existing.get("protocol") == protocol
            and existing.get("username") == username
        ):
            data["credentials"][idx] = entry
            save(data, path)
            return entry

    data["credentials"].append(entry)
    save(data, path)
    return entry


def get(
    host: str,
    protocol: Optional[str] = None,
    port: Optional[int] = None,
    verified_only: bool = False,
    path: Optional[str | Path] = None,
) -> List[Dict[str, Any]]:
    """Returns matching credentials, verified ones first."""
    out = []
    for entry in load(path)["credentials"]:
        if entry.get("host") != host:
            continue
        if protocol and entry.get("protocol") != protocol:
            continue
        if port is not None and entry.get("port") not in (port, None):
            continue
        if verified_only and not entry.get("verified"):
            continue
        out.append(entry)
    out.sort(key=lambda e: (not e.get("verified"), e.get("timestamp", "")))
    return out


def best(
    host: str,
    protocol: Optional[str] = None,
    port: Optional[int] = None,
    path: Optional[str | Path] = None,
) -> Optional[Dict[str, Any]]:
    """Returns the single best (verified, newest) credential for a host, or None."""
    matches = get(host, protocol=protocol, port=port, path=path)
    return matches[0] if matches else None


def delete(host: str, protocol: Optional[str] = None, path: Optional[str | Path] = None) -> int:
    data = load(path)
    before = len(data["credentials"])
    data["credentials"] = [
        e
        for e in data["credentials"]
        if not (e.get("host") == host and (protocol is None or e.get("protocol") == protocol))
    ]
    removed = before - len(data["credentials"])
    if removed:
        save(data, path)
    return removed


def all_credentials(path: Optional[str | Path] = None) -> List[Dict[str, Any]]:
    return load(path)["credentials"]


def export_pairs(host: str, protocol: Optional[str] = None, path: Optional[str | Path] = None) -> List[str]:
    """Returns 'user:pass' strings for a host, suitable for a wordlist."""
    return [f"{e['username']}:{e['password']}" for e in get(host, protocol=protocol, path=path)]


def read_wordlist(wordlist_path: str | Path) -> List[tuple[str, str]]:
    """
    Reads a user:pass wordlist. Blank lines and '#' comments are skipped.
    A line without ':' is treated as a password with an empty username.
    """
    pairs: List[tuple[str, str]] = []
    for raw in Path(wordlist_path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            user, _, pwd = line.partition(":")
            pairs.append((user, pwd))
        else:
            pairs.append(("", line))
    return pairs
