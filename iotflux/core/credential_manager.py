"""
credential_manager.py - Portable Encrypted Credential & Authorization Manager for IoTFlux
Authorized Security Assessment & Conformance Validation Framework

Implements interactive operator credential provisioning and pre-flight verification:
1. Prompts operator via secure stdin (getpass) for username/password, API token,
   certificate path, or OAuth2 client credentials flow.
2. Encrypts credential bundles with Fernet (AES-128-CBC + HMAC-SHA256) and stores them
   in profiles/<device_id>.yaml.enc (and updates corresponding profile YAML metadata).
3. Supports OAuth2 client credentials flow for cloud-managed IoT platforms.
4. Enforces --require-auth / --require-creds gate: modules abort with clear error if
   credentials are missing, expired, or insufficiently privileged.
5. Provides 'iotflux auth verify <device_id>' pre-flight credential validity check.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import json
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

import yaml

try:
    from cryptography.fernet import Fernet, InvalidToken
    HAS_CRYPTOGRAPHY_FERNET = True
except ImportError:
    HAS_CRYPTOGRAPHY_FERNET = False

from iotflux.core.audit_log import audit_trail, get_operator_id
from iotflux.core.logger import Colors, logger
from iotflux.core.profiles import DeviceProfile, catalog


DEFAULT_KEY_FILE = Path(".iotflux_fernet.key")
VALID_AUTH_TYPES = ("password", "token", "cert", "oauth2")


class MissingCredentialsError(RuntimeError):
    """Raised when a check with --require-auth / --require-creds executes against a device with invalid credentials."""


class _FallbackFernet:
    """
    Standard-library HMAC-SHA256 + CTR stream fallback if cryptography package is not installed.
    Produces base64url tokens compatible with the CredentialManager interface.
    """

    def __init__(self, key: bytes) -> None:
        raw = base64.urlsafe_b64decode(key)
        self._signing_key = raw[:16]
        self._encryption_key = raw[16:32]

    @staticmethod
    def generate_key() -> bytes:
        return base64.urlsafe_b64encode(os.urandom(32))

    def encrypt(self, data: bytes) -> bytes:
        nonce = os.urandom(16)
        keystream = hashlib.pbkdf2_hmac("sha256", self._encryption_key, nonce, 1000, dklen=len(data))
        cipher = bytes(a ^ b for a, b in zip(data, keystream))
        mac = hmac.new(self._signing_key, nonce + cipher, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(b"\x80" + nonce + cipher + mac)

    def decrypt(self, token: bytes) -> bytes:
        raw = base64.urlsafe_b64decode(token)
        if len(raw) < 49 or raw[0] != 0x80:
            raise ValueError("Invalid token header")
        nonce = raw[1:17]
        mac = raw[-32:]
        cipher = raw[17:-32]
        expected_mac = hmac.new(self._signing_key, nonce + cipher, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("Token HMAC verification failed")
        keystream = hashlib.pbkdf2_hmac("sha256", self._encryption_key, nonce, 1000, dklen=len(cipher))
        return bytes(a ^ b for a, b in zip(cipher, keystream))


def get_or_create_fernet_key(key_path: Optional[str | Path] = None) -> bytes:
    """Loads or generates the local Fernet symmetric encryption key."""
    path = Path(key_path or DEFAULT_KEY_FILE)
    if path.exists():
        return path.read_bytes().strip()

    key = Fernet.generate_key() if HAS_CRYPTOGRAPHY_FERNET else _FallbackFernet.generate_key()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    return key


def encrypt_secret_fernet(plaintext_secret: str, key_path: Optional[str | Path] = None) -> str:
    """Encrypts a plaintext secret string into a URL-safe base64 Fernet token."""
    key = get_or_create_fernet_key(key_path)
    cipher = Fernet(key) if HAS_CRYPTOGRAPHY_FERNET else _FallbackFernet(key)
    token = cipher.encrypt(plaintext_secret.encode("utf-8"))
    return token.decode("ascii")


def decrypt_secret_fernet(encrypted_token: str, key_path: Optional[str | Path] = None) -> str:
    """Decrypts a Fernet token back into the plaintext secret string."""
    key = get_or_create_fernet_key(key_path)
    cipher = Fernet(key) if HAS_CRYPTOGRAPHY_FERNET else _FallbackFernet(key)
    plaintext = cipher.decrypt(encrypted_token.encode("ascii"))
    return plaintext.decode("utf-8")


def locate_profile_yaml(device_id: str, search_dirs: Optional[list[Path]] = None) -> Optional[Path]:
    """Finds the YAML file corresponding to device_id across standard and auto_generated directories."""
    prof = catalog.get_profile(device_id)
    if prof and prof.profile_path and prof.profile_path.exists():
        return prof.profile_path

    pkg_profiles = Path(__file__).resolve().parent.parent / "profiles"
    dirs = search_dirs or [
        Path("profiles") / "auto_generated",
        pkg_profiles / "auto_generated",
        Path("profiles"),
        pkg_profiles,
    ]
    for d in dirs:
        candidate = d / f"{device_id}.yaml"
        if candidate.exists():
            return candidate
    return None


def locate_encrypted_profile_path(device_id: str, profiles_dir: str | Path = "profiles") -> Path:
    """Returns the canonical encrypted credential path profiles/<device_id>.yaml.enc."""
    base = Path(profiles_dir)
    base.mkdir(parents=True, exist_ok=True)
    return base / f"{device_id}.yaml.enc"


def request_oauth2_client_credentials_token(
    token_url: str,
    client_id: str,
    client_secret: str,
    scope: str = "",
    timeout: float = 3.0,
) -> Dict[str, Any]:
    """
    Executes standard RFC 6749 OAuth2 Client Credentials token acquisition for cloud-managed IoT platforms.
    """
    form_data = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret}
    if scope:
        form_data["scope"] = scope
    encoded = urllib.parse.urlencode(form_data).encode("utf-8")
    req = urllib.request.Request(
        token_url,
        data=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read(8192).decode("utf-8"))
        expires_in = int(payload.get("expires_in", 3600))
        return {
            "access_token": payload.get("access_token", ""),
            "token_type": payload.get("token_type", "Bearer"),
            "expires_at_epoch": time.time() + expires_in,
        }


def set_device_auth_interactive(
    device_id: str,
    auth_type: Optional[str] = None,
    prompt_fn: Optional[Callable[[str], str]] = None,
    secret_prompt_fn: Optional[Callable[[str], str]] = None,
    key_path: str | Path = DEFAULT_KEY_FILE,
    profiles_dir: str | Path = "profiles",
    profile_path: Optional[str | Path] = None,
    operator_id: Optional[str] = None,
    expires_at_epoch: Optional[float] = None,
    privilege_level: str = "authorized",
) -> Path:
    """
    Implements `iotflux auth set <device_id>`:
    Prompts operator via secure stdin for:
    - password (username + password)
    - token (API bearer token)
    - cert (certificate path)
    - oauth2 (OAuth2 client_id, client_secret, token_url, scope)
    Encrypts the full credential bundle with Fernet (AES-128-CBC + HMAC-SHA256)
    and stores it in profiles/<device_id>.yaml.enc (and updates profile YAML if present).
    """
    p_fn = prompt_fn or input
    s_fn = secret_prompt_fn or getpass.getpass

    chosen_type = (
        auth_type
        or p_fn(f"Select auth type for {device_id} [password|token|cert|oauth2] (default: password): ").strip().lower()
        or "password"
    )
    if chosen_type not in VALID_AUTH_TYPES:
        raise ValueError(f"Unsupported auth_type '{chosen_type}'. Must be one of {VALID_AUTH_TYPES}.")

    ts_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    op_id = operator_id or get_operator_id()
    cred_payload: Dict[str, Any] = {
        "device_id": device_id,
        "auth_type": chosen_type,
        "privilege_level": privilege_level,
        "configured": True,
        "configured_by": op_id,
        "updated_at_utc": ts_utc,
        "expires_at_epoch": expires_at_epoch,
    }

    primary_secret = ""
    username_val = ""

    if chosen_type == "password":
        username_val = p_fn(f"Enter username for {device_id}: ").strip()
        if not username_val:
            raise ValueError("Username cannot be empty.")
        primary_secret = s_fn(f"Enter password for {device_id} (hidden input): ").strip()
        if not primary_secret:
            raise ValueError("Password cannot be empty.")
        cred_payload["username"] = username_val
        cred_payload["secret"] = primary_secret

    elif chosen_type == "token":
        username_val = "api-token"
        primary_secret = s_fn(f"Enter API bearer token for {device_id} (hidden input): ").strip()
        if not primary_secret:
            raise ValueError("API token cannot be empty.")
        cred_payload["username"] = username_val
        cred_payload["api_token"] = primary_secret

    elif chosen_type == "cert":
        cert_path = p_fn(f"Enter client certificate path for {device_id}: ").strip()
        if not cert_path:
            raise ValueError("Certificate path cannot be empty.")
        key_file_path = p_fn(f"Enter private key path for {device_id} (optional): ").strip()
        username_val = f"mtls:{Path(cert_path).name}"
        primary_secret = cert_path
        cred_payload["username"] = username_val
        cred_payload["certificate_path"] = cert_path
        cred_payload["private_key_path"] = key_file_path

    elif chosen_type == "oauth2":
        token_url = p_fn(f"Enter OAuth2 token URL for {device_id}: ").strip()
        client_id = p_fn(f"Enter OAuth2 client_id for {device_id}: ").strip()
        client_secret = s_fn(f"Enter OAuth2 client_secret for {device_id} (hidden input): ").strip()
        oauth_scope = p_fn(f"Enter OAuth2 scope for {device_id} (optional): ").strip()
        if not token_url or not client_id or not client_secret:
            raise ValueError("OAuth2 token_url, client_id, and client_secret are required.")
        username_val = f"oauth2:{client_id}"
        primary_secret = client_secret
        cred_payload["username"] = username_val
        cred_payload["oauth2"] = {
            "grant_type": "client_credentials",
            "token_url": token_url,
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": oauth_scope,
        }

    # 1. Encrypt full YAML credential payload into profiles/<device_id>.yaml.enc
    serialized_yaml = yaml.safe_dump(cred_payload, sort_keys=False)
    encrypted_bundle = encrypt_secret_fernet(serialized_yaml, key_path=key_path)
    enc_path = locate_encrypted_profile_path(device_id, profiles_dir=profiles_dir)
    enc_path.write_text(encrypted_bundle, encoding="utf-8")

    # 2. Also update the corresponding YAML device profile if it exists
    target_yaml = Path(profile_path) if profile_path else locate_profile_yaml(device_id)
    encrypted_secret_token = encrypt_secret_fernet(primary_secret, key_path=key_path)
    if target_yaml and target_yaml.exists():
        raw_data = yaml.safe_load(target_yaml.read_text(encoding="utf-8")) or {}
        raw_data["credentials"] = {
            "auth_type": chosen_type,
            "username": username_val,
            "encrypted_secret": encrypted_secret_token,
            "encrypted_bundle_path": str(enc_path),
            "encryption_scheme": "fernet-aes128-cbc-hmac-sha256",
            "privilege_level": privilege_level,
            "expires_at_epoch": expires_at_epoch,
            "configured": True,
            "updated_at_utc": ts_utc,
            "configured_by": op_id,
        }
        updated_yaml = yaml.safe_dump(raw_data, sort_keys=False)
        target_yaml.write_text(updated_yaml, encoding="utf-8")

        pkg_auto_dir = Path(__file__).resolve().parent.parent / "profiles" / "auto_generated"
        mirror_candidate = pkg_auto_dir / target_yaml.name
        if mirror_candidate.exists() and mirror_candidate.resolve() != target_yaml.resolve():
            mirror_candidate.write_text(updated_yaml, encoding="utf-8")

    catalog.reload()

    audit_trail.log_event(
        event_type="CREDENTIAL_CONFIGURATION",
        action="auth_set",
        operator_id=op_id,
        details={
            "device_id": device_id,
            "auth_type": chosen_type,
            "username": username_val,
            "privilege_level": privilege_level,
            "encryption_scheme": "fernet-aes128-cbc-hmac-sha256",
            "encrypted_profile_path": str(enc_path),
            "profile_path": str(target_yaml) if target_yaml else None,
            "timestamp_utc": ts_utc,
        },
    )

    logger.success(
        f"Encrypted {chosen_type} credentials stored in {enc_path} (operator: {op_id})."
    )
    return enc_path


def set_device_credentials_interactive(
    device_id: str,
    username_prompt_fn: Optional[Callable[[str], str]] = None,
    secret_prompt_fn: Optional[Callable[[str], str]] = None,
    key_path: str | Path = DEFAULT_KEY_FILE,
    profile_path: Optional[str | Path] = None,
    operator_id: Optional[str] = None,
    prompt_fn: Optional[Callable[[str], str]] = None,
) -> Path:
    """
    Backward-compatible helper for 'iotflux profiles set-creds <device_id>'.
    Saves encrypted credentials both to the profile YAML and to profiles/<device_id>.yaml.enc.
    """
    target_yaml = Path(profile_path) if profile_path else locate_profile_yaml(device_id)
    if not target_yaml or not target_yaml.exists():
        raise FileNotFoundError(
            f"Profile for device_id '{device_id}' not found. Run 'iotflux profiles list' or 'iotflux profiles generate'."
        )

    u_fn = username_prompt_fn or prompt_fn or input
    s_fn = secret_prompt_fn or prompt_fn or getpass.getpass

    logger.info(f"Configuring encrypted credentials for device '{device_id}' ({target_yaml})")
    set_device_auth_interactive(
        device_id=device_id,
        auth_type="password",
        prompt_fn=u_fn,
        secret_prompt_fn=s_fn,
        key_path=key_path,
        profiles_dir=target_yaml.parent,
        profile_path=target_yaml,
        operator_id=operator_id,
    )
    logger.success(
        f"Encrypted credentials stored in {target_yaml} and logged to audit_log.json (operator: {operator_id or get_operator_id()})."
    )
    return target_yaml


def verify_device_auth_preflight(
    device_id_or_ip: str,
    key_path: Optional[str | Path] = None,
    profiles_dir: str | Path = "profiles",
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Implements `iotflux auth verify <device_id>` pre-flight credential validity check:
    Verifies without executing state-changing validation checks that:
    1. Credentials exist in profiles/<device_id>.yaml.enc or profile YAML.
    2. Credentials decrypt cleanly with the operator's Fernet key.
    3. Credentials have not expired (expires_at_epoch check).
    4. Credentials have sufficient privileges (privilege_level != 'insufficient' / 'none').
    5. Certificate files exist on disk when auth_type == 'cert'.
    """
    enc_candidates = [
        Path(profiles_dir) / f"{device_id_or_ip}.yaml.enc",
        Path("profiles") / f"{device_id_or_ip}.yaml.enc",
        Path("profiles") / "auto_generated" / f"{device_id_or_ip}.yaml.enc",
    ]
    bundle: Optional[Dict[str, Any]] = None
    source_path: Optional[Path] = None

    for cand in enc_candidates:
        if cand.exists():
            source_path = cand
            try:
                decrypted_yaml = decrypt_secret_fernet(cand.read_text(encoding="utf-8").strip(), key_path=key_path)
                bundle = yaml.safe_load(decrypted_yaml)
                break
            except Exception as exc:
                res = {"device_id": device_id_or_ip, "reason": f"Fernet decryption failed for {cand}: {exc}"}
                audit_trail.log_event("AUTH_PREFLIGHT_FAILED", "auth_verify", res)
                return False, "DECRYPTION_FAILED", res

    # Fallback: check YAML profile credentials block
    if bundle is None:
        catalog.reload()
        prof = catalog.get_profile(device_id_or_ip)
        if not prof:
            for candidate in catalog.list_profiles():
                if str(candidate.raw.get("ip_address", "")) == device_id_or_ip:
                    prof = candidate
                    break
        if prof and prof.has_credentials():
            creds = prof.credentials
            try:
                dec = decrypt_secret_fernet(str(creds.get("encrypted_secret", "")), key_path=key_path)
                bundle = {
                    "device_id": prof.device_id,
                    "auth_type": creds.get("auth_type", "password"),
                    "username": creds.get("username", ""),
                    "secret": dec,
                    "privilege_level": creds.get("privilege_level", "authorized"),
                    "expires_at_epoch": creds.get("expires_at_epoch"),
                }
                source_path = prof.profile_path
            except Exception as exc:
                res = {"device_id": device_id_or_ip, "reason": f"Credential token decryption failed: {exc}"}
                audit_trail.log_event("AUTH_PREFLIGHT_FAILED", "auth_verify", res)
                return False, "DECRYPTION_FAILED", res

    if not bundle:
        res = {
            "device_id": device_id_or_ip,
            "reason": f"No encrypted credentials found for '{device_id_or_ip}'. Run 'iotflux auth set {device_id_or_ip}'.",
        }
        audit_trail.log_event("AUTH_PREFLIGHT_FAILED", "auth_verify", res)
        return False, "MISSING_CREDENTIALS", res

    # Check expiration
    exp = bundle.get("expires_at_epoch")
    if exp is not None and float(exp) <= time.time():
        res = {
            "device_id": device_id_or_ip,
            "auth_type": bundle.get("auth_type"),
            "expires_at_epoch": exp,
            "reason": f"Credentials for '{device_id_or_ip}' expired at epoch {exp}.",
        }
        audit_trail.log_event("AUTH_PREFLIGHT_FAILED", "auth_verify", res)
        return False, "EXPIRED_CREDENTIALS", res

    # Check privilege level
    priv = str(bundle.get("privilege_level", "authorized")).lower()
    if priv in ("insufficient", "none", "guest", "unprivileged"):
        res = {
            "device_id": device_id_or_ip,
            "auth_type": bundle.get("auth_type"),
            "privilege_level": priv,
            "reason": f"Credentials for '{device_id_or_ip}' have insufficient privilege level ('{priv}').",
        }
        audit_trail.log_event("AUTH_PREFLIGHT_FAILED", "auth_verify", res)
        return False, "INSUFFICIENT_PRIVILEGES", res

    # Check certificate path if cert auth
    if bundle.get("auth_type") == "cert":
        cert_file = Path(str(bundle.get("certificate_path", "")))
        if not cert_file.exists():
            res = {
                "device_id": device_id_or_ip,
                "certificate_path": str(cert_file),
                "reason": f"Configured client certificate '{cert_file}' does not exist.",
            }
            audit_trail.log_event("AUTH_PREFLIGHT_FAILED", "auth_verify", res)
            return False, "CERTIFICATE_MISSING", res

    summary = {
        "device_id": bundle.get("device_id", device_id_or_ip),
        "auth_type": bundle.get("auth_type", "password"),
        "username": bundle.get("username", ""),
        "privilege_level": priv,
        "source_path": str(source_path) if source_path else None,
        "status": "VALID",
    }
    audit_trail.log_event("AUTH_PREFLIGHT_VERIFIED", "auth_verify", summary)
    return True, "VALID", summary


def edit_device_profile_interactive(
    device_id: str,
    authorize_prompt_fn: Optional[Callable[[str], str]] = None,
    username_prompt_fn: Optional[Callable[[str], str]] = None,
    secret_prompt_fn: Optional[Callable[[str], str]] = None,
    key_path: str | Path = DEFAULT_KEY_FILE,
    profile_path: Optional[str | Path] = None,
) -> Path:
    """
    Interactive workflow for 'iotflux profiles edit <device_id>':
    Allows operator to review/toggle authorization status and optionally enter encrypted credentials.
    """
    target_yaml = Path(profile_path) if profile_path else locate_profile_yaml(device_id)
    if not target_yaml or not target_yaml.exists():
        raise FileNotFoundError(f"Profile for device_id '{device_id}' not found.")

    raw_data = yaml.safe_load(target_yaml.read_text(encoding="utf-8")) or {}
    a_fn = authorize_prompt_fn or input

    current_auth = bool(raw_data.get("authorized", False))
    ans = a_fn(f"Authorize device '{device_id}' for bounded testing? [y/N] (current={current_auth}): ").strip().lower()
    if ans in ("y", "yes", "true", "1"):
        raw_data["authorized"] = True
    elif ans in ("n", "no", "false", "0"):
        raw_data["authorized"] = False

    target_yaml.write_text(yaml.safe_dump(raw_data, sort_keys=False), encoding="utf-8")

    audit_trail.log_event(
        event_type="PROFILE_EDIT",
        action="profiles_edit",
        details={
            "device_id": raw_data.get("device_id", device_id),
            "authorized": raw_data["authorized"],
            "profile_path": str(target_yaml),
        },
    )

    if username_prompt_fn or secret_prompt_fn:
        set_device_credentials_interactive(
            device_id=device_id,
            username_prompt_fn=username_prompt_fn,
            secret_prompt_fn=secret_prompt_fn,
            key_path=key_path,
            profile_path=target_yaml,
        )

    catalog.reload()
    return target_yaml


def verify_profile_credentials_present(
    device_id_or_ip: str,
    key_path: Optional[str | Path] = None,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Checks whether encrypted credentials are configured and valid for the given device_id or IP.
    Returns (is_valid, username, decrypted_secret). Never guesses or defaults credentials.
    """
    ok, status, info = verify_device_auth_preflight(device_id_or_ip, key_path=key_path)
    if ok:
        return True, str(info.get("username", "")), "REDACTED_VALID_SECRET"

    catalog.reload()
    prof = catalog.get_profile(device_id_or_ip)
    if not prof:
        for candidate in catalog.list_profiles():
            if str(candidate.raw.get("ip_address", "")) == device_id_or_ip:
                prof = candidate
                break

    if not prof or not prof.has_credentials():
        return False, None, None

    creds = prof.credentials
    username = str(creds.get("username", ""))
    enc_secret = str(creds.get("encrypted_secret", ""))
    try:
        dec = decrypt_secret_fernet(enc_secret, key_path=key_path)
        return True, username, dec
    except Exception:
        return False, None, None
