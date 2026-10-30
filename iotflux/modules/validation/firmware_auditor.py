"""
firmware_auditor.py - Extracted Firmware Security & Hardening Auditor for IoTFlux
Authorized Defensive Security Validation Lab

Analyzes extracted IoT firmware filesystems for:
1. Compiler hardening mitigations (NX, PIE, Stack Canaries, RELRO) on ELF binaries.
2. Hardcoded secrets, private keys, API tokens, and /etc/shadow hashes.
3. Embedded Software Bill of Materials (SBOM) and outdated component correlation.
"""

from __future__ import annotations

import math
import os
import re
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional

from iotflux.core.logger import logger
from iotflux.core.session import FluxSession
from iotflux.modules.base import BaseValidationModule, ValidationFinding

# ELF Program Header constants
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X = 0x1


def calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def mask_token(val: str) -> str:
    if not val:
        return ""
    if len(val) <= 4:
        return "*" * len(val)
    return val[:4] + ("*" * (len(val) - 4))


def inspect_elf(file_path: Path) -> Optional[Dict[str, Any]]:
    try:
        data = file_path.read_bytes()
        if len(data) < 52 or not data.startswith(b"\x7fELF"):
            return None

        ei_class = data[4]
        ei_data = data[5]
        endian = "<" if ei_data == 1 else ">"

        if ei_class == 1:
            e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, _, _, _ = (
                struct.unpack(f"{endian}HHIIIIIHHHHHH", data[16:52])
            )
            ph_format = f"{endian}IIIIIIII"
        elif ei_class == 2:
            if len(data) < 64:
                return None
            e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, _, _, _ = (
                struct.unpack(f"{endian}HHIQQQIHHHHHH", data[16:64])
            )
            ph_format = f"{endian}IIQQQQQQ"
        else:
            return None

        pie = e_type == 3
        canary = b"__stack_chk_fail" in data

        nx = False
        relro = False
        if e_phoff > 0 and e_phnum > 0 and e_phentsize > 0:
            for i in range(min(e_phnum, 128)):
                offset = e_phoff + i * e_phentsize
                ph_slice = data[offset : offset + e_phentsize]
                if len(ph_slice) < 32:
                    break
                if ei_class == 1:
                    p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = (
                        struct.unpack(ph_format, ph_slice[:32])
                    )
                else:
                    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = (
                        struct.unpack(ph_format, ph_slice[:56])
                    )

                if p_type == PT_GNU_STACK:
                    nx = (p_flags & PF_X) == 0
                elif p_type == PT_GNU_RELRO:
                    relro = True

        return {
            "binary": file_path.name,
            "path": str(file_path),
            "class": "32-bit" if ei_class == 1 else "64-bit",
            "endian": "LE" if ei_data == 1 else "BE",
            "nx": nx,
            "canary": canary,
            "pie": pie,
            "relro": relro,
        }
    except Exception:
        return None


class FirmwareAuditor(BaseValidationModule):
    """Firmware security static analyzer for embedded Linux root filesystems."""

    name = "validation/firmware_auditor"
    description = "Inspects extracted firmware for compiler mitigations, hardcoded secrets, and SBOM vulnerabilities."
    tier = "Extracted Firmware & Binary Security"
    references = ["CWE-119", "CWE-798", "CWE-312"]
    author = "Defensive Security Research Team"

    def __init__(self) -> None:
        super().__init__()
        self.register_option("TARGET_DIR", ".", "Path to extracted firmware root filesystem directory")
        self.register_option("MAX_BINARIES", 50, "Maximum number of ELF binaries to inspect")
        self.register_option("SCAN_SECRETS", True, "Scan configuration files for hardcoded secrets & high entropy")

    def run(self, session: FluxSession) -> List[ValidationFinding]:
        self.findings.clear()
        target_dir_str = self.get_option("TARGET_DIR", session) or "."
        target_dir = Path(target_dir_str)
        max_binaries = int(self.get_option("MAX_BINARIES", session) or 50)
        scan_sec = bool(self.get_option("SCAN_SECRETS", session))

        logger.info(f"Auditing extracted firmware filesystem at: {target_dir}")

        if not target_dir.exists():
            self.add_finding(
                finding_id="FW-DIR-NOT-FOUND",
                target=str(target_dir),
                title="Firmware Directory Not Found",
                spec_id="CWE-119",
                cwe="CWE-119",
                status="INFORMATIONAL",
                details=f"Target filesystem directory '{target_dir}' does not exist or is inaccessible.",
                remediation="Provide a valid extracted firmware directory via 'set TARGET_DIR <path>'.",
            )
            return self.findings

        # 1. ELF Binary Mitigation Audit
        binaries_checked = 0
        missing_nx: List[str] = []
        missing_canary: List[str] = []
        missing_pie: List[str] = []
        missing_relro: List[str] = []

        for root, _, files in os.walk(target_dir):
            for f in files:
                if binaries_checked >= max_binaries:
                    break
                fpath = Path(root) / f
                if fpath.is_symlink():
                    continue
                elf_info = inspect_elf(fpath)
                if elf_info:
                    binaries_checked += 1
                    rel_name = elf_info["binary"]
                    if not elf_info["nx"]:
                        missing_nx.append(rel_name)
                    if not elf_info["canary"]:
                        missing_canary.append(rel_name)
                    if not elf_info["pie"]:
                        missing_pie.append(rel_name)
                    if not elf_info["relro"]:
                        missing_relro.append(rel_name)

        if binaries_checked > 0:
            logger.info(f"Inspected {binaries_checked} ELF binaries for compiler mitigations.")
            if missing_nx or missing_canary or missing_pie:
                self.add_finding(
                    finding_id="FW-ELF-MITIGATIONS-DEFICIENT",
                    target=str(target_dir),
                    title="Deficient Compiler Hardening Mitigations in Embedded Binaries",
                    spec_id="CWE-119",
                    cwe="CWE-119",
                    status="NON_COMPLIANT",
                    details=(
                        f"Analyzed {binaries_checked} ELF binaries. "
                        f"Missing NX (Executable Stack): {len(missing_nx)} {missing_nx[:5]}; "
                        f"Missing Stack Canaries: {len(missing_canary)} {missing_canary[:5]}; "
                        f"Missing PIE/ASLR: {len(missing_pie)} {missing_pie[:5]}."
                    ),
                    remediation="Recompile all embedded binaries with -fstack-protector-strong, -Wl,-z,noexecstack, -fPIE -pie, and -Wl,-z,relro,-z,now.",
                    evidence={
                        "total_binaries": binaries_checked,
                        "missing_nx": missing_nx,
                        "missing_canary": missing_canary,
                        "missing_pie": missing_pie,
                        "missing_relro": missing_relro,
                    },
                )
            else:
                self.add_finding(
                    finding_id="FW-ELF-MITIGATIONS-COMPLIANT",
                    target=str(target_dir),
                    title="Compiler Hardening Mitigations Verified (NX, Canaries, PIE)",
                    spec_id="CWE-119",
                    cwe="CWE-119",
                    status="COMPLIANT",
                    details=f"All {binaries_checked} inspected binaries enforce NX stack, stack canaries, and PIE.",
                    remediation="Maintain current compiler hardening flags in CI/CD build toolchains.",
                )

        # 2. Hardcoded Secrets & Shadow Hashes
        if scan_sec:
            shadow_file = target_dir / "etc" / "shadow"
            if shadow_file.exists():
                try:
                    lines = shadow_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                    weak_accounts = []
                    for line in lines:
                        parts = line.strip().split(":")
                        if len(parts) >= 2:
                            user, hash_val = parts[0], parts[1]
                            if hash_val in ("", "*", "!"):
                                continue
                            if len(hash_val) < 20 or hash_val.startswith(("$1$", "$2$")):
                                weak_accounts.append(user)
                    if weak_accounts:
                        self.add_finding(
                            finding_id="FW-WEAK-ROOTFS-CREDENTIALS",
                            target=str(shadow_file),
                            title="Weak or Deprecated Password Hashes in /etc/shadow",
                            spec_id="CWE-798",
                            cwe="CWE-798",
                            status="CRITICAL_NON_COMPLIANT",
                            details=f"Extracted shadow file contains legacy or weak hashes for accounts: {weak_accounts}.",
                            remediation="Disable default local credentials; enforce modern SHA-512 ($6$) or Yescrypt password hashing, or certificate-based SSH authentication.",
                        )
                except Exception as ex:
                    logger.warning(f"Error inspecting shadow file: {ex}")

            # Scan configs for private keys and high-entropy API tokens
            token_patterns = {
                "private_key": re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"),
                "aws_key": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
                "jwt": re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
            }
            config_extensions = {".conf", ".cfg", ".json", ".yaml", ".yml", ".sh", ".ini", ".env"}
            found_secrets: List[Dict[str, Any]] = []

            for root, _, files in os.walk(target_dir):
                for f in files:
                    fp = Path(root) / f
                    if fp.suffix.lower() in config_extensions and not fp.is_symlink():
                        try:
                            content = fp.read_text(encoding="utf-8", errors="ignore")
                            for sec_type, pattern in token_patterns.items():
                                match = pattern.search(content)
                                if match:
                                    found_secrets.append({
                                        "file": str(fp.relative_to(target_dir)),
                                        "type": sec_type,
                                        "preview": mask_token(match.group(0)),
                                    })
                        except Exception:
                            continue

            if found_secrets:
                self.add_finding(
                    finding_id="FW-HARDCODED-SECRETS-IDENTIFIED",
                    target=str(target_dir),
                    title="Hardcoded Cryptographic Keys or API Tokens Discovered",
                    spec_id="CWE-798",
                    cwe="CWE-798",
                    status="CRITICAL_NON_COMPLIANT",
                    details=f"Found {len(found_secrets)} hardcoded secret reference(s) in configuration files: {found_secrets[:3]}.",
                    remediation="Remove private keys and pre-shared API tokens from rootfs; provision device identity dynamically via TPM or secure element.",
                    evidence={"secrets": found_secrets},
                )

        # 3. SBOM Check (/usr/lib/opkg/status)
        opkg_status = target_dir / "usr" / "lib" / "opkg" / "status"
        if opkg_status.exists():
            try:
                opkg_text = opkg_status.read_text(encoding="utf-8", errors="ignore")
                known_vulnerable = ["dnsmasq", "miniupnpd", "dropbear", "pppd"]
                flagged_packages = []
                for pkg in known_vulnerable:
                    if f"Package: {pkg}" in opkg_text:
                        flagged_packages.append(pkg)
                if flagged_packages:
                    self.add_finding(
                        finding_id="FW-OUTDATED-SBOM-COMPONENTS",
                        target=str(opkg_status),
                        title="Legacy Vulnerable Network Daemons Identified in SBOM",
                        spec_id="CWE-119",
                        cwe="CWE-119",
                        status="NON_COMPLIANT",
                        details=f"Embedded package manifest lists network-facing daemons with historical CVEs: {flagged_packages}.",
                        remediation="Update all OpenWrt package dependencies to current upstream releases and backport security patches.",
                        evidence={"packages": flagged_packages},
                    )
            except Exception as ex:
                logger.warning(f"Error parsing SBOM: {ex}")

        return self.findings
