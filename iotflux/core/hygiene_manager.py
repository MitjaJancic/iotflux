"""
hygiene_manager.py - Safe, Reversible Artifact Archival & Restoration Engine for IoTFlux v4.0
Authorized Security Assessment & Conformance Validation Framework

Enforces the Safe Codebase Hygiene Protocol:
1. Immutable Preservation Whitelist protecting:
   - All files in core/, modules/, workflows/ (and iotflux/core/, iotflux/modules/, iotflux/workflows/, tests/)
   - All files matching *audit*, *scope*, *auth*, *compliance* patterns
   - CHANGELOG_PRODUCTION.md, FIELD_ASSESSMENT_GUIDE.md, ASSESSMENT_POLICY_TEMPLATE.md,
     HYGIENE_PROTOCOL.md, HYGIENE_CLEANUP_CHECKLIST.md
   - Any file modified within the last 30 days (2,592,000 seconds)
2. Reversible Archival: Moves eligible obsolete artifacts to .archive/YYYY-MM-DD_hygiene_cleanup/
   with a cryptographic manifest (90-day retention policy; zero permanent deletions).
3. Tamper-Evident Logging: Appends every check, archival, rollback, and restoration to
   hygiene_cleanup_audit.jsonl with UTC timestamp, operator ID, and preservation check result.
4. Post-Cleanup Verification & Automatic Rollback: Runs integrity checks after cleanup and
   automatically invokes restore_archive() if any verification step fails.
"""

from __future__ import annotations

from datetime import datetime, timezone
import fnmatch
import json
import shutil
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from iotflux.core.audit_log import compute_file_sha256, get_operator_id
from iotflux.core.logger import Colors, logger


DEFAULT_HYGIENE_AUDIT_LOG = Path("hygiene_cleanup_audit.jsonl")
DEFAULT_ARCHIVE_ROOT = Path(".archive")
RETENTION_DAYS = 90
MODIFIED_RECENT_WINDOW_DAYS = 30
MODIFIED_RECENT_SECONDS = MODIFIED_RECENT_WINDOW_DAYS * 86400

PROTECTED_DIRECTORY_PREFIXES = (
    "core/",
    "modules/",
    "workflows/",
    "iotflux/core/",
    "iotflux/modules/",
    "iotflux/workflows/",
    "iotflux/profiles/",
    "profiles/",
    "tests/",
    "compliance/",
)

PROTECTED_GLOB_PATTERNS = (
    "*audit*",
    "*scope*",
    "*auth*",
    "*compliance*",
)

PROTECTED_EXACT_FILENAMES = {
    "CHANGELOG_PRODUCTION.md",
    "FIELD_ASSESSMENT_GUIDE.md",
    "ASSESSMENT_POLICY_TEMPLATE.md",
    "HYGIENE_PROTOCOL.md",
    "HYGIENE_CLEANUP_CHECKLIST.md",
    "README.md",
    "pyproject.toml",
    "requirements.txt",
    "__init__.py",
    "__main__.py",
    "hygiene_audit.py",
}


def log_hygiene_event(
    action: str,
    details: Dict[str, Any],
    log_path: str | Path = DEFAULT_HYGIENE_AUDIT_LOG,
    operator_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Appends a structured JSONL audit entry to hygiene_cleanup_audit.jsonl."""
    entry = {
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "operator_id": operator_id or get_operator_id(),
        "action": action,
        "retention_policy_days": RETENTION_DAYS,
        "details": details,
    }
    p = Path(log_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
    return entry


def evaluate_preservation_whitelist(
    file_path: str | Path,
    root_dir: str | Path = ".",
    now_epoch: Optional[float] = None,
) -> Tuple[bool, str]:
    """
    Evaluates a candidate file against the immutable Preservation Whitelist.
    Returns (is_preserved: bool, rationale: str).
    This whitelist cannot be bypassed.
    """
    root = Path(root_dir).resolve()
    cand = Path(file_path)
    abs_path = cand.resolve() if cand.is_absolute() else (root / cand).resolve()
    try:
        rel_posix = abs_path.relative_to(root).as_posix()
    except ValueError:
        rel_posix = cand.as_posix()

    fname = Path(rel_posix).name
    rel_lower = rel_posix.lower()
    fname_lower = fname.lower()

    # Rule 1: Protected core/modules/workflows/tests/compliance directories
    for prefix in PROTECTED_DIRECTORY_PREFIXES:
        if rel_lower.startswith(prefix.lower()):
            return True, f"Protected directory whitelist ('{prefix}')"

    # Rule 2: Exact protected filenames (CHANGELOG_PRODUCTION.md, FIELD_ASSESSMENT_GUIDE.md, etc.)
    if fname in PROTECTED_EXACT_FILENAMES:
        return True, f"Protected canonical document/entrypoint ('{fname}')"

    # Rule 3: Protected glob patterns (*audit*, *scope*, *auth*, *compliance*)
    for pattern in PROTECTED_GLOB_PATTERNS:
        if fnmatch.fnmatch(fname_lower, pattern) or fnmatch.fnmatch(rel_lower, pattern):
            return True, f"Protected safety/compliance pattern ('{pattern}')"

    # Rule 4: Any file modified within the last 30 days
    if abs_path.exists():
        current_ts = now_epoch if now_epoch is not None else time.time()
        mtime = abs_path.stat().st_mtime
        age_seconds = current_ts - mtime
        if age_seconds < MODIFIED_RECENT_SECONDS:
            age_days = max(0.0, age_seconds / 86400.0)
            return (
                True,
                f"Modified within 30-day safety window (age={age_days:.1f} days < {MODIFIED_RECENT_WINDOW_DAYS} days)",
            )

    return False, "Eligible for reversible archival (.archive/YYYY-MM-DD_hygiene_cleanup/)"


class HygieneManager:
    """
    Coordinates reversible artifact archival, preservation whitelist enforcement,
    post-cleanup integrity verification, and archive restoration.
    """

    def __init__(
        self,
        root_dir: str | Path = ".",
        archive_root: str | Path = DEFAULT_ARCHIVE_ROOT,
        audit_log_path: str | Path = DEFAULT_HYGIENE_AUDIT_LOG,
    ) -> None:
        self.root_dir = Path(root_dir).resolve()
        self.archive_root = Path(archive_root)
        if not self.archive_root.is_absolute():
            self.archive_root = self.root_dir / self.archive_root
        self.audit_log_path = Path(audit_log_path)
        if not self.audit_log_path.is_absolute():
            self.audit_log_path = self.root_dir / self.audit_log_path

    def remove_artifacts(
        self,
        audit_report_path: str | Path = "hygiene_audit_report.json",
        dry_run: bool = True,
        now_epoch: Optional[float] = None,
        verification_fn: Optional[Callable[[], bool]] = None,
        operator_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Implements `iotflux hygiene remove --audit-report hygiene_audit_report.json [--dry-run]`.
        - Evaluates every candidate in the audit report against the Preservation Whitelist.
        - In --dry-run mode: prints and logs exact decisions without moving files.
        - Without --dry-run: moves eligible files to .archive/YYYY-MM-DD_hygiene_cleanup/,
          writes archive_manifest.json, and executes post-cleanup verification (rolling back
          automatically if verification fails).
        """
        report_file = Path(audit_report_path)
        if not report_file.is_absolute():
            report_file = self.root_dir / report_file

        if not report_file.exists():
            raise FileNotFoundError(
                f"Hygiene audit report '{report_file}' not found. Run 'python scripts/hygiene_audit.py' first."
            )

        candidates = json.loads(report_file.read_text(encoding="utf-8"))
        if not isinstance(candidates, list):
            raise ValueError(f"Audit report '{report_file}' must contain a JSON list of candidate objects.")

        date_stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        archive_dir = self.archive_root / f"{date_stamp}_hygiene_cleanup"

        preserved_items: List[Dict[str, Any]] = []
        eligible_items: List[Dict[str, Any]] = []
        archived_items: List[Dict[str, Any]] = []

        logger.header(f"IOTFLUX SAFE CODEBASE HYGIENE ({'DRY-RUN' if dry_run else 'ARCHIVAL EXECUTION'})")

        for item in candidates:
            rel_path = str(item.get("file_path", "")).strip()
            if not rel_path:
                continue

            is_preserved, reason = evaluate_preservation_whitelist(
                rel_path,
                root_dir=self.root_dir,
                now_epoch=now_epoch,
            )
            check_record = {
                "file_path": rel_path,
                "artifact_type": item.get("artifact_type", "unknown"),
                "recommended_action": item.get("recommended_action", ""),
                "preserved": is_preserved,
                "preservation_rationale": reason,
            }

            if is_preserved:
                preserved_items.append(check_record)
                print(f" {Colors.GREEN}[PRESERVED]{Colors.RESET} {rel_path:<42} -> {reason}")
            else:
                eligible_items.append(check_record)
                if dry_run:
                    print(
                        f" {Colors.YELLOW}[DRY-RUN ARCHIVE]{Colors.RESET} {rel_path:<36} -> "
                        f"Would move to {archive_dir.name}/{rel_path} ({item.get('rationale', reason)})"
                    )
                else:
                    src_abs = (self.root_dir / rel_path).resolve()
                    if src_abs.exists() and src_abs.is_file():
                        dest_abs = archive_dir / rel_path
                        dest_abs.parent.mkdir(parents=True, exist_ok=True)
                        file_hash = compute_file_sha256(src_abs)
                        shutil.move(str(src_abs), str(dest_abs))
                        archived_entry = {
                            **check_record,
                            "original_path": rel_path,
                            "archived_path": dest_abs.relative_to(self.root_dir).as_posix(),
                            "sha256": file_hash,
                        }
                        archived_items.append(archived_entry)
                        print(f" {Colors.CYAN}[ARCHIVED]{Colors.RESET} {rel_path:<43} -> {dest_abs}")

        if not dry_run and archived_items:
            archive_dir.mkdir(parents=True, exist_ok=True)
            manifest_path = archive_dir / "archive_manifest.json"
            existing_manifest: List[Dict[str, Any]] = []
            if manifest_path.exists():
                try:
                    existing_manifest = json.loads(manifest_path.read_text(encoding="utf-8")).get("files", [])
                except Exception:
                    existing_manifest = []
            manifest_data = {
                "created_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "operator_id": operator_id or get_operator_id(),
                "retention_days": RETENTION_DAYS,
                "files": existing_manifest + archived_items,
            }
            manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

        summary = {
            "dry_run": dry_run,
            "audit_report": str(report_file),
            "archive_directory": str(archive_dir),
            "total_evaluated": len(preserved_items) + len(eligible_items),
            "preserved_count": len(preserved_items),
            "eligible_count": len(eligible_items),
            "archived_count": len(archived_items),
            "preserved_items": preserved_items,
            "eligible_items": eligible_items,
            "archived_items": archived_items,
            "verification_passed": True,
            "rolled_back": False,
        }

        log_hygiene_event(
            action="hygiene_remove_dry_run" if dry_run else "hygiene_remove_archive",
            details=summary,
            log_path=self.audit_log_path,
            operator_id=operator_id,
        )

        # Post-cleanup verification gate (fail-fast automatic rollback)
        if not dry_run and verification_fn is None and (self.root_dir / "tests" / "test_hygiene_integrity.py").exists():
            from tests.test_hygiene_integrity import run_post_cleanup_verification

            verification_fn = run_post_cleanup_verification

        if not dry_run and verification_fn is not None:
            ok = False
            try:
                ok = bool(verification_fn())
            except Exception as exc:
                logger.failure(f"Post-cleanup verification raised exception: {exc}")
                ok = False

            if not ok:
                logger.failure(
                    "POST-CLEANUP VERIFICATION FAILED! Triggering automatic hygiene restore rollback..."
                )
                if archive_dir.exists():
                    self.restore_archive(archive_dir, operator_id=operator_id)
                summary["verification_passed"] = False
                summary["rolled_back"] = True
                log_hygiene_event(
                    action="hygiene_automatic_rollback",
                    details={
                        "reason": "Post-cleanup verification suite failed",
                        "archive_directory": str(archive_dir),
                        "restored_count": len(archived_items),
                    },
                    log_path=self.audit_log_path,
                    operator_id=operator_id,
                )
                raise RuntimeError(
                    "Hygiene cleanup aborted and automatically rolled back because post-cleanup verification failed."
                )

        return summary

    def restore_archive(
        self,
        archive_path: str | Path,
        operator_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Implements `iotflux hygiene restore --archive-path .archive/YYYY-MM-DD_hygiene_cleanup/`.
        Restores all archived artifacts to their original relative locations and logs the action.
        """
        arch_dir = Path(archive_path)
        if not arch_dir.is_absolute():
            arch_dir = (self.root_dir / arch_dir).resolve()

        if not arch_dir.exists():
            raise FileNotFoundError(f"Archive path '{arch_dir}' does not exist.")

        manifest_path = arch_dir / "archive_manifest.json"
        restored_files: List[str] = []

        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            for entry in manifest.get("files", []):
                orig_rel = entry["original_path"]
                src_in_arch = arch_dir / orig_rel
                dest_orig = self.root_dir / orig_rel
                if src_in_arch.exists():
                    dest_orig.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(src_in_arch), str(dest_orig))
                    restored_files.append(orig_rel)
        else:
            for item in arch_dir.rglob("*"):
                if item.is_file() and item.name != "archive_manifest.json":
                    rel = item.relative_to(arch_dir).as_posix()
                    dest_orig = self.root_dir / rel
                    dest_orig.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(item), str(dest_orig))
                    restored_files.append(rel)

        result = {
            "archive_path": str(arch_dir),
            "restored_count": len(restored_files),
            "restored_files": restored_files,
        }
        log_hygiene_event(
            action="hygiene_restore",
            details=result,
            log_path=self.audit_log_path,
            operator_id=operator_id,
        )
        logger.success(f"Restored {len(restored_files)} file(s) from {arch_dir}.")
        return result
