"""
hygiene_audit.py - Automated Static Dead-Code & Obsolete Artifact Detector for IoTFlux v4.0
Authorized Security Assessment & Conformance Validation Framework

Performs strictly read-only static analysis across the repository:
1. AST-based Python analysis to identify unreferenced functions/classes and legacy modules.
2. Shell script reference scanning across CLI commands and active orchestrator workflows.
3. Configuration file usage tracking against scope_manager.py, credential_manager.py, and profile_generator.py.
4. Documentation cross-link analysis starting from docs/FIELD_ASSESSMENT_GUIDE.md and
   compliance/ASSESSMENT_POLICY_TEMPLATE.md.
5. Outputs a structured JSON array to hygiene_audit_report.json:
   {file_path, artifact_type, last_referenced_by, confidence_score, recommended_action}

CRITICAL SAFETY INVARIANT: This script only reports findings; it never deletes or modifies files.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


DEFAULT_REPORT_PATH = Path("hygiene_audit_report.json")

# Core v4.0 loader modules used as reference anchors for configuration files
CORE_CONFIG_LOADERS = (
    Path("iotflux/core/scope_manager.py"),
    Path("iotflux/core/credential_manager.py"),
    Path("iotflux/core/profile_generator.py"),
)

# Primary v4.0 documentation entry points
PRIMARY_DOC_ANCHORS = (
    Path("docs/FIELD_ASSESSMENT_GUIDE.md"),
    Path("compliance/ASSESSMENT_POLICY_TEMPLATE.md"),
    Path("CHANGELOG_PRODUCTION.md"),
)

IGNORED_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".venv",
    "venv",
    ".archive",
    "iotflux-tool",
    "iotflux.egg-info",
}


def _iter_repo_files(root_dir: Path) -> List[Path]:
    """Recursively lists all files in root_dir excluding ignored/cache directories."""
    files: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fname in filenames:
            files.append(Path(dirpath) / fname)
    return sorted(files)


def _collect_python_ast_references(py_files: List[Path], root_dir: Path) -> Tuple[Dict[str, Set[str]], Dict[str, List[str]]]:
    """
    Parses all Python files with AST to collect:
    - symbol_references: mapping of identifier name -> set of relative file paths referencing it
    - defined_symbols_by_file: mapping of relative file path -> list of top-level functions/classes defined
    """
    symbol_refs: Dict[str, Set[str]] = {}
    defined_by_file: Dict[str, List[str]] = {}

    for py_path in py_files:
        rel_str = py_path.relative_to(root_dir).as_posix()
        try:
            source = py_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=rel_str)
        except Exception:
            continue

        defs: List[str] = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if not node.name.startswith("__"):
                    defs.append(node.name)
        defined_by_file[rel_str] = defs

        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                symbol_refs.setdefault(node.id, set()).add(rel_str)
            elif isinstance(node, ast.Attribute):
                symbol_refs.setdefault(node.attr, set()).add(rel_str)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    for part in alias.name.split("."):
                        symbol_refs.setdefault(part, set()).add(rel_str)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    for part in node.module.split("."):
                        symbol_refs.setdefault(part, set()).add(rel_str)
                for alias in node.names:
                    symbol_refs.setdefault(alias.name, set()).add(rel_str)

    return symbol_refs, defined_by_file


def _collect_text_references(files: List[Path], root_dir: Path) -> Dict[str, str]:
    """Reads text content of all code/config/doc files for cross-reference matching."""
    contents: Dict[str, str] = {}
    for p in files:
        if p.suffix.lower() in {".py", ".sh", ".md", ".yaml", ".yml", ".json", ".env", ".txt"}:
            rel = p.relative_to(root_dir).as_posix()
            try:
                contents[rel] = p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                pass
    return contents


def run_hygiene_audit(
    root_dir: str | Path = ".",
    output_path: str | Path = DEFAULT_REPORT_PATH,
) -> List[Dict[str, Any]]:
    """
    Executes static dead-code and artifact reference analysis across root_dir
    and writes structured findings to output_path (hygiene_audit_report.json).
    """
    root = Path(root_dir).resolve()
    all_files = _iter_repo_files(root)
    py_files = [f for f in all_files if f.suffix == ".py"]

    symbol_refs, defined_by_file = _collect_python_ast_references(py_files, root)
    text_map = _collect_text_references(all_files, root)

    # Concatenate text of core v4.0 config loaders
    loader_texts: Dict[str, str] = {}
    for loader_rel in CORE_CONFIG_LOADERS:
        key = loader_rel.as_posix()
        if key in text_map:
            loader_texts[key] = text_map[key]

    # Concatenate text of primary v4.0 documentation anchors
    doc_anchor_texts: Dict[str, str] = {}
    for doc_rel in PRIMARY_DOC_ANCHORS:
        key = doc_rel.as_posix()
        if key in text_map:
            doc_anchor_texts[key] = text_map[key]

    # Concatenate CLI and v4.0 field workflow texts
    cli_and_workflow_texts: Dict[str, str] = {}
    for rel_path, content in text_map.items():
        if rel_path in ("iotflux/core/cli.py", "iotflux/workflows/field_assessment.py", "workflows/field_assessment.py"):
            cli_and_workflow_texts[rel_path] = content

    report_entries: List[Dict[str, Any]] = []

    for file_path in all_files:
        rel_posix = file_path.relative_to(root).as_posix()
        fname = file_path.name
        suffix = file_path.suffix.lower()

        # Skip the output report itself if already on disk
        if rel_posix == Path(output_path).name:
            continue

        # 1. Shell scripts (.sh)
        if suffix == ".sh":
            referencers = [
                src for src, body in cli_and_workflow_texts.items() if fname in body or rel_posix in body
            ]
            if not referencers:
                # Check if referenced only by legacy lab_orchestrator or script_registry
                legacy_refs = [
                    src for src, body in text_map.items()
                    if src != rel_posix and (fname in body or rel_posix in body)
                ]
                report_entries.append({
                    "file_path": rel_posix,
                    "artifact_type": "shell_script",
                    "last_referenced_by": legacy_refs[0] if legacy_refs else "none (unreferenced by CLI/v4.0 workflows)",
                    "confidence_score": 0.92 if not legacy_refs else 0.85,
                    "recommended_action": "archive_candidate",
                    "rationale": "Shell script is not invoked by any v4.0 CLI command or field assessment workflow.",
                })
            continue

        # 2. Configuration & Environment files (.env, .yaml, .yml, .txt, docker-compose.yml)
        if suffix in {".env", ".yaml", ".yml", ".txt"} and not rel_posix.startswith("iotflux/"):
            loader_refs = [
                ldr for ldr, body in loader_texts.items() if fname in body or rel_posix in body
            ]
            all_other_refs = [
                src for src, body in text_map.items()
                if src != rel_posix and (fname in body or rel_posix in body)
            ]
            if not loader_refs:
                confidence = 0.95 if suffix == ".env" or "docker-compose" in fname else 0.80
                action = "archive_candidate" if not rel_posix.startswith("profiles/") else "preserve_profile"
                report_entries.append({
                    "file_path": rel_posix,
                    "artifact_type": "configuration_file",
                    "last_referenced_by": all_other_refs[0] if all_other_refs else "none",
                    "confidence_score": confidence,
                    "recommended_action": action,
                    "rationale": (
                        "Configuration file is not loaded by scope_manager.py, credential_manager.py, "
                        "or profile_generator.py."
                    ),
                })
            else:
                report_entries.append({
                    "file_path": rel_posix,
                    "artifact_type": "configuration_file",
                    "last_referenced_by": ", ".join(loader_refs),
                    "confidence_score": 0.10,
                    "recommended_action": "preserve_active_config",
                    "rationale": "Actively loaded by v4.0 core configuration managers.",
                })
            continue

        # 3. Documentation files (.md)
        if suffix == ".md":
            is_primary_anchor = rel_posix in doc_anchor_texts or fname in {
                "FIELD_ASSESSMENT_GUIDE.md",
                "ASSESSMENT_POLICY_TEMPLATE.md",
                "CHANGELOG_PRODUCTION.md",
                "HYGIENE_PROTOCOL.md",
                "HYGIENE_CLEANUP_CHECKLIST.md",
                "README.md",
            }
            linked_from_anchors = [
                anchor for anchor, body in doc_anchor_texts.items()
                if fname in body or rel_posix in body
            ]
            other_doc_refs = [
                src for src, body in text_map.items()
                if src != rel_posix and (fname in body or rel_posix in body)
            ]
            if not is_primary_anchor and not linked_from_anchors:
                report_entries.append({
                    "file_path": rel_posix,
                    "artifact_type": "documentation_file",
                    "last_referenced_by": other_doc_refs[0] if other_doc_refs else "none",
                    "confidence_score": 0.88,
                    "recommended_action": "archive_candidate",
                    "rationale": (
                        "Documentation file is not linked from docs/FIELD_ASSESSMENT_GUIDE.md "
                        "or compliance/ASSESSMENT_POLICY_TEMPLATE.md."
                    ),
                })
            continue

        # 4. Python source files (.py) — AST symbol reference check
        if suffix == ".py":
            defs = defined_by_file.get(rel_posix, [])
            unreferenced_symbols: List[str] = []
            external_referencers: Set[str] = set()

            stem = file_path.stem
            if stem != "__init__":
                for ref_file in symbol_refs.get(stem, set()):
                    if ref_file != rel_posix:
                        external_referencers.add(ref_file)

            for sym in defs:
                refs = symbol_refs.get(sym, set())
                other_refs = {r for r in refs if r != rel_posix}
                if other_refs:
                    external_referencers.update(other_refs)
                else:
                    unreferenced_symbols.append(sym)

            if defs and len(unreferenced_symbols) == len(defs) and not external_referencers:
                report_entries.append({
                    "file_path": rel_posix,
                    "artifact_type": "python_module",
                    "last_referenced_by": "none (zero AST import/symbol references)",
                    "confidence_score": 0.78,
                    "recommended_action": "review_unreferenced_symbols",
                    "unreferenced_symbols": unreferenced_symbols,
                    "rationale": f"All top-level symbols ({unreferenced_symbols}) have zero external AST references.",
                })
            elif unreferenced_symbols and not rel_posix.startswith("tests/"):
                report_entries.append({
                    "file_path": rel_posix,
                    "artifact_type": "python_symbols",
                    "last_referenced_by": ", ".join(sorted(external_referencers)[:3]) or "self",
                    "confidence_score": 0.45,
                    "recommended_action": "preserve_core_module",
                    "unreferenced_symbols": unreferenced_symbols,
                    "rationale": (
                        f"Module is actively imported, with {len(unreferenced_symbols)} helper symbol(s) "
                        "only referenced internally or via CLI entrypoints."
                    ),
                })

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(report_entries, indent=2), encoding="utf-8")
    return report_entries


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="hygiene_audit",
        description="IoTFlux v4.0 Static Dead-Code & Obsolete Artifact Audit Tool (Read-Only)",
    )
    parser.add_argument("--root", default=".", help="Repository root directory to scan")
    parser.add_argument("--output", default=str(DEFAULT_REPORT_PATH), help="Output JSON report path")
    args = parser.parse_args(argv)

    entries = run_hygiene_audit(root_dir=args.root, output_path=args.output)
    candidates = [e for e in entries if e["recommended_action"] == "archive_candidate"]
    print(
        f"[+] Hygiene audit complete: {len(entries)} item(s) analyzed, "
        f"{len(candidates)} archive candidate(s) written to {args.output}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
