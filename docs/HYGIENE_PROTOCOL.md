# IoTFlux v4.0 Safe Codebase Hygiene Protocol

**Document Version**: 4.0.0  
**Scope**: Codebase Maintainability, Technical Debt Reduction, and Architectural Clarity  
**Safety Invariant**: Immutable Preservation Whitelist + 90-Day Reversible Archival + Fail-Fast Rollback

---

## 1. Overview

Following the v4.0 production generalization of **IoTFlux**, legacy artifacts (such as pre-v4.0 shell scripts, static environment files, or unlinked draft documentation) may accumulate as technical debt. The **Safe Codebase Hygiene Protocol** provides a deterministic, non-destructive process for identifying, reviewing, and reversibly archiving obsolete artifacts while guaranteeing that all safety gates, scope validators, credential managers, and compliance documentation remain untouched.

---

## 2. Running `scripts/hygiene_audit.py` and Interpreting Results

### 2.1 Execution
Run the read-only static analyzer via Python or the `iotflux` CLI:

```bash
# Direct script execution
python scripts/hygiene_audit.py --output hygiene_audit_report.json

# Or via the IoTFlux CLI
python -m iotflux hygiene audit --audit-report hygiene_audit_report.json
```

> [!IMPORTANT]
> `scripts/hygiene_audit.py` is strictly read-only. It never deletes, moves, or modifies any file.

### 2.2 Report Schema (`hygiene_audit_report.json`)
Each entry in `hygiene_audit_report.json` contains:
- `file_path`: Relative path of the analyzed artifact.
- `artifact_type`: `python_module`, `python_symbols`, `shell_script`, `configuration_file`, or `documentation_file`.
- `last_referenced_by`: The module, workflow, or document referencing the artifact (or `"none"`).
- `confidence_score`: Float (`0.0` to `1.0`) indicating confidence that the artifact is unreferenced by v4.0 workflows.
- `recommended_action`:
  - `archive_candidate`: Unreferenced by v4.0 core loaders/workflows; eligible for evaluation by `iotflux hygiene remove`.
  - `preserve_active_config` / `preserve_core_module` / `preserve_profile`: Actively used by v4.0 components.
  - `review_unreferenced_symbols`: Contains helper symbols for manual operator inspection.

---

## 3. Preservation Whitelist Rationale & Update Procedure

When running `python -m iotflux hygiene remove --audit-report hygiene_audit_report.json`, every candidate is checked against an immutable **Preservation Whitelist** in [`iotflux/core/hygiene_manager.py`](file:///C:/Users/mitja/Downloads/iotsploit/iotflux/core/hygiene_manager.py):

| Whitelist Rule | Protected Artifacts | Rationale |
| :--- | :--- | :--- |
| **Core Directories** | `core/`, `modules/`, `workflows/`, `iotflux/core/`, `iotflux/modules/`, `iotflux/workflows/`, `profiles/`, `tests/`, `compliance/` | Protects all runtime execution engines, protocol conformance modules, and test suites. |
| **Safety & Audit Patterns** | `*audit*`, `*scope*`, `*auth*`, `*compliance*` | Ensures scope enforcement, credential encryption, authorization gates, and audit trails can never be archived. |
| **Canonical Documentation** | `CHANGELOG_PRODUCTION.md`, `FIELD_ASSESSMENT_GUIDE.md`, `ASSESSMENT_POLICY_TEMPLATE.md`, `HYGIENE_PROTOCOL.md`, `HYGIENE_CLEANUP_CHECKLIST.md` | Preserves institutional governance and operator reference guides. |
| **30-Day Modification Window** | Any file modified within the last **30 days** (`mtime < 30d`) | Prevents accidental archival of active work-in-progress or recently updated engagement files. |

### Updating the Whitelist
To add new protected patterns or directories:
1. Update `PROTECTED_DIRECTORY_PREFIXES`, `PROTECTED_GLOB_PATTERNS`, or `PROTECTED_EXACT_FILENAMES` in [`iotflux/core/hygiene_manager.py`](file:///C:/Users/mitja/Downloads/iotsploit/iotflux/core/hygiene_manager.py).
2. Add a corresponding unit test in [`tests/test_hygiene_integrity.py`](file:///C:/Users/mitja/Downloads/iotsploit/tests/test_hygiene_integrity.py).
3. Verify all tests pass via `python -m unittest discover tests -v`.

---

## 4. Archive Retention Policy & Restoration Process

### 4.1 Dry-Run Preview (`--dry-run`)
Always preview archival actions first:
```bash
python -m iotflux hygiene remove --audit-report hygiene_audit_report.json --dry-run
```

### 4.2 Reversible Archival (90-Day Retention Window)
When executed without `--dry-run`:
```bash
python -m iotflux hygiene remove --audit-report hygiene_audit_report.json
```
- Eligible files are **moved** (never deleted) into `.archive/YYYY-MM-DD_hygiene_cleanup/<original_relative_path>`.
- An `archive_manifest.json` file is written inside the archive folder recording the original path, archived path, SHA-256 hash, operator ID, and 90-day retention window.
- Every decision is logged to `hygiene_cleanup_audit.jsonl`.

### 4.3 Restoring Archived Artifacts
To reverse a cleanup operation at any point within the 90-day retention window (or triggered automatically if post-cleanup verification fails):
```bash
python -m iotflux hygiene restore --archive-path .archive/YYYY-MM-DD_hygiene_cleanup/
```

---

## 5. Pre-Cleanup Operator Checklist

Before executing `iotflux hygiene remove` without `--dry-run`, operators must complete [`HYGIENE_CLEANUP_CHECKLIST.md`](file:///C:/Users/mitja/Downloads/iotsploit/HYGIENE_CLEANUP_CHECKLIST.md):
1. Run `python scripts/hygiene_audit.py` and review `hygiene_audit_report.json`.
2. Run `python -m iotflux hygiene remove --audit-report hygiene_audit_report.json --dry-run` and verify preservation whitelist output.
3. Confirm the full pre-cleanup test suite passes (`python -m unittest discover tests -v`).
4. Create a repository backup or Git tag.
5. Obtain lead assessor / stakeholder sign-off.
