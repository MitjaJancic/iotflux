# IoTFlux v4.0 Codebase Hygiene Cleanup Checklist

**Change Request ID**: `[HYG-YYYY-MM-DD]`  
**Operator ID**: `[INSERT OPERATOR USERNAME]`  
**Date (UTC)**: `[YYYY-MM-DD]`  
**Target Repository**: `IoTFlux v4.0 Portable Assessment Framework`

---

## Mandatory Pre-Cleanup Verification Gates

All five verification gates below must be completed and signed off before executing `python -m iotflux hygiene remove` without `--dry-run`:

- [ ] **1. Audit Report Reviewed (`hygiene_audit_report.json`)**
  - Executed `python scripts/hygiene_audit.py --output hygiene_audit_report.json`.
  - Manually inspected all entries marked `recommended_action: "archive_candidate"` and confirmed none are required for active field engagements.

- [ ] **2. Preservation Whitelist Verified (`--dry-run`)**
  - Executed `python -m iotflux hygiene remove --audit-report hygiene_audit_report.json --dry-run`.
  - Confirmed that all files in `core/`, `modules/`, `workflows/`, all `*audit*`, `*scope*`, `*auth*`, `*compliance*` files, `CHANGELOG_PRODUCTION.md`, `FIELD_ASSESSMENT_GUIDE.md`, `ASSESSMENT_POLICY_TEMPLATE.md`, and all files modified within the last 30 days are marked `[PRESERVED]`.

- [ ] **3. Test Suite Passing Pre-Cleanup**
  - Executed `python -m unittest discover tests -v` and confirmed 100% pass rate across all unit, integration, and hygiene integrity tests.

- [ ] **4. Workspace Backup / Snapshot Created**
  - Created a verifiable Git tag / branch snapshot or full workspace archive prior to running archival operations.
  - Confirmed `.archive/YYYY-MM-DD_hygiene_cleanup/` has sufficient disk space for 90-day retention.

- [ ] **5. Stakeholder Approval Obtained**
  - Reviewed proposed archival manifest with the Lead Security Assessor / Maintainer and obtained formal sign-off below.

---

## Sign-Off Record

| Role | Name | Signature | Date (UTC) |
| :--- | :--- | :--- | :--- |
| **Executing Operator** | `[Name]` | `____________________` | `[YYYY-MM-DD]` |
| **Lead Assessor / Maintainer** | `[Name]` | `____________________` | `[YYYY-MM-DD]` |
| **Compliance Reviewer** | `[Name]` | `____________________` | `[YYYY-MM-DD]` |
