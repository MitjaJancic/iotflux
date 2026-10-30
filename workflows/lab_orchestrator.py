"""
workflows/lab_orchestrator.py - Top-level entrypoint for the IoTFlux Lab Orchestrator
Authorized Defensive Security Validation Lab
"""

from __future__ import annotations

import sys

from iotflux.workflows.lab_orchestrator import (
    FALLBACK_ORCHESTRATOR_LOG,
    PRIMARY_ORCHESTRATOR_LOG,
    WORKFLOW_STEPS,
    LabOrchestrator,
    WorkflowStepSpec,
    log_orchestrator_step,
    main,
    resolve_orchestrator_log_path,
    run_infra_start,
)

__all__ = [
    "LabOrchestrator",
    "WorkflowStepSpec",
    "WORKFLOW_STEPS",
    "PRIMARY_ORCHESTRATOR_LOG",
    "FALLBACK_ORCHESTRATOR_LOG",
    "resolve_orchestrator_log_path",
    "log_orchestrator_step",
    "run_infra_start",
    "main",
]

if __name__ == "__main__":
    sys.exit(main())
