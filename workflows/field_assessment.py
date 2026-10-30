"""
workflows/field_assessment.py - Top-level entrypoint for the IoTFlux Field Assessment Orchestrator
Authorized Security Assessment & Conformance Validation Framework
"""

from __future__ import annotations

import sys

from iotflux.workflows.field_assessment import (
    FIELD_ASSESSMENT_STEPS,
    FieldAssessmentOrchestrator,
    FieldAssessmentStep,
    main,
)

__all__ = [
    "FieldAssessmentOrchestrator",
    "FieldAssessmentStep",
    "FIELD_ASSESSMENT_STEPS",
    "main",
]

if __name__ == "__main__":
    sys.exit(main())
