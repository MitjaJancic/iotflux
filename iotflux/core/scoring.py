"""
scoring.py - Formulaic damage quantification and risk weighting engine for IoTFlux
Authorized Defensive Security Validation Lab

Calculates numerical damage scores (0.0 to 10.0) across 5 dimensions:
1. physical_safety (actuator/perimeter danger)
2. privacy (telemetry/video exposure)
3. financial (meter fraud/billing anomalies)
4. availability (daemon denial/lockout)
5. chaining_depth (lateral pivot distance across network zones)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

DIMENSIONS = ["physical_safety", "privacy", "financial", "availability", "chaining_depth"]

DIMENSION_DESCRIPTIONS = {
    "chaining_depth": {
        0: "Isolated (Single Endpoint)",
        1: "Local Subnet (Adjacent Pivot)",
        2: "Multi-Service Pivot (Hub/Broker Compromise)",
        3: "Full Perimeter to Physical Breach",
    },
    "physical_safety": {
        0: "None (Digital Only)",
        1: "Environmental Nuisance / State Tampering",
        2: "Equipment Hazard / Actuator Control",
        3: "Physical Perimeter Breach (Door/Lock/Gate Actuated)",
    },
    "privacy": {
        0: "None",
        1: "Device Fingerprint / Metadata Leak",
        2: "Continuous Telemetry / Sensor Exposure",
        3: "Surveillance Feed / Identity Exfiltration",
    },
    "financial": {
        0: "Negligible",
        1: "Minor / Single Billing Anomaly",
        2: "High Consumption / Meter Fraud",
        3: "Direct Financial Extraction / Fraud",
    },
    "availability": {
        0: "Normal Operation",
        1: "Transient Degradation",
        2: "Service Denial / Daemon Crash",
        3: "Permanent Device Lockout / Bricked",
    },
}

DEFAULT_WEIGHTS: Dict[str, float] = {
    "physical_safety": 1.2,
    "privacy": 0.8,
    "financial": 0.6,
    "availability": 0.8,
    "chaining_depth": 1.0,
}


@dataclass
class Finding:
    finding_id: str
    device_id: str
    check_name: str
    description: str
    cvss: Optional[float] = None
    damage: Dict[str, int] = field(default_factory=dict)
    evidence_path: Optional[str] = None
    remediation: Optional[str] = None
    cve: Optional[str] = None
    override_unvalidated: bool = False

    def damage_score(self, weights: Optional[Dict[str, float]] = None) -> float:
        w = weights or DEFAULT_WEIGHTS
        return sum(self.damage.get(dim, 0) * w.get(dim, 1.0) for dim in DIMENSIONS)

    def impact_levels(self) -> Dict[str, str]:
        levels = {}
        for dim in DIMENSIONS:
            val = int(self.damage.get(dim, 0))
            clamped = min(max(val, 0), 3)
            levels[dim] = DIMENSION_DESCRIPTIONS.get(dim, {}).get(clamped, str(val))
        return levels


@dataclass
class DamageRubric:
    finding_id: str
    composite_score: float
    composite_severity: str
    physical_safety: int
    privacy: int
    financial: int
    availability: int
    chaining_depth: int
    dimension_labels: Dict[str, str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DamageScorer:
    """Calculates weighted 5-dimensional damage score and categorizes severity."""

    def __init__(self, weights: Optional[Dict[str, float]] = None) -> None:
        self.weights = weights or DEFAULT_WEIGHTS

    def score_finding(self, finding: Finding) -> DamageRubric:
        dmg = finding.damage or {}
        raw_score = sum(int(dmg.get(dim, 0)) * self.weights.get(dim, 1.0) for dim in DIMENSIONS)

        # Scale raw score (out of 13.2 max) to 0.0 - 20.0 or 0.0 - 10.0 scale
        scaled_score = round(raw_score * 2.0, 1)

        if scaled_score >= 15.0 or dmg.get("physical_safety", 0) == 3:
            sev = "CRITICAL NON-COMPLIANCE"
        elif scaled_score >= 10.0:
            sev = "HIGH NON-COMPLIANCE"
        elif scaled_score >= 5.0:
            sev = "MEDIUM RISK"
        else:
            sev = "LOW / INFORMATIONAL"

        labels = {}
        for dim in DIMENSIONS:
            v = min(max(int(dmg.get(dim, 0)), 0), 3)
            labels[dim] = DIMENSION_DESCRIPTIONS.get(dim, {}).get(v, str(v))

        return DamageRubric(
            finding_id=finding.finding_id,
            composite_score=scaled_score,
            composite_severity=sev,
            physical_safety=int(dmg.get("physical_safety", 0)),
            privacy=int(dmg.get("privacy", 0)),
            financial=int(dmg.get("financial", 0)),
            availability=int(dmg.get("availability", 0)),
            chaining_depth=int(dmg.get("chaining_depth", 0)),
            dimension_labels=labels,
        )


def calculate_damage_score(damage_ratings: Dict[str, int], weights: Optional[Dict[str, float]] = None) -> float:
    w = weights or DEFAULT_WEIGHTS
    total = sum(damage_ratings.get(dim, 0) * w.get(dim, 1.0) for dim in DIMENSIONS)
    max_score = sum(3.0 * w.get(dim, 1.0) for dim in DIMENSIONS)
    if max_score <= 0:
        return 0.0
    scaled = (total / max_score) * 10.0
    return round(min(max(scaled, 0.0), 10.0), 1)


def get_dimension_descriptions(damage_ratings: Dict[str, int]) -> Dict[str, str]:
    descriptions = {}
    for dim in DIMENSIONS:
        val = min(max(damage_ratings.get(dim, 0), 0), 3)
        descriptions[dim] = DIMENSION_DESCRIPTIONS.get(dim, {}).get(val, str(val))
    return descriptions
