"""
pin_entropy_analyzer.py - Smart lock guest PIN entropy and strength evaluator
Authorized Defensive Security Validation Lab (IoTFlux)
"""

from __future__ import annotations

import math
from typing import Any, Dict, List
import requests

from iotflux.core.logger import logger
from iotflux.core.session import FluxSession
from iotflux.modules.base import BaseValidationModule, ValidationFinding


class PinEntropyAnalyzer(BaseValidationModule):
    name = "validation/pin_entropy_analyzer"
    description = "Evaluates smart lock temporary guest PIN generation entropy and predictability against NIST SP 800-63B."
    tier = "Tier 3 - Perimeter Access & Authentication"
    references = ["NIST-SP-800-63B", "CWE-330", "CAPEC-112"]

    def __init__(self) -> None:
        super().__init__()
        self.register_option("TARGET", "172.30.4.20", "Target smart lock IP address")
        self.register_option("PORT", 80, "Smart lock HTTP service port")
        self.register_option("SAMPLES", 10, "Number of guest PIN samples to evaluate")

    def _shannon_entropy(self, samples: List[str]) -> float:
        if not samples:
            return 0.0
        freq: Dict[str, int] = {}
        for s in samples:
            freq[s] = freq.get(s, 0) + 1
        total = len(samples)
        ent = 0.0
        for count in freq.values():
            p = count / total
            ent -= p * math.log2(p)
        return ent

    def run(self, session: FluxSession) -> List[ValidationFinding]:
        self.findings.clear()
        target = self.get_option("TARGET", session)
        port = int(self.get_option("PORT", session) or 80)
        num_samples = int(self.get_option("SAMPLES") or 10)
        timeout = float(session.get_option("TIMEOUT", 3.0))

        logger.info(f"Auditing PIN generation entropy on {target}:{port} ({num_samples} samples)...")
        url = f"http://{target}:{port}/rpc/Lock.GenerateGuestPin"

        samples: List[str] = []
        for i in range(num_samples):
            try:
                res = requests.post(url, json={"id": i + 1, "params": {"expires_minutes": 60}}, timeout=timeout)
                if res.status_code == 200:
                    data = res.json()
                    pin = data.get("result", {}).get("guest_pin")
                    if pin:
                        samples.append(str(pin))
            except Exception as ex:
                logger.debug(f"PIN sample harvest notice: {ex}")
                break

        if not samples:
            logger.warning(f"No PIN samples could be gathered from {target}:{port}")
            return self.findings

        # Calculate metrics
        entropy_bits = self._shannon_entropy(samples)
        unique_pins = set(samples)
        collision_count = len(samples) - len(unique_pins)
        avg_len = sum(len(p) for p in samples) / len(samples)

        # Check predictability (differences between consecutive PINs)
        diffs = []
        for i in range(len(samples) - 1):
            try:
                diffs.append(abs(int(samples[i + 1]) - int(samples[i])))
            except ValueError:
                pass

        has_predictable_trend = len(set(diffs)) <= 2 and len(diffs) > 3

        logger.info(f"Observed {len(samples)} PINs. Unique: {len(unique_pins)}, Shannon Entropy: {entropy_bits:.2f} bits")

        # NIST SP 800-63B evaluation:
        # Minimum recommended PIN length is >= 6 digits; PRNG must be cryptographically secure (no predictable sequences).
        is_weak = (entropy_bits < 2.5 or collision_count > 0 or avg_len < 6 or has_predictable_trend)

        if is_weak:
            self.add_finding(
                finding_id="PIN-LOW-ENTROPY",
                target=f"{target}:{port}",
                title="Low-Entropy / Predictable Guest PIN Generation (NIST SP 800-63B Non-Conformance)",
                spec_id="NIST-SP-800-63B",
                cwe="CWE-330",
                status="NON_COMPLIANT",
                details=(
                    f"Sampled {len(samples)} PINs with average length {avg_len:.1f} digits. "
                    f"Measured Shannon entropy: {entropy_bits:.2f} bits (Collision count: {collision_count}). "
                    "Algorithm demonstrates linear congruential or timestamp-derived pseudo-random characteristics."
                ),
                remediation=(
                    "Implement a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG, e.g. /dev/urandom "
                    "or hardware TRNG) with minimum 6-digit PIN length and rate-limited attempt throttling per NIST SP 800-63B Section 5.1.1."
                ),
                evidence={
                    "sample_pins": samples,
                    "shannon_entropy_bits": entropy_bits,
                    "unique_pins_count": len(unique_pins),
                    "collision_count": collision_count,
                    "average_length": avg_len,
                },
            )
        else:
            self.add_finding(
                finding_id="PIN-ENTROPY-SUFFICIENT",
                target=f"{target}:{port}",
                title="Sufficient PIN Entropy Conformance",
                spec_id="NIST-SP-800-63B",
                cwe="CWE-330",
                status="COMPLIANT",
                details=f"Sampled PINs exhibited sufficient randomness ({entropy_bits:.2f} bits) with no collisions.",
                remediation="Ensure token expiration and rate-limiting policies remain enforced.",
                evidence={"entropy_bits": entropy_bits},
            )

        return self.findings
