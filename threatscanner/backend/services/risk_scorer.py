"""
Risk scorer — converts a list of weighted signals into a 0-100 threat score.
"""
from dataclasses import dataclass, field
from typing import List


@dataclass
class ScanSignal:
    label: str
    weight: float        # 0.0 – 1.0  (additive; capped at 1.0 total)
    category: str        # "phishing" | "spam" | "malware" | "suspicious"


@dataclass
class ScanResult:
    score: int
    level: str
    summary: str
    signals: List[ScanSignal] = field(default_factory=list)
    extracted_text: str = ""


def compute_score(signals: List[ScanSignal], extracted_text: str = "") -> ScanResult:
    """
    Additive scoring: weights summed, clamped to 1.0, scaled to 0-100.
    A single weight=0.9 signal alone can push the score to 90.
    Multiple moderate signals compound to push past thresholds.
    """
    raw = sum(s.weight for s in signals)
    raw = min(raw, 1.0)
    score = int(raw * 100)

    if score < 30:
        level   = "safe"
        summary = "No significant threats detected. Content appears clean."
    elif score < 65:
        level   = "suspicious"
        summary = "Some indicators found. Review the flags below before interacting."
    else:
        level   = "dangerous"
        summary = "High-confidence threat. Do not click links or share personal data."

    return ScanResult(
        score=score,
        level=level,
        summary=summary,
        signals=signals,
        extracted_text=extracted_text,
    )
