"""Transparent scoring model and risk weighting profiles for NexoraPay.

IMPORTANT:
- This is a DEMONSTRATION prioritisation model, NOT the official CVSS calculation.
- Demo model weights — not an industry standard.
- CVSS Base Score strictly measures intrinsic technical flaw severity.
- Operational priority adds KEV, EPSS, Exposure, Criticality, and Risk Appetite.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from nexorapay.models import (
    Criticality,
    EvaluationContext,
    Exposure,
    PriorityLevel,
    RiskAppetite,
    ScoreContribution,
)


@dataclass(frozen=True)
class ProfileWeights:
    """Weight distribution for contextual risk scoring."""
    cvss: float
    kev: float
    epss: float
    exposure: float
    criticality: float

    def __getitem__(self, item: str) -> float:
        return getattr(self, item)

    def to_dict(self) -> Dict[str, float]:
        return {
            "cvss": self.cvss,
            "kev": self.kev,
            "epss": self.epss,
            "exposure": self.exposure,
            "criticality": self.criticality,
        }

    def format_percentages(self) -> Dict[str, str]:
        return {
            "cvss": f"{int(self.cvss * 100)}%",
            "kev": f"{int(self.kev * 100)}%",
            "epss": f"{int(self.epss * 100)}%",
            "exposure": f"{int(self.exposure * 100)}%",
            "criticality": f"{int(self.criticality * 100)}%",
        }


# Section 8: Three Fictional Organisational Risk Profiles
PROFILE_WEIGHTS: Dict[RiskAppetite, ProfileWeights] = {
    RiskAppetite.LOW: ProfileWeights(
        cvss=0.30,
        kev=0.35,
        epss=0.20,
        exposure=0.10,
        criticality=0.05,
    ),
    RiskAppetite.MEDIUM: ProfileWeights(
        cvss=0.30,
        kev=0.25,
        epss=0.20,
        exposure=0.15,
        criticality=0.10,
    ),
    RiskAppetite.HIGH: ProfileWeights(
        cvss=0.40,
        kev=0.20,
        epss=0.15,
        exposure=0.15,
        criticality=0.10,
    ),
}

# Normalization mappings for discrete contextual dimensions
EXPOSURE_FACTORS: Dict[Exposure, float] = {
    Exposure.INTERNET_FACING: 1.0,
    Exposure.INTERNAL: 0.30,
}

CRITICALITY_FACTORS: Dict[Criticality, float] = {
    Criticality.CRITICAL: 1.0,
    Criticality.HIGH: 0.65,
    Criticality.NORMAL: 0.30,
    Criticality.LOW: 0.10,
}


def normalize_cvss(cvss: float) -> float:
    """Normalize CVSS score (0.0 - 10.0) to a 0.0 - 1.0 range."""
    if cvss is None:
        return 0.0
    return max(0.0, min(10.0, float(cvss))) / 10.0


def normalize_kev(kev: bool) -> float:
    """Convert CISA KEV presence to a 1.0 (True) or 0.0 (False) factor."""
    return 1.0 if bool(kev) else 0.0


def normalize_epss(epss: float) -> float:
    """Normalize EPSS probability (0.0 - 1.0)."""
    if epss is None:
        return 0.0
    return max(0.0, min(1.0, float(epss)))


def normalize_exposure(exposure: Exposure) -> float:
    """Get the numeric factor for asset network exposure."""
    return EXPOSURE_FACTORS.get(exposure, 0.30)


def normalize_criticality(criticality: Criticality) -> float:
    """Get the numeric factor for asset business criticality."""
    return CRITICALITY_FACTORS.get(criticality, 0.30)


def score_to_priority_level(score: float) -> PriorityLevel:
    """Map a 0-100 demo prioritisation score to an operational priority tier."""
    if score >= 80.0:
        return PriorityLevel.URGENT
    elif score >= 60.0:
        return PriorityLevel.HIGH
    elif score >= 40.0:
        return PriorityLevel.MEDIUM
    else:
        return PriorityLevel.LOW


def calculate_score_breakdown(context: EvaluationContext) -> ScoreContribution:
    """Calculate transparent mathematical contributions and final operational priority.

    Formula:
      Score = 100 * (
          w_cvss * norm_cvss +
          w_kev * norm_kev +
          w_epss * norm_epss +
          w_exposure * norm_exposure +
          w_criticality * norm_criticality
      )
    """
    weights = PROFILE_WEIGHTS.get(context.risk_appetite, PROFILE_WEIGHTS[RiskAppetite.LOW])

    norm_cvss = normalize_cvss(context.cvss)
    norm_kev = normalize_kev(context.kev)
    norm_epss = normalize_epss(context.epss)
    norm_exposure = normalize_exposure(context.exposure)
    norm_crit = normalize_criticality(context.criticality)

    cvss_contrib = 100.0 * weights.cvss * norm_cvss
    kev_contrib = 100.0 * weights.kev * norm_kev
    epss_contrib = 100.0 * weights.epss * norm_epss
    exposure_contrib = 100.0 * weights.exposure * norm_exposure
    criticality_contrib = 100.0 * weights.criticality * norm_crit

    total_score = cvss_contrib + kev_contrib + epss_contrib + exposure_contrib + criticality_contrib
    priority_level = score_to_priority_level(total_score)

    return ScoreContribution(
        cvss_contribution=cvss_contrib,
        kev_contribution=kev_contrib,
        epss_contribution=epss_contrib,
        exposure_contribution=exposure_contrib,
        criticality_contribution=criticality_contrib,
        total_score=total_score,
        priority_level=priority_level,
    )
