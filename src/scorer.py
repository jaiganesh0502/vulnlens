"""Deterministic scoring engine for VulnLens Contextual Priority Engine."""

from typing import Optional

from src.matcher import is_critical_product
from src.models import (
    OrganizationProfile,
    PriorityLevel,
    ScoreBreakdown,
    Vulnerability,
)

# Configurable global multiplier for critical assets
DEFAULT_CRITICAL_PRODUCT_MULTIPLIER: float = 1.44

# Configurable priority thresholds
PRIORITY_THRESHOLD_URGENT: float = 90.0
PRIORITY_THRESHOLD_HIGH: float = 75.0
PRIORITY_THRESHOLD_MEDIUM: float = 50.0


def calculate_score(
    vulnerability: Vulnerability,
    profile: OrganizationProfile,
    critical_multiplier: Optional[float] = None,
    exposure: Optional[str] = None,
    importance: Optional[str] = None,
) -> ScoreBreakdown:
    """Calculate the deterministic risk score and breakdown for a vulnerability under a specific profile.
    
    Architecture:
      1. Technical Threat Score:
         cvss_normalized = cvss_base_score / 10.0
         kev_signal = 1.0 if cisa_kev else 0.0
         epss_signal = first_epss (0.0 - 1.0)
         
         threat_score_normalized = (
             cvss_weight * cvss_normalized
             + cisa_kev_weight * kev_signal
             + first_epss_weight * epss_signal
         )
         technical_threat_score = threat_score_normalized * 100.0
         
      2. Organisation Context Multiplier:
         exposure_multiplier: internet-facing (1.20), internal (1.00)
         importance_multiplier: critical (1.20), high (1.10), normal (1.00)
         context_multiplier = exposure_multiplier * importance_multiplier
         
      3. Final VulnLens Priority Score:
         final_priority_score = technical_threat_score * context_multiplier
         
      4. Organisation Context Delta:
         context_delta = final_priority_score - technical_threat_score
    """
    # 1. Technical Threat Signals
    cvss_val = vulnerability.cvss_base_score if vulnerability.cvss_base_score is not None else 0.0
    cvss_norm = cvss_val / 10.0
    cvss_weight = profile.weight_modifiers.cvss_weight
    cvss_contribution = 100.0 * cvss_weight * cvss_norm

    kev_signal = 1.0 if vulnerability.cisa_kev else 0.0
    kev_weight = profile.weight_modifiers.cisa_kev_weight
    kev_contribution = 100.0 * kev_weight * kev_signal

    epss_val = vulnerability.first_epss if vulnerability.first_epss is not None else 0.0
    epss_weight = profile.weight_modifiers.first_epss_weight
    epss_contribution = 100.0 * epss_weight * epss_val

    technical_threat_score = cvss_contribution + kev_contribution + epss_contribution
    threat_score_normalized = technical_threat_score / 100.0

    # 2. Organisation Context Multiplier
    is_critical = is_critical_product(vulnerability.product_name, profile.critical_products)

    if critical_multiplier is not None:
        multiplier = critical_multiplier if is_critical else 1.0
        exp_mult = 1.20 if is_critical else 1.00
        imp_mult = multiplier / 1.20 if is_critical else 1.00
    elif exposure is not None or importance is not None:
        exp_val = (exposure or ("internet-facing" if is_critical else "internal")).lower()
        exp_mult = 1.20 if ("internet" in exp_val or "facing" in exp_val) else 1.00

        if importance is not None:
            imp_val = importance.lower()
            if "crit" in imp_val:
                imp_mult = 1.20
            elif "high" in imp_val:
                imp_mult = 1.10
            else:
                imp_mult = 1.00
        else:
            imp_mult = 1.20 if is_critical else 1.00

        multiplier = exp_mult * imp_mult
    else:
        # Default mapping from product criticality
        if is_critical:
            exp_mult = 1.20
            imp_mult = 1.20
            multiplier = 1.44
        else:
            exp_mult = 1.00
            imp_mult = 1.00
            multiplier = 1.00

    final_priority_score = technical_threat_score * multiplier
    context_delta = final_priority_score - technical_threat_score

    return ScoreBreakdown(
        cvss_base_score=cvss_val,
        cvss_normalized=cvss_norm,
        cvss_weight=cvss_weight,
        cvss_contribution=round(cvss_contribution, 4),
        cisa_kev=vulnerability.cisa_kev,
        kev_signal=kev_signal,
        cisa_kev_weight=kev_weight,
        kev_contribution=round(kev_contribution, 4),
        first_epss=epss_val,
        epss_signal=epss_val,
        first_epss_weight=epss_weight,
        epss_contribution=round(epss_contribution, 4),
        base_score=round(technical_threat_score, 4),
        is_critical_product=is_critical,
        critical_multiplier=round(multiplier, 4),
        final_score=round(final_priority_score, 4),
        threat_score_normalized=round(threat_score_normalized, 4),
        technical_threat_score=round(technical_threat_score, 4),
        exposure_multiplier=round(exp_mult, 4),
        importance_multiplier=round(imp_mult, 4),
        context_multiplier=round(multiplier, 4),
        context_delta=round(context_delta, 4),
        final_priority_score=round(final_priority_score, 4),
    )


def determine_priority_level(
    score: float,
    urgent_thresh: float = PRIORITY_THRESHOLD_URGENT,
    high_thresh: float = PRIORITY_THRESHOLD_HIGH,
    med_thresh: float = PRIORITY_THRESHOLD_MEDIUM,
) -> PriorityLevel:
    """Map a numerical final score to a standardized PriorityLevel."""
    if score >= urgent_thresh:
        return PriorityLevel.URGENT
    elif score >= high_thresh:
        return PriorityLevel.HIGH
    elif score >= med_thresh:
        return PriorityLevel.MEDIUM
    else:
        return PriorityLevel.LOW
