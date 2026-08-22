"""Unit tests for transparent scoring formulas, normalization, and contribution math."""

import pytest
from nexorapay.models import (
    Criticality,
    EvaluationContext,
    Exposure,
    PriorityLevel,
    RiskAppetite,
)
from nexorapay.scoring import (
    PROFILE_WEIGHTS,
    calculate_score_breakdown,
    normalize_criticality,
    normalize_cvss,
    normalize_epss,
    normalize_exposure,
    normalize_kev,
    score_to_priority_level,
)


def test_profile_weights_sum_to_one():
    """Ensure all risk appetite profile weights sum to exactly 1.0 (100%)."""
    for appetite, weights in PROFILE_WEIGHTS.items():
        total = weights.cvss + weights.kev + weights.epss + weights.exposure + weights.criticality
        assert total == pytest.approx(1.0, 0.0001), f"Profile {appetite} weights do not sum to 1.0"


def test_cvss_normalization_boundaries():
    assert normalize_cvss(0.0) == 0.0
    assert normalize_cvss(5.0) == 0.5
    assert normalize_cvss(10.0) == 1.0
    # Out of bounds clamping
    assert normalize_cvss(-2.5) == 0.0
    assert normalize_cvss(12.5) == 1.0
    assert normalize_cvss(None) == 0.0


def test_kev_normalization():
    assert normalize_kev(True) == 1.0
    assert normalize_kev(False) == 0.0
    assert normalize_kev(1) == 1.0
    assert normalize_kev(0) == 0.0


def test_epss_normalization_boundaries():
    assert normalize_epss(0.0) == 0.0
    assert normalize_epss(0.91) == 0.91
    assert normalize_epss(1.0) == 1.0
    # Out of bounds clamping
    assert normalize_epss(-0.5) == 0.0
    assert normalize_epss(1.5) == 1.0
    assert normalize_epss(None) == 0.0


def test_exposure_normalization():
    assert normalize_exposure(Exposure.INTERNET_FACING) == 1.0
    assert normalize_exposure(Exposure.INTERNAL) == 0.30


def test_criticality_normalization():
    assert normalize_criticality(Criticality.CRITICAL) == 1.0
    assert normalize_criticality(Criticality.HIGH) == 0.65
    assert normalize_criticality(Criticality.NORMAL) == 0.30
    assert normalize_criticality(Criticality.LOW) == 0.10


def test_priority_level_mapping():
    assert score_to_priority_level(95.0) == PriorityLevel.URGENT
    assert score_to_priority_level(80.0) == PriorityLevel.URGENT
    assert score_to_priority_level(79.9) == PriorityLevel.HIGH
    assert score_to_priority_level(60.0) == PriorityLevel.HIGH
    assert score_to_priority_level(59.9) == PriorityLevel.MEDIUM
    assert score_to_priority_level(40.0) == PriorityLevel.MEDIUM
    assert score_to_priority_level(39.9) == PriorityLevel.LOW
    assert score_to_priority_level(0.0) == PriorityLevel.LOW


def test_nxp_demo_002_urgent_priority_math():
    """Verify NXP-DEMO-002 (CVSS 8.4, KEV=True, EPSS=0.91, Internet-facing, Critical, Low Appetite)."""
    ctx = EvaluationContext(
        cvss=8.4,
        kev=True,
        epss=0.91,
        exposure=Exposure.INTERNET_FACING,
        criticality=Criticality.CRITICAL,
        risk_appetite=RiskAppetite.LOW,
    )
    b = calculate_score_breakdown(ctx)

    # Weights: cvss=0.30, kev=0.35, epss=0.20, exp=0.10, crit=0.05
    # cvss_contrib = 100 * 0.30 * 0.84 = 25.2
    # kev_contrib = 100 * 0.35 * 1.0 = 35.0
    # epss_contrib = 100 * 0.20 * 0.91 = 18.2
    # exp_contrib = 100 * 0.10 * 1.0 = 10.0
    # crit_contrib = 100 * 0.05 * 1.0 = 5.0
    # total = 25.2 + 35.0 + 18.2 + 10.0 + 5.0 = 93.4

    assert b.cvss_contribution == pytest.approx(25.2, 0.01)
    assert b.kev_contribution == pytest.approx(35.0, 0.01)
    assert b.epss_contribution == pytest.approx(18.2, 0.01)
    assert b.exposure_contribution == pytest.approx(10.0, 0.01)
    assert b.criticality_contribution == pytest.approx(5.0, 0.01)
    assert b.total_score == pytest.approx(93.4, 0.01)
    assert b.priority_level == PriorityLevel.URGENT


def test_nxp_demo_001_lower_priority_than_002():
    """Key concept test: High CVSS (9.8) on internal asset ranks lower than 8.4 on internet-facing weaponized asset."""
    ctx_001 = EvaluationContext(
        cvss=9.8,
        kev=False,
        epss=0.21,
        exposure=Exposure.INTERNAL,
        criticality=Criticality.NORMAL,
        risk_appetite=RiskAppetite.LOW,
    )
    b_001 = calculate_score_breakdown(ctx_001)

    ctx_002 = EvaluationContext(
        cvss=8.4,
        kev=True,
        epss=0.91,
        exposure=Exposure.INTERNET_FACING,
        criticality=Criticality.CRITICAL,
        risk_appetite=RiskAppetite.LOW,
    )
    b_002 = calculate_score_breakdown(ctx_002)

    # Technical CVSS: 9.8 > 8.4
    assert ctx_001.cvss > ctx_002.cvss

    # Operational Demo Priority: 002 (93.4 URGENT) > 001 (~38.1 LOW/MEDIUM)
    assert b_002.total_score > b_001.total_score
    assert b_002.priority_level == PriorityLevel.URGENT
    assert b_001.priority_level in (PriorityLevel.LOW, PriorityLevel.MEDIUM)
