"""Tests for deterministic scoring formula and breakdown calculations."""

import pytest

from src.models import (
    OrganizationProfile,
    PriorityLevel,
    Vulnerability,
    WeightModifiers,
)
from src.scorer import (
    calculate_score,
    determine_priority_level,
)


@pytest.fixture
def sample_profile() -> OrganizationProfile:
    return OrganizationProfile(
        org_id="ORG-TEST",
        name="Test Bank",
        sector="Financial",
        risk_appetite="Low",
        weight_modifiers=WeightModifiers(
            cvss_weight=0.3,
            cisa_kev_weight=0.45,
            first_epss_weight=0.25,
        ),
        critical_products=["Core Banking Framework"],
    )


def test_calculate_score_standard_product(sample_profile: OrganizationProfile):
    """Verify score calculation for a non-critical product without critical multiplier."""
    vuln = Vulnerability(
        cve_id="CVE-2025-0001",
        product_name="Standard Router OS",
        cvss_base_score=8.0,  # norm = 0.8 -> 100 * 0.3 * 0.8 = 24.0
        cisa_kev=True,         # signal = 1.0 -> 100 * 0.45 * 1.0 = 45.0
        first_epss=0.4,        # signal = 0.4 -> 100 * 0.25 * 0.4 = 10.0
    )
    # Expected base score = 24.0 + 45.0 + 10.0 = 79.0
    # Final score = 79.0 (multiplier = 1.0)
    breakdown = calculate_score(vuln, sample_profile, critical_multiplier=1.4)
    
    assert breakdown.cvss_contribution == pytest.approx(24.0, 0.01)
    assert breakdown.kev_contribution == pytest.approx(45.0, 0.01)
    assert breakdown.epss_contribution == pytest.approx(10.0, 0.01)
    assert breakdown.base_score == pytest.approx(79.0, 0.01)
    assert breakdown.is_critical_product is False
    assert breakdown.critical_multiplier == 1.0
    assert breakdown.final_score == pytest.approx(79.0, 0.01)


def test_calculate_score_critical_product(sample_profile: OrganizationProfile):
    """Verify 1.4x multiplier is applied when product is critical for the organization."""
    vuln = Vulnerability(
        cve_id="CVE-2025-0002",
        product_name="Core Banking Framework",
        cvss_base_score=10.0,  # norm = 1.0 -> 100 * 0.3 * 1.0 = 30.0
        cisa_kev=True,          # signal = 1.0 -> 100 * 0.45 * 1.0 = 45.0
        first_epss=0.5,         # signal = 0.5 -> 100 * 0.25 * 0.5 = 12.5
    )
    # Base score = 30.0 + 45.0 + 12.5 = 87.5
    # Final score = 87.5 * 1.4 = 122.5
    breakdown = calculate_score(vuln, sample_profile, critical_multiplier=1.4)

    assert breakdown.base_score == pytest.approx(87.5, 0.01)
    assert breakdown.is_critical_product is True
    assert breakdown.critical_multiplier == 1.4
    assert breakdown.final_score == pytest.approx(122.5, 0.01)


def test_calculate_score_missing_signals(sample_profile: OrganizationProfile):
    """Verify calculation safely defaults missing CVSS or EPSS to 0 without throwing errors."""
    vuln = Vulnerability(
        cve_id="CVE-2025-0003",
        product_name="Other Tool",
        cvss_base_score=None,  # Missing -> 0.0
        cisa_kev=False,         # signal = 0.0 -> 0.0
        first_epss=None,        # Missing -> 0.0
    )
    breakdown = calculate_score(vuln, sample_profile)
    assert breakdown.cvss_contribution == 0.0
    assert breakdown.kev_contribution == 0.0
    assert breakdown.epss_contribution == 0.0
    assert breakdown.base_score == 0.0
    assert breakdown.final_score == 0.0


def test_determine_priority_level_thresholds():
    """Verify priority classification maps correctly across all ranges."""
    assert determine_priority_level(95.0) == PriorityLevel.URGENT
    assert determine_priority_level(90.0) == PriorityLevel.URGENT
    assert determine_priority_level(89.99) == PriorityLevel.HIGH
    assert determine_priority_level(75.0) == PriorityLevel.HIGH
    assert determine_priority_level(74.99) == PriorityLevel.MEDIUM
    assert determine_priority_level(50.0) == PriorityLevel.MEDIUM
    assert determine_priority_level(49.99) == PriorityLevel.LOW
    assert determine_priority_level(0.0) == PriorityLevel.LOW
