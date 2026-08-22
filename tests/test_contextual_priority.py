"""Unit tests for VulnLens Contextual Priority Engine architecture."""

import pytest
from src.models import (
    ConfidenceLevel,
    OrganizationProfile,
    PriorityLevel,
    Vulnerability,
    WeightModifiers,
)
from src.ranking import rank_all_vulnerabilities, rank_vulnerabilities
from src.scorer import calculate_score, determine_priority_level


@pytest.fixture
def sample_bank_profile():
    return OrganizationProfile(
        org_id="ORG-001",
        name="Global Retail Bank",
        sector="Financial Services",
        risk_appetite="Low",
        weight_modifiers=WeightModifiers(
            cvss_weight=0.30,
            cisa_kev_weight=0.45,
            first_epss_weight=0.25,
        ),
        critical_products=["Core Banking Framework", "Identity Provider SaaS"],
    )


@pytest.fixture
def sample_startup_profile():
    return OrganizationProfile(
        org_id="ORG-002",
        name="Cloud Tech Startup",
        sector="Technology",
        risk_appetite="High",
        weight_modifiers=WeightModifiers(
            cvss_weight=0.20,
            cisa_kev_weight=0.30,
            first_epss_weight=0.50,
        ),
        critical_products=["Kubernetes Ingress Controller"],
    )


def test_organisation_fingerprint_philosophy(sample_bank_profile, sample_startup_profile):
    fp_bank = sample_bank_profile.get_fingerprint()
    assert "known exploitation" in fp_bank.priority_philosophy.lower()
    assert "█" in fp_bank.to_ascii_display()

    fp_startup = sample_startup_profile.get_fingerprint()
    assert "probability" in fp_startup.priority_philosophy.lower()


def test_technical_threat_score_calculation(sample_bank_profile):
    # CVSS: 8.0 (norm: 0.8), KEV: True (1.0), EPSS: 0.90
    # Technical Threat = 100 * (0.80*0.30 + 1.0*0.45 + 0.90*0.25) = 100 * (0.24 + 0.45 + 0.225) = 91.5
    vuln = Vulnerability(
        cve_id="CVE-2023-TEST",
        product_name="Standard Internal Tool",
        cvss_base_score=8.0,
        cisa_kev=True,
        first_epss=0.90,
    )
    b = calculate_score(vuln, sample_bank_profile)
    assert b.technical_threat_score == 91.5
    assert b.context_multiplier == 1.00
    assert b.context_delta == 0.0
    assert b.final_priority_score == 91.5


def test_context_multiplier_and_delta_on_critical_asset(sample_bank_profile):
    # Critical asset: Exposure 1.20 x Criticality 1.20 = 1.44
    vuln = Vulnerability(
        cve_id="CVE-2023-CORE",
        product_name="Core Banking Framework",
        cvss_base_score=8.0,
        cisa_kev=True,
        first_epss=0.90,
    )
    b = calculate_score(vuln, sample_bank_profile)
    assert b.technical_threat_score == 91.5
    assert b.context_multiplier == 1.44
    assert round(b.final_priority_score, 2) == round(91.5 * 1.44, 2)  # 131.76
    assert round(b.context_delta, 2) == round(131.76 - 91.5, 2)  # +40.26


def test_decision_margin_calculation(sample_bank_profile):
    vuln1 = Vulnerability(
        cve_id="CVE-2023-0001",
        product_name="Core Banking Framework",
        cvss_base_score=8.0,
        cisa_kev=True,
        first_epss=0.90,
    )
    vuln2 = Vulnerability(
        cve_id="CVE-2023-0002",
        product_name="Core Banking Framework",
        cvss_base_score=7.0,
        cisa_kev=True,
        first_epss=0.50,
    )
    results = rank_vulnerabilities([vuln1, vuln2], sample_bank_profile, top_n=2)
    assert len(results) == 2
    assert results[0].decision_margin is not None
    assert results[0].decision_margin > 0.0
    assert results[1].decision_margin is None  # last item has no next


def test_counterfactual_what_would_change_decision(sample_bank_profile):
    vuln1 = Vulnerability(
        cve_id="CVE-2023-0001",
        product_name="Core Banking Framework",
        cvss_base_score=8.0,
        cisa_kev=True,
        first_epss=0.90,
    )
    vuln2 = Vulnerability(
        cve_id="CVE-2023-0002",
        product_name="Internal Dev Server",  # non critical
        cvss_base_score=8.0,
        cisa_kev=True,
        first_epss=0.90,
    )
    results = rank_vulnerabilities([vuln1, vuln2], sample_bank_profile, top_n=2)
    rank2_item = results[1]
    assert rank2_item.rank == 2
    assert len(rank2_item.what_would_change_decision) > 0

    # Ensure projected scores are present
    projected = [cf["projected_priority_score"] for cf in rank2_item.what_would_change_decision]
    assert any(p > rank2_item.score_breakdown.final_priority_score for p in projected)
