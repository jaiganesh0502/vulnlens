"""Tests for negative test scenarios proving that high CVSS != high priority."""

from pathlib import Path
import pytest

from src.loader import load_profiles, load_vulnerabilities
from src.models import (
    OrganizationProfile,
    PriorityLevel,
    Vulnerability,
    WeightModifiers,
)
from src.negative_test import find_negative_test_candidates
from src.ranking import rank_all_vulnerabilities, rank_vulnerabilities


def test_cvss_9_ranks_below_lower_cvss_due_to_context():
    """CRITICAL TEST: Prove that a CVSS 9.9 vulnerability ranks BELOW a CVSS 5.1 vulnerability

    because the CVSS 5.1 item has confirmed active exploitation (KEV=True), high EPSS (0.80),
    and is deployed on a critical asset, whereas the CVSS 9.9 item has KEV=False, low EPSS,
    and is on a non-critical asset.
    """
    # Profile: Global Retail Bank
    profile = OrganizationProfile(
        org_id="ORG-001",
        name="Global Retail Bank",
        sector="Financial Services",
        risk_appetite="Low",
        weight_modifiers=WeightModifiers(
            cvss_weight=0.3,
            cisa_kev_weight=0.45,
            first_epss_weight=0.25,
        ),
        critical_products=["Core Banking Framework"],
    )

    # Candidate 1: Theoretical severe flaw on non-critical asset (No KEV, low EPSS)
    high_cvss_vuln = Vulnerability(
        cve_id="CVE-2026-HIGH-CVSS",
        product_name="Unused Cloud DB",
        cvss_base_score=9.9,
        cisa_kev=False,
        first_epss=0.01,
    )
    # Math: base_score = 100 * (0.3 * 0.99 + 0.45 * 0 + 0.25 * 0.01) = 29.7 + 0.25 = 29.95. Multiplier = 1.0 -> Final = 29.95 (LOW)

    # Candidate 2: Moderate technical severity, but actively exploited on critical banking framework
    contextual_threat_vuln = Vulnerability(
        cve_id="CVE-2025-ACTIVE-THREAT",
        product_name="Core Banking Framework",
        cvss_base_score=5.1,
        cisa_kev=True,
        first_epss=0.85,
    )
    # Math: base_score = 100 * (0.3 * 0.51 + 0.45 * 1.0 + 0.25 * 0.85) = 15.3 + 45.0 + 21.25 = 81.55. Multiplier = 1.4 -> Final = 114.17 (URGENT)

    results = rank_vulnerabilities([high_cvss_vuln, contextual_threat_vuln], profile, top_n=2)

    assert results[0].vulnerability.cve_id == "CVE-2025-ACTIVE-THREAT"
    assert results[0].priority == PriorityLevel.URGENT
    assert results[0].score_breakdown.final_score > 100.0

    assert results[1].vulnerability.cve_id == "CVE-2026-HIGH-CVSS"
    assert results[1].priority == PriorityLevel.LOW
    assert results[1].score_breakdown.final_score < 50.0

    # Assert rank: contextual threat is #1, CVSS 9.9 is #2
    assert results[0].rank == 1
    assert results[1].rank == 2


def test_find_negative_test_candidates_in_dataset():
    """Verify finding real high-CVSS negative test examples from the bundled production dataset."""
    data_dir = Path(__file__).parent.parent / "data"
    vulns = load_vulnerabilities(data_dir / "vulnerabilities.csv")
    profiles = load_profiles(data_dir / "profiles.json")
    bank_profile = profiles[0]

    neg_items = find_negative_test_candidates(vulns, bank_profile, min_cvss=9.0, max_rank_threshold=10)
    assert len(neg_items) > 0

    first_neg = neg_items[0]
    assert (first_neg.vulnerability.cvss_base_score or 0.0) >= 9.0
    assert first_neg.rank > 10 or first_neg.score_breakdown.final_score < 75.0
    assert "Key de-prioritization factors:" in first_neg.reason_low_or_excluded
