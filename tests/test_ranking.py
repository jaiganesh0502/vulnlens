"""Tests for ranking, deduplication, and Top-5 bounding."""

import pytest

from src.models import (
    ConfidenceLevel,
    OrganizationProfile,
    PriorityLevel,
    Vulnerability,
    WeightModifiers,
)
from src.ranking import (
    deduplicate_vulnerabilities,
    rank_all_vulnerabilities,
    rank_vulnerabilities,
)


@pytest.fixture
def sample_profile() -> OrganizationProfile:
    return OrganizationProfile(
        org_id="ORG-TEST",
        name="Test FinTech",
        sector="Finance",
        risk_appetite="Low",
        weight_modifiers=WeightModifiers(
            cvss_weight=0.3,
            cisa_kev_weight=0.4,
            first_epss_weight=0.3,
        ),
        critical_products=["Core Banking Framework"],
    )


def test_deduplicate_vulnerabilities():
    """Verify duplicate (cve_id, product_name) rows are removed cleanly."""
    vulns = [
        Vulnerability(cve_id="CVE-2025-001", product_name="App A", cvss_base_score=7.0, cisa_kev=False, first_epss=0.1),
        Vulnerability(cve_id="CVE-2025-001", product_name="App A", cvss_base_score=8.5, cisa_kev=False, first_epss=0.1),  # Duplicate with higher CVSS
        Vulnerability(cve_id="CVE-2025-001", product_name="App B", cvss_base_score=7.0, cisa_kev=False, first_epss=0.1),  # Different product -> keep
        Vulnerability(cve_id="CVE-2025-002", product_name="App A", cvss_base_score=9.0, cisa_kev=True, first_epss=0.5),
    ]
    deduped = deduplicate_vulnerabilities(vulns)
    assert len(deduped) == 3
    # Check that for (CVE-2025-001, App A) the higher CVSS (8.5) was retained
    app_a_item = next(v for v in deduped if v.cve_id == "CVE-2025-001" and v.product_name == "App A")
    assert app_a_item.cvss_base_score == 8.5


def test_rank_vulnerabilities_top_5_bounding(sample_profile: OrganizationProfile):
    """Verify rank_vulnerabilities returns strictly bounded top 5 results sorted descending."""
    vulns = [
        Vulnerability(cve_id=f"CVE-2025-{i:04d}", product_name="Generic Tool", cvss_base_score=float(i % 10), cisa_kev=False, first_epss=0.01 * i)
        for i in range(1, 20)
    ]
    top_5 = rank_vulnerabilities(vulns, sample_profile, top_n=5)
    assert len(top_5) == 5
    
    # Check rank order is strictly descending by score
    scores = [res.score_breakdown.final_score for res in top_5]
    assert scores == sorted(scores, reverse=True)
    assert [res.rank for res in top_5] == [1, 2, 3, 4, 5]


def test_triage_result_fields_populated(sample_profile: OrganizationProfile):
    """Verify every triage result contains non-empty explanation, provenance, confidence and next action."""
    vulns = [
        Vulnerability(cve_id="CVE-2025-1111", product_name="Core Banking Framework", cvss_base_score=9.8, cisa_kev=True, first_epss=0.9),
    ]
    results = rank_vulnerabilities(vulns, sample_profile, top_n=1)
    assert len(results) == 1
    r = results[0]

    assert r.rank == 1
    assert r.priority == PriorityLevel.URGENT
    assert "Core Banking Framework" in r.plain_title
    assert "Critical Core Asset" in r.matched_context
    assert len(r.why_this_matters) >= 3
    assert "URGENT ACTION" in r.safe_next_action or "HIGH PRIORITY" in r.safe_next_action
    assert r.confidence == ConfidenceLevel.HIGH
    assert "Complete verified telemetry" in r.confidence_reason
    assert r.source_info["cve_id"] == "CVE-2025-1111"
    assert "https://nvd.nist.gov" in r.source_info["nvd_reference_url"]
