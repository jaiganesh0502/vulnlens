"""Tests for multi-profile comparative analysis."""

from pathlib import Path
import pytest

from src.comparison import compare_profiles
from src.loader import load_profiles, load_vulnerabilities


def test_compare_profiles_bank_vs_startup():
    """Verify that comparing Bank and Startup produces distinct top priorities and driver explanations."""
    data_dir = Path(__file__).parent.parent / "data"
    vulns = load_vulnerabilities(data_dir / "vulnerabilities.csv")
    profiles = load_profiles(data_dir / "profiles.json")

    bank = next(p for p in profiles if p.org_id == "ORG-001")
    startup = next(p for p in profiles if p.org_id == "ORG-002")

    report = compare_profiles(vulns, bank, startup, top_n=5)
    assert report.org_a.org_id == "ORG-001"
    assert report.org_b.org_id == "ORG-002"
    assert len(report.top_5_a) == 5
    assert len(report.top_5_b) == 5

    # Check that the two Top 5 lists are not identical
    top_a_cves = [it.vulnerability.cve_id for it in report.top_5_a]
    top_b_cves = [it.vulnerability.cve_id for it in report.top_5_b]
    assert top_a_cves != top_b_cves

    # Verify comparison items have drivers populated
    assert len(report.comparison_items) > 0
    for item in report.comparison_items:
        assert bool(item.driver_summary) is True
