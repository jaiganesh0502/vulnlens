"""Tests for gold-set benchmark calibration and dataset isolation."""

from pathlib import Path
import pytest

from src.calibration import (
    compute_spearman_correlation,
    evaluate_gold_set,
)
from src.loader import load_gold_set, load_profiles, load_vulnerabilities


def test_spearman_correlation_math():
    """Verify Spearman correlation calculation against known arrays."""
    # Perfect positive correlation
    assert compute_spearman_correlation([1.0, 2.0, 3.0, 4.0, 5.0], [1.0, 2.0, 3.0, 4.0, 5.0]) == 1.0
    # Perfect negative correlation
    assert compute_spearman_correlation([1.0, 2.0, 3.0, 4.0, 5.0], [5.0, 4.0, 3.0, 2.0, 1.0]) == -1.0


def test_evaluate_gold_set_for_bank_and_startup():
    """Verify gold set evaluation against practitioner benchmarks for Bank and Startup."""
    data_dir = Path(__file__).parent.parent / "data"
    gold_records = load_gold_set(data_dir / "gold_set.csv")
    profiles = load_profiles(data_dir / "profiles.json")

    bank_profile = next(p for p in profiles if p.org_id == "ORG-001")
    startup_profile = next(p for p in profiles if p.org_id == "ORG-002")

    report_bank = evaluate_gold_set(gold_records, bank_profile, practitioner_field="practitioner_rank_bank")
    assert len(report_bank.items) == 5
    assert report_bank.spearman_correlation is not None
    assert report_bank.spearman_correlation > 0.6  # High positive correlation

    report_startup = evaluate_gold_set(gold_records, startup_profile, practitioner_field="practitioner_rank_startup")
    assert len(report_startup.items) == 5
    assert report_startup.spearman_correlation is not None
    assert report_startup.spearman_correlation > 0.6


def test_gold_set_dataset_isolation():
    """Verify that gold set records are strictly isolated and not in vulnerabilities.csv."""
    data_dir = Path(__file__).parent.parent / "data"
    vulns = load_vulnerabilities(data_dir / "vulnerabilities.csv")
    gold = load_gold_set(data_dir / "gold_set.csv")

    prod_cves = {v.cve_id for v in vulns}
    gold_cves = {g.cve_id for g in gold}

    # Gold set CVEs (e.g. CVE-2025-1111, CVE-2026-2222, etc.) must not be merged into production dataset
    for gcve in gold_cves:
        assert gcve not in prod_cves, f"Contamination detected: Gold set record {gcve} found in production dataset!"
