"""Tests for CSV and JSON data loading and schema resilience."""

from io import StringIO
from pathlib import Path
import pytest

from src.loader import (
    load_gold_set,
    load_profiles,
    load_vulnerabilities,
    parse_boolean,
    parse_float_safe,
)


def test_parse_boolean_variants():
    """Verify robust boolean parsing across various representations."""
    assert parse_boolean(True) is True
    assert parse_boolean(False) is False
    assert parse_boolean("True") is True
    assert parse_boolean("true") is True
    assert parse_boolean("1") is True
    assert parse_boolean("yes") is True
    assert parse_boolean("False") is False
    assert parse_boolean("0") is False
    assert parse_boolean("no") is False
    assert parse_boolean(None) is False
    assert parse_boolean("") is False


def test_parse_float_safe():
    """Verify float parsing with boundary constraints."""
    assert parse_float_safe("9.8", 0.0, 10.0) == 9.8
    assert parse_float_safe("0.027", 0.0, 1.0) == 0.027
    assert parse_float_safe("11.5", 0.0, 10.0) is None  # Exceeds max
    assert parse_float_safe("-1.0", 0.0, 10.0) is None  # Below min
    assert parse_float_safe("invalid", 0.0, 10.0) is None
    assert parse_float_safe(None, 0.0, 10.0) is None
    assert parse_float_safe("NaN", 0.0, 10.0) is None


def test_load_vulnerabilities_from_file():
    """Verify loading from the actual bundled data/vulnerabilities.csv."""
    data_path = Path(__file__).parent.parent / "data" / "vulnerabilities.csv"
    vulns = load_vulnerabilities(data_path)
    assert len(vulns) > 200
    first = vulns[0]
    assert first.cve_id.startswith("CVE-")
    assert bool(first.product_name) is True
    assert first.cvss_base_score is not None


def test_load_vulnerabilities_resilience():
    """Verify parser does not crash on malformed rows or missing fields."""
    corrupt_csv = StringIO(
        "cve_id,product_name,cvss_base_score,cisa_kev,first_epss\n"
        "CVE-2025-0001,App A,9.5,True,0.5\n"
        ",App Missing CVE,8.0,False,0.1\n"  # Missing CVE ID
        "CVE-2025-0002,,7.0,False,0.1\n"  # Missing product
        "CVE-2025-0003,App B,99.9,invalid_bool,2.5\n"  # Out of bounds CVSS and EPSS
    )
    vulns = load_vulnerabilities(corrupt_csv)
    assert len(vulns) == 2
    assert vulns[0].cve_id == "CVE-2025-0001"
    assert vulns[1].cve_id == "CVE-2025-0003"
    assert vulns[1].cvss_base_score is None  # 99.9 rejected
    assert vulns[1].cisa_kev is False  # invalid parsed as false
    assert vulns[1].first_epss is None  # 2.5 rejected


def test_load_profiles_from_file():
    """Verify loading default organization profiles."""
    data_path = Path(__file__).parent.parent / "data" / "profiles.json"
    profiles = load_profiles(data_path)
    assert len(profiles) == 3
    org_ids = [p.org_id for p in profiles]
    assert "ORG-001" in org_ids
    assert "ORG-002" in org_ids
    assert "ORG-003" in org_ids

    bank = next(p for p in profiles if p.org_id == "ORG-001")
    assert bank.name == "Global Retail Bank"
    assert bank.weight_modifiers.cvss_weight == 0.3
    assert bank.weight_modifiers.cisa_kev_weight == 0.45
    assert bank.weight_modifiers.first_epss_weight == 0.25
    assert "Core Banking Framework" in bank.critical_products


def test_load_gold_set_from_file():
    """Verify loading practitioner gold set."""
    data_path = Path(__file__).parent.parent / "data" / "gold_set.csv"
    gold = load_gold_set(data_path)
    assert len(gold) == 5
    assert gold[0].cve_id == "CVE-2025-1111"
    assert gold[0].practitioner_rank_bank == 1
    assert gold[0].practitioner_rank_startup == 2
