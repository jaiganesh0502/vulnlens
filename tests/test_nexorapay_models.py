"""Unit tests for NexoraPay data models, enums, and validations."""

import pytest
from nexorapay.models import (
    Asset,
    Criticality,
    CVSSSeverity,
    EvaluationContext,
    Exposure,
    Organisation,
    PriorityLevel,
    RiskAppetite,
    ScoreContribution,
    VulnerabilityScenario,
    WhatIfChange,
    WhatIfResult,
)


def test_exposure_enum_parsing():
    assert Exposure.from_str("internet-facing") == Exposure.INTERNET_FACING
    assert Exposure.from_str("internet") == Exposure.INTERNET_FACING
    assert Exposure.from_str("public") == Exposure.INTERNET_FACING
    assert Exposure.from_str("internal") == Exposure.INTERNAL
    assert Exposure.from_str("private") == Exposure.INTERNAL

    with pytest.raises(ValueError, match="Unknown exposure value"):
        Exposure.from_str("dmz-unknown")


def test_criticality_enum_parsing():
    assert Criticality.from_str("critical") == Criticality.CRITICAL
    assert Criticality.from_str("high") == Criticality.HIGH
    assert Criticality.from_str("normal") == Criticality.NORMAL
    assert Criticality.from_str("medium") == Criticality.NORMAL
    assert Criticality.from_str("low") == Criticality.LOW

    with pytest.raises(ValueError, match="Unknown criticality value"):
        Criticality.from_str("ultra-high")


def test_risk_appetite_enum_parsing():
    assert RiskAppetite.from_str("low") == RiskAppetite.LOW
    assert RiskAppetite.from_str("conservative") == RiskAppetite.LOW
    assert RiskAppetite.from_str("medium") == RiskAppetite.MEDIUM
    assert RiskAppetite.from_str("high") == RiskAppetite.HIGH

    with pytest.raises(ValueError, match="Unknown risk appetite profile"):
        RiskAppetite.from_str("zero-risk")


def test_cvss_severity_categories():
    assert CVSSSeverity.from_score(10.0) == CVSSSeverity.CRITICAL
    assert CVSSSeverity.from_score(9.0) == CVSSSeverity.CRITICAL
    assert CVSSSeverity.from_score(8.9) == CVSSSeverity.HIGH
    assert CVSSSeverity.from_score(7.0) == CVSSSeverity.HIGH
    assert CVSSSeverity.from_score(6.9) == CVSSSeverity.MEDIUM
    assert CVSSSeverity.from_score(4.0) == CVSSSeverity.MEDIUM
    assert CVSSSeverity.from_score(3.9) == CVSSSeverity.LOW
    assert CVSSSeverity.from_score(0.0) == CVSSSeverity.NONE


def test_organisation_asset_counts():
    assets = [
        Asset("A1", "Portal", Exposure.INTERNET_FACING, Criticality.CRITICAL, "Payment"),
        Asset("A2", "API", Exposure.INTERNET_FACING, Criticality.CRITICAL, "API"),
        Asset("A3", "File Server", Exposure.INTERNAL, Criticality.HIGH, "Files"),
        Asset("A4", "Dev", Exposure.INTERNAL, Criticality.NORMAL, "Dev"),
    ]
    org = Organisation(name="TestOrg", assets=assets)

    assert org.critical_services_count == 2
    assert org.internet_facing_count == 2
    assert org.internal_count == 2


def test_vulnerability_scenario_serialization():
    scen = VulnerabilityScenario(
        vuln_id="NXP-DEMO-999",
        product="Mock Gateway",
        cvss=8.5,
        cvss_severity="HIGH",
        kev=True,
        epss=0.88,
        affected_asset_name="Customer Portal",
        exposure=Exposure.INTERNET_FACING,
        criticality=Criticality.CRITICAL,
        business_importance="Mission-critical",
        explanation="Test explanation",
    )
    d = scen.to_dict()
    assert d["vuln_id"] == "NXP-DEMO-999"
    assert d["cvss"] == 8.5
    assert d["exposure"] == "Internet-facing"
    assert d["criticality"] == "Critical"
    assert d["kev"] is True
