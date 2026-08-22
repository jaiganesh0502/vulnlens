"""Tests for the What-If simulation engine and strict CVSS immutability invariants."""

import pytest
from nexorapay.models import (
    Criticality,
    Exposure,
    PriorityLevel,
    RiskAppetite,
)
from nexorapay.simulator import CyberRiskSimulator


@pytest.fixture
def simulator():
    return CyberRiskSimulator()


def test_invariant_changing_exposure_never_changes_cvss(simulator):
    """CRITICAL INVARIANT: Changing exposure from Internet-facing to Internal must not change CVSS."""
    original_vuln = simulator.get_scenario("NXP-DEMO-002")
    original_cvss = original_vuln.cvss  # 8.4

    result = simulator.run_what_if(
        vuln_id="NXP-DEMO-002",
        exposure=Exposure.INTERNAL,
    )

    # Invariant: CVSS is strictly untouched
    assert result.cvss == original_cvss
    assert result.before_context.cvss == original_cvss
    assert result.after_context.cvss == original_cvss

    # Context exposure changed
    assert result.before_context.exposure == Exposure.INTERNET_FACING
    assert result.after_context.exposure == Exposure.INTERNAL

    # Operational score dropped, but CVSS remained 8.4
    assert result.after_breakdown.total_score < result.before_breakdown.total_score


def test_invariant_changing_criticality_never_changes_cvss(simulator):
    """CRITICAL INVARIANT: Changing asset criticality must not change CVSS."""
    original_vuln = simulator.get_scenario("NXP-DEMO-002")
    original_cvss = original_vuln.cvss

    result = simulator.run_what_if(
        vuln_id="NXP-DEMO-002",
        criticality=Criticality.NORMAL,
    )

    assert result.cvss == original_cvss
    assert result.before_context.cvss == original_cvss
    assert result.after_context.cvss == original_cvss

    assert result.before_context.criticality == Criticality.CRITICAL
    assert result.after_context.criticality == Criticality.NORMAL
    assert result.after_breakdown.total_score < result.before_breakdown.total_score


def test_invariant_changing_epss_and_kev_never_changes_cvss(simulator):
    """CRITICAL INVARIANT: Threat signal changes must not change CVSS."""
    original_vuln = simulator.get_scenario("NXP-DEMO-002")
    original_cvss = original_vuln.cvss

    result = simulator.run_what_if(
        vuln_id="NXP-DEMO-002",
        kev=False,
        epss=0.10,
    )

    assert result.cvss == original_cvss
    assert result.before_context.cvss == original_cvss
    assert result.after_context.cvss == original_cvss

    assert result.before_context.kev is True
    assert result.after_context.kev is False
    assert result.before_context.epss == 0.91
    assert result.after_context.epss == 0.10

    # Dramatic drop in operational priority
    assert result.before_breakdown.priority_level == PriorityLevel.URGENT
    assert result.after_breakdown.total_score < 50.0


def test_invariant_changing_profile_never_changes_cvss(simulator):
    """CRITICAL INVARIANT: Changing risk appetite profile must not change CVSS."""
    original_vuln = simulator.get_scenario("NXP-DEMO-002")
    original_cvss = original_vuln.cvss

    result = simulator.run_what_if(
        vuln_id="NXP-DEMO-002",
        risk_appetite=RiskAppetite.HIGH,
    )

    assert result.cvss == original_cvss
    assert result.before_context.cvss == original_cvss
    assert result.after_context.cvss == original_cvss


def test_what_if_changes_and_explanations(simulator):
    result = simulator.run_what_if(
        vuln_id="NXP-DEMO-002",
        exposure=Exposure.INTERNAL,
        criticality=Criticality.NORMAL,
        kev=False,
    )

    # 3 factors changed
    assert len(result.changes) == 3
    factors = [c.factor for c in result.changes]
    assert "Exposure" in factors
    assert "Asset Criticality" in factors
    assert "CISA KEV" in factors

    # Explanations generated
    assert len(result.why_explanation) == 3
    assert any("Exposure decreased" in exp for exp in result.why_explanation)
    assert any("Asset criticality shifted" in exp for exp in result.why_explanation)
    assert any("Threat signal removed" in exp for exp in result.why_explanation)


def test_what_if_unknown_scenario_raises_key_error(simulator):
    with pytest.raises(KeyError):
        simulator.run_what_if(vuln_id="NXP-NON-EXISTENT")
