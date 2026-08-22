"""Explainability engine for VulnLens."""

from typing import Any, Dict, List, Tuple

from src.models import (
    ConfidenceLevel,
    OrganizationProfile,
    ScoreBreakdown,
    Vulnerability,
)


def generate_plain_title(vulnerability: Vulnerability, breakdown: ScoreBreakdown) -> str:
    """Generate a plain-language consequence title based strictly on available structured signals."""
    product = vulnerability.product_name
    if vulnerability.cisa_kev:
        return f"Active In-The-Wild Exploitation on {product}"
    elif vulnerability.first_epss and vulnerability.first_epss >= 0.5:
        return f"High Exploitation Probability ({vulnerability.first_epss:.1%}) Threat on {product}"
    elif vulnerability.cvss_base_score and vulnerability.cvss_base_score >= 9.0:
        return f"Critical Technical Severity Flaw (CVSS {vulnerability.cvss_base_score}) on {product}"
    elif vulnerability.cvss_base_score and vulnerability.cvss_base_score >= 7.0:
        return f"High Severity Security Flaw on {product}"
    else:
        return f"Security Advisory for {product}"


def generate_matched_context(
    vulnerability: Vulnerability,
    profile: OrganizationProfile,
    breakdown: ScoreBreakdown,
) -> str:
    """Generate plain-text context regarding the asset match and criticality status."""
    if breakdown.is_critical_product:
        return f"Critical Core Asset ({vulnerability.product_name}) for {profile.name} [{profile.sector}]"
    return f"Standard Deployed Asset ({vulnerability.product_name}) for {profile.name} [{profile.sector}]"


def generate_why_this_matters(
    vulnerability: Vulnerability,
    profile: OrganizationProfile,
    breakdown: ScoreBreakdown,
) -> List[str]:
    """Generate a list of plain-language contributing factors derived solely from structured data."""
    factors: List[str] = []

    # KEV Factor
    if vulnerability.cisa_kev:
        factors.append(
            f"Confirmed exploitation signal (CISA KEV active) — contributed +{breakdown.kev_contribution:.1f} pts "
            f"({profile.weight_modifiers.cisa_kev_weight:.0%} profile weight)"
        )
    else:
        factors.append("No confirmed in-the-wild exploitation reported in CISA KEV (0.0 pts)")

    # CVSS Factor
    cvss = vulnerability.cvss_base_score
    if cvss is not None:
        if cvss >= 9.0:
            severity_label = "Critical technical severity"
        elif cvss >= 7.0:
            severity_label = "High technical severity"
        elif cvss >= 4.0:
            severity_label = "Medium technical severity"
        else:
            severity_label = "Low technical severity"
        factors.append(
            f"{severity_label} (CVSS {cvss:.1f}/10) — contributed +{breakdown.cvss_contribution:.1f} pts "
            f"({profile.weight_modifiers.cvss_weight:.0%} profile weight)"
        )
    else:
        factors.append("Missing CVSS base score (0.0 pts assigned, reduced confidence)")

    # EPSS Factor
    epss = vulnerability.first_epss
    if epss is not None:
        if epss >= 0.5:
            epss_label = "High 30-day exploitation likelihood"
        elif epss >= 0.1:
            epss_label = "Moderate 30-day exploitation likelihood"
        else:
            epss_label = "Low 30-day exploitation likelihood"
        factors.append(
            f"{epss_label} (EPSS {epss:.1%}) — contributed +{breakdown.epss_contribution:.1f} pts "
            f"({profile.weight_modifiers.first_epss_weight:.0%} profile weight)"
        )
    else:
        factors.append("Missing EPSS score (0.0 pts assigned, reduced confidence)")

    # Critical Product Context Factor
    if breakdown.is_critical_product:
        factors.append(
            f"Critical Product status for {profile.name} — applied {breakdown.critical_multiplier}x contextual priority multiplier"
        )
    else:
        factors.append("Non-critical asset tier (standard 1.0x baseline weighting)")

    return factors


def generate_safe_next_action(
    vulnerability: Vulnerability,
    breakdown: ScoreBreakdown,
) -> str:
    """Recommend a safe, defensible next action without fabricating versions or instructions."""
    if vulnerability.cisa_kev:
        return "URGENT ACTION: Verify asset exposure and prioritize emergency patch verification or network isolation."
    elif vulnerability.first_epss is not None and vulnerability.first_epss >= 0.5:
        return "HIGH PRIORITY: Verify if product is internet-facing, review vendor guidance, and schedule expedited patching."
    elif vulnerability.cvss_base_score is not None and vulnerability.cvss_base_score >= 8.5 and breakdown.is_critical_product:
        return "ELEVATED DEFENSE: Core critical asset flaw. Review vendor mitigation guidelines and confirm deployment boundaries."
    elif breakdown.is_critical_product:
        return "STANDARD REVIEW: Verify affected product installation and monitor vendor updates during routine maintenance."
    else:
        return "ROUTINE MONITORING: Record vulnerability and track during standard periodic patch cycles."


def determine_confidence(vulnerability: Vulnerability) -> Tuple[ConfidenceLevel, str]:
    """Determine confidence level and machine-generated justification based on signal integrity."""
    has_valid_cvss = vulnerability.is_valid_cvss
    has_valid_epss = vulnerability.is_valid_epss
    has_product = bool(vulnerability.product_name)

    missing_fields: List[str] = []
    if not has_valid_cvss:
        missing_fields.append("CVSS base score")
    if not has_valid_epss:
        missing_fields.append("EPSS probability")
    if not has_product:
        missing_fields.append("Product name")

    if not missing_fields:
        cvss_str = f"{vulnerability.cvss_base_score:.1f}" if vulnerability.cvss_base_score is not None else "N/A"
        epss_str = f"{vulnerability.first_epss:.3f}" if vulnerability.first_epss is not None else "N/A"
        reason = (
            f"Complete verified telemetry: valid CVSS ({cvss_str}), "
            f"confirmed KEV state ({vulnerability.cisa_kev}), "
            f"valid EPSS ({epss_str}), and exact product match ({vulnerability.product_name})."
        )
        return ConfidenceLevel.HIGH, reason
    elif len(missing_fields) == 1:
        reason = (
            f"Moderate data completeness: valid product match, but missing/unbounded {missing_fields[0]}."
        )
        return ConfidenceLevel.MEDIUM, reason
    else:
        reason = (
            f"Low data completeness: multiple signals missing or malformed ({', '.join(missing_fields)})."
        )
        return ConfidenceLevel.LOW, reason


def extract_source_info(vulnerability: Vulnerability) -> Dict[str, Any]:
    """Extract provenance and reference information from the vulnerability record."""
    cve_id = vulnerability.cve_id
    return {
        "cve_id": cve_id,
        "product_name": vulnerability.product_name,
        "cvss_base_score": vulnerability.cvss_base_score,
        "cisa_kev": vulnerability.cisa_kev,
        "first_epss": vulnerability.first_epss,
        "nvd_reference_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "cisa_kev_catalog_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "first_epss_url": "https://www.first.org/epss/",
        "raw_attributes": vulnerability.raw_data,
    }
