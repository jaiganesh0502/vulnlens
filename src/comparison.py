"""Profile comparison engine to explain why different organizations receive different triage results."""

from dataclasses import dataclass
from typing import Dict, List, Optional

from src.models import OrganizationProfile, TriageResult, Vulnerability
from src.ranking import rank_all_vulnerabilities, rank_vulnerabilities


@dataclass
class ProfileComparisonItem:
    cve_id: str
    product_name: str
    cvss_base_score: float
    cisa_kev: bool
    first_epss: float
    # Org A data
    rank_a: Optional[int]
    score_a: Optional[float]
    is_critical_a: bool
    # Org B data
    rank_b: Optional[int]
    score_b: Optional[float]
    is_critical_b: bool
    # Diffs
    score_delta: float  # score_b - score_a
    rank_delta: Optional[int]  # rank_a - rank_b (positive means improved rank in B)
    driver_summary: str


@dataclass
class ProfileComparisonReport:
    org_a: OrganizationProfile
    org_b: OrganizationProfile
    top_5_a: List[TriageResult]
    top_5_b: List[TriageResult]
    comparison_items: List[ProfileComparisonItem]
    overall_narrative: str


def compare_profiles(
    vulnerabilities: List[Vulnerability],
    profile_a: OrganizationProfile,
    profile_b: OrganizationProfile,
    top_n: int = 5,
) -> ProfileComparisonReport:
    """Compare triage prioritization between two organization profiles."""
    all_a = {item.vulnerability.cve_id: item for item in rank_all_vulnerabilities(vulnerabilities, profile_a)}
    all_b = {item.vulnerability.cve_id: item for item in rank_all_vulnerabilities(vulnerabilities, profile_b)}

    top_5_a = rank_vulnerabilities(vulnerabilities, profile_a, top_n=top_n)
    top_5_b = rank_vulnerabilities(vulnerabilities, profile_b, top_n=top_n)

    # Collect union of CVEs in top 5 of either profile
    union_cves = list(dict.fromkeys([item.vulnerability.cve_id for item in top_5_a] + [item.vulnerability.cve_id for item in top_5_b]))

    comparison_items: List[ProfileComparisonItem] = []

    for cve in union_cves:
        item_a = all_a.get(cve)
        item_b = all_b.get(cve)

        if not item_a and not item_b:
            continue

        ref_vuln = item_a.vulnerability if item_a else item_b.vulnerability
        score_a = item_a.score_breakdown.final_score if item_a else 0.0
        rank_a = item_a.rank if item_a else None
        crit_a = item_a.score_breakdown.is_critical_product if item_a else False

        score_b = item_b.score_breakdown.final_score if item_b else 0.0
        rank_b = item_b.rank if item_b else None
        crit_b = item_b.score_breakdown.is_critical_product if item_b else False

        score_delta = round(score_b - score_a, 2)
        rank_delta = (rank_a - rank_b) if (rank_a is not None and rank_b is not None) else None

        # Build driver summary
        drivers: List[str] = []
        if crit_a != crit_b:
            if crit_b:
                drivers.append(f"Critical asset in {profile_b.name} (+1.4x multiplier)")
            else:
                drivers.append(f"Critical asset in {profile_a.name} (lost 1.4x multiplier in {profile_b.name})")

        # Check weights impact
        epss_wt_diff = profile_b.weight_modifiers.first_epss_weight - profile_a.weight_modifiers.first_epss_weight
        cvss_wt_diff = profile_b.weight_modifiers.cvss_weight - profile_a.weight_modifiers.cvss_weight
        kev_wt_diff = profile_b.weight_modifiers.cisa_kev_weight - profile_a.weight_modifiers.cisa_kev_weight

        if abs(epss_wt_diff) >= 0.15 and (ref_vuln.first_epss or 0.0) >= 0.4:
            drivers.append(
                f"EPSS weight is {profile_b.weight_modifiers.first_epss_weight:.0%} in {profile_b.name} vs "
                f"{profile_a.weight_modifiers.first_epss_weight:.0%} in {profile_a.name} (EPSS: {ref_vuln.first_epss:.1%})"
            )
        if abs(kev_wt_diff) >= 0.15 and ref_vuln.cisa_kev:
            drivers.append(
                f"KEV weight is {profile_b.weight_modifiers.cisa_kev_weight:.0%} in {profile_b.name} vs "
                f"{profile_a.weight_modifiers.cisa_kev_weight:.0%} in {profile_a.name}"
            )
        if abs(cvss_wt_diff) >= 0.15 and (ref_vuln.cvss_base_score or 0.0) >= 8.0:
            drivers.append(
                f"CVSS weight is {profile_b.weight_modifiers.cvss_weight:.0%} in {profile_b.name} vs "
                f"{profile_a.weight_modifiers.cvss_weight:.0%} in {profile_a.name}"
            )

        driver_text = "; ".join(drivers) if drivers else "Subtle weight balancing difference"

        comparison_items.append(
            ProfileComparisonItem(
                cve_id=ref_vuln.cve_id,
                product_name=ref_vuln.product_name,
                cvss_base_score=ref_vuln.cvss_base_score or 0.0,
                cisa_kev=ref_vuln.cisa_kev,
                first_epss=ref_vuln.first_epss or 0.0,
                rank_a=rank_a,
                score_a=score_a,
                is_critical_a=crit_a,
                rank_b=rank_b,
                score_b=score_b,
                is_critical_b=crit_b,
                score_delta=score_delta,
                rank_delta=rank_delta,
                driver_summary=driver_text,
            )
        )

    narrative = (
        f"Comparison between '{profile_a.name}' ({profile_a.sector}, Risk Appetite: {profile_a.risk_appetite}) "
        f"and '{profile_b.name}' ({profile_b.sector}, Risk Appetite: {profile_b.risk_appetite}). "
        f"Differences in top priorities are driven strictly by asset criticality mappings "
        f"and calibrated weight modifiers (CVSS: {profile_a.weight_modifiers.cvss_weight:.0%} vs {profile_b.weight_modifiers.cvss_weight:.0%}, "
        f"KEV: {profile_a.weight_modifiers.cisa_kev_weight:.0%} vs {profile_b.weight_modifiers.cisa_kev_weight:.0%}, "
        f"EPSS: {profile_a.weight_modifiers.first_epss_weight:.0%} vs {profile_b.weight_modifiers.first_epss_weight:.0%})."
    )

    return ProfileComparisonReport(
        org_a=profile_a,
        org_b=profile_b,
        top_5_a=top_5_a,
        top_5_b=top_5_b,
        comparison_items=comparison_items,
        overall_narrative=narrative,
    )
