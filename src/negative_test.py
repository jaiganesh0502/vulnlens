"""Negative testing engine to prove that high CVSS != high priority."""

from typing import List, Optional

from src.models import (
    NegativeTestItem,
    OrganizationProfile,
    PriorityLevel,
    TriageResult,
    Vulnerability,
)
from src.ranking import rank_all_vulnerabilities


def explain_negative_test_result(
    triage_item: TriageResult,
    profile: OrganizationProfile,
    total_candidates: int,
) -> str:
    """Generate a step-by-step diagnostic explaining why a high-CVSS CVE ranked low or was de-prioritized."""
    breakdown = triage_item.score_breakdown
    vuln = triage_item.vulnerability
    reasons: List[str] = []

    # 1. Check KEV
    if not vuln.cisa_kev:
        reasons.append(
            f"Zero exploitation evidence in CISA KEV (0.0 pts awarded out of {profile.weight_modifiers.cisa_kev_weight * 100:.0f} max KEV points)."
        )

    # 2. Check EPSS
    epss = vuln.first_epss or 0.0
    if epss < 0.05:
        reasons.append(
            f"Extremely low 30-day exploitation probability (EPSS {epss:.2%} contributes only {breakdown.epss_contribution:.1f} pts)."
        )
    elif epss < 0.20:
        reasons.append(
            f"Low exploitation probability (EPSS {epss:.2%} contributes only {breakdown.epss_contribution:.1f} pts)."
        )

    # 3. Check Critical Product Context
    if not breakdown.is_critical_product:
        reasons.append(
            f"Asset '{vuln.product_name}' is NOT in {profile.name}'s critical products list ({', '.join(profile.critical_products)}), forfeiting the 1.4x priority multiplier."
        )

    # 4. Check Profile Weighting Impact
    cvss_wt = profile.weight_modifiers.cvss_weight
    if cvss_wt <= 0.35:
        reasons.append(
            f"{profile.name}'s risk appetite allocates only {cvss_wt:.0%} weight to theoretical severity (CVSS), prioritizing real-world exploitation signals instead."
        )

    explanation = (
        f"Despite a high technical severity of CVSS {vuln.cvss_base_score:.1f}, {vuln.cve_id} ranked #{triage_item.rank} "
        f"of {total_candidates} candidates (Score: {breakdown.final_score:.1f}/100, Priority: {triage_item.priority.value}). "
        f"Key de-prioritization factors: " + " ".join(reasons)
    )
    return explanation


def find_negative_test_candidates(
    vulnerabilities: List[Vulnerability],
    profile: OrganizationProfile,
    min_cvss: float = 9.0,
    max_rank_threshold: int = 15,
) -> List[NegativeTestItem]:
    """Find vulnerabilities with CVSS >= min_cvss that ranked outside the top tier for the given organization."""
    all_ranked = rank_all_vulnerabilities(vulnerabilities, profile)
    total_candidates = len(all_ranked)
    candidates: List[NegativeTestItem] = []

    for item in all_ranked:
        cvss = item.vulnerability.cvss_base_score or 0.0
        if cvss >= min_cvss and (item.rank > max_rank_threshold or item.priority in (PriorityLevel.LOW, PriorityLevel.MEDIUM)):
            reason = explain_negative_test_result(item, profile, total_candidates)
            candidates.append(
                NegativeTestItem(
                    vulnerability=item.vulnerability,
                    score_breakdown=item.score_breakdown,
                    rank=item.rank,
                    total_candidates=total_candidates,
                    reason_low_or_excluded=reason,
                )
            )

    return candidates
