"""Ranking, deduplication, and prioritization engine for VulnLens."""

from typing import Dict, List, Optional, Tuple

from src.explainer import (
    determine_confidence,
    extract_source_info,
    generate_matched_context,
    generate_plain_title,
    generate_safe_next_action,
    generate_why_this_matters,
)
from src.matcher import normalize_product_name
from src.models import (
    OrganizationProfile,
    ScoreBreakdown,
    TriageResult,
    Vulnerability,
)
from src.scorer import (
    calculate_score,
    determine_priority_level,
)


def deduplicate_vulnerabilities(
    vulnerabilities: List[Vulnerability],
) -> List[Vulnerability]:
    """Deduplicate records by (cve_id, normalized_product_name).
    
    Preserves the first occurrence or highest CVSS entry if identical.
    """
    seen: Dict[Tuple[str, str], Vulnerability] = {}
    
    for v in vulnerabilities:
        key = (v.cve_id.strip().upper(), normalize_product_name(v.product_name))
        if key not in seen:
            seen[key] = v
        else:
            # If duplicate exists, keep the record with higher CVSS or valid data
            existing = seen[key]
            curr_cvss = v.cvss_base_score or 0.0
            exist_cvss = existing.cvss_base_score or 0.0
            if curr_cvss > exist_cvss:
                seen[key] = v

    return list(seen.values())


def rank_all_vulnerabilities(
    vulnerabilities: List[Vulnerability],
    profile: OrganizationProfile,
    critical_multiplier: Optional[float] = None,
) -> List[TriageResult]:
    """Score, explain, and rank all deduplicated vulnerabilities for an organization."""
    # 1. Deduplicate
    unique_vulns = deduplicate_vulnerabilities(vulnerabilities)

    scored_items: List[Tuple[Vulnerability, ScoreBreakdown]] = []
    for vuln in unique_vulns:
        breakdown = calculate_score(vuln, profile, critical_multiplier=critical_multiplier)
        scored_items.append((vuln, breakdown))

    # 2. Sort deterministically:
    # Primary: final_score DESC
    # Secondary: cvss_base_score DESC
    # Tertiary: first_epss DESC
    # Quaternary: cve_id ASC
    scored_items.sort(
        key=lambda item: (
            -item[1].final_score,
            -(item[0].cvss_base_score or 0.0),
            -(item[0].first_epss or 0.0),
            item[0].cve_id,
        )
    )

    # 3. Build TriageResult with rankings
    results: List[TriageResult] = []
    for rank_idx, (vuln, breakdown) in enumerate(scored_items, start=1):
        priority = determine_priority_level(breakdown.final_score)
        plain_title = generate_plain_title(vuln, breakdown)
        matched_context = generate_matched_context(vuln, profile, breakdown)
        why_this_matters = generate_why_this_matters(vuln, profile, breakdown)
        safe_next_action = generate_safe_next_action(vuln, breakdown)
        confidence, confidence_reason = determine_confidence(vuln)
        source_info = extract_source_info(vuln)

        results.append(
            TriageResult(
                rank=rank_idx,
                vulnerability=vuln,
                score_breakdown=breakdown,
                priority=priority,
                plain_title=plain_title,
                matched_context=matched_context,
                why_this_matters=why_this_matters,
                safe_next_action=safe_next_action,
                confidence=confidence,
                confidence_reason=confidence_reason,
                source_info=source_info,
            )
        )

    # 4. Calculate Decision Margins and What-Would-Change-Decision Counterfactuals
    for i, res in enumerate(results):
        if i < len(results) - 1:
            next_score = results[i + 1].score_breakdown.final_priority_score
            res.decision_margin = round(res.score_breakdown.final_priority_score - next_score, 2)
        else:
            res.decision_margin = None

        if res.rank > 1:
            tech_threat = res.score_breakdown.technical_threat_score
            counterfactuals = []

            # Test 1: Exposure -> Internet-facing (1.20x)
            p_score_exp = round(tech_threat * 1.20, 2)
            counterfactuals.append({
                "factor": "Exposure → Internet-facing",
                "multiplier": "×1.20",
                "projected_priority_score": p_score_exp,
                "projected_priority": determine_priority_level(p_score_exp).value,
            })

            # Test 2: Importance -> High (1.10x)
            p_score_high = round(tech_threat * 1.10, 2)
            counterfactuals.append({
                "factor": "Importance → High",
                "multiplier": "×1.10",
                "projected_priority_score": p_score_high,
                "projected_priority": determine_priority_level(p_score_high).value,
            })

            # Test 3: Importance -> Critical (1.20x)
            p_score_crit = round(tech_threat * 1.20, 2)
            counterfactuals.append({
                "factor": "Importance → Critical",
                "multiplier": "×1.20",
                "projected_priority_score": p_score_crit,
                "projected_priority": determine_priority_level(p_score_crit).value,
            })

            # Test 4: Combined Internet-facing + Critical (1.44x)
            p_score_both = round(tech_threat * 1.44, 2)
            counterfactuals.append({
                "factor": "Internet-facing + Critical Asset",
                "multiplier": "×1.44",
                "projected_priority_score": p_score_both,
                "projected_priority": determine_priority_level(p_score_both).value,
            })

            res.what_would_change_decision = counterfactuals

    return results


def rank_vulnerabilities(
    vulnerabilities: List[Vulnerability],
    profile: OrganizationProfile,
    top_n: int = 5,
    critical_multiplier: Optional[float] = None,
) -> List[TriageResult]:
    """Score, rank, and return the Top-N personalized vulnerability priorities for an organization."""
    all_ranked = rank_all_vulnerabilities(
        vulnerabilities,
        profile,
        critical_multiplier=critical_multiplier,
    )
    return all_ranked[:top_n]
