"""Gold set calibration and sanity check benchmarking engine."""

import math
from dataclasses import dataclass
from typing import List, Optional

from src.models import (
    CalibrationRecord,
    OrganizationProfile,
    ScoreBreakdown,
    Vulnerability,
)
from src.scorer import calculate_score


@dataclass
class GoldSetEvaluationItem:
    cve_id: str
    product_name: str
    cvss_base_score: float
    cisa_kev: bool
    first_epss: float
    score_breakdown: ScoreBreakdown
    engine_rank: int
    practitioner_rank: Optional[int]
    rank_delta: Optional[int]
    notes: str


@dataclass
class CalibrationReport:
    org_name: str
    org_id: str
    items: List[GoldSetEvaluationItem]
    spearman_correlation: Optional[float]
    mean_absolute_rank_error: Optional[float]
    summary_text: str


def compute_spearman_correlation(ranks_x: List[float], ranks_y: List[float]) -> Optional[float]:
    """Calculate Spearman's rank correlation coefficient between two equal-length rank arrays."""
    n = len(ranks_x)
    if n <= 1 or len(ranks_y) != n:
        return None
    d_sq_sum = sum((rx - ry) ** 2 for rx, ry in zip(ranks_x, ranks_y))
    rho = 1.0 - (6.0 * d_sq_sum) / (n * (n**2 - 1))
    return round(rho, 4)


def evaluate_gold_set(
    gold_records: List[CalibrationRecord],
    profile: OrganizationProfile,
    practitioner_field: str = "practitioner_rank_bank",
) -> CalibrationReport:
    """Evaluate the deterministic engine against a practitioner-ranked gold set baseline.
    
    CRITICAL CONSTRAINT: This function evaluates ONLY the isolated gold set records.
    It never mixes or pollutes the production vulnerability dataset.
    """
    # 1. Convert gold records to temporary Vulnerability objects
    scored_candidates = []
    for rec in gold_records:
        vuln = Vulnerability(
            cve_id=rec.cve_id,
            product_name=rec.product_name,
            cvss_base_score=rec.cvss_base_score,
            cisa_kev=rec.cisa_kev,
            first_epss=rec.first_epss,
        )
        breakdown = calculate_score(vuln, profile)
        
        # Get target practitioner rank based on field
        p_rank = getattr(rec, practitioner_field, None)
        scored_candidates.append((rec, vuln, breakdown, p_rank))

    # 2. Sort by engine final_score descending
    scored_candidates.sort(
        key=lambda x: (
            -x[2].final_score,
            -(x[1].cvss_base_score or 0.0),
            -(x[1].first_epss or 0.0),
            x[1].cve_id,
        )
    )

    # 3. Build evaluation items
    items: List[GoldSetEvaluationItem] = []
    engine_ranks: List[float] = []
    practitioner_ranks: List[float] = []
    abs_errors: List[float] = []

    for rank_idx, (rec, vuln, breakdown, p_rank) in enumerate(scored_candidates, start=1):
        delta = (rank_idx - p_rank) if p_rank is not None else None
        
        # Build diagnostic notes
        notes = []
        if breakdown.is_critical_product:
            notes.append("Critical Asset (1.4x)")
        if vuln.cisa_kev:
            notes.append("KEV Active")
        if (vuln.first_epss or 0.0) >= 0.5:
            notes.append(f"High EPSS ({vuln.first_epss:.1%})")
        if (vuln.cvss_base_score or 0.0) >= 9.0:
            notes.append(f"CVSS {vuln.cvss_base_score}")

        item_note = ", ".join(notes) if notes else "Standard priority signals"

        items.append(
            GoldSetEvaluationItem(
                cve_id=rec.cve_id,
                product_name=rec.product_name,
                cvss_base_score=rec.cvss_base_score,
                cisa_kev=rec.cisa_kev,
                first_epss=rec.first_epss,
                score_breakdown=breakdown,
                engine_rank=rank_idx,
                practitioner_rank=p_rank,
                rank_delta=delta,
                notes=item_note,
            )
        )

        if p_rank is not None:
            engine_ranks.append(float(rank_idx))
            practitioner_ranks.append(float(p_rank))
            abs_errors.append(abs(rank_idx - p_rank))

    # 4. Compute metrics
    corr = compute_spearman_correlation(engine_ranks, practitioner_ranks) if len(engine_ranks) >= 3 else None
    mean_err = (sum(abs_errors) / len(abs_errors)) if abs_errors else None

    if corr is not None and corr >= 0.8:
        alignment = f"Strong rank alignment (Spearman ρ = {corr:.2f}, Mean Rank Delta = {mean_err:.2f})"
    elif corr is not None and corr >= 0.5:
        alignment = f"Moderate rank alignment (Spearman ρ = {corr:.2f}, Mean Rank Delta = {mean_err:.2f})"
    else:
        corr_str = f"{corr:.2f}" if corr is not None else "N/A"
        alignment = f"Calibration benchmark computed (Spearman ρ = {corr_str})"

    summary = (
        f"Gold-set sanity check against practitioner ranking for {profile.name}. "
        f"{alignment}. Evaluated across {len(items)} curated ground-truth records."
    )

    return CalibrationReport(
        org_name=profile.name,
        org_id=profile.org_id,
        items=items,
        spearman_correlation=corr,
        mean_absolute_rank_error=mean_err,
        summary_text=summary,
    )
