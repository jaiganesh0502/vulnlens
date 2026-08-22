"""Core simulation engine, What-If evaluator, and reasoning generator for NexoraPay."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from nexorapay.models import (
    Criticality,
    EvaluationContext,
    Exposure,
    PriorityLevel,
    RiskAppetite,
    ScoreContribution,
    VulnerabilityScenario,
    WhatIfChange,
    WhatIfResult,
)
from nexorapay.scenarios import (
    DEMO_SCENARIOS,
    NEXORAPAY_ORG,
    SCENARIOS_BY_ID,
)
from nexorapay.scoring import (
    calculate_score_breakdown,
)


class CyberRiskSimulator:
    """Offline-first simulation engine for analyzing contextual cybersecurity risk."""

    def __init__(self, organisation=NEXORAPAY_ORG, scenarios: List[VulnerabilityScenario] = None):
        self.organisation = organisation
        self.scenarios = list(scenarios or DEMO_SCENARIOS)
        self.scenarios_by_id: Dict[str, VulnerabilityScenario] = {
            s.vuln_id: s for s in self.scenarios
        }

    def get_scenario(self, vuln_id: str) -> Optional[VulnerabilityScenario]:
        """Retrieve a scenario by its fictional identifier."""
        return self.scenarios_by_id.get(vuln_id.strip().upper())

    def evaluate_scenario(
        self,
        scenario: VulnerabilityScenario,
        risk_appetite: RiskAppetite = RiskAppetite.LOW,
    ) -> ScoreContribution:
        """Evaluate a scenario under a given organizational risk appetite profile."""
        ctx = EvaluationContext(
            cvss=scenario.cvss,
            kev=scenario.kev,
            epss=scenario.epss,
            exposure=scenario.exposure,
            criticality=scenario.criticality,
            risk_appetite=risk_appetite,
        )
        return calculate_score_breakdown(ctx)

    def evaluate_all(
        self,
        risk_appetite: RiskAppetite = RiskAppetite.LOW,
    ) -> List[Tuple[VulnerabilityScenario, ScoreContribution]]:
        """Evaluate all loaded scenarios and sort by operational priority descending."""
        results = []
        for s in self.scenarios:
            breakdown = self.evaluate_scenario(s, risk_appetite=risk_appetite)
            results.append((s, breakdown))

        # Sort descending by total score, then CVSS as tie-breaker
        results.sort(key=lambda item: (item[1].total_score, item[0].cvss), reverse=True)
        return results

    def run_what_if(
        self,
        vuln_id: str = "NXP-DEMO-002",
        exposure: Optional[Exposure] = None,
        criticality: Optional[Criticality] = None,
        kev: Optional[bool] = None,
        epss: Optional[float] = None,
        risk_appetite: Optional[RiskAppetite] = None,
    ) -> WhatIfResult:
        """Execute a What-If simulation on a scenario with modified context variables.

        CRITICAL INVARIANT:
        The CVSS base score measures intrinsic technical flaw severity and is NEVER altered
        by exposure, criticality, KEV, EPSS, or risk appetite profile changes.
        """
        scenario = self.get_scenario(vuln_id)
        if not scenario:
            raise KeyError(f"Vulnerability scenario '{vuln_id}' not found.")

        # Invariant: CVSS is immutable
        immutable_cvss = scenario.cvss

        # Baseline context (Before)
        before_context = EvaluationContext(
            cvss=immutable_cvss,
            kev=scenario.kev,
            epss=scenario.epss,
            exposure=scenario.exposure,
            criticality=scenario.criticality,
            risk_appetite=self.organisation.risk_appetite,
        )
        before_breakdown = calculate_score_breakdown(before_context)

        # Target modified context (After)
        target_exposure = exposure if exposure is not None else scenario.exposure
        target_criticality = criticality if criticality is not None else scenario.criticality
        target_kev = kev if kev is not None else scenario.kev
        target_epss = epss if epss is not None else scenario.epss
        target_appetite = risk_appetite if risk_appetite is not None else self.organisation.risk_appetite

        after_context = EvaluationContext(
            cvss=immutable_cvss,  # Strictly unchanged
            kev=target_kev,
            epss=target_epss,
            exposure=target_exposure,
            criticality=target_criticality,
            risk_appetite=target_appetite,
        )
        after_breakdown = calculate_score_breakdown(after_context)

        # Detect changes and generate explanations
        changes: List[WhatIfChange] = []
        why_explanations: List[str] = []

        if target_exposure != scenario.exposure:
            changes.append(WhatIfChange(
                factor="Exposure",
                before_value=scenario.exposure.value,
                after_value=target_exposure.value,
            ))
            if target_exposure == Exposure.INTERNAL:
                why_explanations.append(
                    "Exposure decreased (Internet-facing -> Internal): Internal network segmentation limits remote accessibility."
                )
            else:
                why_explanations.append(
                    "Exposure increased (Internal -> Internet-facing): Direct boundary accessibility substantially expands attack surface."
                )

        if target_criticality != scenario.criticality:
            changes.append(WhatIfChange(
                factor="Asset Criticality",
                before_value=scenario.criticality.value,
                after_value=target_criticality.value,
            ))
            why_explanations.append(
                f"Asset criticality shifted ({scenario.criticality.value} -> {target_criticality.value}): Modified business mission role adjusted operational urgency."
            )

        if target_kev != scenario.kev:
            changes.append(WhatIfChange(
                factor="CISA KEV",
                before_value="YES" if scenario.kev else "NO",
                after_value="YES" if target_kev else "NO",
            ))
            if target_kev:
                why_explanations.append(
                    "Threat signal added (KEV NO -> YES): Confirmed weaponization in the wild sharply escalated threat factor."
                )
            else:
                why_explanations.append(
                    "Threat signal removed (KEV YES -> NO): Flaw lacks confirmed in-the-wild exploitation evidence."
                )

        if abs(target_epss - scenario.epss) > 1e-4:
            changes.append(WhatIfChange(
                factor="EPSS Probability",
                before_value=f"{scenario.epss:.2f}",
                after_value=f"{target_epss:.2f}",
            ))
            if target_epss < scenario.epss:
                why_explanations.append(
                    f"EPSS decreased ({scenario.epss:.2f} -> {target_epss:.2f}): Lower forward-looking exploitation probability reduced threat score."
                )
            else:
                why_explanations.append(
                    f"EPSS increased ({scenario.epss:.2f} -> {target_epss:.2f}): Higher exploitation likelihood increased threat score."
                )

        if target_appetite != self.organisation.risk_appetite:
            changes.append(WhatIfChange(
                factor="Risk Appetite",
                before_value=self.organisation.risk_appetite.value,
                after_value=target_appetite.value,
            ))
            why_explanations.append(
                f"Risk profile changed ({self.organisation.risk_appetite.value} -> {target_appetite.value}): Re-weighted CVSS vs KEV/EPSS trade-offs."
            )

        if not why_explanations:
            why_explanations.append("No context variables were modified from the baseline scenario.")

        return WhatIfResult(
            vuln_id=scenario.vuln_id,
            product=scenario.product,
            cvss=immutable_cvss,
            before_context=before_context,
            after_context=after_context,
            before_breakdown=before_breakdown,
            after_breakdown=after_breakdown,
            changes=changes,
            why_explanation=why_explanations,
        )
