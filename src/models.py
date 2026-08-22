"""Data models for VulnLens."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class PriorityLevel(str, Enum):
    URGENT = "URGENT"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NEEDS_VERIFICATION = "NEEDS_VERIFICATION"


@dataclass
class WeightModifiers:
    cvss_weight: float
    cisa_kev_weight: float
    first_epss_weight: float

    def __post_init__(self):
        # Convert values to float if parsed as strings
        self.cvss_weight = float(self.cvss_weight)
        self.cisa_kev_weight = float(self.cisa_kev_weight)
        self.first_epss_weight = float(self.first_epss_weight)


@dataclass
class OrganisationFingerprint:
    org_name: str
    org_id: str
    sector: str
    risk_appetite: str
    cvss_weight: float
    cisa_kev_weight: float
    first_epss_weight: float
    exposure_impact: str = "HIGH IMPACT (1.20x)"
    criticality_impact: str = "HIGH IMPACT (1.20x)"
    priority_philosophy: str = ""

    def __post_init__(self):
        if not self.priority_philosophy:
            self.priority_philosophy = self._generate_philosophy()

    def _generate_philosophy(self) -> str:
        w_kev = self.cisa_kev_weight
        w_epss = self.first_epss_weight
        w_cvss = self.cvss_weight

        if w_kev >= w_epss and w_kev >= w_cvss and w_kev >= 0.40:
            return "Strong emphasis on known exploitation and active in-the-wild threat signals."
        elif w_epss >= w_kev and w_epss >= w_cvss and w_epss >= 0.40:
            return "Strong emphasis on forward-looking exploitation probability and weaponization likelihood."
        elif w_cvss >= w_kev and w_cvss >= w_epss and w_cvss >= 0.40:
            return "Strong emphasis on intrinsic technical severity and full system compromise impact."
        else:
            return "Balanced threat-signal prioritisation across technical and active exploitation signals."

    def to_ascii_display(self) -> str:
        def make_bar(wt: float) -> str:
            filled = int(round(wt * 12))
            unfilled = 12 - filled
            return "█" * filled + "░" * unfilled

        return f"""============================================================
{self.org_name.upper()}
ORGANISATION FINGERPRINT
============================================================

THREAT SIGNAL WEIGHTS

CVSS
{make_bar(self.cvss_weight)} {int(round(self.cvss_weight * 100))}%

KEV
{make_bar(self.cisa_kev_weight)} {int(round(self.cisa_kev_weight * 100))}%

EPSS
{make_bar(self.first_epss_weight)} {int(round(self.first_epss_weight * 100))}%

CONTEXT

Exposure:
{self.exposure_impact}

Criticality:
{self.criticality_impact}

PRIORITY PHILOSOPHY:

{self.priority_philosophy}

============================================================"""


def extract_fingerprint(profile: "OrganizationProfile") -> OrganisationFingerprint:
    """Robust helper to extract OrganisationFingerprint from any OrganizationProfile instance."""
    if hasattr(profile, "get_fingerprint") and callable(profile.get_fingerprint):
        return profile.get_fingerprint()
    return OrganisationFingerprint(
        org_name=getattr(profile, "name", "Custom Organization"),
        org_id=getattr(profile, "org_id", "ORG-CUSTOM"),
        sector=getattr(profile, "sector", "General"),
        risk_appetite=getattr(profile, "risk_appetite", "Moderate"),
        cvss_weight=profile.weight_modifiers.cvss_weight,
        cisa_kev_weight=profile.weight_modifiers.cisa_kev_weight,
        first_epss_weight=profile.weight_modifiers.first_epss_weight,
    )


@dataclass
class OrganizationProfile:
    org_id: str
    name: str
    sector: str
    risk_appetite: str
    weight_modifiers: WeightModifiers
    critical_products: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OrganizationProfile":
        wm_data = data.get("weight_modifiers", {})
        weight_modifiers = WeightModifiers(
            cvss_weight=wm_data.get("cvss_weight", 0.33),
            cisa_kev_weight=wm_data.get("cisa_kev_weight", 0.33),
            first_epss_weight=wm_data.get("first_epss_weight", 0.34),
        )
        return cls(
            org_id=data.get("org_id", "ORG-CUSTOM"),
            name=data.get("name", "Custom Organization"),
            sector=data.get("sector", "General"),
            risk_appetite=data.get("risk_appetite", "Moderate"),
            weight_modifiers=weight_modifiers,
            critical_products=data.get("critical_products", []),
        )

    def get_fingerprint(self) -> OrganisationFingerprint:
        return OrganisationFingerprint(
            org_name=self.name,
            org_id=self.org_id,
            sector=self.sector,
            risk_appetite=self.risk_appetite,
            cvss_weight=self.weight_modifiers.cvss_weight,
            cisa_kev_weight=self.weight_modifiers.cisa_kev_weight,
            first_epss_weight=self.weight_modifiers.first_epss_weight,
        )


@dataclass
class Vulnerability:
    cve_id: str
    product_name: str
    cvss_base_score: Optional[float]
    cisa_kev: bool
    first_epss: Optional[float]
    raw_data: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_valid_cvss(self) -> bool:
        return self.cvss_base_score is not None and 0.0 <= self.cvss_base_score <= 10.0

    @property
    def is_valid_epss(self) -> bool:
        return self.first_epss is not None and 0.0 <= self.first_epss <= 1.0


@dataclass
class ScoreBreakdown:
    cvss_base_score: float
    cvss_normalized: float
    cvss_weight: float
    cvss_contribution: float
    cisa_kev: bool
    kev_signal: float
    cisa_kev_weight: float
    kev_contribution: float
    first_epss: float
    epss_signal: float
    first_epss_weight: float
    epss_contribution: float
    base_score: float
    is_critical_product: bool
    critical_multiplier: float
    final_score: float
    threat_score_normalized: float = 0.0
    technical_threat_score: float = 0.0
    exposure_multiplier: float = 1.00
    importance_multiplier: float = 1.00
    context_multiplier: float = 1.00
    context_delta: float = 0.0
    final_priority_score: float = 0.0

    def __post_init__(self):
        if self.technical_threat_score == 0.0:
            self.technical_threat_score = self.base_score
        if self.final_priority_score == 0.0:
            self.final_priority_score = self.final_score
        if self.context_multiplier == 1.00 and self.critical_multiplier != 1.00:
            self.context_multiplier = self.critical_multiplier
        if self.context_delta == 0.0:
            self.context_delta = round(self.final_priority_score - self.technical_threat_score, 4)
        if self.threat_score_normalized == 0.0 and self.technical_threat_score > 0:
            self.threat_score_normalized = round(self.technical_threat_score / 100.0, 4)


@dataclass
class TriageResult:
    rank: int
    vulnerability: Vulnerability
    score_breakdown: ScoreBreakdown
    priority: PriorityLevel
    plain_title: str
    matched_context: str
    why_this_matters: List[str]
    safe_next_action: str
    confidence: ConfidenceLevel
    confidence_reason: str
    source_info: Dict[str, Any]
    decision_margin: Optional[float] = None
    what_would_change_decision: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class NegativeTestItem:
    vulnerability: Vulnerability
    score_breakdown: ScoreBreakdown
    rank: Optional[int]
    total_candidates: int
    reason_low_or_excluded: str

    @property
    def explanation(self) -> str:
        return self.reason_low_or_excluded

    @property
    def reason(self) -> str:
        return self.reason_low_or_excluded


@dataclass
class CalibrationRecord:
    cve_id: str
    product_name: str
    cvss_base_score: float
    cisa_kev: bool
    first_epss: float
    practitioner_rank_bank: Optional[int] = None
    practitioner_rank_startup: Optional[int] = None
