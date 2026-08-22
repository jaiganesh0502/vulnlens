"""Data models and enums for the NexoraPay Cyber Risk Simulator."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Exposure(str, Enum):
    """Network accessibility tier."""
    INTERNET_FACING = "Internet-facing"
    INTERNAL = "Internal"

    @classmethod
    def from_str(cls, val: str) -> Exposure:
        v = val.strip().lower()
        if v in ("internet", "internet-facing", "external", "public"):
            return cls.INTERNET_FACING
        elif v in ("internal", "private", "intranet"):
            return cls.INTERNAL
        raise ValueError(f"Unknown exposure value: '{val}'. Expected 'internet-facing' or 'internal'.")


class Criticality(str, Enum):
    """Asset business criticality level."""
    CRITICAL = "Critical"
    HIGH = "High"
    NORMAL = "Normal"
    LOW = "Low"

    @classmethod
    def from_str(cls, val: str) -> Criticality:
        v = val.strip().lower()
        if v == "critical":
            return cls.CRITICAL
        elif v == "high":
            return cls.HIGH
        elif v in ("normal", "medium"):
            return cls.NORMAL
        elif v == "low":
            return cls.LOW
        raise ValueError(f"Unknown criticality value: '{val}'. Expected 'critical', 'high', 'normal', or 'low'.")


class RiskAppetite(str, Enum):
    """Organizational risk appetite profile."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"

    @classmethod
    def from_str(cls, val: str) -> RiskAppetite:
        v = val.strip().lower()
        if v in ("low", "conservative"):
            return cls.LOW
        elif v in ("medium", "moderate"):
            return cls.MEDIUM
        elif v in ("high", "aggressive"):
            return cls.HIGH
        raise ValueError(f"Unknown risk appetite profile: '{val}'. Expected 'low', 'medium', or 'high'.")


class PriorityLevel(str, Enum):
    """Operational remediation priority level."""
    URGENT = "URGENT"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def badge_color(self) -> str:
        """Hex color code for UI rendering."""
        if self == PriorityLevel.URGENT:
            return "#EF4444"  # Red
        elif self == PriorityLevel.HIGH:
            return "#F97316"  # Orange
        elif self == PriorityLevel.MEDIUM:
            return "#EAB308"  # Yellow
        else:
            return "#10B981"  # Green

    @property
    def terminal_color(self) -> str:
        """ANSI escape code for terminal rendering."""
        if self == PriorityLevel.URGENT:
            return "\033[91m"  # Bright Red
        elif self == PriorityLevel.HIGH:
            return "\033[33m"  # Bright Yellow/Orange
        elif self == PriorityLevel.MEDIUM:
            return "\033[93m"  # Yellow
        else:
            return "\033[92m"  # Bright Green


class CVSSSeverity(str, Enum):
    """Official CVSS technical severity category."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"

    @classmethod
    def from_score(cls, score: float) -> CVSSSeverity:
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0.0:
            return cls.LOW
        return cls.NONE


@dataclass(frozen=True)
class Asset:
    """Fictional organizational asset representation."""
    asset_id: str
    name: str
    exposure: Exposure
    criticality: Criticality
    business_role: str
    icon: str = "server"
    tier: str = "Internal Network"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "name": self.name,
            "exposure": self.exposure.value,
            "criticality": self.criticality.value,
            "business_role": self.business_role,
            "icon": self.icon,
            "tier": self.tier,
        }


@dataclass
class Organisation:
    """Fictional organization metadata."""
    name: str = "NexoraPay"
    industry: str = "Financial Services / Digital Payments"
    size: str = "Regional organisation"
    risk_appetite: RiskAppetite = RiskAppetite.LOW
    assets: List[Asset] = field(default_factory=list)

    @property
    def critical_services_count(self) -> int:
        return sum(1 for a in self.assets if a.criticality == Criticality.CRITICAL)

    @property
    def internet_facing_count(self) -> int:
        return sum(1 for a in self.assets if a.exposure == Exposure.INTERNET_FACING)

    @property
    def internal_count(self) -> int:
        return sum(1 for a in self.assets if a.exposure == Exposure.INTERNAL)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "industry": self.industry,
            "size": self.size,
            "risk_appetite": self.risk_appetite.value,
            "critical_services_count": self.critical_services_count,
            "internet_facing_count": self.internet_facing_count,
            "internal_count": self.internal_count,
            "assets": [a.to_dict() for a in self.assets],
        }


@dataclass(frozen=True)
class VulnerabilityScenario:
    """Fictional vulnerability scenario."""
    vuln_id: str
    product: str
    cvss: float
    cvss_severity: str
    kev: bool
    epss: float
    affected_asset_name: str
    exposure: Exposure
    criticality: Criticality
    business_importance: str
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_id": self.vuln_id,
            "product": self.product,
            "cvss": self.cvss,
            "cvss_severity": self.cvss_severity,
            "kev": self.kev,
            "epss": self.epss,
            "affected_asset_name": self.affected_asset_name,
            "exposure": self.exposure.value,
            "criticality": self.criticality.value,
            "business_importance": self.business_importance,
            "explanation": self.explanation,
        }


@dataclass(frozen=True)
class ScoreContribution:
    """Transparent mathematical breakdown of prioritisation factors."""
    cvss_contribution: float
    kev_contribution: float
    epss_contribution: float
    exposure_contribution: float
    criticality_contribution: float
    total_score: float
    priority_level: PriorityLevel

    @property
    def base_score(self) -> float:
        return round(self.cvss_contribution + self.kev_contribution + self.epss_contribution, 2)

    @property
    def technical_threat_score(self) -> float:
        return self.base_score

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cvss_contribution": round(self.cvss_contribution, 2),
            "kev_contribution": round(self.kev_contribution, 2),
            "epss_contribution": round(self.epss_contribution, 2),
            "exposure_contribution": round(self.exposure_contribution, 2),
            "criticality_contribution": round(self.criticality_contribution, 2),
            "total_score": round(self.total_score, 1),
            "priority_level": self.priority_level.value,
            "badge_color": self.priority_level.badge_color,
        }


@dataclass(frozen=True)
class EvaluationContext:
    """Context state used for prioritizing a vulnerability."""
    cvss: float
    kev: bool
    epss: float
    exposure: Exposure
    criticality: Criticality
    risk_appetite: RiskAppetite = RiskAppetite.LOW

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cvss": self.cvss,
            "kev": self.kev,
            "epss": self.epss,
            "exposure": self.exposure.value,
            "criticality": self.criticality.value,
            "risk_appetite": self.risk_appetite.value,
        }


@dataclass
class WhatIfChange:
    """Represents a single variable modification in a simulation."""
    factor: str
    before_value: str
    after_value: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "factor": self.factor,
            "before_value": self.before_value,
            "after_value": self.after_value,
        }


@dataclass
class WhatIfResult:
    """Complete output of a What-If simulation comparing before and after states."""
    vuln_id: str
    product: str
    cvss: float  # Invariant: technical CVSS never changes
    before_context: EvaluationContext
    after_context: EvaluationContext
    before_breakdown: ScoreContribution
    after_breakdown: ScoreContribution
    changes: List[WhatIfChange]
    why_explanation: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_id": self.vuln_id,
            "product": self.product,
            "cvss": self.cvss,
            "before_context": self.before_context.to_dict(),
            "after_context": self.after_context.to_dict(),
            "before_breakdown": self.before_breakdown.to_dict(),
            "after_breakdown": self.after_breakdown.to_dict(),
            "changes": [c.to_dict() for c in self.changes],
            "why_explanation": self.why_explanation,
        }
