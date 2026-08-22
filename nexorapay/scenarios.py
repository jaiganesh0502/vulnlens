"""Synthetic scenarios, assets, and educational metadata for NexoraPay.

IMPORTANT:
- NexoraPay is a COMPLETELY FICTIONAL regional digital-payments organisation.
- All scenarios, identifiers (NXP-DEMO-001..005), and network topologies are synthetic.
- No real systems, IP addresses, domains, or infrastructure are referenced.
"""

from __future__ import annotations

from typing import Dict, List

from nexorapay.models import (
    Asset,
    Criticality,
    CVSSSeverity,
    Exposure,
    Organisation,
    RiskAppetite,
    VulnerabilityScenario,
)

# Section 3: Fictional Assets
NEXORAPAY_ASSETS: List[Asset] = [
    Asset(
        asset_id="AST-PAY-01",
        name="Customer Payment Portal",
        exposure=Exposure.INTERNET_FACING,
        criticality=Criticality.CRITICAL,
        business_role="Customer payment transactions",
        icon="credit-card",
        tier="Internet-Facing Tier",
    ),
    Asset(
        asset_id="AST-IDP-01",
        name="Identity Provider",
        exposure=Exposure.INTERNET_FACING,
        criticality=Criticality.CRITICAL,
        business_role="Authentication and access",
        icon="shield-check",
        tier="Internet-Facing Tier",
    ),
    Asset(
        asset_id="AST-API-01",
        name="Transaction API",
        exposure=Exposure.INTERNET_FACING,
        criticality=Criticality.CRITICAL,
        business_role="Payment transaction processing",
        icon="cpu",
        tier="Internet-Facing Tier",
    ),
    Asset(
        asset_id="AST-FIL-01",
        name="Employee File Server",
        exposure=Exposure.INTERNAL,
        criticality=Criticality.HIGH,
        business_role="Internal documents",
        icon="folder",
        tier="Internal Network",
    ),
    Asset(
        asset_id="AST-REP-01",
        name="Internal Reporting Server",
        exposure=Exposure.INTERNAL,
        criticality=Criticality.NORMAL,
        business_role="Reporting and analytics",
        icon="bar-chart-2",
        tier="Internal Network",
    ),
    Asset(
        asset_id="AST-DEV-01",
        name="Development Server",
        exposure=Exposure.INTERNAL,
        criticality=Criticality.NORMAL,
        business_role="Application development",
        icon="terminal",
        tier="Internal Network",
    ),
]

# Fictional Organisation Metadata
NEXORAPAY_ORG = Organisation(
    name="NexoraPay",
    industry="Financial Services / Digital Payments",
    size="Regional organisation",
    risk_appetite=RiskAppetite.LOW,
    assets=NEXORAPAY_ASSETS,
)

# Section 5: Fictional Vulnerability Scenarios
DEMO_SCENARIOS: List[VulnerabilityScenario] = [
    VulnerabilityScenario(
        vuln_id="NXP-DEMO-001",
        product="Payment Gateway Framework",
        cvss=9.8,
        cvss_severity="CRITICAL",
        kev=False,
        epss=0.21,
        affected_asset_name="Internal Reporting Server",
        exposure=Exposure.INTERNAL,
        criticality=Criticality.NORMAL,
        business_importance="Reporting & Analytics",
        explanation=(
            "High technical severity (CVSS 9.8), but resides on an internal reporting "
            "server with no known active exploitation in the wild."
        ),
    ),
    VulnerabilityScenario(
        vuln_id="NXP-DEMO-002",
        product="Payment Gateway Framework",
        cvss=8.4,
        cvss_severity="HIGH",
        kev=True,
        epss=0.91,
        affected_asset_name="Customer Payment Portal",
        exposure=Exposure.INTERNET_FACING,
        criticality=Criticality.CRITICAL,
        business_importance="Mission-critical (Direct Customer Payments)",
        explanation=(
            "Confirmed in-the-wild exploitation (CISA KEV) combined with extreme exploitation "
            "probability (EPSS 0.91) on an internet-facing crown jewel asset elevates operational "
            "priority to URGENT."
        ),
    ),
    VulnerabilityScenario(
        vuln_id="NXP-DEMO-003",
        product="Identity Component",
        cvss=8.1,
        cvss_severity="HIGH",
        kev=True,
        epss=0.78,
        affected_asset_name="Identity Provider",
        exposure=Exposure.INTERNET_FACING,
        criticality=Criticality.CRITICAL,
        business_importance="Mission-critical (Authentication & SSO)",
        explanation=(
            "Active exploitation signal on an external authentication core with high EPSS (0.78), "
            "requiring immediate operational remediation."
        ),
    ),
    VulnerabilityScenario(
        vuln_id="NXP-DEMO-004",
        product="Internal Analytics Platform",
        cvss=7.2,
        cvss_severity="HIGH",
        kev=False,
        epss=0.08,
        affected_asset_name="Internal Reporting Server",
        exposure=Exposure.INTERNAL,
        criticality=Criticality.NORMAL,
        business_importance="Internal Analytics",
        explanation=(
            "High theoretical CVSS, but internal segmentation and negligible exploitation probability "
            "(EPSS 0.08) yield moderate organizational risk."
        ),
    ),
    VulnerabilityScenario(
        vuln_id="NXP-DEMO-005",
        product="Employee File Platform",
        cvss=9.1,
        cvss_severity="CRITICAL",
        kev=False,
        epss=0.04,
        affected_asset_name="Employee File Server",
        exposure=Exposure.INTERNAL,
        criticality=Criticality.HIGH,
        business_importance="Internal Documents Repository",
        explanation=(
            "Critical technical CVSS (9.1) on an internal server containing sensitive files; "
            "warrants high attention but is tempered by lack of internet exposure and zero active KEV."
        ),
    ),
]

SCENARIOS_BY_ID: Dict[str, VulnerabilityScenario] = {
    s.vuln_id: s for s in DEMO_SCENARIOS
}

# Section 16: Educational Signal Cards
EDUCATIONAL_SIGNALS = [
    {
        "signal": "CVSS",
        "title": "Common Vulnerability Scoring System",
        "question": "How severe is the vulnerability technically?",
        "description": (
            "CVSS measures intrinsic flaw severity under standardized laboratory conditions. "
            "It evaluates attack vector, complexity, privileges required, and impact on CIA triad. "
            "It does NOT know if the product is in your network, internet-facing, or actively exploited."
        ),
        "source": "FIRST / NIST NVD",
    },
    {
        "signal": "CISA KEV",
        "title": "Known Exploited Vulnerabilities",
        "question": "Is there evidence this vulnerability has already been exploited?",
        "description": (
            "The CISA KEV catalog identifies vulnerabilities with confirmed evidence of active exploitation "
            "in the wild. It is the strongest defensive signal that an adversary has operationalized an attack."
        ),
        "source": "Cybersecurity and Infrastructure Security Agency (CISA)",
    },
    {
        "signal": "EPSS",
        "title": "Exploit Prediction Scoring System",
        "question": "How likely is exploitation?",
        "description": (
            "EPSS uses predictive machine learning to estimate the empirical probability (0% - 100%) that a "
            "vulnerability will be actively exploited in the wild within the next 30 days."
        ),
        "source": "FIRST EPSS SIG",
    },
]

# Section 17: Real-World Defensive Case Study (Log4Shell)
REAL_WORLD_CASE_STUDY = {
    "title": "LOG4SHELL",
    "cve_id": "CVE-2021-44228",
    "product": "Apache Log4j Core",
    "cvss": 10.0,
    "cvss_severity": "CRITICAL",
    "kev": True,
    "epss": 0.97,
    "educational_note": (
        "Log4Shell became a major defensive prioritisation event because of its technical severity "
        "and evidence of exploitation."
    ),
    "why_defensive_priority": (
        "Log4Shell combined a maximum CVSS (10.0) with ubiquitous exposure, instant weaponization (CISA KEV), "
        "and a near 1.0 EPSS. Defense teams prioritized internet-facing identity, payment, and boundary gateways "
        "first before addressing isolated internal logging servers."
    ),
    "official_sources": [
        {"name": "CISA Vulnerability Guidance", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
        {"name": "NIST NVD CVE-2021-44228", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
        {"name": "FIRST EPSS Metric", "url": "https://www.first.org/epss"},
    ],
}
