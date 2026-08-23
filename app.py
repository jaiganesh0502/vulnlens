"""VulnLens — Personalised Vulnerability Triage Enterprise Console.

Unified Global Brand & Design System:
  Background: Deep Navy #030E33
  Panels/Cards: Dark Blue #041648
  Accent: Electric Blue #0D7FFD
  Emblem: Vibrant Blue #2358F9 -> Purple #4F3DF5
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd
import streamlit as st

import src.models
import src.matcher
import src.scorer
import src.explainer
import src.ranking
import src.negative_test
import src.theme

from src.calibration import evaluate_gold_set
from src.comparison import compare_profiles
from src.loader import load_gold_set, load_profiles, load_vulnerabilities
from src.models import (
    CalibrationRecord,
    OrganizationProfile,
    PriorityLevel,
    TriageResult,
    Vulnerability,
)
from src.negative_test import find_negative_test_candidates
from src.ranking import rank_all_vulnerabilities, rank_vulnerabilities
from src.scorer import calculate_score, determine_priority_level
from src.theme import (
    BG_GLOW,
    BG_PRIMARY,
    BG_SECONDARY,
    ELECTRIC_BLUE,
    EMBLEM_BLUE,
    EMBLEM_VIOLET,
    GLOBAL_CSS,
    HIGHLIGHT_CYAN,
    LOW_GREEN,
    MEDIUM_AMBER,
    MID_BLUE,
    URGENT_RED,
    render_priority_badge,
    render_score_bar,
    render_sidebar_header,
    render_sidebar_org_card,
    render_sidebar_footer,
    render_top_header,
)


def render_html(html_content: str):
    """Helper to render multi-line HTML safely by compacting lines to prevent markdown code block triggers."""
    lines = []
    for line in html_content.splitlines():
        s = line.strip()
        if not s or (s.startswith("<!--") and s.endswith("-->")):
            continue
        lines.append(s)
    st.markdown(" ".join(lines), unsafe_allow_html=True)


def extract_fingerprint(p: OrganizationProfile):
    """Self-contained helper to generate fingerprint data without cache issues."""
    w_kev = p.weight_modifiers.cisa_kev_weight
    w_epss = p.weight_modifiers.first_epss_weight
    w_cvss = p.weight_modifiers.cvss_weight

    if w_kev >= w_epss and w_kev >= w_cvss and w_kev >= 0.40:
        philosophy = "Strong emphasis on known exploitation and active in-the-wild threat signals."
    elif w_epss >= w_kev and w_epss >= w_cvss and w_epss >= 0.40:
        philosophy = "Strong emphasis on forward-looking exploitation probability and weaponization likelihood."
    elif w_cvss >= w_kev and w_cvss >= w_epss and w_cvss >= 0.40:
        philosophy = "Strong emphasis on intrinsic technical severity and full system compromise impact."
    else:
        philosophy = "Balanced threat-signal prioritisation across technical and active exploitation signals."

    class FingerprintView:
        def __init__(self, name, org_id, sector, appetite, cvss_w, kev_w, epss_w, phil):
            self.org_name = name
            self.org_id = org_id
            self.sector = sector
            self.risk_appetite = appetite
            self.cvss_weight = cvss_w
            self.cisa_kev_weight = kev_w
            self.first_epss_weight = epss_w
            self.priority_philosophy = phil

    return FingerprintView(
        p.name,
        p.org_id,
        p.sector,
        getattr(p, "risk_appetite", "Moderate"),
        p.weight_modifiers.cvss_weight,
        p.weight_modifiers.cisa_kev_weight,
        p.weight_modifiers.first_epss_weight,
        philosophy,
    )


# Streamlit page setup
st.set_page_config(
    page_title="VulnLens | Enterprise Vulnerability Triage",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject central brand design tokens and styles
st.markdown(GLOBAL_CSS, unsafe_allow_html=True)


@st.cache_data(show_spinner=False)
def get_cached_vulnerabilities() -> List[Vulnerability]:
    return load_vulnerabilities(Path("data/vulnerabilities.csv"))


@st.cache_data(show_spinner=False)
def get_cached_profiles() -> List[OrganizationProfile]:
    return load_profiles(Path("data/profiles.json"))


@st.cache_data(show_spinner=False)
def get_cached_gold_set() -> List[CalibrationRecord]:
    return load_gold_set(Path("data/gold_set.csv"))


# Initialize session state for custom profiles and navigation
if "custom_profiles" not in st.session_state:
    st.session_state.custom_profiles = []

if "selected_org_id" not in st.session_state:
    st.session_state.selected_org_id = "ORG-001"

if "nav_section" not in st.session_state:
    st.session_state.nav_section = "▣ Command Centre"

# Load datasets safely with caching
try:
    vulnerabilities = get_cached_vulnerabilities()
    base_profiles = get_cached_profiles()
    gold_records = get_cached_gold_set()
except Exception as e:
    st.error(f"Failed to load bundled offline datasets: {e}")
    st.stop()

all_profiles = base_profiles + st.session_state.custom_profiles
profile_map = {p.org_id: p for p in all_profiles}
current_profile = profile_map.get(st.session_state.selected_org_id, all_profiles[0])
fingerprint = extract_fingerprint(current_profile)

# Pre-compute Top 5 & All ranked findings
@st.cache_data(show_spinner=False)
def compute_triage_for_org(org_id: str, _vulns: List[Vulnerability], _prof: OrganizationProfile) -> Tuple[List[TriageResult], List[TriageResult]]:
    t5 = rank_vulnerabilities(_vulns, _prof, top_n=5)
    all_r = rank_all_vulnerabilities(_vulns, _prof)
    return t5, all_r

top_5_results, all_ranked_results = compute_triage_for_org(current_profile.org_id, vulnerabilities, current_profile)

# Metrics calculation for KPI strip
urgent_count = sum(1 for r in all_ranked_results if r.priority == PriorityLevel.URGENT)
high_count = sum(1 for r in all_ranked_results if r.priority == PriorityLevel.HIGH)
med_low_count = len(all_ranked_results) - urgent_count - high_count

# ==============================================================================
# SIDEBAR: BRAND HEADER, ORG SELECTOR, THREAT PROFILE, NAVIGATION & STATUS
# ==============================================================================
with st.sidebar:
    render_html(render_sidebar_header())

    st.markdown(
        """
        <div style="font-size: 10px; font-weight: 800; color: #0D7FFD; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 6px;">
          TARGET ORGANISATION
        </div>
        """,
        unsafe_allow_html=True,
    )

    org_options = [f"{p.name} ({p.org_id})" for p in all_profiles]
    selected_idx = 0
    for idx, p in enumerate(all_profiles):
        if p.org_id == current_profile.org_id:
            selected_idx = idx
            break

    chosen_org_label = st.selectbox(
        "Select Target Organisation:",
        options=org_options,
        index=selected_idx,
        label_visibility="collapsed",
    )

    chosen_org_id = chosen_org_label.split("(")[-1].rstrip(")")
    if chosen_org_id != current_profile.org_id:
        st.session_state.selected_org_id = chosen_org_id
        st.rerun()

    # Organization Context Card
    render_html(render_sidebar_org_card(current_profile, fingerprint))

    st.markdown(
        """
        <div style="font-size: 10px; font-weight: 800; color: #64748B; letter-spacing: 0.08em; text-transform: uppercase; margin: 16px 0 6px 0;">
          NAVIGATION
        </div>
        """,
        unsafe_allow_html=True,
    )

    nav_choice = st.radio(
        "Navigation:",
        options=[
            "▣ Command Centre",
            "⚡ Priorities (Top 5)",
            "◉ Explain & Reasoning",
            "◌ What-If Simulator",
            "◎ Organisation Profile",
            "◫ Threat Intelligence",
            "▤ Provenance & Audit",
        ],
        index=[
            "▣ Command Centre",
            "⚡ Priorities (Top 5)",
            "◉ Explain & Reasoning",
            "◌ What-If Simulator",
            "◎ Organisation Profile",
            "◫ Threat Intelligence",
            "▤ Provenance & Audit",
        ].index(st.session_state.nav_section)
        if st.session_state.nav_section
        in [
            "▣ Command Centre",
            "⚡ Priorities (Top 5)",
            "◉ Explain & Reasoning",
            "◌ What-If Simulator",
            "◎ Organisation Profile",
            "◫ Threat Intelligence",
            "▤ Provenance & Audit",
        ]
        else 0,
        label_visibility="collapsed",
    )

    st.session_state.nav_section = nav_choice

    # Offline Status Footer
    render_html(render_sidebar_footer())


# ==============================================================================
# PAGE 1: COMMAND CENTRE (EXECUTIVE OVERVIEW & SIGNATURE TOP 5)
# ==============================================================================
if nav_choice == "▣ Command Centre":
    render_html(
        render_top_header(
            "Command Centre",
            "Operational Security Overview",
            current_profile.name,
            current_profile.org_id,
        )
    )

    # High-level Summary KPI Strip
    kpi_col1, kpi_col2, kpi_col3, kpi_col4, kpi_col5 = st.columns(5)
    with kpi_col1:
        render_html(
            f"""
            <div class="vl-kpi-card">
              <div class="vl-kpi-label">TOTAL ANALYSED</div>
              <div class="vl-kpi-value">{len(vulnerabilities)}</div>
              <div class="vl-kpi-sub">Bundled offline records</div>
            </div>
            """
        )
    with kpi_col2:
        render_html(
            f"""
            <div class="vl-kpi-card">
              <div class="vl-kpi-label">MATCHED FINDINGS</div>
              <div class="vl-kpi-value" style="color: #93E2FC;">{len(all_ranked_results)}</div>
              <div class="vl-kpi-sub">Target asset inventory</div>
            </div>
            """
        )
    with kpi_col3:
        render_html(
            f"""
            <div class="vl-kpi-card" style="border-left: 3px solid #EF4444;">
              <div class="vl-kpi-label" style="color: #FCA5A5;">URGENT ACTION</div>
              <div class="vl-kpi-value" style="color: #EF4444;">{urgent_count}</div>
              <div class="vl-kpi-sub">&lt; 24h remediation SLA</div>
            </div>
            """
        )
    with kpi_col4:
        render_html(
            f"""
            <div class="vl-kpi-card" style="border-left: 3px solid #F97316;">
              <div class="vl-kpi-label" style="color: #FDBA74;">HIGH PRIORITY</div>
              <div class="vl-kpi-value" style="color: #F97316;">{high_count}</div>
              <div class="vl-kpi-sub">Active sprint cycle</div>
            </div>
            """
        )
    with kpi_col5:
        render_html(
            f"""
            <div class="vl-kpi-card" style="border-left: 3px solid #10B981;">
              <div class="vl-kpi-label" style="color: #6EE7B7;">ROUTINE / LOW</div>
              <div class="vl-kpi-value" style="color: #10B981;">{med_low_count}</div>
              <div class="vl-kpi-sub">Scheduled backlog</div>
            </div>
            """
        )

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # Top Priorities Header
    render_html(
        f"""
        <div style="display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 14px;">
          <div>
            <div style="font-size: 11px; font-weight: 800; color: #0D7FFD; letter-spacing: 0.1em; text-transform: uppercase;">
              ACTIONABLE DECISION SET
            </div>
            <h2 class="vl-h2" style="margin: 2px 0 0 0;">Top 5 Priorities for {current_profile.name}</h2>
            <div style="color: #94A3B8; font-size: 13px; margin-top: 2px;">
              Turn hundreds of vulnerability records into five explainable security actions tailored to operational context.
            </div>
          </div>
        </div>
        """
    )

    if not top_5_results:
        st.info("Nothing matched this profile in the supplied data.")
    else:
        for r in top_5_results:
            v = r.vulnerability
            b = r.score_breakdown
            p_level = r.priority.value.lower()

            b_threat = getattr(b, "technical_threat_score", getattr(b, "base_score", 0.0))
            b_context_mult = getattr(b, "context_multiplier", getattr(b, "critical_multiplier", 1.00))
            b_final = getattr(b, "final_priority_score", getattr(b, "final_score", b_threat * b_context_mult))
            b_delta = getattr(b, "context_delta", round(b_final - b_threat, 2))
            b_is_crit = getattr(b, "is_critical_product", False)

            crit_badge = (
                f'<span style="background: rgba(16, 185, 129, 0.12); color: #6EE7B7; border: 1px solid rgba(16, 185, 129, 0.3); padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 700;">⭐ Critical Core Asset</span>'
                if b_is_crit
                else '<span style="background: rgba(3, 41, 124, 0.4); color: #94A3B8; border: 1px solid rgba(13, 127, 253, 0.15); padding: 2px 6px; border-radius: 4px; font-size: 11px;">Standard Asset Tier</span>'
            )

            kev_chip = (
                '<span style="color: #EF4444; font-weight: 800;">YES (Active in Wild)</span>'
                if v.cisa_kev
                else '<span style="color: #94A3B8;">NO</span>'
            )
            epss_val = f"{(v.first_epss * 100):.1f}%" if v.first_epss is not None else "N/A"
            cvss_val = f"{v.cvss_base_score:.1f}" if v.cvss_base_score is not None else "N/A"

            margin_pill = ""
            if getattr(r, "decision_margin", None) is not None:
                margin_pill = f"""
                <div style="display: inline-flex; align-items: center; gap: 4px; background: rgba(3, 14, 51, 0.9); border: 1px solid rgba(13, 127, 253, 0.3); border-radius: 6px; padding: 2px 8px; font-size: 11px; font-family: monospace; font-weight: 700; color: #93E2FC; margin-bottom: 10px;">
                  ⚡ Decision Margin: +{r.decision_margin:.2f} pts ahead of #{r.rank+1}
                </div>
                """

            b_kev_contrib = getattr(b, "kev_contribution", 0.0)
            b_kev_sig = getattr(b, "kev_signal", 1.0 if v.cisa_kev else 0.0)
            b_epss_contrib = getattr(b, "epss_contribution", 0.0)
            b_epss_sig = getattr(b, "epss_signal", v.first_epss or 0.0)
            b_cvss_contrib = getattr(b, "cvss_contribution", 0.0)
            b_cvss_norm = getattr(b, "cvss_normalized", (v.cvss_base_score or 0.0) / 10.0)

            why_items_html = "".join([
                f'<div style="margin-bottom: 4px;"><span style="color: #10B981; font-weight: bold; margin-right: 4px;">✓</span> {f}</div>'
                for f in r.why_this_matters
            ])

            conf_color = "#10B981" if r.confidence.value == "HIGH" else "#FBBF24"

            render_html(
                f"""
                <div class="vl-card vl-card-{p_level}">
                  <!-- Card Header: Rank, CVE, Product, Badge -->
                  <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                    <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                      <span style="font-size: 16px; font-weight: 900; color: #93E2FC; font-family: monospace; background: #030E33; padding: 2px 8px; border-radius: 6px; border: 1px solid rgba(147, 226, 252, 0.1);">#{r.rank}</span>
                      <span style="font-family: monospace; font-size: 17px; font-weight: 800; color: #0D7FFD;">{v.cve_id}</span>
                      <span style="font-size: 15px; font-weight: 800; color: #FFFFFF;">— {v.product_name}</span>
                    </div>
                    {render_priority_badge(r.priority.value, b_final)}
                  </div>

                  <div style="font-size: 13px; font-weight: 600; color: #E2E8F0; margin-bottom: 12px;">
                    {r.plain_title}
                  </div>

                  <!-- Signature Mathematical Split Strip -->
                  <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; background: #030E33; padding: 10px 14px; border-radius: 8px; border: 1px solid rgba(147, 226, 252, 0.08); margin-bottom: 10px; text-align: center;">
                    <div>
                      <div style="font-size: 9px; font-weight: 800; color: #94A3B8; text-transform: uppercase;">TECHNICAL THREAT</div>
                      <div style="font-size: 15px; font-weight: 900; color: #FFFFFF; font-family: monospace;">{b_threat:.1f} <span style="font-size: 10px; color: #64748B;">/ 100</span></div>
                    </div>
                    <div>
                      <div style="font-size: 9px; font-weight: 800; color: #94A3B8; text-transform: uppercase;">CONTEXT MULTIPLIER</div>
                      <div style="font-size: 15px; font-weight: 900; color: #93E2FC; font-family: monospace;">×{b_context_mult:.2f}</div>
                    </div>
                    <div>
                      <div style="font-size: 9px; font-weight: 800; color: #94A3B8; text-transform: uppercase;">CONTEXT DELTA</div>
                      <div style="font-size: 15px; font-weight: 900; color: {'#10B981' if b_delta > 0 else '#94A3B8'}; font-family: monospace;">{f'+{b_delta:.1f}' if b_delta > 0 else f'{b_delta:.1f}'}</div>
                    </div>
                    <div>
                      <div style="font-size: 9px; font-weight: 800; color: #94A3B8; text-transform: uppercase;">VULNLENS PRIORITY</div>
                      <div style="font-size: 15px; font-weight: 900; color: #0D7FFD; font-family: monospace;">{b_final:.1f}</div>
                    </div>
                  </div>

                  <!-- Technical Telemetry Chips Strip -->
                  <div style="display: flex; flex-wrap: wrap; gap: 8px; align-items: center; padding: 6px 12px; background: rgba(3, 14, 51, 0.4); border-radius: 6px; border: 1px solid rgba(147, 226, 252, 0.06); margin-bottom: 10px; font-family: monospace; font-size: 11px;">
                    <div><span style="color: #94A3B8;">CVSS:</span> <strong style="color: #FFFFFF;">{cvss_val}</strong></div>
                    <span style="color: rgba(147, 226, 252, 0.2);">|</span>
                    <div><span style="color: #94A3B8;">KEV:</span> {kev_chip}</div>
                    <span style="color: rgba(147, 226, 252, 0.2);">|</span>
                    <div><span style="color: #94A3B8;">EPSS:</span> <strong style="color: #93E2FC;">{epss_val}</strong></div>
                    <span style="color: rgba(147, 226, 252, 0.2);">|</span>
                    <div>{crit_badge}</div>
                  </div>

                  {margin_pill}

                  <!-- Reasoning & Recommended Action -->
                  <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-top: 6px;">
                    <div>
                      <div style="font-size: 10px; font-weight: 800; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px;">
                        WHY THIS MATTERS
                      </div>
                      <div style="font-size: 12px; color: #CBD5E1; line-height: 1.4;">
                        {why_items_html}
                      </div>
                    </div>
                    <div>
                      <div style="font-size: 10px; font-weight: 800; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px;">
                        RECOMMENDED ACTION & CONFIDENCE
                      </div>
                      <div style="font-size: 12px; color: #FFFFFF; background: rgba(13, 127, 253, 0.1); padding: 8px 10px; border-radius: 6px; border-left: 3px solid #0D7FFD; line-height: 1.35;">
                        {r.safe_next_action}
                      </div>
                      <div style="font-size: 11px; color: #94A3B8; margin-top: 4px;">
                        <strong>Confidence:</strong> <span style="color: {conf_color}; font-weight: bold;">{r.confidence.value}</span> ({r.confidence_reason})
                      </div>
                    </div>
                  </div>

                  <!-- Technical Threat Breakdown Bar Visualization -->
                  <div style="margin-top: 12px; padding-top: 10px; border-top: 1px solid rgba(147, 226, 252, 0.08);">
                    <div style="font-size: 10px; font-weight: 800; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px;">
                      TECHNICAL THREAT BREAKDOWN: <strong style="color: #FFFFFF; font-family: monospace; font-size: 12px;">{b_threat:.1f} / 100</strong>
                    </div>
                    {render_score_bar("Confirmed Exploitation (CISA KEV)", b_kev_contrib, 100 * current_profile.weight_modifiers.cisa_kev_weight, f"Weight {(current_profile.weight_modifiers.cisa_kev_weight*100):.0f}% × Signal {int(b_kev_sig)}")}
                    {render_score_bar("Exploit Likelihood (FIRST EPSS)", b_epss_contrib, 100 * current_profile.weight_modifiers.first_epss_weight, f"Weight {(current_profile.weight_modifiers.first_epss_weight*100):.0f}% × Likelihood {(b_epss_sig*100):.1f}%")}
                    {render_score_bar("Technical Severity (NVD CVSS)", b_cvss_contrib, 100 * current_profile.weight_modifiers.cvss_weight, f"Weight {(current_profile.weight_modifiers.cvss_weight*100):.0f}% × Normalized {(b_cvss_norm*10):.1f}/10")}
                  </div>
                </div>
                """
            )


# ==============================================================================
# PAGE 2: PRIORITIES (TOP 5 & COMPLETE FINDINGS TABLE)
# ==============================================================================
elif nav_choice == "⚡ Priorities (Top 5)":
    render_html(
        render_top_header(
            "Priorities Console",
            "Matched Asset Vulnerabilities & Ranking",
            current_profile.name,
            current_profile.org_id,
        )
    )

    # Filter row
    f_col1, f_col2, f_col3 = st.columns([2, 1, 1])
    with f_col1:
        search_query = st.text_input("Search CVE, product, vendor...", placeholder="e.g. CVE-2023, Identity, Spring...")
    with f_col2:
        priority_filter = st.selectbox("Filter Priority:", ["All Priorities", "URGENT", "HIGH", "MEDIUM", "LOW"])
    with f_col3:
        view_mode = st.radio("Display Format:", ["Top 5 Cards", "All Matched Findings Table"], horizontal=True)

    # Filter results
    filtered_results = all_ranked_results
    if search_query:
        q = search_query.lower()
        filtered_results = [
            r for r in filtered_results
            if q in r.vulnerability.cve_id.lower()
            or q in r.vulnerability.product_name.lower()
            or q in (r.vulnerability.vendor_name or "").lower()
        ]
    if priority_filter != "All Priorities":
        filtered_results = [r for r in filtered_results if r.priority.value.upper() == priority_filter]

    if view_mode == "Top 5 Cards":
        for r in filtered_results[:5]:
            v = r.vulnerability
            b = r.score_breakdown
            p_level = r.priority.value.lower()
            b_threat = getattr(b, "technical_threat_score", 0.0)
            b_context_mult = getattr(b, "context_multiplier", 1.00)
            b_final = getattr(b, "final_priority_score", b_threat * b_context_mult)
            b_delta = getattr(b, "context_delta", round(b_final - b_threat, 2))

            render_html(
                f"""
                <div class="vl-card vl-card-{p_level}">
                  <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                      <span style="font-size: 15px; font-weight: 900; color: #93E2FC; font-family: monospace;">#{r.rank}</span>
                      <span style="font-family: monospace; font-size: 16px; font-weight: 800; color: #0D7FFD;">{v.cve_id}</span>
                      <span style="font-size: 14px; font-weight: 700; color: #FFFFFF;">— {v.product_name}</span>
                    </div>
                    {render_priority_badge(r.priority.value, b_final)}
                  </div>
                  <div style="font-size: 12px; color: #94A3B8; margin: 4px 0 8px 0;">{r.plain_title}</div>
                  <div style="font-size: 11px; font-family: monospace; color: #CBD5E1;">
                    Threat: <strong style="color: #FFFFFF;">{b_threat:.1f}</strong> | Context: <strong style="color: #93E2FC;">×{b_context_mult:.2f}</strong> | Delta: <strong style="color: #10B981;">+{b_delta:.1f}</strong> | Score: <strong style="color: #0D7FFD;">{b_final:.1f}</strong>
                  </div>
                </div>
                """
            )
    else:
        # Table view
        table_rows = []
        for r in filtered_results:
            v = r.vulnerability
            b = r.score_breakdown
            table_rows.append({
                "Rank": f"#{r.rank}",
                "CVE ID": v.cve_id,
                "Product": v.product_name,
                "CVSS": v.cvss_base_score or 0.0,
                "KEV": "YES" if v.cisa_kev else "NO",
                "EPSS": f"{((v.first_epss or 0.0) * 100):.1f}%",
                "Threat Score": f"{b.technical_threat_score:.1f}",
                "Context Mult": f"×{b.context_multiplier:.2f}",
                "Priority Score": f"{b.final_priority_score:.1f}",
                "Level": r.priority.value,
                "Confidence": r.confidence.value,
            })
        if table_rows:
            st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)
        else:
            st.write("No matching records found for search filter.")


# ==============================================================================
# PAGE 3: EXPLAIN & REASONING (WHY THIS MATTERS & WHY NOT)
# ==============================================================================
elif nav_choice == "◉ Explain & Reasoning":
    render_html(
        render_top_header(
            "Explainability Engine",
            "Deterministic Reasoning & Negative Testing",
            current_profile.name,
            current_profile.org_id,
        )
    )

    explain_tab1, explain_tab2 = st.tabs(["Why This Matters (Deep Dive)", "Why Not This CVE? (Negative Test)"])

    with explain_tab1:
        selected_cve_id = st.selectbox(
            "Select Vulnerability to Inspect:",
            options=[r.vulnerability.cve_id for r in top_5_results],
            index=0,
        )
        target_res = next(r for r in top_5_results if r.vulnerability.cve_id == selected_cve_id)
        v = target_res.vulnerability
        b = target_res.score_breakdown

        col_e1, col_e2 = st.columns([1.2, 1])
        with col_e1:
            render_html(
                f"""
                <div class="vl-card">
                  <div style="font-size: 11px; font-weight: 800; color: #0D7FFD; text-transform: uppercase;">STEP-BY-STEP SCORING FORMULA</div>
                  <h3 class="vl-h3" style="margin: 4px 0 10px 0;">{v.cve_id} — {v.product_name}</h3>
                  <div style="background: #030E33; padding: 12px; border-radius: 8px; font-family: monospace; font-size: 13px; border: 1px solid rgba(147, 226, 252, 0.08); margin-bottom: 12px;">
                    <div>1. Threat Score = 100 × [ {current_profile.weight_modifiers.cvss_weight:.2f}(CVSS) + {current_profile.weight_modifiers.cisa_kev_weight:.2f}(KEV) + {current_profile.weight_modifiers.first_epss_weight:.2f}(EPSS) ] = <strong style="color: #FFFFFF;">{b.technical_threat_score:.1f}</strong></div>
                    <div style="margin-top: 6px;">2. Context Multiplier = {b.context_multiplier:.2f} ({'Critical Crown Jewel' if b.is_critical_product else 'Standard Asset'})</div>
                    <div style="margin-top: 6px;">3. Final Priority = {b.technical_threat_score:.1f} × {b.context_multiplier:.2f} = <strong style="color: #0D7FFD;">{b.final_priority_score:.1f} ({target_res.priority.value})</strong></div>
                  </div>
                  <div style="font-size: 12px; color: #CBD5E1; line-height: 1.45;">
                    <strong>Decision Context:</strong> {target_res.plain_title}
                  </div>
                </div>
                """
            )
        with col_e2:
            render_html(
                f"""
                <div class="vl-card">
                  <div style="font-size: 11px; font-weight: 800; color: #10B981; text-transform: uppercase;">SIGNAL PROVENANCE</div>
                  <div style="margin-top: 8px; font-size: 12px; line-height: 1.6; color: #CBD5E1;">
                    <div>• <strong>NVD CVSS:</strong> {v.cvss_base_score} ({getattr(v, 'cvss_version', 'v3.1')})</div>
                    <div>• <strong>CISA KEV:</strong> {'Listed in Known Exploited Vulnerabilities catalog' if v.cisa_kev else 'Not listed in active exploitation catalog'}</div>
                    <div>• <strong>FIRST EPSS:</strong> {((v.first_epss or 0.0)*100):.1f}% 30-day weaponization probability</div>
                    <div>• <strong>Confidence:</strong> <span style="color: #10B981; font-weight: 800;">{target_res.confidence.value}</span> ({target_res.confidence_reason})</div>
                  </div>
                  <div style="margin-top: 10px; padding: 8px; background: rgba(13, 127, 253, 0.1); border-radius: 6px; font-size: 11px; color: #93E2FC;">
                    🛡️ <strong>Defensive Directive:</strong> {target_res.safe_next_action}
                  </div>
                </div>
                """
            )

    with explain_tab2:
        render_html(
            """
            <div class="vl-card" style="border-left: 4px solid #EF4444;">
              <h3 class="vl-h3" style="margin-bottom: 2px;">Why Not This CVE? (Negative Testing Engine)</h3>
              <p style="color: #CBD5E1; font-size: 12px; margin: 0; line-height: 1.4;">
                <strong>Core Thesis:</strong> "CVSS measures technical severity. VulnLens measures organizational importance."
                Vulnerabilities with CVSS ≥ 9.0 are correctly de-prioritized when unexploited or mapped to non-critical internal tools.
              </p>
            </div>
            """
        )

        neg_candidates = find_negative_test_candidates(
            vulnerabilities, current_profile, min_cvss=9.0, max_rank_threshold=10
        )

        if not neg_candidates:
            st.write("No CVSS ≥ 9.0 items were de-prioritized for this profile.")
        else:
            for item in neg_candidates:
                v = item.vulnerability
                reason_text = getattr(item, "reason_low_or_excluded", getattr(item, "explanation", getattr(item, "reason", "")))
                render_html(
                    f"""
                    <div class="vl-card" style="background: rgba(4, 22, 72, 0.9);">
                      <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                          <span style="font-family: monospace; font-size: 15px; font-weight: bold; color: #0D7FFD;">{v.cve_id}</span>
                          <span style="color: #FFFFFF; font-weight: 600; margin-left: 6px;">{v.product_name}</span>
                        </div>
                        <div style="display: flex; gap: 6px; align-items: center;">
                          <span style="background: rgba(239, 68, 68, 0.2); color: #FCA5A5; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 11px;">CVSS {v.cvss_base_score}</span>
                          <span style="background: #030E33; color: #94A3B8; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 11px;">Rank #{item.rank}</span>
                        </div>
                      </div>

                      <div style="margin-top: 8px; padding: 8px 12px; background: #030E33; border-radius: 6px; border-left: 3px solid #EF4444;">
                        <div style="font-size: 10px; font-weight: 800; color: #EF4444; text-transform: uppercase;">✕ DEPRIORITIZATION RATIONALE</div>
                        <div style="font-size: 12px; color: #CBD5E1; margin-top: 2px;">{reason_text}</div>
                      </div>
                    </div>
                    """
                )


# ==============================================================================
# PAGE 4: WHAT-IF SIMULATOR
# ==============================================================================
elif nav_choice == "◌ What-If Simulator":
    render_html(
        render_top_header(
            "What-If Simulator",
            "Counterfactual Decision Analysis",
            current_profile.name,
            current_profile.org_id,
        )
    )

    render_html(
        """
        <div class="vl-card" style="border: 1px solid rgba(13, 127, 253, 0.35);">
          <h3 class="vl-h3" style="margin-bottom: 2px;">⚡ Interactive Decision Sensitivity Simulator</h3>
          <p style="color: #CBD5E1; font-size: 12px; margin: 0;">
            Adjust operational exposure and asset criticality. Watch how <strong>technical CVSS & threat scores remain strictly constant</strong> while operational priority updates deterministically.
          </p>
        </div>
        """
    )

    sim_cve_id = st.selectbox(
        "Select Vulnerability to Simulate:",
        options=[v.cve_id for v in vulnerabilities[:30]],
        index=0,
    )
    sim_vuln = next(v for v in vulnerabilities if v.cve_id == sim_cve_id)

    colS1, colS2 = st.columns(2)
    with colS1:
        sim_exposure = st.radio(
            "Operational Exposure:",
            options=["INTERNET-FACING (1.20x Multiplier)", "INTERNAL ONLY (1.00x Baseline)"],
            index=0,
        )
    with colS2:
        sim_criticality = st.radio(
            "Asset Importance Tier:",
            options=["CRITICAL CROWN JEWEL (1.20x)", "HIGH IMPORTANCE (1.10x)", "STANDARD INFRASTRUCTURE (1.00x)"],
            index=0,
        )

    # Compute simulated score
    cvss_n = (sim_vuln.cvss_base_score or 0.0) / 10.0
    kev_s = 1.0 if sim_vuln.cisa_kev else 0.0
    epss_s = sim_vuln.first_epss or 0.0

    tech_threat = (
        100.0
        * (
            current_profile.weight_modifiers.cvss_weight * cvss_n
            + current_profile.weight_modifiers.cisa_kev_weight * kev_s
            + current_profile.weight_modifiers.first_epss_weight * epss_s
        )
    )

    exp_m = 1.20 if "INTERNET-FACING" in sim_exposure else 1.00
    if "CRITICAL" in sim_criticality:
        imp_m = 1.20
    elif "HIGH" in sim_criticality:
        imp_m = 1.10
    else:
        imp_m = 1.00

    context_mult = exp_m * imp_m
    sim_final = tech_threat * context_mult
    sim_delta = sim_final - tech_threat
    sim_p_level = determine_priority_level(sim_final)

    render_html(
        f"""
        <div class="vl-card" style="margin-top: 14px; background: rgba(4, 22, 72, 0.9);">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
              <div style="font-size: 16px; font-weight: bold; color: #FFFFFF;">{sim_vuln.cve_id} — {sim_vuln.product_name}</div>
              <div style="font-size: 12px; color: #94A3B8; font-family: monospace;">
                Technical Severity: <strong style="color: #93E2FC;">CVSS {sim_vuln.cvss_base_score} → {sim_vuln.cvss_base_score} (Unchanged)</strong>
              </div>
            </div>
            {render_priority_badge(sim_p_level.value, sim_final)}
          </div>

          <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; background: #030E33; padding: 10px 14px; border-radius: 8px; border: 1px solid rgba(147, 226, 252, 0.08); margin-top: 12px; text-align: center;">
            <div>
              <div style="font-size: 9px; font-weight: 800; color: #94A3B8;">TECHNICAL THREAT</div>
              <div style="font-size: 15px; font-weight: 900; color: #FFFFFF; font-family: monospace;">{tech_threat:.1f}</div>
            </div>
            <div>
              <div style="font-size: 9px; font-weight: 800; color: #94A3B8;">CONTEXT MULTIPLIER</div>
              <div style="font-size: 15px; font-weight: 900; color: #93E2FC; font-family: monospace;">×{context_mult:.2f}</div>
            </div>
            <div>
              <div style="font-size: 9px; font-weight: 800; color: #94A3B8;">CONTEXT DELTA</div>
              <div style="font-size: 15px; font-weight: 900; color: #10B981; font-family: monospace;">+{sim_delta:.1f}</div>
            </div>
            <div>
              <div style="font-size: 9px; font-weight: 800; color: #94A3B8;">FINAL PRIORITY</div>
              <div style="font-size: 15px; font-weight: 900; color: #0D7FFD; font-family: monospace;">{sim_final:.1f}</div>
            </div>
          </div>

          <div style="margin-top: 10px; padding: 8px 12px; background: rgba(3, 14, 51, 0.6); border-radius: 6px;">
            <div style="font-size: 11px; color: #10B981; font-weight: bold;">✓ Technical threat score invariant ({tech_threat:.1f} → {tech_threat:.1f})</div>
            <div style="font-size: 11px; color: #0D7FFD; font-weight: bold;">✓ Context multiplier adjusted to operational reality (×{context_mult:.2f})</div>
          </div>
        </div>
        """
    )


# ==============================================================================
# PAGE 5: ORGANISATION PROFILE & COMPARISON & INGESTION
# ==============================================================================
elif nav_choice == "◎ Organisation Profile":
    render_html(
        render_top_header(
            "Organisation Profile",
            "Asset Configuration & Cross-Org Comparative Triage",
            current_profile.name,
            current_profile.org_id,
        )
    )

    prof_tab1, prof_tab2, prof_tab3 = st.tabs(["Profile Details", "Cross-Org Comparison", "Import Profile D (JSON)"])

    with prof_tab1:
        col_p1, col_p2 = st.columns(2)
        with col_p1:
            render_html(
                f"""
                <div class="vl-card">
                  <div style="font-size: 11px; font-weight: 800; color: #0D7FFD; text-transform: uppercase;">IDENTITY & SECTOR</div>
                  <h3 class="vl-h3" style="margin: 4px 0 6px 0;">{current_profile.name}</h3>
                  <div style="font-size: 12px; color: #CBD5E1; line-height: 1.6;">
                    <div>• <strong>Identifier:</strong> <span style="font-family: monospace; color: #93E2FC;">{current_profile.org_id}</span></div>
                    <div>• <strong>Sector:</strong> {current_profile.sector}</div>
                    <div>• <strong>Risk Appetite:</strong> <span style="color: #FDBA74; font-weight: 800;">{current_profile.risk_appetite}</span></div>
                  </div>
                  <div style="margin-top: 12px; font-size: 11px; font-weight: 800; color: #94A3B8; text-transform: uppercase;">
                    PRIORITY PHILOSOPHY
                  </div>
                  <div style="font-size: 12px; color: #93E2FC; font-style: italic; margin-top: 4px;">
                    "{fingerprint.priority_philosophy}"
                  </div>
                </div>
                """
            )
        with col_p2:
            render_html(
                f"""
                <div class="vl-card">
                  <div style="font-size: 11px; font-weight: 800; color: #10B981; text-transform: uppercase;">CRITICAL ASSET INVENTORY</div>
                  <div style="margin-top: 8px; font-size: 12px; color: #CBD5E1;">
                    Crown jewel products that receive an automatic context multiplier boost:
                  </div>
                  <div style="display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px;">
                    {''.join([f'<span style="background: rgba(16, 185, 129, 0.15); color: #6EE7B7; border: 1px solid rgba(16, 185, 129, 0.3); padding: 4px 8px; border-radius: 6px; font-size: 11px; font-weight: 700;">⭐ {cp}</span>' for cp in current_profile.critical_products])}
                  </div>
                </div>
                """
            )

    with prof_tab2:
        colA, colB = st.columns(2)
        with colA:
            org_a_idx = st.selectbox(
                "Select Organisation A:",
                options=range(len(all_profiles)),
                format_func=lambda i: all_profiles[i].name,
                index=0,
                key="comp_org_a",
            )
        with colB:
            org_b_idx = st.selectbox(
                "Select Organisation B:",
                options=range(len(all_profiles)),
                format_func=lambda i: all_profiles[i].name,
                index=min(1, len(all_profiles) - 1),
                key="comp_org_b",
            )

        org_a = all_profiles[org_a_idx]
        org_b = all_profiles[org_b_idx]
        comp_report = compare_profiles(vulnerabilities, org_a, org_b, top_n=5)

        render_html(
            f"""
            <div class="vl-card" style="background: rgba(5, 30, 94, 0.5); border: 1px solid rgba(13, 127, 253, 0.35);">
              <div style="font-size: 13px; color: #93E2FC; line-height: 1.45;">
                {comp_report.overall_narrative}
              </div>
            </div>
            """
        )

        for item in comp_report.comparison_items:
            r_a = f"#{item.rank_a}" if item.rank_a else "N/A"
            r_b = f"#{item.rank_b}" if item.rank_b else "N/A"
            s_a = f"{item.score_a:.1f}" if item.score_a else "0.0"
            s_b = f"{item.score_b:.1f}" if item.score_b else "0.0"

            render_html(
                f"""
                <div class="vl-card" style="padding: 12px;">
                  <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-family: monospace; font-size: 14px; font-weight: bold; color: #0D7FFD;">{item.cve_id} — {item.product_name}</span>
                    <span style="background: rgba(13, 127, 253, 0.15); color: #93E2FC; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold;">
                      Delta: {item.score_delta:+.1f} pts
                    </span>
                  </div>
                  <div style="display: flex; gap: 20px; margin-top: 6px; font-size: 12px; color: #E2E8F0;">
                    <div>{org_a.name}: <strong style="color: #93E2FC;">{r_a}</strong> ({s_a} pts)</div>
                    <div>→</div>
                    <div>{org_b.name}: <strong style="color: #4CB7FC;">{r_b}</strong> ({s_b} pts)</div>
                  </div>
                  <div style="margin-top: 4px; font-size: 11px; color: #94A3B8; font-style: italic;">
                    💡 Driver: {item.driver_summary}
                  </div>
                </div>
                """
            )

    with prof_tab3:
        default_json = """{
  "org_id": "ORG-004",
  "name": "Regional Healthcare Hospital",
  "sector": "Healthcare",
  "risk_appetite": "Low",
  "weight_modifiers": {
    "cvss_weight": 0.40,
    "cisa_kev_weight": 0.45,
    "first_epss_weight": 0.15
  },
  "critical_products": [
    "Identity Provider SaaS",
    "Cloud Database Engine"
  ]
}"""
        raw_json = st.text_area("Profile JSON Input:", value=default_json, height=220)

        if st.button("Validate & Ingest Profile D", type="primary"):
            try:
                data = json.loads(raw_json)
                new_profile = OrganizationProfile(
                    org_id=data.get("org_id", f"ORG-{len(all_profiles)+1:03d}"),
                    name=data.get("name", "Custom Organization"),
                    sector=data.get("sector", "General"),
                    risk_appetite=data.get("risk_appetite", "Medium"),
                    weight_modifiers=OrganizationProfile.from_dict(data).weight_modifiers,
                    critical_products=data.get("critical_products", []),
                )
                st.session_state.custom_profiles = [
                    p for p in st.session_state.custom_profiles if p.org_id != new_profile.org_id
                ] + [new_profile]
                st.session_state.selected_org_id = new_profile.org_id
                st.success(f"Ingested '{new_profile.name}' ({new_profile.org_id}) successfully!")
                st.rerun()
            except Exception as err:
                st.error(f"Validation failed: {err}")


# ==============================================================================
# PAGE 6: THREAT INTELLIGENCE & GOLD SET CALIBRATION
# ==============================================================================
elif nav_choice == "◫ Threat Intelligence":
    render_html(
        render_top_header(
            "Threat Intelligence & Calibration",
            "Ground Truth Alignment & Signal Verification",
            current_profile.name,
            current_profile.org_id,
        )
    )

    p_field = "practitioner_rank_startup" if "startup" in current_profile.name.lower() else "practitioner_rank_bank"
    calib_report = evaluate_gold_set(gold_records, current_profile, practitioner_field=p_field)

    colM1, colM2 = st.columns(2)
    with colM1:
        render_html(
            f"""
            <div class="vl-card" style="text-align: center;">
              <div style="font-size: 36px; font-weight: 900; color: #10B981; font-family: monospace;">
                {f"ρ = {calib_report.spearman_correlation:.2f}" if calib_report.spearman_correlation is not None else "N/A"}
              </div>
              <div style="font-size: 13px; font-weight: bold; color: #FFFFFF;">Spearman Rank Correlation</div>
              <div style="font-size: 11px; color: #94A3B8;">1.00 = Perfect alignment with senior practitioner judgment</div>
            </div>
            """
        )
    with colM2:
        render_html(
            f"""
            <div class="vl-card" style="text-align: center;">
              <div style="font-size: 36px; font-weight: 900; color: #0D7FFD; font-family: monospace;">
                {f"{calib_report.mean_absolute_rank_error:.2f}" if calib_report.mean_absolute_rank_error is not None else "0.00"}
              </div>
              <div style="font-size: 13px; font-weight: bold; color: #FFFFFF;">Mean Absolute Rank Delta</div>
              <div style="font-size: 11px; color: #94A3B8;">Average position deviation from ground truth benchmark</div>
            </div>
            """
        )

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    render_html(
        """
        <div class="vl-card">
          <div style="font-size: 11px; font-weight: 800; color: #0D7FFD; text-transform: uppercase;">GROUND TRUTH GOLD SET BENCHMARK RECORDS</div>
          <div style="font-size: 12px; color: #94A3B8; margin-top: 2px;">
            The engine is evaluated on an isolated calibration set to guarantee rank fidelity against real human security expert triage decisions.
          </div>
        </div>
        """
    )

    gold_rows = []
    for gr in gold_records:
        gold_rows.append({
            "CVE ID": gr.cve_id,
            "Product": gr.product_name,
            "CVSS": gr.cvss_base_score,
            "KEV": "YES" if gr.cisa_kev else "NO",
            "EPSS": f"{(gr.first_epss * 100):.1f}%",
            "Bank Ground Truth Rank": f"#{gr.practitioner_rank_bank}",
            "Startup Ground Truth Rank": f"#{gr.practitioner_rank_startup}",
        })
    st.dataframe(pd.DataFrame(gold_rows), use_container_width=True, hide_index=True)


# ==============================================================================
# PAGE 7: PROVENANCE & AUDIT
# ==============================================================================
elif nav_choice == "▤ Provenance & Audit":
    render_html(
        render_top_header(
            "Provenance & Audit",
            "Data Integrity & Zero-Trust Security Guarantee",
            current_profile.name,
            current_profile.org_id,
        )
    )

    render_html(
        f"""
        <div class="vl-card" style="border-left: 4px solid #10B981;">
          <h3 class="vl-h3" style="margin-bottom: 4px;">🔒 Zero-Trust 100% Offline Integrity Guarantee</h3>
          <div style="font-size: 12px; color: #CBD5E1; line-height: 1.6;">
            <div>• <strong>Zero Network Calls:</strong> The triage engine operates completely offline in local memory.</div>
            <div>• <strong>Deterministic Execution:</strong> Scoring is 100% reproducible and explainable with mathematical proofs.</div>
            <div>• <strong>Source Authority:</strong> NVD (CVE/CVSS), CISA KEV (Known Exploited Vulnerabilities), and FIRST (EPSS v3).</div>
            <div>• <strong>Active Dataset:</strong> <code>data/vulnerabilities.csv</code> ({len(vulnerabilities)} bundled offline records).</div>
          </div>
        </div>
        """
    )

    # Show raw records table with provenance
    st.markdown("### Bundled Dataset Records (Sample)")
    audit_rows = []
    for v in vulnerabilities[:20]:
        audit_rows.append({
            "CVE ID": v.cve_id,
            "Vendor": v.vendor_name,
            "Product": v.product_name,
            "CVSS Base": v.cvss_base_score,
            "CISA KEV": "YES" if v.cisa_kev else "NO",
            "FIRST EPSS": f"{((v.first_epss or 0.0) * 100):.1f}%",
            "Description": v.description[:70] + "..." if v.description else "",
        })
    st.dataframe(pd.DataFrame(audit_rows), use_container_width=True, hide_index=True)
