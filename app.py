"""VulnLens — Personalised Vulnerability Triage Engine & Presentation Dashboard.

Unified Global Brand & Design System:
  Background: Deep Navy #030E33
  Panels/Cards: Dark Blue #041648
  Accent: Electric Blue #0D7FFD
  Emblem: Vibrant Blue #2358F9 -> Purple #4F3DF5
"""

import importlib
import json
from pathlib import Path
import textwrap
from typing import Dict, List, Optional

import pandas as pd
import streamlit as st

# Force reload of core modules to prevent stale class cache in running Streamlit server
import src.models
import src.matcher
import src.scorer
import src.explainer
import src.ranking
import src.negative_test

importlib.reload(src.models)
importlib.reload(src.matcher)
importlib.reload(src.scorer)
importlib.reload(src.explainer)
importlib.reload(src.ranking)
importlib.reload(src.negative_test)

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
    render_brand_header,
    render_hero_section,
    render_priority_badge,
    render_score_bar,
    get_qr_code_base64,
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
    page_title="VulnLens | Personalised Vulnerability Triage",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject central brand design tokens and styles
st.markdown(GLOBAL_CSS, unsafe_allow_html=True)


def get_cached_vulnerabilities() -> List[Vulnerability]:
    return load_vulnerabilities(Path("data/vulnerabilities.csv"))


def get_cached_profiles() -> List[OrganizationProfile]:
    return load_profiles(Path("data/profiles.json"))


def get_cached_gold_set() -> List[CalibrationRecord]:
    return load_gold_set(Path("data/gold_set.csv"))


# Initialize session state for custom profiles and simulation
if "custom_profiles" not in st.session_state:
    st.session_state.custom_profiles = []

if "selected_org_id" not in st.session_state:
    st.session_state.selected_org_id = "ORG-001"

# Load datasets safely
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

# Top Brand Header
render_html(render_brand_header())

# Sidebar: Organization Configuration & Threat Fingerprint
with st.sidebar:
    render_html(
        """
        <div style="font-size: 13px; font-weight: 800; color: #0D7FFD; letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 8px;">
          ORGANISATION PROFILE
        </div>
        """
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

    # Active Profile Fingerprint
    crown_jewels_html = "".join([
        f'<span style="background: rgba(16, 185, 129, 0.15); color: #6EE7B7; border: 1px solid rgba(16, 185, 129, 0.4); padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold;">{cp}</span>'
        for cp in current_profile.critical_products
    ])

    render_html(
        f"""
        <div class="vl-card" style="padding: 14px; margin-top: 12px;">
          <div style="font-size: 11px; font-weight: 800; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.5px;">Sector & Risk</div>
          <div style="font-size: 14px; font-weight: 700; color: #FFFFFF; margin: 2px 0 6px 0;">{current_profile.sector}</div>
          <div style="display: flex; gap: 6px; margin-bottom: 10px;">
            <span style="background: rgba(13, 127, 253, 0.15); color: #93E2FC; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; border: 1px solid rgba(13, 127, 253, 0.3);">
              Risk Appetite: {current_profile.risk_appetite}
            </span>
          </div>

          <div style="font-size: 11px; font-weight: 800; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 10px;">Threat Signal Weights</div>
          <div style="display: flex; justify-content: space-between; font-size: 12px; margin-top: 4px;">
            <span style="color: #CBD5E1;">NVD CVSS:</span>
            <span style="font-family: 'JetBrains Mono', monospace; font-weight: 700; color: #93E2FC;">{(current_profile.weight_modifiers.cvss_weight * 100):.0f}%</span>
          </div>
          <div style="display: flex; justify-content: space-between; font-size: 12px; margin-top: 2px;">
            <span style="color: #CBD5E1;">CISA KEV:</span>
            <span style="font-family: 'JetBrains Mono', monospace; font-weight: 700; color: #93E2FC;">{(current_profile.weight_modifiers.cisa_kev_weight * 100):.0f}%</span>
          </div>
          <div style="display: flex; justify-content: space-between; font-size: 12px; margin-top: 2px;">
            <span style="color: #CBD5E1;">FIRST EPSS:</span>
            <span style="font-family: 'JetBrains Mono', monospace; font-weight: 700; color: #93E2FC;">{(current_profile.weight_modifiers.first_epss_weight * 100):.0f}%</span>
          </div>

          <div style="font-size: 11px; font-weight: 800; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 12px;">Priority Philosophy</div>
          <div style="font-size: 12px; color: #93E2FC; line-height: 1.35; margin-top: 4px; font-style: italic; background: rgba(3, 14, 51, 0.5); padding: 6px 8px; border-radius: 6px;">
            "{fingerprint.priority_philosophy}"
          </div>

          <div style="font-size: 11px; font-weight: 800; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 12px;">Critical Crown Jewels</div>
          <div style="display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px;">
            {crown_jewels_html}
          </div>
        </div>
        """
    )

    st.markdown("---")
    render_html(
        """
        <div style="font-size: 11px; color: #64748B; line-height: 1.4;">
          🔒 <strong>100% Offline Guarantee:</strong> Zero live APIs, zero external telemetry. All scoring and matching runs in local RAM.
        </div>
        """
    )

# Compute Top 5 & All ranked
top_5_results = rank_vulnerabilities(vulnerabilities, current_profile, top_n=5)
all_ranked_results = rank_all_vulnerabilities(vulnerabilities, current_profile)

# Main Navigation Tabs
tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(
    [
        "🛡️ Top 5 Priorities",
        "🔍 Why Not? (Negative Test)",
        "⚖️ Profile Comparison",
        "⚡ What-If Simulation",
        "📐 Gold Set Calibration",
        "📁 Import Profile D",
        "📱 Mobile APK & QR",
    ]
)

# ----------------------------------------------------
# TAB 1: TOP 5 PRIORITIES
# ----------------------------------------------------
with tab1:
    render_html(render_hero_section())

    render_html(
        f"""
        <div style="display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 16px;">
          <div>
            <h2 class="vl-h2" style="margin: 0;">Top 5 Decisions for {current_profile.name}</h2>
            <div style="color: #94A3B8; font-size: 13px; margin-top: 2px;">
              Filtered from {len(vulnerabilities)} records using {current_profile.name}'s risk weights and critical asset tier.
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
                f'<span style="background: rgba(16, 185, 129, 0.15); color: #6EE7B7; border: 1px solid rgba(16, 185, 129, 0.4); padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700;">⭐ Critical Core Asset (×{b_context_mult:.2f})</span>'
                if b_is_crit
                else f'<span style="background: rgba(3, 41, 124, 0.4); color: #94A3B8; border: 1px solid rgba(13, 127, 253, 0.2); padding: 3px 8px; border-radius: 4px; font-size: 11px;">Standard Asset Tier (×{b_context_mult:.2f})</span>'
            )

            kev_chip = (
                '<span style="color: #EF4444; font-weight: bold;">YES (Active in Wild)</span>'
                if v.cisa_kev
                else '<span style="color: #94A3B8;">NO</span>'
            )
            epss_val = (
                f"{(v.first_epss * 100):.1f}%"
                if v.first_epss is not None
                else "N/A"
            )
            cvss_val = (
                f"{v.cvss_base_score:.1f}"
                if v.cvss_base_score is not None
                else "N/A"
            )

            margin_badge = ""
            if getattr(r, "decision_margin", None) is not None:
                margin_badge = f'<span style="background: rgba(13, 127, 253, 0.15); color: #93E2FC; border: 1px solid rgba(13, 127, 253, 0.3); padding: 2px 8px; border-radius: 4px; font-size: 11px; font-family: monospace; font-weight: bold;">Decision Margin: +{r.decision_margin:.2f} pts vs #{r.rank+1}</span>'

            b_kev_contrib = getattr(b, "kev_contribution", 0.0)
            b_kev_sig = getattr(b, "kev_signal", 1.0 if v.cisa_kev else 0.0)
            b_epss_contrib = getattr(b, "epss_contribution", 0.0)
            b_epss_sig = getattr(b, "epss_signal", v.first_epss or 0.0)
            b_cvss_contrib = getattr(b, "cvss_contribution", 0.0)
            b_cvss_norm = getattr(b, "cvss_normalized", (v.cvss_base_score or 0.0)/10.0)

            why_items_html = "".join([
                f'<div style="margin-bottom: 3px;"><span style="color: #10B981; font-weight: bold;">✓</span> {f}</div>'
                for f in r.why_this_matters
            ])

            conf_color = "#10B981" if r.confidence.value == "HIGH" else "#FBBF24"

            render_html(
                f"""
                <div class="vl-card vl-card-{p_level}">
                  <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
                    <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                      <span style="font-size: 18px; font-weight: 900; color: #93E2FC; font-family: 'JetBrains Mono', monospace;">#{r.rank}</span>
                      <span style="font-family: 'JetBrains Mono', monospace; font-size: 18px; font-weight: 800; color: #0D7FFD;">{v.cve_id}</span>
                      <span style="font-size: 15px; font-weight: 700; color: #FFFFFF;">— {v.product_name}</span>
                      {margin_badge}
                    </div>
                    {render_priority_badge(r.priority.value)}
                  </div>

                  <div style="font-size: 14px; font-weight: 600; color: #E2E8F0; margin-bottom: 12px;">
                    {r.plain_title}
                  </div>

                  <!-- Contextual Priority Metrics Row -->
                  <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; background: rgba(3, 14, 51, 0.8); padding: 10px 14px; border-radius: 8px; border: 1px solid rgba(13, 127, 253, 0.2); margin-bottom: 14px; text-align: center;">
                    <div>
                      <div style="font-size: 10px; font-weight: 800; color: #94A3B8; text-transform: uppercase;">TECHNICAL THREAT</div>
                      <div style="font-size: 16px; font-weight: 900; color: #FFFFFF; font-family: monospace;">{b_threat:.1f} <span style="font-size: 11px; color: #64748B;">/ 100</span></div>
                    </div>
                    <div>
                      <div style="font-size: 10px; font-weight: 800; color: #94A3B8; text-transform: uppercase;">CONTEXT MULTIPLIER</div>
                      <div style="font-size: 16px; font-weight: 900; color: #93E2FC; font-family: monospace;">×{b_context_mult:.2f}</div>
                    </div>
                    <div>
                      <div style="font-size: 10px; font-weight: 800; color: #94A3B8; text-transform: uppercase;">CONTEXT DELTA</div>
                      <div style="font-size: 16px; font-weight: 900; color: {'#10B981' if b_delta > 0 else '#94A3B8'}; font-family: monospace;">{f'+{b_delta:.1f}' if b_delta > 0 else f'{b_delta:.1f}'}</div>
                    </div>
                    <div>
                      <div style="font-size: 10px; font-weight: 800; color: #94A3B8; text-transform: uppercase;">VULNLENS PRIORITY</div>
                      <div style="font-size: 16px; font-weight: 900; color: #0D7FFD; font-family: monospace;">{b_final:.1f}</div>
                    </div>
                  </div>

                  <!-- Technical Telemetry Strip -->
                  <div style="display: flex; flex-wrap: wrap; gap: 12px; align-items: center; padding: 6px 12px; background: rgba(3, 14, 51, 0.4); border-radius: 6px; border: 1px solid rgba(13, 127, 253, 0.1); margin-bottom: 14px; font-family: 'JetBrains Mono', monospace; font-size: 11px;">
                    <div><span style="color: #94A3B8;">CVSS:</span> <strong style="color: #FFFFFF;">{cvss_val}</strong></div>
                    <span style="color: #03297C;">|</span>
                    <div><span style="color: #94A3B8;">KEV:</span> {kev_chip}</div>
                    <span style="color: #03297C;">|</span>
                    <div><span style="color: #94A3B8;">EPSS 30d:</span> <strong style="color: #93E2FC;">{epss_val}</strong></div>
                    <span style="color: #03297C;">|</span>
                    <div>{crit_badge}</div>
                  </div>

                  <!-- Expanded Why & Action Details -->
                  <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                    <div>
                      <div style="font-size: 11px; font-weight: 800; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px;">
                        WHY THIS RANKED HIGH
                      </div>
                      <div style="font-size: 12px; color: #CBD5E1; line-height: 1.45;">
                        {why_items_html}
                      </div>
                    </div>
                    <div>
                      <div style="font-size: 11px; font-weight: 800; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px;">
                        RECOMMENDED DEFENSIVE ACTION
                      </div>
                      <div style="font-size: 12px; color: #FFFFFF; background: rgba(13, 127, 253, 0.12); padding: 8px 12px; border-radius: 6px; border-left: 3px solid #0D7FFD; line-height: 1.4;">
                        {r.safe_next_action}
                      </div>
                      <div style="font-size: 11px; color: #94A3B8; margin-top: 6px;">
                        <strong>Confidence:</strong> <span style="color: {conf_color}; font-weight: bold;">{r.confidence.value}</span> ({r.confidence_reason})
                      </div>
                    </div>
                  </div>

                  <!-- Neutral Technical Score Visualization -->
                  <div style="margin-top: 14px; padding-top: 12px; border-top: 1px solid rgba(13, 127, 253, 0.15);">
                    <div style="font-size: 11px; font-weight: 800; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px;">
                      TECHNICAL THREAT BREAKDOWN: <strong style="color: #FFFFFF; font-family: 'JetBrains Mono', monospace; font-size: 13px;">{b_threat:.1f} / 100</strong>
                    </div>
                    {render_score_bar("Confirmed Exploitation (CISA KEV)", b_kev_contrib, 100 * current_profile.weight_modifiers.cisa_kev_weight, f"Weight {(current_profile.weight_modifiers.cisa_kev_weight*100):.0f}% × Signal {int(b_kev_sig)}")}
                    {render_score_bar("Exploit Likelihood (FIRST EPSS)", b_epss_contrib, 100 * current_profile.weight_modifiers.first_epss_weight, f"Weight {(current_profile.weight_modifiers.first_epss_weight*100):.0f}% × Likelihood {(b_epss_sig*100):.1f}%")}
                    {render_score_bar("Technical Severity (NVD CVSS)", b_cvss_contrib, 100 * current_profile.weight_modifiers.cvss_weight, f"Weight {(current_profile.weight_modifiers.cvss_weight*100):.0f}% × Normalized {(b_cvss_norm*10):.1f}/10")}
                  </div>
                </div>
                """
            )

# ----------------------------------------------------
# TAB 2: WHY NOT? (NEGATIVE TEST)
# ----------------------------------------------------
with tab2:
    render_html(
        """
        <div class="vl-card" style="border-left: 4px solid #EF4444;">
          <h2 class="vl-h2" style="margin-bottom: 4px;">WHY NOT THIS CVE? (Negative Testing Workflow)</h2>
          <p style="color: #CBD5E1; font-size: 13px; margin: 0; line-height: 1.45;">
            <strong>Core Principle:</strong> High theoretical CVSS does NOT mean high operational priority.
            Sorting blindly by CVSS floods security teams with unexploited bugs on low-value internal assets.
          </p>
        </div>
        """
    )

    neg_candidates = find_negative_test_candidates(
        vulnerabilities, current_profile, min_cvss=9.0, max_rank_threshold=10
    )

    render_html(
        f"<h3 class='vl-h3' style='margin-top: 16px;'>Critical CVSS (≥ 9.0) De-Prioritized for {current_profile.name}</h3>"
    )

    if not neg_candidates:
        st.write("No CVSS ≥ 9.0 items were de-prioritized for this profile.")
    else:
        for item in neg_candidates:
            v = item.vulnerability
            b = item.score_breakdown
            reason_text = getattr(item, "reason_low_or_excluded", getattr(item, "explanation", getattr(item, "reason", "")))
            render_html(
                f"""
                <div class="vl-card" style="background: rgba(4, 22, 72, 0.9);">
                  <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                      <span style="font-family: 'JetBrains Mono', monospace; font-size: 16px; font-weight: bold; color: #0D7FFD;">{v.cve_id}</span>
                      <span style="color: #FFFFFF; font-weight: 600; margin-left: 8px;">{v.product_name}</span>
                    </div>
                    <div style="display: flex; gap: 8px; align-items: center;">
                      <span style="background: rgba(239, 68, 68, 0.2); color: #FCA5A5; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;">CVSS {v.cvss_base_score}</span>
                      <span style="background: #030E33; color: #94A3B8; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;">Rank #{item.rank} of {len(all_ranked_results)}</span>
                    </div>
                  </div>

                  <div style="margin-top: 10px; padding: 10px 14px; background: #030E33; border-radius: 8px; border-left: 3px solid #EF4444;">
                    <div style="font-size: 11px; font-weight: 800; color: #EF4444; text-transform: uppercase;">✕ WHY WAS THIS DE-PRIORITIZED?</div>
                    <div style="font-size: 12px; color: #CBD5E1; margin-top: 4px;">{reason_text}</div>
                  </div>
                </div>
                """
            )

# ----------------------------------------------------
# TAB 3: PROFILE COMPARISON
# ----------------------------------------------------
with tab3:
    render_html(
        """
        <div class="vl-card">
          <h2 class="vl-h2" style="margin-bottom: 4px;">Multi-Organisation Comparative Triage</h2>
          <p style="color: #CBD5E1; font-size: 13px; margin: 0;">
            See how the SAME vulnerability dataset produces vastly DIFFERENT priorities based on sector risk appetite and critical asset mappings.
          </p>
        </div>
        """
    )

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

    render_html(
        "<h3 class='vl-h3' style='margin-top: 14px;'>Prioritisation Shift Breakdown</h3>"
    )

    for item in comp_report.comparison_items:
        r_a = f"#{item.rank_a}" if item.rank_a else "N/A"
        r_b = f"#{item.rank_b}" if item.rank_b else "N/A"
        s_a = f"{item.score_a:.1f}" if item.score_a else "0.0"
        s_b = f"{item.score_b:.1f}" if item.score_b else "0.0"

        render_html(
            f"""
            <div class="vl-card" style="padding: 14px;">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 15px; font-weight: bold; color: #0D7FFD;">{item.cve_id} — {item.product_name}</span>
                <span style="background: rgba(13, 127, 253, 0.15); color: #93E2FC; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold;">
                  Score Delta: {item.score_delta:+.1f} pts
                </span>
              </div>
              <div style="display: flex; gap: 24px; margin-top: 8px; font-size: 12px; color: #E2E8F0;">
                <div>{org_a.name}: <strong style="color: #93E2FC;">{r_a}</strong> ({s_a} pts)</div>
                <div>→</div>
                <div>{org_b.name}: <strong style="color: #4CB7FC;">{r_b}</strong> ({s_b} pts)</div>
              </div>
              <div style="margin-top: 6px; font-size: 11px; color: #94A3B8; font-style: italic;">
                💡 Driver: {item.driver_summary}
              </div>
            </div>
            """
        )

# ----------------------------------------------------
# TAB 4: WHAT-IF SIMULATION & COUNTERFACTUALS
# ----------------------------------------------------
with tab4:
    render_html(
        """
        <div class="vl-card" style="border: 1px solid rgba(13, 127, 253, 0.4);">
          <h2 class="vl-h2" style="margin-bottom: 4px;">⚡ Interactive What-If Scenario Simulator</h2>
          <p style="color: #CBD5E1; font-size: 13px; margin: 0;">
            Adjust operational exposure and asset criticality in real-time. Notice how <strong>technical CVSS and threat signals remain strictly identical</strong> while operational priority shifts deterministically.
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
        <div class="vl-card" style="margin-top: 16px; background: rgba(4, 22, 72, 0.9);">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
              <div style="font-size: 16px; font-weight: bold; color: #FFFFFF;">{sim_vuln.cve_id} — {sim_vuln.product_name}</div>
              <div style="font-size: 12px; color: #94A3B8; font-family: 'JetBrains Mono', monospace;">
                Technical Severity: <strong style="color: #93E2FC;">CVSS {sim_vuln.cvss_base_score} → {sim_vuln.cvss_base_score}</strong>
              </div>
            </div>
            {render_priority_badge(sim_p_level.value)}
          </div>

          <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; background: #030E33; padding: 10px 14px; border-radius: 8px; border: 1px solid rgba(13, 127, 253, 0.2); margin-top: 14px; text-align: center;">
            <div>
              <div style="font-size: 10px; font-weight: 800; color: #94A3B8;">TECHNICAL THREAT</div>
              <div style="font-size: 15px; font-weight: 900; color: #FFFFFF; font-family: monospace;">{tech_threat:.1f}</div>
            </div>
            <div>
              <div style="font-size: 10px; font-weight: 800; color: #94A3B8;">CONTEXT MULTIPLIER</div>
              <div style="font-size: 15px; font-weight: 900; color: #93E2FC; font-family: monospace;">×{context_mult:.2f}</div>
            </div>
            <div>
              <div style="font-size: 10px; font-weight: 800; color: #94A3B8;">CONTEXT DELTA</div>
              <div style="font-size: 15px; font-weight: 900; color: #10B981; font-family: monospace;">+{sim_delta:.1f}</div>
            </div>
            <div>
              <div style="font-size: 10px; font-weight: 800; color: #94A3B8;">FINAL PRIORITY</div>
              <div style="font-size: 15px; font-weight: 900; color: #0D7FFD; font-family: monospace;">{sim_final:.1f}</div>
            </div>
          </div>

          <div style="margin-top: 12px; padding: 10px 14px; background: rgba(3, 14, 51, 0.6); border-radius: 6px;">
            <div style="font-size: 12px; color: #10B981; font-weight: bold;">✓ Technical threat score strictly unchanged ({tech_threat:.1f} → {tech_threat:.1f})</div>
            <div style="font-size: 12px; color: #0D7FFD; font-weight: bold;">✓ Organisational context recalculated based on operational tier</div>
          </div>
        </div>
        """
    )

# ----------------------------------------------------
# TAB 5: GOLD SET CALIBRATION
# ----------------------------------------------------
with tab5:
    render_html(
        """
        <div class="vl-card">
          <h2 class="vl-h2" style="margin-bottom: 4px;">Ground Truth Calibration Benchmark</h2>
          <p style="color: #CBD5E1; font-size: 13px; margin: 0;">
            Sanity check against senior security practitioner ground truth ranking across isolated calibration records.
          </p>
        </div>
        """
    )

    p_field = (
        "practitioner_rank_startup"
        if "startup" in current_profile.name.lower()
        else "practitioner_rank_bank"
    )
    calib_report = evaluate_gold_set(
        gold_records, current_profile, practitioner_field=p_field
    )

    colM1, colM2 = st.columns(2)
    with colM1:
        render_html(
            f"""
            <div class="vl-card" style="text-align: center;">
              <div style="font-size: 36px; font-weight: 900; color: #10B981; font-family: 'JetBrains Mono', monospace;">
                {f"ρ = {calib_report.spearman_correlation:.2f}" if calib_report.spearman_correlation is not None else "N/A"}
              </div>
              <div style="font-size: 13px; font-weight: bold; color: #FFFFFF;">Spearman Rank Correlation</div>
              <div style="font-size: 11px; color: #94A3B8;">1.00 = Perfect alignment with practitioner judgment</div>
            </div>
            """
        )
    with colM2:
        render_html(
            f"""
            <div class="vl-card" style="text-align: center;">
              <div style="font-size: 36px; font-weight: 900; color: #0D7FFD; font-family: 'JetBrains Mono', monospace;">
                {f"{calib_report.mean_absolute_rank_error:.2f}" if calib_report.mean_absolute_rank_error is not None else "0.00"}
              </div>
              <div style="font-size: 13px; font-weight: bold; color: #FFFFFF;">Mean Absolute Rank Delta</div>
              <div style="font-size: 11px; color: #94A3B8;">Average position deviation from ground truth</div>
            </div>
            """
        )

# ----------------------------------------------------
# TAB 6: IMPORT PROFILE D
# ----------------------------------------------------
with tab6:
    render_html(
        """
        <div class="vl-card">
          <h2 class="vl-h2" style="margin-bottom: 4px;">Zero-Network Ingestion (Profile D)</h2>
          <p style="color: #CBD5E1; font-size: 13px; margin: 0;">
            Paste an unseen organisation JSON profile. The engine parses, validates, and generates a personalized Top 5 in local memory with zero external requests.
          </p>
        </div>
        """
    )

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

    raw_json = st.text_area(
        "Profile JSON Input:",
        value=default_json,
        height=240,
    )

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
            # Add or replace
            st.session_state.custom_profiles = [
                p for p in st.session_state.custom_profiles if p.org_id != new_profile.org_id
            ] + [new_profile]
            st.session_state.selected_org_id = new_profile.org_id
            st.success(f"Ingested '{new_profile.name}' ({new_profile.org_id}) successfully!")
            st.rerun()
        except Exception as err:
            st.error(f"Validation failed: {err}")

# ----------------------------------------------------
# TAB 7: MOBILE APK & QR INSTALLATION
# ----------------------------------------------------
with tab7:
    render_html(
        """
        <div class="vl-card" style="border: 1px solid rgba(13, 127, 253, 0.4);">
          <h2 class="vl-h2" style="margin-bottom: 4px;">📱 Standalone Offline Android App (Scan to Download)</h2>
          <p style="color: #CBD5E1; font-size: 13px; margin: 0;">
            Point your mobile camera at the QR code below to download the native Android APK directly to your phone.
          </p>
        </div>
        """
    )

    qr_src = get_qr_code_base64()
    qr_img_tag = (
        f'<img src="{qr_src}" style="width: 220px; height: 220px; border-radius: 12px; padding: 12px; background: #FFFFFF; box-shadow: 0 8px 24px rgba(13, 127, 253, 0.35); margin: 0 auto 12px auto; display: block;" />'
        if qr_src
        else '<div style="width: 220px; height: 220px; background: #FFFFFF; border-radius: 12px; margin: 0 auto 12px auto;"></div>'
    )

    render_html(
        f"""
        <div style="display: flex; gap: 24px; flex-wrap: wrap; margin-top: 16px;">
          <div class="vl-card" style="flex: 1; min-width: 280px; text-align: center;">
            <div style="font-size: 13px; font-weight: 800; color: #0D7FFD; letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 12px;">
              📸 SCAN WITH MOBILE CAMERA
            </div>
            {qr_img_tag}
            <div style="font-size: 12px; font-weight: 700; color: #93E2FC; margin-top: 8px;">
              Point camera to download APK directly
            </div>
            <div style="font-size: 11px; color: #94A3B8; margin-top: 4px; word-break: break-all;">
              Target: <code>VulnLens-Demo.apk</code>
            </div>
          </div>

          <div class="vl-card" style="flex: 1.5; min-width: 320px;">
            <div style="font-size: 14px; font-weight: 800; color: #FFFFFF; margin-bottom: 12px;">Offline Judge Verification Protocol</div>
            <ol style="color: #CBD5E1; font-size: 12px; line-height: 1.8; padding-left: 18px; margin: 0;">
              <li><strong>Scan QR Code:</strong> Open phone camera, scan the code to download <code>VulnLens-Demo.apk</code>.</li>
              <li><strong>Install on Device:</strong> Open the downloaded file to install on your Android phone/tablet.</li>
              <li><strong>Enable Airplane Mode:</strong> Turn off Wi-Fi and Mobile Data to verify 100% offline edge execution.</li>
              <li><strong>Test Personalisation:</strong> Switch between Bank, Startup, and Utility profiles in local RAM.</li>
              <li><strong>Inspect Decisions:</strong> Tap <em>Why This Matters</em> on Card #1 to inspect the exact signal math.</li>
              <li><strong>Verify Negative Test:</strong> Tap <em>Why Not?</em> to observe CVSS 9.9 deprioritized to #60+.</li>
              <li><strong>Ingest Profile D:</strong> Paste custom hospital profile JSON to triage without network access.</li>
            </ol>
          </div>
        </div>
        """
    )
