"""VulnLens Global Brand & Design System — Enterprise Theme & Component Generators.

Official Brand Tokens:
  --vl-bg-primary: #030E33 (Deep Navy)
  --vl-bg-secondary: #041648 (Dark Blue)
  --vl-bg-glow: #051E5E (Royal Deep Blue)
  --vl-blue-glow: #03297C (Strong Blue)
  --vl-electric-blue: #0D7FFD (Electric Blue)
  --vl-emblem-blue: #2358F9 (Vibrant Blue)
  --vl-emblem-violet: #4F3DF5 (Purple)
  --vl-highlight: #93E2FC (Light Cyan)
  --vl-mid-blue: #4CB7FC (Sky Blue)
  --vl-border-subtle: rgba(147, 226, 252, 0.08)
"""

import base64
from pathlib import Path

# Fixed Brand Colors
BG_PRIMARY = "#030E33"
BG_SECONDARY = "#041648"
BG_GLOW = "#051E5E"
BLUE_GLOW = "#03297C"
ELECTRIC_BLUE = "#0D7FFD"
EMBLEM_BLUE = "#2358F9"
EMBLEM_VIOLET = "#4F3DF5"
HIGHLIGHT_CYAN = "#93E2FC"
MID_BLUE = "#4CB7FC"
BORDER_SUBTLE = "rgba(147, 226, 252, 0.08)"

# Semantic Security Colors
URGENT_RED = "#EF4444"
URGENT_BG = "rgba(239, 68, 68, 0.15)"
URGENT_BORDER = "rgba(239, 68, 68, 0.4)"

HIGH_ORANGE = "#F97316"
HIGH_BG = "rgba(249, 115, 22, 0.15)"
HIGH_BORDER = "rgba(249, 115, 22, 0.4)"

MEDIUM_AMBER = "#FBBF24"
MEDIUM_BG = "rgba(251, 191, 36, 0.15)"
MEDIUM_BORDER = "rgba(251, 191, 36, 0.4)"

LOW_GREEN = "#10B981"
LOW_BG = "rgba(16, 185, 129, 0.15)"
LOW_BORDER = "rgba(16, 185, 129, 0.4)"


def compact_html(html_str: str) -> str:
    """Strip all newlines, leading/trailing whitespace, and comments to produce pure inline HTML."""
    lines = []
    for line in html_str.splitlines():
        s = line.strip()
        if not s or (s.startswith("<!--") and s.endswith("-->")):
            continue
        lines.append(s)
    return " ".join(lines)


def get_logo_base64() -> str:
    """Read local logo and return as base64 data URI."""
    logo_path = Path("assets/images/vulnlens_logo.png")
    if logo_path.exists():
        data = logo_path.read_bytes()
        encoded = base64.b64encode(data).decode("utf-8")
        return f"data:image/png;base64,{encoded}"
    return ""


def get_qr_code_base64() -> str:
    """Read generated QR code image and return as base64 data URI."""
    qr_path = Path("assets/images/qr_download.png")
    if qr_path.exists():
        data = qr_path.read_bytes()
        encoded = base64.b64encode(data).decode("utf-8")
        return f"data:image/png;base64,{encoded}"
    return ""


GLOBAL_CSS = compact_html("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@500;600;700;800&display=swap');

:root {
  --vl-bg-primary: #030E33;
  --vl-bg-secondary: #041648;
  --vl-bg-glow: #051E5E;
  --vl-blue-glow: #03297C;
  --vl-electric-blue: #0D7FFD;
  --vl-emblem-blue: #2358F9;
  --vl-emblem-violet: #4F3DF5;
  --vl-highlight: #93E2FC;
  --vl-mid-blue: #4CB7FC;
  --vl-border-subtle: rgba(147, 226, 252, 0.08);
  --vl-font-sans: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --vl-font-mono: 'JetBrains Mono', Consolas, monospace;
}

html, body, [data-testid="stAppViewContainer"], .main, .stApp {
  background-color: var(--vl-bg-primary) !important;
  color: #E2E8F0 !important;
  font-family: var(--vl-font-sans) !important;
  overflow-x: hidden !important;
}

/* Custom Scrollbars */
::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}
::-webkit-scrollbar-track {
  background: var(--vl-bg-primary);
}
::-webkit-scrollbar-thumb {
  background: rgba(13, 127, 253, 0.4);
  border-radius: 4px;
}
::-webkit-scrollbar-thumb:hover {
  background: var(--vl-electric-blue);
}

/* Subtle background lighting effect */
.stApp::before {
  content: "";
  position: fixed;
  top: -100px;
  left: 25%;
  width: 50%;
  height: 400px;
  background: radial-gradient(circle, rgba(5, 30, 94, 0.5) 0%, rgba(3, 41, 124, 0.2) 40%, rgba(3, 14, 51, 0) 70%);
  pointer-events: none;
  z-index: 0;
}

/* Hide Streamlit default headers, footers & decorations */
header[data-testid="stHeader"] {
  background-color: transparent !important;
  z-index: 10 !important;
}
footer {
  display: none !important;
}
#MainMenu {
  visibility: hidden !important;
}
.stDeployButton {
  display: none !important;
}

/* Global Content Padding & Clean Spacing */
.block-container {
  padding-top: 1.5rem !important;
  padding-bottom: 3rem !important;
  padding-left: 2rem !important;
  padding-right: 2rem !important;
  max-width: 1360px !important;
}

/* Enterprise Sidebar Navigation */
section[data-testid="stSidebar"] {
  background-color: #041648 !important;
  border-right: 1px solid rgba(147, 226, 252, 0.08) !important;
  width: 270px !important;
}

section[data-testid="stSidebar"] > div {
  padding-top: 1.2rem !important;
  padding-left: 1.1rem !important;
  padding-right: 1.1rem !important;
}

/* Sidebar Radio Styling as Enterprise Menu */
section[data-testid="stSidebar"] div[data-testid="stRadio"] > div {
  gap: 4px !important;
}

section[data-testid="stSidebar"] div[data-testid="stRadio"] label {
  background: transparent !important;
  border-radius: 8px !important;
  padding: 8px 12px !important;
  margin: 1px 0 !important;
  color: #94A3B8 !important;
  font-family: var(--vl-font-sans) !important;
  font-size: 13px !important;
  font-weight: 600 !important;
  transition: all 0.15s ease !important;
  border-left: 3px solid transparent !important;
  cursor: pointer !important;
}

section[data-testid="stSidebar"] div[data-testid="stRadio"] label:hover {
  background: rgba(13, 127, 253, 0.08) !important;
  color: #FFFFFF !important;
}

section[data-testid="stSidebar"] div[data-testid="stRadio"] label[data-checked="true"],
section[data-testid="stSidebar"] div[data-testid="stRadio"] label:has(input:checked) {
  background: rgba(13, 127, 253, 0.14) !important;
  color: #FFFFFF !important;
  border-left: 3px solid var(--vl-electric-blue) !important;
  font-weight: 700 !important;
  box-shadow: 0 2px 8px rgba(13, 127, 253, 0.2) !important;
}

section[data-testid="stSidebar"] div[data-testid="stRadio"] label span:first-child {
  display: none !important;
}

/* Base Enterprise Cards */
.vl-card {
  background-color: var(--vl-bg-secondary);
  border: 1px solid rgba(147, 226, 252, 0.08);
  border-radius: 12px;
  padding: 20px;
  margin-bottom: 16px;
  position: relative;
  transition: transform 0.15s ease, border-color 0.15s ease, box-shadow 0.15s ease;
}

.vl-card:hover {
  border-color: rgba(13, 127, 253, 0.3);
  box-shadow: 0 6px 20px rgba(3, 41, 124, 0.25);
}

.vl-card-urgent {
  border-left: 4px solid #EF4444 !important;
}

.vl-card-high {
  border-left: 4px solid #F97316 !important;
}

.vl-card-medium {
  border-left: 4px solid #FBBF24 !important;
}

.vl-card-low {
  border-left: 4px solid #10B981 !important;
}

/* Typography Hierarchy */
.vl-h1 {
  font-size: 1.85rem;
  font-weight: 900;
  letter-spacing: -0.02em;
  color: #FFFFFF;
  line-height: 1.25;
  margin-bottom: 4px;
}

.vl-h2 {
  font-size: 1.35rem;
  font-weight: 800;
  color: #F8FAFC;
  letter-spacing: -0.01em;
  margin-bottom: 6px;
}

.vl-h3 {
  font-size: 1.05rem;
  font-weight: 700;
  color: #E2E8F0;
  letter-spacing: -0.01em;
}

.vl-mono {
  font-family: var(--vl-font-mono) !important;
}

.vl-text-secondary {
  color: #94A3B8;
  font-size: 13px;
  line-height: 1.45;
}

/* Badges */
.vl-badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 11px;
  font-weight: 800;
  letter-spacing: 0.03em;
  font-family: var(--vl-font-sans);
}

.vl-badge-urgent {
  background: rgba(239, 68, 68, 0.15);
  color: #FCA5A5;
  border: 1px solid rgba(239, 68, 68, 0.4);
}

.vl-badge-high {
  background: rgba(249, 115, 22, 0.15);
  color: #FDBA74;
  border: 1px solid rgba(249, 115, 22, 0.4);
}

.vl-badge-medium {
  background: rgba(251, 191, 36, 0.15);
  color: #FDE68A;
  border: 1px solid rgba(251, 191, 36, 0.4);
}

.vl-badge-low {
  background: rgba(16, 185, 129, 0.15);
  color: #6EE7B7;
  border: 1px solid rgba(16, 185, 129, 0.4);
}

.vl-badge-offline {
  background: rgba(13, 127, 253, 0.12);
  color: var(--vl-highlight);
  border: 1px solid rgba(13, 127, 253, 0.3);
  border-radius: 16px;
  padding: 4px 10px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.03em;
}

/* KPI Summary Cards */
.vl-kpi-card {
  background: var(--vl-bg-secondary);
  border: 1px solid rgba(147, 226, 252, 0.08);
  border-radius: 10px;
  padding: 14px 16px;
  transition: all 0.15s ease;
}

.vl-kpi-card:hover {
  border-color: rgba(13, 127, 253, 0.25);
  box-shadow: 0 4px 14px rgba(3, 41, 124, 0.2);
}

.vl-kpi-label {
  font-size: 11px;
  font-weight: 800;
  color: #94A3B8;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 4px;
}

.vl-kpi-value {
  font-size: 24px;
  font-weight: 900;
  color: #FFFFFF;
  font-family: var(--vl-font-mono);
  line-height: 1.1;
}

.vl-kpi-sub {
  font-size: 11px;
  color: #64748B;
  margin-top: 3px;
}

/* Buttons */
.stButton > button {
  background: linear-gradient(135deg, var(--vl-electric-blue) 0%, var(--vl-emblem-blue) 100%) !important;
  color: #FFFFFF !important;
  font-weight: 700 !important;
  font-family: var(--vl-font-sans) !important;
  font-size: 13px !important;
  border: none !important;
  border-radius: 8px !important;
  padding: 8px 18px !important;
  box-shadow: 0 3px 10px rgba(13, 127, 253, 0.25) !important;
  transition: all 0.15s ease !important;
}

.stButton > button:hover {
  background: linear-gradient(135deg, #2358F9 0%, #4F3DF5 100%) !important;
  box-shadow: 0 5px 16px rgba(79, 61, 245, 0.35) !important;
  transform: translateY(-1px);
}

/* Selectbox & Inputs */
.stSelectbox div[data-baseweb="select"] > div {
  background-color: var(--vl-bg-primary) !important;
  border: 1px solid rgba(147, 226, 252, 0.12) !important;
  border-radius: 8px !important;
  color: #FFFFFF !important;
}

.stTextInput input, .stTextArea textarea {
  background-color: var(--vl-bg-primary) !important;
  border: 1px solid rgba(147, 226, 252, 0.12) !important;
  border-radius: 8px !important;
  color: #FFFFFF !important;
  font-family: var(--vl-font-mono) !important;
}

/* Progress Track */
.vl-progress-track {
  background: rgba(3, 41, 124, 0.4);
  border-radius: 4px;
  height: 6px;
  overflow: hidden;
  position: relative;
  border: 1px solid rgba(13, 127, 253, 0.15);
}

.vl-progress-fill {
  height: 100%;
  border-radius: 4px;
  background: linear-gradient(90deg, var(--vl-emblem-blue) 0%, var(--vl-electric-blue) 50%, var(--vl-highlight) 100%);
}
</style>
""")


def render_sidebar_header() -> str:
    """Render top of sidebar with logo, product name and positioning subtitle."""
    logo_src = get_logo_base64()
    logo_img = (
        f'<img src="{logo_src}" style="width: 34px; height: 34px; border-radius: 50%; box-shadow: 0 0 12px rgba(13, 127, 253, 0.4); margin-right: 10px;" />'
        if logo_src
        else '<div style="width: 34px; height: 34px; border-radius: 50%; background: linear-gradient(135deg, #2358F9, #4F3DF5); margin-right: 10px;"></div>'
    )

    return compact_html(f"""
    <div style="display: flex; align-items: center; padding-bottom: 14px; border-bottom: 1px solid rgba(147, 226, 252, 0.08); margin-bottom: 14px;">
      {logo_img}
      <div>
        <div style="font-size: 18px; font-weight: 900; letter-spacing: 0.04em; color: #FFFFFF; font-family: 'Inter', sans-serif;">
          VULN<span style="color: #0D7FFD;">LENS</span>
        </div>
        <div style="font-size: 9px; font-weight: 800; color: #94A3B8; letter-spacing: 0.06em; text-transform: uppercase;">
          Personalised Triage
        </div>
      </div>
    </div>
    """)


def render_sidebar_org_card(profile, fingerprint) -> str:
    """Render polished organization context card inside sidebar."""
    w_kev = profile.weight_modifiers.cisa_kev_weight * 100
    w_epss = profile.weight_modifiers.first_epss_weight * 100
    w_cvss = profile.weight_modifiers.cvss_weight * 100

    jewels_chips = "".join([
        f'<span style="background: rgba(16, 185, 129, 0.12); color: #6EE7B7; border: 1px solid rgba(16, 185, 129, 0.3); padding: 1px 5px; border-radius: 4px; font-size: 9px; font-weight: 700;">{cp}</span>'
        for cp in profile.critical_products[:3]
    ])
    if len(profile.critical_products) > 3:
        jewels_chips += f'<span style="color: #64748B; font-size: 9px;">+{len(profile.critical_products)-3} more</span>'

    return compact_html(f"""
    <div style="background: #030E33; border: 1px solid rgba(147, 226, 252, 0.08); border-radius: 10px; padding: 12px; margin: 12px 0 16px 0;">
      <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 6px;">
        <div>
          <div style="font-size: 12px; font-weight: 800; color: #FFFFFF;">{profile.name}</div>
          <div style="font-size: 10px; color: #94A3B8;">{profile.sector} · <span style="font-family: monospace; color: #93E2FC;">{profile.org_id}</span></div>
        </div>
        <span style="background: rgba(13, 127, 253, 0.15); color: #93E2FC; border: 1px solid rgba(13, 127, 253, 0.3); padding: 2px 6px; border-radius: 4px; font-size: 9px; font-weight: 800;">
          {profile.risk_appetite.upper()}
        </span>
      </div>

      <div style="font-size: 9px; font-weight: 800; color: #64748B; letter-spacing: 0.06em; text-transform: uppercase; margin: 10px 0 4px 0;">
        THREAT PROFILE WEIGHTS
      </div>
      
      <div style="margin-bottom: 4px;">
        <div style="display: flex; justify-content: space-between; font-size: 10px; color: #CBD5E1; margin-bottom: 2px;">
          <span>KEV Exploitation</span>
          <span style="font-family: monospace; font-weight: 700; color: #93E2FC;">{w_kev:.0f}%</span>
        </div>
        <div class="vl-progress-track"><div class="vl-progress-fill" style="width: {w_kev}%;"></div></div>
      </div>

      <div style="margin-bottom: 4px;">
        <div style="display: flex; justify-content: space-between; font-size: 10px; color: #CBD5E1; margin-bottom: 2px;">
          <span>EPSS Probability</span>
          <span style="font-family: monospace; font-weight: 700; color: #93E2FC;">{w_epss:.0f}%</span>
        </div>
        <div class="vl-progress-track"><div class="vl-progress-fill" style="width: {w_epss}%;"></div></div>
      </div>

      <div style="margin-bottom: 8px;">
        <div style="display: flex; justify-content: space-between; font-size: 10px; color: #CBD5E1; margin-bottom: 2px;">
          <span>CVSS Severity</span>
          <span style="font-family: monospace; font-weight: 700; color: #93E2FC;">{w_cvss:.0f}%</span>
        </div>
        <div class="vl-progress-track"><div class="vl-progress-fill" style="width: {w_cvss}%;"></div></div>
      </div>

      <div style="font-size: 9px; font-weight: 800; color: #64748B; letter-spacing: 0.06em; text-transform: uppercase; margin-bottom: 4px;">
        CRITICAL ASSETS
      </div>
      <div style="display: flex; flex-wrap: wrap; gap: 4px;">
        {jewels_chips}
      </div>
    </div>
    """)


def render_sidebar_footer() -> str:
    """Render offline security status footer in sidebar."""
    return compact_html("""
    <div style="padding-top: 14px; border-top: 1px solid rgba(147, 226, 252, 0.08); margin-top: 20px;">
      <div style="display: flex; align-items: center; gap: 6px; margin-bottom: 3px;">
        <span style="display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: #10B981; box-shadow: 0 0 6px #10B981;"></span>
        <span style="font-size: 11px; font-weight: 800; color: #93E2FC; letter-spacing: 0.04em;">OFFLINE READY</span>
      </div>
      <div style="font-size: 10px; color: #64748B; line-height: 1.35;">
        Local deterministic engine · Zero external API telemetry
      </div>
    </div>
    """)


def render_top_header(title: str, subtitle: str, org_name: str, org_id: str) -> str:
    """Render top application header bar."""
    return compact_html(f"""
    <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px 0 18px 0; border-bottom: 1px solid rgba(147, 226, 252, 0.08); margin-bottom: 22px;">
      <div>
        <div style="font-size: 20px; font-weight: 900; color: #FFFFFF; letter-spacing: -0.01em; font-family: 'Inter', sans-serif;">
          {title}
        </div>
        <div style="font-size: 12px; color: #94A3B8; margin-top: 2px;">
          {subtitle} · <span style="color: #0D7FFD; font-weight: 700;">{org_name}</span> (<span style="font-family: monospace; color: #93E2FC;">{org_id}</span>)
        </div>
      </div>
      <div style="display: flex; align-items: center; gap: 12px;">
        <span class="vl-badge vl-badge-offline">
          <span style="display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: #10B981; box-shadow: 0 0 6px #10B981; margin-right: 3px;"></span>
          100% OFFLINE
        </span>
        <div style="width: 32px; height: 32px; border-radius: 50%; background: rgba(13, 127, 253, 0.2); border: 1px solid rgba(13, 127, 253, 0.4); display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 800; color: #93E2FC; font-family: monospace;">
          {org_id.replace('ORG-', '')}
        </div>
      </div>
    </div>
    """)


def render_priority_badge(priority_str: str, score: float = None) -> str:
    """Render semantic priority badge with score."""
    p = priority_str.upper()
    score_str = f" | {score:.1f}" if score is not None else ""
    if p == "URGENT":
        return f'<span class="vl-badge vl-badge-urgent"><span style="color:#EF4444">🔴</span> URGENT{score_str}</span>'
    elif p == "HIGH":
        return f'<span class="vl-badge vl-badge-high"><span style="color:#F97316">🟠</span> HIGH{score_str}</span>'
    elif p == "MEDIUM":
        return f'<span class="vl-badge vl-badge-medium"><span style="color:#FBBF24">🟡</span> MEDIUM{score_str}</span>'
    else:
        return f'<span class="vl-badge vl-badge-low"><span style="color:#10B981">🟢</span> LOW{score_str}</span>'


def render_score_bar(
    label: str, value_pts: float, max_pts: float = 140.0, formula: str = ""
) -> str:
    """Render a brand-colored score contribution progress bar."""
    pct = min(100.0, max(0.0, (value_pts / max_pts) * 100)) if max_pts > 0 else 0.0
    formula_html = f'<div style="font-size: 10px; color: #64748B; margin-top: 2px;">{formula}</div>' if formula else ""
    return compact_html(f"""
    <div style="margin-bottom: 8px;">
      <div style="display: flex; justify-content: space-between; font-size: 11px; font-weight: 600; color: #CBD5E1; margin-bottom: 3px;">
        <span>{label}</span>
        <span style="font-family: monospace; font-weight: 700; color: #93E2FC;">+{value_pts:.1f} pts</span>
      </div>
      <div class="vl-progress-track">
        <div class="vl-progress-fill" style="width: {pct:.1f}%;"></div>
      </div>
      {formula_html}
    </div>
    """)
