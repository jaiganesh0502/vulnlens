"""VulnLens Global Brand & Design System — Theme & Component Generators.

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
  --vl-font-sans: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --vl-font-mono: 'JetBrains Mono', Consolas, 'Courier New', monospace;
}

.stApp {
  background-color: var(--vl-bg-primary) !important;
  color: #E2E8F0 !important;
  font-family: var(--vl-font-sans) !important;
}

.stApp::before {
  content: "";
  position: fixed;
  top: -150px;
  left: 20%;
  width: 60%;
  height: 450px;
  background: radial-gradient(circle, rgba(5, 30, 94, 0.65) 0%, rgba(3, 41, 124, 0.3) 40%, rgba(3, 14, 51, 0) 75%);
  pointer-events: none;
  z-index: 0;
}

header[data-testid="stHeader"] {
  background-color: transparent !important;
}

.stTabs [data-baseweb="tab-list"] {
  background-color: var(--vl-bg-secondary) !important;
  border-radius: 12px !important;
  padding: 6px !important;
  border: 1px solid rgba(13, 127, 253, 0.2) !important;
  gap: 8px !important;
}

.stTabs [data-baseweb="tab"] {
  color: #94A3B8 !important;
  font-family: var(--vl-font-sans) !important;
  font-weight: 600 !important;
  font-size: 14px !important;
  border-radius: 8px !important;
  padding: 8px 16px !important;
  border: none !important;
  background: transparent !important;
  transition: all 0.2s ease-in-out !important;
}

.stTabs [data-baseweb="tab"]:hover {
  color: #E2E8F0 !important;
  background-color: rgba(3, 41, 124, 0.4) !important;
}

.stTabs [aria-selected="true"] {
  background: linear-gradient(135deg, var(--vl-electric-blue) 0%, var(--vl-emblem-blue) 100%) !important;
  color: #FFFFFF !important;
  box-shadow: 0 4px 12px rgba(13, 127, 253, 0.35) !important;
}

.vl-card {
  background-color: var(--vl-bg-secondary);
  border: 1px solid rgba(13, 127, 253, 0.18);
  border-radius: 14px;
  padding: 20px;
  margin-bottom: 16px;
  position: relative;
  transition: transform 0.18s ease, border-color 0.18s ease, box-shadow 0.18s ease;
}

.vl-card:hover {
  border-color: rgba(76, 183, 252, 0.4);
  box-shadow: 0 8px 24px rgba(3, 41, 124, 0.35);
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

.vl-h1 {
  font-size: 2.2rem;
  font-weight: 900;
  letter-spacing: -0.02em;
  color: #FFFFFF;
  line-height: 1.2;
}

.vl-h2 {
  font-size: 1.5rem;
  font-weight: 800;
  color: #F8FAFC;
  letter-spacing: -0.01em;
}

.vl-h3 {
  font-size: 1.15rem;
  font-weight: 700;
  color: #E2E8F0;
}

.vl-mono {
  font-family: var(--vl-font-mono) !important;
  letter-spacing: -0.01em;
}

.vl-gradient-text {
  background: linear-gradient(135deg, #FFFFFF 0%, var(--vl-highlight) 50%, var(--vl-electric-blue) 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

.vl-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 12px;
  font-weight: 800;
  letter-spacing: 0.03em;
  font-family: var(--vl-font-sans);
}

.vl-badge-urgent {
  background: rgba(239, 68, 68, 0.18);
  color: #FCA5A5;
  border: 1px solid rgba(239, 68, 68, 0.45);
}

.vl-badge-high {
  background: rgba(249, 115, 22, 0.18);
  color: #FDBA74;
  border: 1px solid rgba(249, 115, 22, 0.45);
}

.vl-badge-medium {
  background: rgba(251, 191, 36, 0.18);
  color: #FDE68A;
  border: 1px solid rgba(251, 191, 36, 0.45);
}

.vl-badge-low {
  background: rgba(16, 185, 129, 0.18);
  color: #6EE7B7;
  border: 1px solid rgba(16, 185, 129, 0.45);
}

.vl-badge-offline {
  background: rgba(13, 127, 253, 0.15);
  color: var(--vl-highlight);
  border: 1px solid rgba(76, 183, 252, 0.35);
  border-radius: 20px;
  padding: 5px 12px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.04em;
}

.stButton > button {
  background: linear-gradient(135deg, var(--vl-electric-blue) 0%, var(--vl-emblem-blue) 100%) !important;
  color: #FFFFFF !important;
  font-weight: 700 !important;
  font-family: var(--vl-font-sans) !important;
  border: none !important;
  border-radius: 8px !important;
  padding: 10px 22px !important;
  box-shadow: 0 4px 14px rgba(13, 127, 253, 0.3) !important;
  transition: all 0.2s ease !important;
}

.stButton > button:hover {
  background: linear-gradient(135deg, #2358F9 0%, #4F3DF5 100%) !important;
  box-shadow: 0 6px 20px rgba(79, 61, 245, 0.4) !important;
  transform: translateY(-1px);
}

.vl-progress-track {
  background: rgba(3, 41, 124, 0.4);
  border-radius: 6px;
  height: 10px;
  overflow: hidden;
  position: relative;
  border: 1px solid rgba(13, 127, 253, 0.2);
}

.vl-progress-fill {
  height: 100%;
  border-radius: 6px;
  background: linear-gradient(90deg, var(--vl-emblem-blue) 0%, var(--vl-electric-blue) 50%, var(--vl-highlight) 100%);
}

section[data-testid="stSidebar"] {
  background-color: #020922 !important;
  border-right: 1px solid rgba(13, 127, 253, 0.15) !important;
}
</style>
""")


def render_brand_header() -> str:
    """Render top brand header with official emblem and offline badge."""
    logo_src = get_logo_base64()
    logo_img = (
        f'<img src="{logo_src}" style="width: 42px; height: 42px; border-radius: 50%; box-shadow: 0 0 16px rgba(13, 127, 253, 0.45); margin-right: 14px;" />'
        if logo_src
        else '<div style="width: 42px; height: 42px; border-radius: 50%; background: linear-gradient(135deg, #2358F9, #4F3DF5); margin-right: 14px;"></div>'
    )

    return compact_html(f"""
    <div style="display: flex; align-items: center; justify-content: space-between; padding: 12px 0 24px 0; border-bottom: 1px solid rgba(13, 127, 253, 0.15); margin-bottom: 24px;">
      <div style="display: flex; align-items: center;">
        {logo_img}
        <div>
          <div style="font-size: 24px; font-weight: 900; letter-spacing: 0.05em; color: #FFFFFF; font-family: 'Inter', sans-serif;">
            VULN<span style="color: #0D7FFD;">LENS</span>
          </div>
          <div style="font-size: 12px; font-weight: 600; color: #94A3B8; letter-spacing: 0.02em;">
            Personalised Vulnerability Triage
          </div>
        </div>
      </div>
      <div style="display: flex; align-items: center; gap: 10px;">
        <span class="vl-badge vl-badge-offline">
          <span style="display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: #10B981; box-shadow: 0 0 8px #10B981; margin-right: 4px;"></span>
          OFFLINE READY
        </span>
      </div>
    </div>
    """)


def render_hero_section() -> str:
    """Render the presentation landing hero with pipeline architecture."""
    logo_src = get_logo_base64()
    logo_markup = (
        f'<img src="{logo_src}" style="width: 84px; height: 84px; border-radius: 50%; box-shadow: 0 0 32px rgba(35, 88, 249, 0.6); margin-bottom: 18px;" />'
        if logo_src
        else ""
    )

    return compact_html(f"""
    <div style="text-align: center; padding: 36px 20px 48px 20px; background: radial-gradient(circle at 50% 30%, rgba(5, 30, 94, 0.7) 0%, rgba(3, 14, 51, 0) 70%); border-radius: 20px; margin-bottom: 32px; border: 1px solid rgba(13, 127, 253, 0.15);">
      {logo_markup}
      <div style="font-size: 13px; font-weight: 800; color: #0D7FFD; letter-spacing: 0.15em; text-transform: uppercase; margin-bottom: 8px;">
        Enterprise Security Decision Support
      </div>
      <h1 style="font-size: 42px; font-weight: 900; letter-spacing: -0.02em; color: #FFFFFF; margin-bottom: 12px; font-family: 'Inter', sans-serif;">
        Personalised Vulnerability Triage
      </h1>
      <p style="font-size: 17px; color: #94A3B8; max-width: 680px; margin: 0 auto 28px auto; line-height: 1.5;">
        Turn hundreds of public vulnerability records into <strong style="color: #F8FAFC;">five explainable security actions</strong> tailored specifically to your organisation's operational asset context.
      </p>

      <div style="display: flex; align-items: center; justify-content: center; flex-wrap: wrap; gap: 8px; max-width: 880px; margin: 0 auto; padding: 18px; background: rgba(4, 22, 72, 0.7); border-radius: 14px; border: 1px solid rgba(13, 127, 253, 0.25);">
        <div style="padding: 10px 16px; background: #030E33; border-radius: 8px; border: 1px solid rgba(147, 226, 252, 0.2); font-family: 'JetBrains Mono', monospace; font-size: 12px; font-weight: 700; color: #93E2FC;">
          500+ Vulnerabilities (NVD/KEV/EPSS)
        </div>
        <span style="color: #0D7FFD; font-size: 16px; font-weight: 900;">→</span>
        <div style="padding: 10px 16px; background: #030E33; border-radius: 8px; border: 1px solid rgba(147, 226, 252, 0.2); font-family: 'JetBrains Mono', monospace; font-size: 12px; font-weight: 700; color: #93E2FC;">
          Organisation Context & Risk
        </div>
        <span style="color: #0D7FFD; font-size: 16px; font-weight: 900;">→</span>
        <div style="padding: 10px 16px; background: #030E33; border-radius: 8px; border: 1px solid rgba(147, 226, 252, 0.2); font-family: 'JetBrains Mono', monospace; font-size: 12px; font-weight: 700; color: #93E2FC;">
          Deterministic Matching
        </div>
        <span style="color: #0D7FFD; font-size: 16px; font-weight: 900;">→</span>
        <div style="padding: 10px 18px; background: linear-gradient(135deg, #2358F9, #4F3DF5); border-radius: 8px; font-family: 'Inter', sans-serif; font-size: 13px; font-weight: 800; color: #FFFFFF; box-shadow: 0 4px 14px rgba(79, 61, 245, 0.4);">
          TOP 5 DECISIONS
        </div>
      </div>
    </div>
    """)


def render_priority_badge(priority_str: str) -> str:
    """Render semantic priority badge with symbol and text."""
    p = priority_str.upper()
    if p == "URGENT":
        return '<span class="vl-badge vl-badge-urgent"><span style="color:#EF4444">🔴</span> URGENT</span>'
    elif p == "HIGH":
        return '<span class="vl-badge vl-badge-high"><span style="color:#F97316">🟠</span> HIGH</span>'
    elif p == "MEDIUM":
        return '<span class="vl-badge vl-badge-medium"><span style="color:#FBBF24">🟡</span> MEDIUM</span>'
    else:
        return '<span class="vl-badge vl-badge-low"><span style="color:#10B981">🟢</span> LOW</span>'


def render_score_bar(
    label: str, value_pts: float, max_pts: float = 140.0, formula: str = ""
) -> str:
    """Render a neutral brand-colored score contribution progress bar."""
    pct = min(100.0, max(0.0, (value_pts / max_pts) * 100))
    formula_html = f'<div style="font-size: 10px; color: #64748B; margin-top: 2px;">{formula}</div>' if formula else ""
    return compact_html(f"""
    <div style="margin-bottom: 10px;">
      <div style="display: flex; justify-content: space-between; font-size: 12px; font-weight: 600; color: #CBD5E1; margin-bottom: 4px;">
        <span>{label}</span>
        <span style="font-family: 'JetBrains Mono', monospace; font-weight: 700; color: #93E2FC;">+{value_pts:.1f} pts</span>
      </div>
      <div class="vl-progress-track">
        <div class="vl-progress-fill" style="width: {pct:.1f}%;"></div>
      </div>
      {formula_html}
    </div>
    """)
