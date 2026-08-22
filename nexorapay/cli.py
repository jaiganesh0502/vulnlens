"""Command-Line Interface for NexoraPay Cyber Risk Simulator.

Supports:
- Default overview and table
- Single vulnerability inspection
- Contextual What-If simulations
- Interactive live analyst hackathon scenario
- Organisation fingerprinting
- Web console launching
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from nexorapay.models import (
    Criticality,
    CVSSSeverity,
    Exposure,
    PriorityLevel,
    RiskAppetite,
)
from nexorapay.scenarios import (
    DEMO_SCENARIOS,
    NEXORAPAY_ORG,
    REAL_WORLD_CASE_STUDY,
    SCENARIOS_BY_ID,
)
from nexorapay.scoring import (
    PROFILE_WEIGHTS,
    calculate_score_breakdown,
)
from nexorapay.simulator import CyberRiskSimulator


def print_header(title: str, subtitle: Optional[str] = None):
    border = "=" * 44
    print(border)
    print(title.upper())
    print("=" * len(title))
    if subtitle:
        print(subtitle)
    print("FICTIONAL DEMO ORGANISATION")
    print(border)
    print()


def print_fingerprint(simulator: CyberRiskSimulator, appetite: RiskAppetite = RiskAppetite.LOW):
    weights = PROFILE_WEIGHTS[appetite]
    w_cvss = weights["cvss"]
    w_kev = weights["kev"]
    w_epss = weights["epss"]

    def make_bar(wt: float) -> str:
        filled = int(round(wt * 12))
        unfilled = 12 - filled
        return "█" * filled + "░" * unfilled

    if w_kev >= w_epss and w_kev >= w_cvss:
        philosophy = "Strong emphasis on known exploitation."
    elif w_epss >= w_kev:
        philosophy = "Strong emphasis on exploitation probability."
    else:
        philosophy = "Strong emphasis on technical severity."

    print("============================================================")
    print("NEXORAPAY")
    print("ORGANISATION FINGERPRINT")
    print("============================================================")
    print()
    print("THREAT SIGNAL WEIGHTS")
    print()
    print("CVSS")
    print(f"{make_bar(w_cvss)} {int(round(w_cvss * 100))}%")
    print()
    print("KEV")
    print(f"{make_bar(w_kev)} {int(round(w_kev * 100))}%")
    print()
    print("EPSS")
    print(f"{make_bar(w_epss)} {int(round(w_epss * 100))}%")
    print()
    print("CONTEXT")
    print()
    print("Exposure:")
    print("HIGH")
    print()
    print("Importance:")
    print("HIGH")
    print()
    print("PRIORITY PHILOSOPHY:")
    print()
    print(philosophy)
    print()
    print("============================================================")


def print_table(simulator: CyberRiskSimulator, appetite: RiskAppetite = RiskAppetite.LOW):
    print("ORGANISATION SNAPSHOT")
    print(f"Industry:                 {simulator.organisation.industry}")
    print(f"Risk appetite:            {appetite.value.upper()}")
    print(f"Critical services:        {simulator.organisation.critical_services_count}")
    print(f"Internet-facing services: {simulator.organisation.internet_facing_count}")
    print(f"Internal services:        {simulator.organisation.internal_count}")
    print()

    print("============================================================")
    print("VULNLENS PRIORITY RANKING")
    print("============================================================")
    print(f"{'#':<3} {'CVE':<16} {'THREAT':<8} {'CONTEXT':<9} {'DELTA':<8} {'PRIORITY':<12}")
    print("-" * 60)

    results = simulator.evaluate_all(risk_appetite=appetite)
    for rank_idx, (vuln, breakdown) in enumerate(results, start=1):
        threat = breakdown.base_score
        exp_m = 1.20 if vuln.exposure == Exposure.INTERNET_FACING else 1.00
        imp_m = 1.20 if vuln.criticality == Criticality.CRITICAL else (1.10 if vuln.criticality == Criticality.HIGH else 1.00)
        context_mult = exp_m * imp_m
        final = threat * context_mult
        delta = final - threat
        delta_str = f"+{delta:.1f}" if delta > 0 else f"{delta:.1f}"
        sym = (
            "🔴" if breakdown.priority_level == PriorityLevel.URGENT
            else ("🟠" if breakdown.priority_level == PriorityLevel.HIGH
                  else ("🟡" if breakdown.priority_level == PriorityLevel.MEDIUM else "🟢"))
        )
        print(f"{rank_idx:<3} {vuln.vuln_id:<16} {threat:<8.1f} ×{context_mult:<8.2f} {delta_str:<8} {final:<6.1f} {sym}")
    print("============================================================")
    print("Notice: Highest technical CVSS (9.8 on Internal) ranks BELOW weaponized 8.4 on Internet Portal!")
    print()


def print_default_demo(simulator: CyberRiskSimulator, cve_id: str = "NXP-DEMO-002", appetite: RiskAppetite = RiskAppetite.LOW):
    vuln = simulator.get_scenario(cve_id)
    if not vuln:
        vuln = DEMO_SCENARIOS[1]  # NXP-DEMO-002

    breakdown = simulator.evaluate_scenario(vuln, risk_appetite=appetite)

    print("=" * 44)
    print("NEXORAPAY CYBER RISK SIMULATOR")
    print("=" * 30)
    print()
    print("Organisation:")
    print(simulator.organisation.name)
    print()
    print("Asset:")
    print(vuln.affected_asset_name)
    print()
    print("Exposure:")
    print(vuln.exposure.value)
    print()
    print("Criticality:")
    print(vuln.criticality.value)
    print()
    print("---")
    print()
    print("Vulnerability:")
    print(vuln.vuln_id)
    print()
    print("CVSS:")
    print(f"{vuln.cvss:.1f}")
    print()
    print("KEV:")
    print("YES" if vuln.kev else "NO")
    print()
    print("EPSS:")
    print(f"{vuln.epss:.2f}")
    print()
    print("---")
    print()
    print("TECHNICAL THREAT SCORE:")
    print(f"{breakdown.base_score:.1f} / 100")
    print()
    print("DEMO PRIORITY:")
    print(breakdown.priority_level.value)
    print()
    print("---")
    print()
    print("WHY?")
    print()
    if vuln.cvss >= 7.0:
        print("[+] High technical severity")
    if vuln.kev:
        print("[+] Known exploitation signal")
    if vuln.epss >= 0.5:
        print("[+] High exploitation probability")
    if vuln.exposure == Exposure.INTERNET_FACING:
        print("[+] Internet-facing asset")
    if vuln.criticality == Criticality.CRITICAL:
        print("[+] Critical business service")
    print()


def print_what_if_output(result):
    print("BEFORE")
    if result.changes:
        first_change = result.changes[0]
        print(f"{first_change.factor}:")
        print(first_change.before_value)
    else:
        print("Context:")
        print(f"{result.before_context.exposure.value}, {result.before_context.criticality.value}")
    print()
    print("Score:")
    print(f"{result.before_breakdown.total_score:.0f}")
    print()
    print("Priority:")
    print(result.before_breakdown.priority_level.value)
    print()
    print("CHANGE")
    for change in result.changes:
        print(change.before_value)
        print("->")
        print(change.after_value)
    print()
    print("AFTER")
    print("Score:")
    print(f"{result.after_breakdown.total_score:.0f}")
    print()
    print("Priority:")
    print(result.after_breakdown.priority_level.value)
    print()
    print("WHY")
    for exp in result.why_explanation:
        print(exp)
    print()


def run_live_scenario(simulator: CyberRiskSimulator, interactive: bool = True):
    def step_prompt(prompt_text: str):
        if interactive:
            print(f"\n{prompt_text}", end="")
            sys.stdout.flush()
            try:
                input()
            except EOFError:
                pass
            print()
        else:
            print(f"\n[{prompt_text}]")

    print("=" * 44)
    print("LIVE ANALYST SIMULATION")
    print("=" * 23)
    print()
    print("Scenario:")
    print("A vulnerability has been discovered.")
    print()
    print("CVSS:")
    print("8.4")
    print()
    print("KEV:")
    print("YES")
    print()
    print("EPSS:")
    print("0.91")
    print()
    print("Affected service:")
    print("Customer Payment Portal")
    print()
    print("Exposure:")
    print("Internet-facing")
    print()
    print("Criticality:")
    print("Critical")
    print()

    step_prompt("Press ENTER to analyse...")

    print("---")
    print()
    print("ANALYST ASSESSMENT")
    print()
    print("Technical severity:")
    print("HIGH")
    print()
    print("Threat:")
    print("HIGH")
    print()
    print("Exposure:")
    print("HIGH")
    print()
    print("Business impact:")
    print("CRITICAL")
    print()
    print("---")
    print()
    print("PRIORITY:")
    print("URGENT")
    print()

    step_prompt("Press ENTER to change exposure...")

    print("Exposure:")
    print("Internet-facing")
    print("->")
    print("Internal")
    print()
    print("Recalculating...")
    print()
    print("PRIORITY:")
    print("HIGH")
    print()

    step_prompt("Press ENTER to change asset criticality...")

    print("Critical")
    print("->")
    print("Normal")
    print()
    print("Recalculating...")
    print()
    print("PRIORITY:")
    print("MEDIUM")
    print()
    print("---")
    print()
    print("CONCLUSION")
    print()
    print('"Severity remained 8.4.')
    print()
    print("The vulnerability's technical severity did not change.")
    print()
    print('The organisational priority changed because the context changed."')
    print()
    print("This manual reasoning is what VulnLens automates.")
    print()


def parse_args():
    parser = argparse.ArgumentParser(
        prog="python -m nexorapay.demo",
        description="NexoraPay Cyber Risk Simulator — Contextual Vulnerability Prioritisation Engine.",
    )
    parser.add_argument("--cve", type=str, default=None, help="Target vulnerability ID (e.g. NXP-DEMO-002)")
    parser.add_argument("--exposure", type=str, choices=["internet", "internal", "internet-facing"], help="Simulate asset network exposure")
    parser.add_argument("--criticality", type=str, choices=["critical", "high", "normal", "low"], help="Simulate asset criticality")
    parser.add_argument("--kev", type=str, choices=["yes", "no", "true", "false"], help="Simulate CISA KEV status")
    parser.add_argument("--epss", type=float, help="Simulate EPSS probability (0.0 to 1.0)")
    parser.add_argument("--profile", type=str, choices=["low", "medium", "high"], help="Organisation risk appetite profile")
    parser.add_argument("--scenario", type=str, choices=["live"], help="Run live interactive hackathon scenario")
    parser.add_argument("--table", action="store_true", help="Display complete scenario prioritisation table")
    parser.add_argument("--fingerprint", action="store_true", help="Display organisation threat fingerprint")
    parser.add_argument("--web", action="store_true", help="Launch local offline web console")
    parser.add_argument("--non-interactive", action="store_true", help="Run live scenario without pausing for input")
    return parser.parse_args()


def main():
    args = parse_args()
    simulator = CyberRiskSimulator()

    if args.web:
        from nexorapay.web import launch_server
        launch_server()
        return

    if args.fingerprint:
        appetite = RiskAppetite.from_str(args.profile) if args.profile else RiskAppetite.LOW
        print_fingerprint(simulator, appetite=appetite)
        return

    if args.scenario == "live":
        is_interactive = sys.stdin.isatty() and not args.non_interactive
        run_live_scenario(simulator, interactive=is_interactive)
        return

    # Check if any What-If parameter is provided
    has_what_if = (
        args.exposure is not None
        or args.criticality is not None
        or args.kev is not None
        or args.epss is not None
        or (args.profile is not None and args.cve is not None)
    )

    if has_what_if:
        target_cve = args.cve or "NXP-DEMO-002"
        exp = Exposure.from_str(args.exposure) if args.exposure else None
        crit = Criticality.from_str(args.criticality) if args.criticality else None
        kev = (args.kev.lower() in ("yes", "true")) if args.kev else None
        epss = args.epss if args.epss is not None else None
        profile = RiskAppetite.from_str(args.profile) if args.profile else None

        result = simulator.run_what_if(
            vuln_id=target_cve,
            exposure=exp,
            criticality=crit,
            kev=kev,
            epss=epss,
            risk_appetite=profile,
        )
        print_what_if_output(result)
        return

    if args.profile and not args.cve:
        appetite = RiskAppetite.from_str(args.profile)
        print_table(simulator, appetite=appetite)
        return

    if args.table:
        print_table(simulator)
        return

    # Default overview
    target_cve = args.cve or "NXP-DEMO-002"
    print_default_demo(simulator, cve_id=target_cve)


if __name__ == "__main__":
    main()
