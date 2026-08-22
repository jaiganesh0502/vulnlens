"""Command-Line Interface for VulnLens Contextual Priority Engine."""

import argparse
import sys
from pathlib import Path

from src.loader import load_profiles, load_vulnerabilities
from src.models import OrganizationProfile, PriorityLevel
from src.ranking import rank_all_vulnerabilities, rank_vulnerabilities
from src.scorer import calculate_score, determine_priority_level

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def print_table(profile: OrganizationProfile, top_n: int = 5):
    vulns = load_vulnerabilities(Path("data/vulnerabilities.csv"))
    ranked = rank_vulnerabilities(vulns, profile, top_n=top_n)

    print("============================================================")
    print("VULNLENS PRIORITY RANKING")
    print("============================================================")
    print(f"Target: {profile.name} ({profile.org_id}) | Sector: {profile.sector}")
    print()
    print(f"{'#':<3} {'CVE':<16} {'THREAT':<8} {'CONTEXT':<9} {'DELTA':<8} {'PRIORITY':<12}")
    print("-" * 60)

    for r in ranked:
        b = r.score_breakdown
        sym = (
            "🔴" if r.priority == PriorityLevel.URGENT
            else ("🟠" if r.priority == PriorityLevel.HIGH
                  else ("🟡" if r.priority == PriorityLevel.MEDIUM else "🟢"))
        )
        delta_str = f"+{b.context_delta:.1f}" if b.context_delta > 0 else f"{b.context_delta:.1f}"
        print(
            f"{r.rank:<3} {r.vulnerability.cve_id:<16} {b.technical_threat_score:<8.1f} "
            f"×{b.context_multiplier:<8.2f} {delta_str:<8} {b.final_priority_score:<6.1f} {sym}"
        )
    print("============================================================")


def print_fingerprint(profile: OrganizationProfile):
    fp = profile.get_fingerprint()
    print(fp.to_ascii_display())


def run_live_scenario(profile: OrganizationProfile, interactive: bool = True):
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

    vulns = load_vulnerabilities(Path("data/vulnerabilities.csv"))
    ranked = rank_vulnerabilities(vulns, profile, top_n=5)
    first = ranked[0]
    second = ranked[1]
    b1 = first.score_breakdown
    b2 = second.score_breakdown

    print("============================================================")
    print("VULNLENS LIVE ANALYST DEMONSTRATION")
    print("============================================================")
    print()
    print("STEP 1: ORGANISATION FINGERPRINT")
    print_fingerprint(profile)

    step_prompt("Press ENTER to view Top Priority Candidate...")

    print("STEP 2 & 3: SELECTED VULNERABILITY & TECHNICAL THREAT")
    print(f"CVE ID:            {first.vulnerability.cve_id}")
    print(f"Product:           {first.vulnerability.product_name}")
    print(f"CVSS:              {first.vulnerability.cvss_base_score} (Normalised: {b1.cvss_normalized:.2f})")
    print(f"KEV:               {'YES' if first.vulnerability.cisa_kev else 'NO'}")
    print(f"EPSS:              {first.vulnerability.first_epss:.2%}")
    print(f"TECHNICAL THREAT:  {b1.technical_threat_score:.1f} / 100")
    print()

    step_prompt("Press ENTER to apply Organisation Context...")

    print("STEP 4 & 5: ORGANISATIONAL CONTEXT & CONTEXT DELTA")
    print(f"Exposure:          Internet-facing (×{b1.exposure_multiplier:.2f})")
    print(f"Importance:        Critical Crown Jewel (×{b1.importance_multiplier:.2f})")
    print(f"Context Multiplier:×{b1.context_multiplier:.2f}")
    print(f"Context Delta:     +{b1.context_delta:.2f} pts")
    print(f"FINAL PRIORITY:    {b1.final_priority_score:.2f} [{first.priority.value}]")
    print()

    step_prompt("Press ENTER to run 'What-If' Simulation (Change Exposure)...")

    print("STEP 8: WHAT-IF SIMULATION (Exposure: Internet-facing → Internal)")
    sim_exp_score = b1.technical_threat_score * 1.00 * b1.importance_multiplier
    print("Technical Threat:  UNCHANGED (91.5)")
    print(f"Recalculated Score:{sim_exp_score:.2f} [{determine_priority_level(sim_exp_score).value}]")
    print("Organisational Priority: CHANGED")
    print()

    step_prompt("Press ENTER to view Decision Margin between #1 and #2...")

    print("STEP 10: DECISION MARGIN (WHY #1?)")
    print(f"#1: {first.vulnerability.cve_id} ({first.vulnerability.product_name}) -> Score: {b1.final_priority_score:.2f}")
    print(f"#2: {second.vulnerability.cve_id} ({second.vulnerability.product_name}) -> Score: {b2.final_priority_score:.2f}")
    margin = b1.final_priority_score - b2.final_priority_score
    print(f"DECISION MARGIN:   +{margin:.2f} pts")
    print()

    print("STEP 11: WHAT WOULD MAKE #2 #1?")
    print("Counterfactual Context Tests for #2:")
    for cf in second.what_would_change_decision:
        print(f"  • {cf['factor']} ({cf['multiplier']}) -> Projected Score: {cf['projected_priority_score']:.1f} [{cf['projected_priority']}]")
    print()
    print("============================================================")


def main():
    parser = argparse.ArgumentParser(
        prog="python -m src.cli",
        description="VulnLens — Contextual Vulnerability Priority Engine CLI",
    )
    parser.add_argument("--table", action="store_true", help="Display prioritized vulnerability table")
    parser.add_argument("--fingerprint", action="store_true", help="Display organisation fingerprint")
    parser.add_argument("--scenario", choices=["live"], help="Run interactive live demo")
    parser.add_argument("--profile", type=str, default="ORG-001", help="Organisation profile ID (ORG-001, ORG-002, ORG-003)")
    parser.add_argument("--non-interactive", action="store_true", help="Run scenario without pausing")
    args = parser.parse_args()

    profiles = load_profiles(Path("data/profiles.json"))
    profile = next((p for p in profiles if p.org_id.upper() == args.profile.upper()), profiles[0])

    if args.fingerprint:
        print_fingerprint(profile)
        return

    if args.scenario == "live":
        is_interactive = sys.stdin.isatty() and not args.non_interactive
        run_live_scenario(profile, interactive=is_interactive)
        return

    # Default table output
    print_table(profile)


if __name__ == "__main__":
    main()
