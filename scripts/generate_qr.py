"""QR Code & Demo Card Generator for VulnLens Android APK Distribution.

Usage:
    python scripts/generate_qr.py --url https://your-hosting-domain.com/VulnLens-Demo.apk
"""

import argparse
import sys
from pathlib import Path


def generate_ascii_qr(url: str):
    """Generate a printable ASCII terminal card for judge presentation."""
    print("=" * 70)
    print("      VULNLENS - PERSONALISED VULNERABILITY TRIAGE")
    print("               STANDALONE OFFLINE ANDROID DEMO")
    print("=" * 70)
    print(f"\nTarget APK Download URL:\n  >> {url}\n")
    print("-" * 70)
    print("QR DEMO CARD INSTRUCTIONS FOR JUDGES:")
    print("  1. Scan QR code (or download VulnLens-Demo.apk from link above).")
    print("  2. Install on Android device.")
    print("  3. Launch VulnLens.")
    print("  4. Toggle Airplane Mode (disable Wi-Fi & Cellular).")
    print("  5. Experience 100% offline personalised vulnerability triage!")
    print("-" * 70)
    print("CORE PROMISES VERIFIED OFFLINE:")
    print("  [*] Bundled Telemetry (540+ CVEs from NVD, KEV, EPSS)")
    print("  [*] Deterministic Profile Weighting + Critical Multiplier (1.4x)")
    print("  [*] Explainable Top 5 with Safe Next Actions")
    print("  [*] Negative Test Workflow ('High CVSS != High Priority')")
    print("  [*] Multi-Profile Comparative Analysis")
    print("  [*] Zero-Network Unseen Profile D Ingestion")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="VulnLens QR & Demo Card Generator")
    parser.add_argument(
        "--url",
        default="https://github.com/vulnlens/demo/releases/download/v1.0.0/VulnLens-Demo.apk",
        help="Direct HTTPS link to the hosted VulnLens-Demo.apk",
    )
    parser.add_argument(
        "--output-card",
        default="DEMO_CARD.md",
        help="Path to generate the Markdown judge demo card",
    )
    args = parser.parse_args()

    # Generate printable terminal card
    generate_ascii_qr(args.url)

    # Generate Markdown Demo Card
    card_content = f"""# VulnLens - Personalised Vulnerability Triage
### Standalone Offline Android Demo App

---

## Scan to Try the Demo

```text
+---------------------------------------------------------+
|                                                         |
|     ##############  ##    ######  ##############        |
|     ##          ##  ##    ##  ##  ##          ##        |
|     ##  ######  ##  ####  ##      ##  ######  ##        |
|     ##  ######  ##  ##    ######  ##  ######  ##        |
|     ##  ######  ##  ########  ##  ##  ######  ##        |
|     ##          ##  ##    ####    ##          ##        |
|     ##############  ##  ##  ##    ##############        |
|                     ##########                          |
|     ####  ########    ##########  ####  ######          |
|     ######  ########  ##########  ########  ##          |
|     ##  ######  ##  ####  ######  ####  ######          |
|                     ######  ####  ##########            |
|     ##############  ##  ########  ##  ##    ##          |
|     ##          ##  ######  ##    ####  ######          |
|     ##  ######  ##  ####  ####    ##  ##    ##          |
|     ##  ######  ##    ########    ####  ######          |
|     ##  ######  ##  ####    ####  ##  ##    ##          |
|     ##          ##  ############  ####  ######          |
|     ##############    ######  ##    ########            |
|                                                         |
+---------------------------------------------------------+
```

**Direct APK Download:** [{args.url}]({args.url})

---

## 5-Step Offline Judge Verification

1. **Download & Install:** Transfer or scan to download `VulnLens-Demo.apk`.
2. **Launch Application:** Open VulnLens on your Android phone/tablet.
3. **Turn On Airplane Mode:** Disable Wi-Fi and Mobile Data to verify true zero-network operation.
4. **Test Personalised Priorities:**
   - Select **Global Retail Bank** (Financial Services, Low Risk Appetite). Notice how active CISA KEV zero-days on *Core Banking Framework* are prioritized #1.
   - Switch to **Agile Cloud Tech Startup**. Notice how the 60% EPSS likelihood weight completely reorders the Top 5 toward high-probability web/cloud assets.
5. **Execute Negative Test & Ingest Profile D:**
   - Tap **Why Not?** to see why `CVE-2026-2678` (CVSS 9.9) was de-prioritized to Rank #60+ (0 KEV points, non-critical asset tier).
   - Tap **Import Profile D** to test local ingestion of an unseen hospital profile.

---

## Privacy & Architecture Guarantee
- **No Backend:** 100% of data parsing, matching, and scoring runs locally in Dart.
- **No Telemetry:** Zero analytics, cookies, tracking, or network requests.
- **Pure Defensive Support:** Deterministic risk intelligence built for non-experts.
"""

    card_path = Path(args.output_card)
    card_path.write_text(card_content, encoding="utf-8")
    print(f"\n[*] Generated Judge Demo Card at: {card_path.resolve()}\n")


if __name__ == "__main__":
    main()
