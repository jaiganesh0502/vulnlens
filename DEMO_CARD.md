# VulnLens - Personalised Vulnerability Triage
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

**Direct APK Download:** [https://github.com/vulnlens/demo/releases/download/v1.0.0/VulnLens-Demo.apk](https://github.com/vulnlens/demo/releases/download/v1.0.0/VulnLens-Demo.apk)

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
