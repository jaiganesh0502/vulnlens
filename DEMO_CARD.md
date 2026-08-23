# 🛡️ VulnLens — Personalised Vulnerability Triage
### Standalone Offline Android Demo App

---

## 📸 Scan with Mobile Camera to Download APK

Scan the QR code below with your phone camera. It links directly to the `VulnLens-Demo.apk` build:

![VulnLens QR Download](assets/images/qr_download.png)

> **Direct Download Link in QR:**  
> [`https://github.com/jaiganesh0502/vulnlens/releases/latest/download/VulnLens-Demo.apk`](https://github.com/jaiganesh0502/vulnlens/releases/latest/download/VulnLens-Demo.apk)

---

## ✈️ 5-Step Offline Judge Verification

1. **Scan QR Code:** Open your phone camera, scan the code above, and download `VulnLens-Demo.apk`.
2. **Install Application:** Open the downloaded APK on your Android phone or tablet.
3. **Turn On Airplane Mode:** Disable Wi-Fi and Mobile Data to verify true zero-network operation.
4. **Test Personalised Priorities:**
   - Select **Global Retail Bank** (Financial Services, Low Risk Appetite). Notice how active CISA KEV zero-days on *Core Banking Framework* are prioritized #1.
   - Switch to **Agile Cloud Tech Startup**. Notice how the 60% EPSS likelihood weight completely reorders the Top 5 toward high-probability web/cloud assets.
5. **Execute Negative Test & Ingest Profile D:**
   - Tap **Why Not?** to see why `CVE-2026-2678` (CVSS 9.9) was de-prioritized to Rank #60+ (0 KEV points, non-critical asset tier).
   - Tap **Import Profile D** to test local ingestion of an unseen hospital profile.

---

## 🔒 Privacy & Architecture Guarantee
- **No Backend:** 100% of data parsing, matching, and scoring runs locally on the device in Dart.
- **No Telemetry:** Zero analytics, cookies, tracking, or network requests.
- **Pure Defensive Support:** Deterministic risk intelligence built for non-experts.
