# 🛡️ VulnLens — Contextual Priority Engine

> **"CVSS tells us how technically severe a vulnerability is. VulnLens determines how important that vulnerability is to THIS organisation — and explains why."**

VulnLens is an offline, deterministic, explainable vulnerability triage engine. Instead of dumping a generic catalog of thousands of CVEs sorted solely by theoretical severity, VulnLens computes an organization-specific **Contextual Priority** combining **Technical Threat Signals** with the organization's **Operational Asset Context**.

---

## ⚠️ Prototype Design Statement & Methodology Scope

> **Important Disclosure:**
> 1. **The VulnLens Priority Score is a deterministic prototype prioritisation score, not a probability and not an industry-standard risk score.**
> 2. **The weights and context multipliers are transparent design choices for this hackathon prototype.**
> 3. VulnLens operates **100% offline** without calling live external APIs or scraping external commercial feeds.

---

## 🏛️ Contextual Priority Engine Architecture

```text
                    VULNERABILITY DATA
                           |
                           v
                      MATCHING
                           |
              +------------+------------+
              |                         |
              v                         v
      TECHNICAL THREAT            ORGANISATION
           SCORE                  FINGERPRINT
              |                         |
       CVSS / KEV / EPSS         Exposure
                                 Importance
                                 Profile weights
              |                         |
              +------------+------------+
                           |
                           v
                  CONTEXTUAL PRIORITY
                           |
              +------------+-------------+
              |                          |
              v                          v
       CONTEXT DELTA              CONFIDENCE
              |
              v
      FINAL PRIORITY SCORE
              |
              v
        DECISION MARGIN
              |
              v
             TOP 5
              |
      +-------+-------+
      |       |       |
      v       v       v
     WHY    WHAT-IF  WHY NOT
              |
              v
       NEXT ACTION
```

---

## 🧮 Exact Mathematical Scoring Formulas

### 1. Technical Threat Score
Measures intrinsic threat based on normalized signals and the organization's profile weights:
$$\text{CVSS}_{\text{NORM}} = \frac{\text{CVSS}}{10.0}$$
$$\text{KEV}_{\text{SIGNAL}} = \begin{cases} 1.0 & \text{if in CISA KEV} \\ 0.0 & \text{otherwise} \end{cases}$$
$$\text{EPSS}_{\text{SIGNAL}} = \text{FIRST EPSS Score} \quad (0.0 - 1.0)$$
$$\text{THREAT}_{\text{NORM}} = (\text{CVSS}_{\text{NORM}} \times w_{\text{CVSS}}) + (\text{KEV}_{\text{SIGNAL}} \times w_{\text{KEV}}) + (\text{EPSS}_{\text{SIGNAL}} \times w_{\text{EPSS}})$$
$$\mathbf{TECHNICAL\_THREAT\_SCORE} = \text{THREAT}_{\text{NORM}} \times 100.0$$

### 2. Organisation Context Multipliers
$$\text{Exposure Multiplier} = \begin{cases} 1.20 & \text{if Internet-Facing} \\ 1.00 & \text{if Internal} \end{cases}$$
$$\text{Importance Multiplier} = \begin{cases} 1.20 & \text{if Critical Crown Jewel} \\ 1.10 & \text{if High Importance} \\ 1.00 & \text{if Normal Infrastructure} \end{cases}$$
$$\mathbf{CONTEXT\_MULTIPLIER} = \text{Exposure Multiplier} \times \text{Importance Multiplier}$$

*(Example: Internet-Facing + Critical Crown Jewel $= 1.20 \times 1.20 = 1.44$)*

### 3. Final VulnLens Priority Score
$$\mathbf{FINAL\_PRIORITY\_SCORE} = \text{TECHNICAL\_THREAT\_SCORE} \times \text{CONTEXT\_MULTIPLIER}$$

### 4. Organisation Context Delta
Explains how much organizational context shifted the technical threat baseline:
$$\mathbf{CONTEXT\_DELTA} = \text{FINAL\_PRIORITY\_SCORE} - \text{TECHNICAL\_THREAT\_SCORE}$$

### 5. Decision Margin
Explains why item $\#i$ ranked above item $\#(i+1)$:
$$\mathbf{DECISION\_MARGIN} = \text{SCORE}_i - \text{SCORE}_{i+1}$$

---

## 🔍 Organisation Fingerprint

The Organisation Fingerprint visualizes the organization's threat signal philosophy derived deterministically from their risk profile:

```text
============================================================
GLOBAL RETAIL BANK
ORGANISATION FINGERPRINT
============================================================

THREAT SIGNAL WEIGHTS

CVSS
████░░░░░░░░ 30%

KEV
█████░░░░░░░ 45%

EPSS
███░░░░░░░░░ 25%

CONTEXT

Exposure:
HIGH IMPACT (1.20x)

Criticality:
HIGH IMPACT (1.20x)

PRIORITY PHILOSOPHY:

Strong emphasis on known exploitation and active in-the-wild threat signals.

============================================================
```

---

## 💻 CLI Commands & Usage

### 1. Priority Ranking Table
```bash
python -m src.cli --table
```
```text
============================================================
VULNLENS PRIORITY RANKING
============================================================
Target: Global Retail Bank (ORG-001) | Sector: Financial Services

#   CVE              THREAT   CONTEXT   DELTA    PRIORITY    
------------------------------------------------------------
1   CVE-2023-1262    88.1     ×1.44     +38.8    126.9  🔴
2   CVE-2025-1728    85.4     ×1.44     +37.6    122.9  🔴
3   CVE-2023-8330    84.2     ×1.44     +37.1    121.3  🔴
4   CVE-2024-1699    80.7     ×1.44     +35.5    116.3  🔴
5   CVE-2025-7287    79.7     ×1.44     +35.1    114.8  🔴
============================================================
```

### 2. Organisation Fingerprint
```bash
python -m src.cli --fingerprint
python -m nexorapay.demo --fingerprint
```

### 3. Live Interactive Demo
```bash
python -m src.cli --scenario live
python -m nexorapay.demo --scenario live
```

### 4. Contextual What-If Simulations
```bash
python -m nexorapay.demo --cve NXP-DEMO-002 --exposure internal
```

---

## 📱 Mobile APK & Offline Guarantee

The Android mobile app bundles the dataset locally. In Airplane Mode:
- Ingests and normalizes all CVEs in RAM
- Evaluates personalizations for Bank (`ORG-001`), Startup (`ORG-002`), and Utility (`ORG-003`)
- Executes "Why Not?" negative test (CVSS 9.9 de-prioritized to Rank #60+ due to zero active exploitation)
- Ingests unseen Profile D (`ORG-004`) dynamically

---

## 🧪 Automated Test Suite

- **Python Pytest Suite:** `pytest -v` (**54/54 passed in 0.28s**)
- **Flutter / Dart Test Suite:** `flutter test` (**9/9 passed**)
