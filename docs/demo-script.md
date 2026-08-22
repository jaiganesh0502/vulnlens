# 🎤 NexoraPay Cyber Risk Simulator — Hackathon Demo Script

> **Opening Act Presentation Guide (3–5 Minutes)**  
> **Key Thesis:** *"CVSS tells me how severe the vulnerability is. It does not, by itself, tell me what my organisation should fix first."*

---

## ⏱️ Timeline & Presentation Flow

```
[00:00 - 00:45] Act 1: The Problem — The CVSS Fallacy & Alert Fatigue
[00:45 - 01:45] Act 2: Live Demonstration — Meet NexoraPay & The Scenario Table
[01:45 - 03:00] Act 3: The "What If?" Live Simulation & Context Shift
[03:00 - 03:45] Act 4: The 3 Defensive Questions (CVSS vs KEV vs EPSS)
[03:45 - 04:30] Act 5: The Bridge & Transition into VulnLens
```

---

## 🎬 Step-by-Step Presenter Script

### Act 1: The Problem — The CVSS Fallacy (0:00 - 0:45)
**Presenter Action:** Stand in front of judges, terminal or web console ready on screen.

**Speaker:**
> "Judges, every security team in the world faces the exact same crisis: **alert fatigue**.  
> Every week, hundreds of CVEs are published. Standard practice in too many companies is simply to sort vulnerabilities by CVSS score from 10.0 down to 0.0.  
> 
> But here is the fatal flaw: **CVSS only measures intrinsic technical severity in a laboratory setting.**  
> It does *not* know where that product lives in your network, whether attackers are weaponizing it right now, or if it touches customer money.  
> 
> To prove this, let's open the **NexoraPay Cyber Risk Simulator**."

---

### Act 2: Live Demonstration — The Scenario Table (0:45 - 1:45)

**Presenter Action (Terminal or Web Console):**
Run the terminal command:
```bash
python -m nexorapay.demo --table
```
*(Or show Tab 1 on the Web Console via `python -m nexorapay.web`)*

**Speaker:**
> "NexoraPay is a fictional regional digital payments company. They run 6 core services: 3 internet-facing payment gateways and identity providers, and 3 internal intranet servers.  
> 
> Look closely at this table:  
> - **NXP-DEMO-001** is a **CVSS 9.8 Critical** vulnerability. In a naive security team, this triggers immediate panic. But it is on an internal reporting server, with no active in-the-wild exploits and low exploitation probability. Operational Priority: **LOW**.  
> - **NXP-DEMO-002** is a **CVSS 8.4 High** vulnerability. But it has **CISA KEV = YES** (active in-the-wild attacks), **EPSS = 0.91** (91% exploitation probability), and sits directly on the internet-facing **Customer Payment Portal**. Operational Priority: **URGENT**!  
> 
> The 8.4 outranks the 9.8. Context flipped the operational priority."

---

### Act 3: The "What If?" Interactive Simulation (1:45 - 3:00)

**Presenter Action:**
Run the interactive live analyst scenario:
```bash
python -m nexorapay.demo --scenario live
```
*(Or use the interactive **[ WHAT IF? ]** tab in the Web Console)*

**Speaker:**
> *(Press ENTER on prompt 1)*  
> "We discover NXP-DEMO-002 on the Customer Payment Portal.  
> Technical CVSS is 8.4. KEV is YES. EPSS is 0.91.  
> It is internet-facing and critical. Operational Priority: **URGENT**."  
> 
> *(Press ENTER on prompt 2)*  
> "Now watch what happens when we ask: **'What if this asset was moved behind internal firewall segmentation?'**  
> We change exposure: `Internet-facing ➔ Internal`.  
> Recalculating... Operational Priority drops to **HIGH**."  
> 
> *(Press ENTER on prompt 3)*  
> "Now, **'What if this was an internal non-critical test server instead of our crown-jewel payment portal?'**  
> We change asset criticality: `Critical ➔ Normal`.  
> Recalculating... Operational Priority drops to **MEDIUM**."  
> 
> *(Pause for dramatic impact)*  
> "**Notice: CVSS remained 8.4.**  
> The technical severity of the vulnerability did not change by a single decimal point.  
> The organisational priority changed because the **context** changed."

---

### Act 4: Grounding — Why These Signals Exist (3:00 - 3:45)

**Presenter Action:**
Open Tab 4 (**Why Signals Exist**) or show the educational overview:

**Speaker:**
> "To do this right, security teams must answer three distinct questions with three distinct tools:  
> 1. **CVSS:** *'How severe is the flaw technically?'* (Intrinsic lab physics)  
> 2. **CISA KEV:** *'Is there active proof adversaries are exploiting it in the real world?'* (Current threat)  
> 3. **EPSS:** *'What is the probability of exploitation over the next 30 days?'* (Predictive threat)  
> 4. **Asset Context:** *'Can it reach our crown jewels?'* (Business impact)  
> 
> We saw this in real life during **Log4Shell (CVE-2021-44228)**: every enterprise had thousands of instances, but defenders who survived triaged their external perimeter and payment gateways first."

---

### Act 5: The Bridge to VulnLens (3:45 - 4:30)

**Presenter Action:**
Navigate to the final tab / run transition:
Click **[ INTRODUCE VULNLENS ]**.

**Speaker:**
> "We just reasoned through this manually for one scenario.  
> 
> But a real enterprise has **tens of thousands of assets** and receives **hundreds of newly disclosed CVEs every single week**.  
> Human analysts cannot manually cross-reference CVSS, CISA KEV, EPSS feeds, network exposure maps, and asset inventories in their heads for 500 alerts a day.  
> 
> **That is the exact problem VulnLens solves.**  
> 
> VulnLens automates this entire multi-signal reasoning pipeline—matching your organization's exact inventory, computing deterministic contextual priorities, and producing plain-language defensive action cards in milliseconds.  
> 
> Let's look at **VulnLens**."

---

## 💻 CLI Quick-Reference Sheet for Presenters

| Demonstration Goal | Command Line |
| :--- | :--- |
| **Full Interactive Hackathon Walkthrough** | `python -m nexorapay.demo --scenario live` |
| **Standard Baseline Summary** | `python -m nexorapay.demo` |
| **All Scenarios Prioritisation Table** | `python -m nexorapay.demo --table` |
| **What-If: Change Exposure to Internal** | `python -m nexorapay.demo --exposure internal` |
| **What-If: Change Asset Criticality** | `python -m nexorapay.demo --criticality normal` |
| **What-If: Threat Signal Removed (KEV NO)**| `python -m nexorapay.demo --kev no` |
| **What-If: Low EPSS Probability** | `python -m nexorapay.demo --epss 0.10` |
| **What-If: High Risk Appetite Profile** | `python -m nexorapay.demo --profile high` |
| **Launch Offline Web Console GUI** | `python -m nexorapay.demo --web` |
