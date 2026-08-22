/**
 * NexoraPay Cyber Risk Simulator — Client-side interactive engine.
 * Supports online API calls and zero-server local client-side deterministic fallback.
 */

// Bundled synthetic data for offline/standalone execution
const FALLBACK_DATA = {
  organisation: {
    name: "NexoraPay",
    industry: "Financial Services / Digital Payments",
    size: "Regional organisation",
    risk_appetite: "Low",
    critical_services_count: 3,
    internet_facing_count: 3,
    internal_count: 3,
    assets: [
      { asset_id: "AST-PAY-01", name: "Customer Payment Portal", exposure: "Internet-facing", criticality: "Critical", business_role: "Customer payment transactions", icon: "credit-card", tier: "Internet-Facing Tier" },
      { asset_id: "AST-IDP-01", name: "Identity Provider", exposure: "Internet-facing", criticality: "Critical", business_role: "Authentication and access", icon: "shield-check", tier: "Internet-Facing Tier" },
      { asset_id: "AST-API-01", name: "Transaction API", exposure: "Internet-facing", criticality: "Critical", business_role: "Payment transaction processing", icon: "cpu", tier: "Internet-Facing Tier" },
      { asset_id: "AST-FIL-01", name: "Employee File Server", exposure: "Internal", criticality: "High", business_role: "Internal documents", icon: "folder", tier: "Internal Network" },
      { asset_id: "AST-REP-01", name: "Internal Reporting Server", exposure: "Internal", criticality: "Normal", business_role: "Reporting and analytics", icon: "bar-chart-2", tier: "Internal Network" },
      { asset_id: "AST-DEV-01", name: "Development Server", exposure: "Internal", criticality: "Normal", business_role: "Application development", icon: "terminal", tier: "Internal Network" }
    ]
  },
  scenarios: [
    {
      scenario: {
        vuln_id: "NXP-DEMO-001",
        product: "Payment Gateway Framework",
        cvss: 9.8,
        cvss_severity: "CRITICAL",
        kev: false,
        epss: 0.21,
        affected_asset_name: "Internal Reporting Server",
        exposure: "Internal",
        criticality: "Normal",
        business_importance: "Reporting & Analytics",
        explanation: "High technical severity (CVSS 9.8), but resides on an internal reporting server with no known active exploitation in the wild."
      }
    },
    {
      scenario: {
        vuln_id: "NXP-DEMO-002",
        product: "Payment Gateway Framework",
        cvss: 8.4,
        cvss_severity: "HIGH",
        kev: true,
        epss: 0.91,
        affected_asset_name: "Customer Payment Portal",
        exposure: "Internet-facing",
        criticality: "Critical",
        business_importance: "Mission-critical (Direct Customer Payments)",
        explanation: "Confirmed in-the-wild exploitation (CISA KEV) combined with extreme exploitation probability (EPSS 0.91) on an internet-facing crown jewel asset elevates operational priority to URGENT."
      }
    },
    {
      scenario: {
        vuln_id: "NXP-DEMO-003",
        product: "Identity Component",
        cvss: 8.1,
        cvss_severity: "HIGH",
        kev: true,
        epss: 0.78,
        affected_asset_name: "Identity Provider",
        exposure: "Internet-facing",
        criticality: "Critical",
        business_importance: "Mission-critical (Authentication & SSO)",
        explanation: "Active exploitation signal on an external authentication core with high EPSS (0.78), requiring immediate operational remediation."
      }
    },
    {
      scenario: {
        vuln_id: "NXP-DEMO-004",
        product: "Internal Analytics Platform",
        cvss: 7.2,
        cvss_severity: "HIGH",
        kev: false,
        epss: 0.08,
        affected_asset_name: "Internal Reporting Server",
        exposure: "Internal",
        criticality: "Normal",
        business_importance: "Internal Analytics",
        explanation: "High theoretical CVSS, but internal segmentation and negligible exploitation probability (EPSS 0.08) yield moderate organizational risk."
      }
    },
    {
      scenario: {
        vuln_id: "NXP-DEMO-005",
        product: "Employee File Platform",
        cvss: 9.1,
        cvss_severity: "CRITICAL",
        kev: false,
        epss: 0.04,
        affected_asset_name: "Employee File Server",
        exposure: "Internal",
        criticality: "High",
        business_importance: "Internal Documents Repository",
        explanation: "Critical technical CVSS (9.1) on an internal server containing sensitive files; warrants high attention but is tempered by lack of internet exposure and zero active KEV."
      }
    }
  ],
  educational_signals: [
    {
      signal: "CVSS",
      title: "Common Vulnerability Scoring System",
      question: "How severe is the vulnerability technically?",
      description: "CVSS measures intrinsic flaw severity under standardized laboratory conditions. It evaluates attack vector, complexity, privileges required, and impact on CIA triad. It does NOT know if the product is in your network, internet-facing, or actively exploited.",
      source: "FIRST / NIST NVD"
    },
    {
      signal: "CISA KEV",
      title: "Known Exploited Vulnerabilities",
      question: "Is there evidence this vulnerability has already been exploited?",
      description: "The CISA KEV catalog identifies vulnerabilities with confirmed evidence of active exploitation in the wild. It is the strongest defensive signal that an adversary has operationalized an attack.",
      source: "Cybersecurity and Infrastructure Security Agency (CISA)"
    },
    {
      signal: "EPSS",
      title: "Exploit Prediction Scoring System",
      question: "How likely is exploitation?",
      description: "EPSS uses predictive machine learning to estimate the empirical probability (0% - 100%) that a vulnerability will be actively exploited in the wild within the next 30 days.",
      source: "FIRST EPSS SIG"
    }
  ],
  profiles: {
    "Low": {
      weights: { cvss: 0.30, kev: 0.35, epss: 0.20, exposure: 0.10, criticality: 0.05 },
      percentages: { cvss: "30%", kev: "35%", epss: "20%", exposure: "10%", criticality: "5%" }
    },
    "Medium": {
      weights: { cvss: 0.30, kev: 0.25, epss: 0.20, exposure: 0.15, criticality: 0.10 },
      percentages: { cvss: "30%", kev: "25%", epss: "20%", exposure: "15%", criticality: "10%" }
    },
    "High": {
      weights: { cvss: 0.40, kev: 0.20, epss: 0.15, exposure: 0.15, criticality: 0.10 },
      percentages: { cvss: "40%", kev: "20%", epss: "15%", exposure: "15%", criticality: "10%" }
    }
  }
};

// Client-side scoring math mirror
const SCORING_ENGINE = {
  exposureFactors: { "Internet-facing": 1.0, "Internal": 0.30 },
  criticalityFactors: { "Critical": 1.0, "High": 0.65, "Normal": 0.30, "Low": 0.10 },

  calculate: function(cvss, kev, epss, exposure, criticality, appetite = "Low") {
    const p = FALLBACK_DATA.profiles[appetite] || FALLBACK_DATA.profiles["Low"];
    const w = p.weights;

    const normCvss = Math.max(0, Math.min(10, parseFloat(cvss))) / 10.0;
    const normKev = (kev === true || kev === "true" || kev === "yes" || kev === "YES") ? 1.0 : 0.0;
    const normEpss = Math.max(0, Math.min(1, parseFloat(epss) || 0));
    const normExp = this.exposureFactors[exposure] || 0.30;
    const normCrit = this.criticalityFactors[criticality] || 0.30;

    const cvssContrib = 100.0 * w.cvss * normCvss;
    const kevContrib = 100.0 * w.kev * normKev;
    const epssContrib = 100.0 * w.epss * normEpss;
    const expContrib = 100.0 * w.exposure * normExp;
    const critContrib = 100.0 * w.criticality * normCrit;

    const total = cvssContrib + kevContrib + epssContrib + expContrib + critContrib;
    let priority = "LOW";
    let badgeColor = "#3fb950";

    if (total >= 80) {
      priority = "URGENT";
      badgeColor = "#f85149";
    } else if (total >= 60) {
      priority = "HIGH";
      badgeColor = "#f0883e";
    } else if (total >= 40) {
      priority = "MEDIUM";
      badgeColor = "#d29922";
    }

    return {
      cvss_contribution: cvssContrib,
      kev_contribution: kevContrib,
      epss_contribution: epssContrib,
      exposure_contribution: expContrib,
      criticality_contribution: critContrib,
      total_score: total,
      priority_level: priority,
      badge_color: badgeColor
    };
  }
};

// Application State
const state = {
  activeTab: "dashboard-tab",
  activeAppetite: "Low",
  data: FALLBACK_DATA,
  selectedVulnId: "NXP-DEMO-002"
};

// Initialize App
document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initProfileSelector();
  initEduCards();
  initWhatIfWorkbench();
  initBridgeModal();
  loadData();
});

// Tab Switching
function initTabs() {
  const navBtns = document.querySelectorAll(".nav-btn");
  navBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetTab = btn.getAttribute("data-tab");
      switchTab(targetTab);
    });
  });
}

function switchTab(tabId) {
  state.activeTab = tabId;
  document.querySelectorAll(".nav-btn").forEach(b => {
    b.classList.toggle("active", b.getAttribute("data-tab") === tabId);
  });
  document.querySelectorAll(".tab-pane").forEach(pane => {
    pane.classList.toggle("active", pane.id === tabId);
  });
}

// Risk Appetite Selector
function initProfileSelector() {
  const sel = document.getElementById("appetite-select");
  if (sel) {
    sel.addEventListener("change", (e) => {
      state.activeAppetite = e.target.value;
      updateSnapshot();
      renderScenarioTable();
      if (state.selectedVulnId) {
        inspectVulnerability(state.selectedVulnId);
      }
      runWhatIfSimulation();
    });
  }
}

// Load data from API or use bundled fallback
async function loadData() {
  try {
    const res = await fetch(`/api/bootstrap?appetite=${state.activeAppetite}`);
    if (res.ok) {
      const data = await res.json();
      state.data = data;
    }
  } catch (err) {
    console.info("Using offline client-side dataset fallback.");
  }
  updateSnapshot();
  renderScenarioTable();
  inspectVulnerability("NXP-DEMO-002");
  runWhatIfSimulation();
}

function updateSnapshot() {
  const snapApp = document.getElementById("snapshot-appetite");
  const snapWeights = document.getElementById("snapshot-weights");
  if (snapApp) snapApp.textContent = state.activeAppetite.toUpperCase();
  if (snapWeights && state.data.profiles && state.data.profiles[state.activeAppetite]) {
    const pct = state.data.profiles[state.activeAppetite].percentages;
    snapWeights.textContent = `CVSS ${pct.cvss} | KEV ${pct.kev} | EPSS ${pct.epss} | Exposure ${pct.exposure} | Crit ${pct.criticality}`;
  }
}

// Render Scenario Prioritisation Table
function renderScenarioTable() {
  const tbody = document.getElementById("vuln-table-body");
  if (!tbody) return;
  tbody.innerHTML = "";

  // Calculate scores for all scenarios
  const rows = state.data.scenarios.map(item => {
    const s = item.scenario;
    const b = SCORING_ENGINE.calculate(s.cvss, s.kev, s.epss, s.exposure, s.criticality, state.activeAppetite);
    return { scenario: s, breakdown: b };
  });

  // Sort descending by total_score
  rows.sort((a, b) => b.breakdown.total_score - a.breakdown.total_score || b.scenario.cvss - a.scenario.cvss);

  rows.forEach(({ scenario, breakdown }) => {
    const tr = document.createElement("tr");
    if (scenario.vuln_id === state.selectedVulnId) {
      tr.classList.add("selected-row");
    }

    const kevBadge = scenario.kev 
      ? `<span class="badge-priority badge-URGENT">YES</span>` 
      : `<span class="badge-priority badge-LOW">NO</span>`;

    const exposureTag = scenario.exposure === "Internet-facing" 
      ? `<span class="badge-tag tag-ext">Internet-facing</span>` 
      : `<span class="badge-tag tag-int">Internal</span>`;

    const critTag = scenario.criticality === "Critical" 
      ? `<span class="badge-tag tag-crit">Critical</span>` 
      : (scenario.criticality === "High" ? `<span class="badge-tag tag-high">High</span>` : `<span class="badge-tag tag-norm">${scenario.criticality}</span>`);

    tr.innerHTML = `
      <td><strong>${scenario.vuln_id}</strong></td>
      <td>${scenario.product}</td>
      <td><span class="text-bold">${scenario.cvss.toFixed(1)}</span> <span class="badge-severity ${scenario.cvss >= 9 ? 'badge-crit' : 'badge-hi'}">${scenario.cvss_severity}</span></td>
      <td>${kevBadge}</td>
      <td><code>${scenario.epss.toFixed(2)}</code></td>
      <td>${exposureTag}</td>
      <td>${critTag}</td>
      <td><span class="badge-priority badge-${breakdown.priority_level}">${breakdown.priority_level}</span></td>
      <td>
        <button class="btn-secondary btn-sm inspect-btn" data-id="${scenario.vuln_id}">Inspect</button>
      </td>
    `;

    tr.querySelector(".inspect-btn").addEventListener("click", () => {
      inspectVulnerability(scenario.vuln_id);
    });

    tbody.appendChild(tr);
  });
}

// Inspect Selected Scenario
function inspectVulnerability(vulnId) {
  state.selectedVulnId = vulnId;
  const item = state.data.scenarios.find(s => s.scenario.vuln_id === vulnId);
  if (!item) return;

  const s = item.scenario;
  const b = SCORING_ENGINE.calculate(s.cvss, s.kev, s.epss, s.exposure, s.criticality, state.activeAppetite);

  const panel = document.getElementById("inspector-card");
  if (panel) panel.style.display = "block";

  document.getElementById("detail-vuln-id").textContent = s.vuln_id;
  document.getElementById("detail-product").textContent = s.product;
  document.getElementById("detail-cvss").textContent = s.cvss.toFixed(1);
  document.getElementById("detail-severity").textContent = s.cvss_severity;
  document.getElementById("detail-severity").className = `metric-val badge-severity ${s.cvss >= 9 ? 'badge-crit' : 'badge-hi'}`;

  document.getElementById("detail-kev").innerHTML = s.kev 
    ? `<span class="badge-priority badge-URGENT">YES (In-The-Wild)</span>` 
    : `<span class="badge-priority badge-LOW">NO (Not Listed)</span>`;

  document.getElementById("detail-epss").textContent = `${(s.epss * 100).toFixed(0)}% (${s.epss.toFixed(2)})`;
  document.getElementById("detail-asset").textContent = s.affected_asset_name;
  document.getElementById("detail-exposure").textContent = s.exposure;
  document.getElementById("detail-criticality").textContent = s.criticality;
  document.getElementById("detail-importance").textContent = s.business_importance;

  // Breakdown Bars
  const p = state.data.profiles[state.activeAppetite] || state.data.profiles["Low"];
  const pct = p.percentages;

  document.getElementById("bar-cvss").style.width = `${(b.cvss_contribution / (p.weights.cvss * 100)) * 100}%`;
  document.getElementById("bar-cvss-val").textContent = `+${b.cvss_contribution.toFixed(1)} pts (Weight: ${pct.cvss})`;

  document.getElementById("bar-kev").style.width = `${(b.kev_contribution / (p.weights.kev * 100)) * 100}%`;
  document.getElementById("bar-kev-val").textContent = `+${b.kev_contribution.toFixed(1)} pts (Weight: ${pct.kev})`;

  document.getElementById("bar-epss").style.width = `${(b.epss_contribution / (p.weights.epss * 100)) * 100}%`;
  document.getElementById("bar-epss-val").textContent = `+${b.epss_contribution.toFixed(1)} pts (Weight: ${pct.epss})`;

  document.getElementById("bar-exp").style.width = `${(b.exposure_contribution / (p.weights.exposure * 100)) * 100}%`;
  document.getElementById("bar-exp-val").textContent = `+${b.exposure_contribution.toFixed(1)} pts (Weight: ${pct.exposure})`;

  document.getElementById("bar-crit").style.width = `${(b.criticality_contribution / (p.weights.criticality * 100)) * 100}%`;
  document.getElementById("bar-crit-val").textContent = `+${b.criticality_contribution.toFixed(1)} pts (Weight: ${pct.criticality})`;

  document.getElementById("detail-total-score").textContent = `${b.total_score.toFixed(1)} / 100`;
  const badge = document.getElementById("detail-priority-badge");
  badge.textContent = b.priority_level;
  badge.className = `badge-priority badge-${b.priority_level}`;

  document.getElementById("detail-explanation").textContent = s.explanation;

  // What-If button in inspector
  const whatIfBtn = document.getElementById("detail-whatif-btn");
  if (whatIfBtn) {
    whatIfBtn.onclick = () => {
      document.getElementById("whatif-scenario-select").value = s.vuln_id;
      loadScenarioIntoWhatIf(s.vuln_id);
      switchTab("whatif-tab");
    };
  }

  const closeBtn = document.getElementById("close-inspector-btn");
  if (closeBtn) {
    closeBtn.onclick = () => {
      panel.style.display = "none";
    };
  }
}

// What-If Simulator Logic
function initWhatIfWorkbench() {
  const scenSel = document.getElementById("whatif-scenario-select");
  const expSel = document.getElementById("whatif-exposure-select");
  const critSel = document.getElementById("whatif-criticality-select");
  const kevSel = document.getElementById("whatif-kev-select");
  const epssSlider = document.getElementById("whatif-epss-slider");
  const appSel = document.getElementById("whatif-appetite-select");
  const resetBtn = document.getElementById("whatif-reset-btn");

  if (scenSel) {
    scenSel.addEventListener("change", () => {
      loadScenarioIntoWhatIf(scenSel.value);
    });
  }

  [expSel, critSel, kevSel, appSel].forEach(elem => {
    if (elem) elem.addEventListener("change", runWhatIfSimulation);
  });

  if (epssSlider) {
    epssSlider.addEventListener("input", (e) => {
      document.getElementById("epss-slider-val").textContent = parseFloat(e.target.value).toFixed(2);
      runWhatIfSimulation();
    });
  }

  document.querySelectorAll(".preset-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const val = parseFloat(btn.getAttribute("data-epss"));
      epssSlider.value = val;
      document.getElementById("epss-slider-val").textContent = val.toFixed(2);
      runWhatIfSimulation();
    });
  });

  if (resetBtn) {
    resetBtn.addEventListener("click", () => {
      const vulnId = scenSel.value;
      loadScenarioIntoWhatIf(vulnId);
    });
  }

  loadScenarioIntoWhatIf("NXP-DEMO-002");
}

function loadScenarioIntoWhatIf(vulnId) {
  const item = state.data.scenarios.find(s => s.scenario.vuln_id === vulnId);
  if (!item) return;
  const s = item.scenario;

  document.getElementById("whatif-cvss-display").textContent = s.cvss.toFixed(1);
  document.getElementById("whatif-exposure-select").value = s.exposure;
  document.getElementById("whatif-criticality-select").value = s.criticality;
  document.getElementById("whatif-kev-select").value = s.kev ? "yes" : "no";
  document.getElementById("whatif-epss-slider").value = s.epss;
  document.getElementById("epss-slider-val").textContent = s.epss.toFixed(2);
  document.getElementById("whatif-appetite-select").value = state.activeAppetite;

  runWhatIfSimulation();
}

function runWhatIfSimulation() {
  const scenSel = document.getElementById("whatif-scenario-select");
  if (!scenSel) return;
  const vulnId = scenSel.value;
  const item = state.data.scenarios.find(s => s.scenario.vuln_id === vulnId);
  if (!item) return;

  const baseline = item.scenario;

  const targetExposure = document.getElementById("whatif-exposure-select").value;
  const targetCriticality = document.getElementById("whatif-criticality-select").value;
  const targetKev = document.getElementById("whatif-kev-select").value === "yes";
  const targetEpss = parseFloat(document.getElementById("whatif-epss-slider").value);
  const targetAppetite = document.getElementById("whatif-appetite-select").value;

  // Invariant check: CVSS is strictly baseline.cvss
  const cvss = baseline.cvss;

  const beforeBreakdown = SCORING_ENGINE.calculate(cvss, baseline.kev, baseline.epss, baseline.exposure, baseline.criticality, "Low");
  const afterBreakdown = SCORING_ENGINE.calculate(cvss, targetKev, targetEpss, targetExposure, targetCriticality, targetAppetite);

  // Update Before Box
  document.getElementById("whatif-before-context").innerHTML = `
    <div><strong>Exposure:</strong> ${baseline.exposure}</div>
    <div><strong>Criticality:</strong> ${baseline.criticality}</div>
    <div><strong>KEV:</strong> ${baseline.kev ? 'YES' : 'NO'} | <strong>EPSS:</strong> ${baseline.epss.toFixed(2)}</div>
  `;
  document.getElementById("whatif-before-score").textContent = Math.round(beforeBreakdown.total_score);
  const beforeBadge = document.getElementById("whatif-before-priority");
  beforeBadge.textContent = beforeBreakdown.priority_level;
  beforeBadge.className = `compare-priority badge-priority badge-${beforeBreakdown.priority_level}`;

  // Update After Box
  document.getElementById("whatif-after-context").innerHTML = `
    <div><strong>Exposure:</strong> ${targetExposure}</div>
    <div><strong>Criticality:</strong> ${targetCriticality}</div>
    <div><strong>KEV:</strong> ${targetKev ? 'YES' : 'NO'} | <strong>EPSS:</strong> ${targetEpss.toFixed(2)}</div>
  `;
  document.getElementById("whatif-after-score").textContent = Math.round(afterBreakdown.total_score);
  const afterBadge = document.getElementById("whatif-after-priority");
  afterBadge.textContent = afterBreakdown.priority_level;
  afterBadge.className = `compare-priority badge-priority badge-${afterBreakdown.priority_level}`;

  // Changes list
  const changesUl = document.getElementById("whatif-changes-list");
  const whyUl = document.getElementById("whatif-why-list");
  changesUl.innerHTML = "";
  whyUl.innerHTML = "";

  const changes = [];
  const whys = [];

  if (targetExposure !== baseline.exposure) {
    changes.push(`Exposure: ${baseline.exposure} ➔ ${targetExposure}`);
    if (targetExposure === "Internal") {
      whys.push("Exposure decreased (Internet-facing → Internal): Reduced attack surface lowered contextual exposure contribution.");
    } else {
      whys.push("Exposure increased (Internal → Internet-facing): Direct boundary accessibility substantially expanded attack surface.");
    }
  }

  if (targetCriticality !== baseline.criticality) {
    changes.push(`Asset Criticality: ${baseline.criticality} ➔ ${targetCriticality}`);
    whys.push(`Asset criticality shifted (${baseline.criticality} → ${targetCriticality}): Modified business mission role adjusted operational urgency.`);
  }

  if (targetKev !== baseline.kev) {
    changes.push(`CISA KEV: ${baseline.kev ? 'YES' : 'NO'} ➔ ${targetKev ? 'YES' : 'NO'}`);
    if (targetKev) {
      whys.push("Threat signal added (KEV NO → YES): Confirmed weaponization in the wild sharply escalated threat factor.");
    } else {
      whys.push("Threat signal removed (KEV YES → NO): Flaw lacks confirmed in-the-wild exploitation evidence.");
    }
  }

  if (Math.abs(targetEpss - baseline.epss) > 0.001) {
    changes.push(`EPSS Probability: ${baseline.epss.toFixed(2)} ➔ ${targetEpss.toFixed(2)}`);
    if (targetEpss < baseline.epss) {
      whys.push(`EPSS decreased (${baseline.epss.toFixed(2)} → ${targetEpss.toFixed(2)}): Lower forward-looking exploitation probability reduced threat score.`);
    } else {
      whys.push(`EPSS increased (${baseline.epss.toFixed(2)} → ${targetEpss.toFixed(2)}): Higher exploitation likelihood increased threat score.`);
    }
  }

  if (targetAppetite !== "Low") {
    changes.push(`Risk Appetite: Low ➔ ${targetAppetite}`);
    whys.push(`Risk profile changed (Low → ${targetAppetite}): Re-weighted CVSS vs KEV/EPSS trade-offs.`);
  }

  if (changes.length === 0) {
    changes.push("No context variables were modified from the baseline scenario.");
    whys.push("The simulation matches baseline scenario parameters exactly.");
  }

  changes.forEach(c => {
    const li = document.createElement("li");
    li.textContent = c;
    changesUl.appendChild(li);
  });

  whys.forEach(w => {
    const li = document.createElement("li");
    li.textContent = w;
    whyUl.appendChild(li);
  });

  document.getElementById("conclusion-cvss").textContent = cvss.toFixed(1);
}

// Educational Cards
function initEduCards() {
  const container = document.getElementById("edu-card-container");
  if (!container) return;
  container.innerHTML = "";

  state.data.educational_signals.forEach(item => {
    const card = document.createElement("div");
    card.className = "edu-card";
    card.innerHTML = `
      <div class="edu-card-signal">${item.signal}</div>
      <div class="edu-card-title">${item.title}</div>
      <div class="edu-card-q">"${item.question}"</div>
      <p class="edu-card-desc">${item.description}</p>
      <div class="edu-card-src">Authority: ${item.source}</div>
    `;
    container.appendChild(card);
  });
}

// VulnLens Transition Modal
function initBridgeModal() {
  const btn = document.getElementById("introduce-vulnlens-btn");
  const modal = document.getElementById("vulnlens-intro-modal");
  if (btn && modal) {
    btn.addEventListener("click", () => {
      modal.style.display = modal.style.display === "none" ? "block" : "none";
      if (modal.style.display === "block") {
        modal.scrollIntoView({ behavior: "smooth" });
      }
    });
  }
}
