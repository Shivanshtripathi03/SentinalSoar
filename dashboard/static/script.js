/**
 * SentinelSOAR Dashboard — JavaScript
 * Real-time charts (Chart.js), tables, AI analysis, threat intel,
 * incident management, SOAR log, and auto-refresh (1s).
 */

const REFRESH_INTERVAL = 1000;

// ── IP Color Mapping ───────────────────────────────

const IP_COLORS = {
  "10.10.0.10": "#3b82f6",
  "10.10.0.11": "#a78bfa",
  "10.10.0.12": "#22d3ee",
  "10.10.0.100": "#ef4444",
  "10.10.0.101": "#10b981",
  "10.10.0.102": "#f97316",
  "10.10.0.103": "#eab308",
  "10.10.0.104": "#ec4899",
  "10.10.0.105": "#f43f5e",
};

const SERVICE_COLORS = {
  web: "#3b82f6",
  auth: "#a78bfa",
  db: "#22d3ee",
};

// Flood threshold: 50 events in 10s → 5/s shown as reference
const FLOOD_THRESHOLD_PER_SEC = 5;

// Range slider state
let logRangeValue = 200;

// ── Tab Switching ──────────────────────────────────

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document
      .querySelectorAll(".tab")
      .forEach((t) => t.classList.remove("active"));
    document
      .querySelectorAll(".tab-content")
      .forEach((c) => c.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("tab-" + tab.dataset.tab).classList.add("active");
  });
});

// ── Data Fetching ──────────────────────────────────

async function fetchJSON(url) {
  try {
    const res = await fetch(url);
    return await res.json();
  } catch (e) {
    console.error("Fetch error:", e);
    return null;
  }
}

// ── Chart.js Setup ─────────────────────────────────

const chartDefaults = {
  color: "#94a3b8",
  borderColor: "rgba(42,58,92,0.5)",
  font: { family: "'Inter', sans-serif" },
};
Chart.defaults.color = chartDefaults.color;
Chart.defaults.font.family = chartDefaults.font.family;

// Events Over Time — line chart
const tsCtx = document.getElementById("timeseriesChart").getContext("2d");
const timeseriesChart = new Chart(tsCtx, {
  type: "line",
  data: { labels: [], datasets: [] },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 300 },
    interaction: { mode: "index", intersect: false },
    plugins: {
      legend: {
        position: "bottom",
        labels: { boxWidth: 12, padding: 12, font: { size: 11 } },
      },
      tooltip: {
        backgroundColor: "#1a2236",
        borderColor: "#2a3a5c",
        borderWidth: 1,
        titleFont: { size: 11 },
        bodyFont: { size: 11, family: "'JetBrains Mono', monospace" },
      },
    },
    scales: {
      x: {
        grid: { color: "rgba(42,58,92,0.3)" },
        ticks: { maxTicksLimit: 12, font: { size: 10 } },
      },
      y: {
        beginAtZero: true,
        grid: { color: "rgba(42,58,92,0.3)" },
        ticks: { font: { size: 10 }, stepSize: 1 },
        title: { display: true, text: "Events / sec", font: { size: 11 } },
      },
    },
  },
});

// Service Distribution — doughnut chart
const distCtx = document.getElementById("distributionChart").getContext("2d");
const distributionChart = new Chart(distCtx, {
  type: "doughnut",
  data: {
    labels: ["Web", "Auth", "DB"],
    datasets: [
      {
        data: [0, 0, 0],
        backgroundColor: [
          SERVICE_COLORS.web,
          SERVICE_COLORS.auth,
          SERVICE_COLORS.db,
        ],
        borderColor: "#1a2236",
        borderWidth: 2,
      },
    ],
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 400 },
    cutout: "60%",
    plugins: {
      legend: {
        position: "bottom",
        labels: { boxWidth: 12, padding: 10, font: { size: 11 } },
      },
      tooltip: {
        backgroundColor: "#1a2236",
        borderColor: "#2a3a5c",
        borderWidth: 1,
      },
    },
  },
});

// ── Chart Update Functions ─────────────────────────

function updateTimeseriesChart(data) {
  if (!data || !data.timestamps) return;

  const labels = data.timestamps.map((ts) => {
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString("en-IN", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  });

  const datasets = [];
  for (const [ip, values] of Object.entries(data.series || {})) {
    datasets.push({
      label: ip,
      data: values,
      borderColor: IP_COLORS[ip] || "#64748b",
      backgroundColor: (IP_COLORS[ip] || "#64748b") + "18",
      borderWidth: 1.5,
      pointRadius: 0,
      tension: 0.3,
      fill: false,
    });
  }

  // Add flood threshold reference line
  if (labels.length > 0) {
    datasets.push({
      label: "Flood Threshold (5/s)",
      data: new Array(labels.length).fill(FLOOD_THRESHOLD_PER_SEC),
      borderColor: "#ef4444",
      borderWidth: 1,
      borderDash: [6, 4],
      pointRadius: 0,
      fill: false,
    });
  }

  timeseriesChart.data.labels = labels;
  timeseriesChart.data.datasets = datasets;
  timeseriesChart.update("none");
}

function updateDistributionChart(data) {
  if (!data) return;
  distributionChart.data.datasets[0].data = [
    data.web || 0,
    data.auth || 0,
    data.db || 0,
  ];
  distributionChart.update("none");
}

// ── Render Alert Summary ───────────────────────────

function renderAlertSummary(summary) {
  const tbody = document.getElementById("alert-summary-body");
  if (!summary || summary.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="3" class="empty">No alerts yet</td></tr>';
    return;
  }
  const rows = summary
    .map((s) => {
      const sevClass = "badge-" + (s.severity || "low");
      return `<tr>
            <td><strong>${escapeHtml(s.rule || "")}</strong></td>
            <td><span class="badge ${sevClass}">${escapeHtml(s.severity || "")}</span></td>
            <td class="count-cell">${s.count || 0}</td>
        </tr>`;
    })
    .join("");
  tbody.innerHTML = rows;
}

// ── Render Logs ────────────────────────────────────

function renderLogs(events) {
  const tbody = document.getElementById("log-body");
  const filter = document.getElementById("log-filter").value.toLowerCase();
  const sourceFilter = document.getElementById("log-source-filter").value;

  let filtered = events;
  if (sourceFilter) {
    filtered = filtered.filter((e) => e.source_type === sourceFilter);
  }
  if (filter) {
    filtered = filtered.filter((e) =>
      JSON.stringify(e).toLowerCase().includes(filter),
    );
  }

  if (filtered.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="7" class="empty">No events matching filter</td></tr>';
    return;
  }

  const rows = filtered
    .reverse()
    .slice(0, 200)
    .map((e) => {
      const sourceClass = "source-" + (e.source_type || "web");
      return `<tr>
            <td>${escapeHtml(e.timestamp || "")}</td>
            <td><span class="source-badge ${sourceClass}">${escapeHtml(e.source_type || "")}</span></td>
            <td>${escapeHtml(e.src_ip || "")}</td>
            <td>${escapeHtml(e.dst_ip || "")}:${e.dst_port || ""}</td>
            <td>${escapeHtml(e.action || "")}</td>
            <td>${escapeHtml(e.status || "-")}</td>
            <td>${escapeHtml(e.detail || "")}</td>
        </tr>`;
    })
    .join("");

  tbody.innerHTML = rows;
}

// ── Render Alerts (with AI button) ────────────────

function renderAlerts(alerts) {
  const tbody = document.getElementById("alert-body");

  if (!alerts || alerts.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="8" class="empty">No alerts yet</td></tr>';
    return;
  }

  const rows = alerts
    .reverse()
    .map((a) => {
      const sevClass = "badge-" + (a.severity || "low");
      const evidence = Array.isArray(a.evidence)
        ? a.evidence
        : [a.evidence || ""];
      return `<tr>
            <td>${a.id || ""}</td>
            <td>${escapeHtml(a.created_at || a.timestamp || "")}</td>
            <td><strong>${escapeHtml(a.rule || "")}</strong></td>
            <td><span class="badge ${sevClass}">${escapeHtml(a.severity || "")}</span></td>
            <td>${escapeHtml(a.src_ip || "")}</td>
            <td style="max-width:300px;word-wrap:break-word;font-family:var(--font-sans);font-size:0.78rem">${escapeHtml(a.trigger || "")}</td>
            <td><button class="btn btn-evidence" onclick='showEvidence(${JSON.stringify(JSON.stringify(evidence))})'>View</button></td>
            <td><button class="btn btn-ai btn-sm" onclick="explainAlert(${a.id})">🤖 AI</button></td>
        </tr>`;
    })
    .join("");

  tbody.innerHTML = rows;
}

// ── Render Blocklist (with Threat Intel button) ───

function renderBlocklist(blocklist) {
  const tbody = document.getElementById("blocklist-body");

  const entries = Object.entries(blocklist || {});
  if (entries.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="5" class="empty">No blocked IPs</td></tr>';
    return;
  }

  const rows = entries
    .map(([ip, info]) => {
      return `<tr>
            <td><strong>${escapeHtml(ip)}</strong></td>
            <td>${escapeHtml(info.blocked_at || "")}</td>
            <td style="font-family:var(--font-sans);font-size:0.78rem">${escapeHtml(info.reason || "")}</td>
            <td><button class="btn btn-intel btn-sm" onclick="lookupThreatIntel('${escapeHtml(ip)}')">🔍 Intel</button></td>
            <td><button class="btn btn-danger" onclick="unblockIP('${escapeHtml(ip)}')">Unblock</button></td>
        </tr>`;
    })
    .join("");

  tbody.innerHTML = rows;
}

// ── Render Incidents ──────────────────────────────

function renderIncidents(incidents) {
  const tbody = document.getElementById("incident-body");
  const statusFilter = document.getElementById("incident-status-filter").value;

  let filtered = incidents || [];
  if (statusFilter) {
    filtered = filtered.filter((i) => i.status === statusFilter);
  }

  if (filtered.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="9" class="empty">No incidents yet</td></tr>';
    return;
  }

  const rows = filtered
    .reverse()
    .map((inc) => {
      const sevClass = "badge-" + (inc.severity || "low");
      const statusClass = "status-" + (inc.status || "open");
      const killChain = (inc.kill_chain || [])
        .map((s) => `<span class="kill-chain-tag">${escapeHtml(s)}</span>`)
        .join("");

      return `<tr>
            <td>${inc.id || ""}</td>
            <td><span class="status-badge ${statusClass}">${escapeHtml(inc.status || "")}</span></td>
            <td><span class="badge ${sevClass}">${escapeHtml(inc.severity || "")}</span></td>
            <td>${escapeHtml(inc.src_ip || "")}</td>
            <td style="font-family:var(--font-sans);font-size:0.78rem">${escapeHtml(inc.title || "")}</td>
            <td class="count-cell">${inc.alert_count || 0}</td>
            <td>${killChain || "-"}</td>
            <td>${escapeHtml(inc.created_at || "")}</td>
            <td>
              <select class="status-select" onchange="updateIncidentStatus(${inc.id}, this.value)">
                <option value="open" ${inc.status === "open" ? "selected" : ""}>Open</option>
                <option value="investigating" ${inc.status === "investigating" ? "selected" : ""}>Investigating</option>
                <option value="resolved" ${inc.status === "resolved" ? "selected" : ""}>Resolved</option>
                <option value="closed" ${inc.status === "closed" ? "selected" : ""}>Closed</option>
              </select>
            </td>
        </tr>`;
    })
    .join("");

  tbody.innerHTML = rows;
}

// ── Render SOAR Executions ────────────────────────

function renderSOARLog(executions) {
  const container = document.getElementById("soar-log-container");

  if (!executions || executions.length === 0) {
    container.innerHTML =
      '<p class="empty" style="text-align:center;padding:36px;color:var(--text-muted);font-style:italic;">No playbook executions yet</p>';
    return;
  }

  const cards = executions
    .reverse()
    .slice(0, 50)
    .map((exec) => {
      const actionChips = (exec.actions || [])
        .map((a) => {
          let chipClass = "action-ok";
          let icon = "✓";
          if (a.status === "skipped" || a.status === "already_blocked") {
            chipClass = "action-skip";
            icon = "–";
          } else if (a.status === "error") {
            chipClass = "action-err";
            icon = "✗";
          }
          return `<span class="soar-action-chip ${chipClass}">${icon} ${escapeHtml(a.action || "")}</span>`;
        })
        .join("");

      return `<div class="soar-card">
          <div class="soar-card-header">
            <span class="soar-card-title">⚡ ${escapeHtml(exec.playbook || "")}</span>
            <span class="soar-card-meta">${escapeHtml(exec.executed_at || "")} · ${exec.duration_ms || 0}ms</span>
          </div>
          <div style="font-size:0.76rem;color:var(--text-secondary);margin-bottom:8px;font-family:var(--font-mono);">
            ${escapeHtml(exec.rule || "")} → ${escapeHtml(exec.src_ip || "")}
          </div>
          <div class="soar-actions-row">${actionChips}</div>
        </div>`;
    })
    .join("");

  container.innerHTML = cards;
}

// ── Update Stats Cards ─────────────────────────────

function updateStats(stats) {
  if (!stats) return;
  document.getElementById("stat-events").textContent =
    stats.events_processed || 0;
  document.getElementById("stat-alerts").textContent =
    stats.alerts_generated || 0;
  document.getElementById("stat-blocked").textContent = stats.ips_blocked || 0;
}

// ── Evidence Modal ─────────────────────────────────

function showEvidence(evidenceJson) {
  const evidence = JSON.parse(evidenceJson);
  const content = Array.isArray(evidence)
    ? evidence.join("\n")
    : String(evidence);
  document.getElementById("evidence-content").textContent = content;
  document.getElementById("evidence-modal").classList.remove("hidden");
}

function closeModal() {
  document.getElementById("evidence-modal").classList.add("hidden");
}

document.getElementById("evidence-modal").addEventListener("click", (e) => {
  if (e.target === e.currentTarget) closeModal();
});

// ── AI Analysis Modal ──────────────────────────────

function closeAIModal() {
  document.getElementById("ai-modal").classList.add("hidden");
}

document.getElementById("ai-modal").addEventListener("click", (e) => {
  if (e.target === e.currentTarget) closeAIModal();
});

async function explainAlert(alertId) {
  const modal = document.getElementById("ai-modal");
  const body = document.getElementById("ai-modal-body");

  modal.classList.remove("hidden");
  body.innerHTML = '<div class="ai-loading"><div class="spinner"></div>Analyzing alert with AI...</div>';

  try {
    const res = await fetch("/api/ai/explain-alert", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert_id: alertId }),
    });
    const data = await res.json();

    if (data.error) {
      body.innerHTML = `<div class="ai-loading" style="color:var(--accent-red)">Error: ${escapeHtml(data.error)}</div>`;
      return;
    }

    const riskColors = {
      critical: "var(--severity-critical)",
      high: "var(--severity-high)",
      medium: "var(--severity-medium)",
      low: "var(--severity-low)",
    };
    const riskColor = riskColors[data.risk_level] || "var(--text-secondary)";

    const actions = (data.recommended_actions || [])
      .map((a) => `<li>${escapeHtml(a)}</li>`)
      .join("");

    const mitre = data.mitre_attack || {};
    const queries = (data.investigation_queries || [])
      .map((q) => `<li>${escapeHtml(q)}</li>`)
      .join("");

    body.innerHTML = `
      <div class="ai-section">
        <div class="ai-section-title">📋 Summary <span class="ai-source-tag">${escapeHtml(data.source || "")}</span></div>
        <div class="ai-summary-text">${escapeHtml(data.summary || "No summary available")}</div>
      </div>

      <div class="ai-section" style="display:flex;gap:16px;flex-wrap:wrap;">
        <div>
          <div class="ai-section-title">⚠️ Risk Level</div>
          <span class="ai-risk-badge" style="background:${riskColor}22;color:${riskColor};border:1px solid ${riskColor}44;">
            ${escapeHtml((data.risk_level || "unknown").toUpperCase())}
          </span>
        </div>
        <div>
          <div class="ai-section-title">🎯 Attack Stage</div>
          <span class="kill-chain-tag" style="font-size:0.76rem;padding:3px 10px;">
            ${escapeHtml(data.attack_stage || "unknown")}
          </span>
        </div>
        <div>
          <div class="ai-section-title">🎲 False Positive</div>
          <span style="font-size:0.82rem;font-family:var(--font-sans);color:var(--text-primary);">
            ${escapeHtml((data.false_positive_likelihood || "unknown"))} likelihood
          </span>
        </div>
      </div>

      <div class="ai-section">
        <div class="ai-section-title">🛡️ Recommended Actions</div>
        <ul class="ai-actions-list">${actions}</ul>
      </div>

      <div class="ai-section">
        <div class="ai-section-title">🔬 MITRE ATT&CK Mapping</div>
        <dl class="ai-mitre-card">
          <dt>Tactic</dt><dd>${escapeHtml(mitre.tactic || "N/A")}</dd>
          <dt>Technique</dt><dd>${escapeHtml(mitre.technique || "N/A")}</dd>
          <dt>Description</dt><dd>${escapeHtml(mitre.description || "N/A")}</dd>
        </dl>
      </div>

      ${queries ? `<div class="ai-section">
        <div class="ai-section-title">🔍 Investigation Queries</div>
        <ul class="ai-actions-list">${queries}</ul>
      </div>` : ""}
    `;
  } catch (e) {
    body.innerHTML = `<div class="ai-loading" style="color:var(--accent-red)">Failed to connect: ${escapeHtml(String(e))}</div>`;
  }
}

// ── AI Summary (Header Button) ────────────────────

async function showAISummary() {
  const modal = document.getElementById("ai-modal");
  const body = document.getElementById("ai-modal-body");
  const header = modal.querySelector(".modal-header h3");
  header.textContent = "🤖 AI Activity Summary";

  modal.classList.remove("hidden");
  body.innerHTML = '<div class="ai-loading"><div class="spinner"></div>Generating AI summary...</div>';

  try {
    const data = await fetchJSON("/api/ai/summarize?minutes=5");
    if (!data) {
      body.innerHTML = '<div class="ai-loading" style="color:var(--accent-red)">Failed to fetch summary</div>';
      return;
    }

    const topIPs = Object.entries(data.top_source_ips || {})
      .map(([ip, count]) => `<li>${escapeHtml(ip)} — <strong>${count}</strong> events</li>`)
      .join("");

    const svcDist = Object.entries(data.service_distribution || {})
      .map(([svc, count]) => `<span class="source-badge source-${svc}">${escapeHtml(svc)}: ${count}</span>`)
      .join(" ");

    body.innerHTML = `
      <div class="ai-section">
        <div class="ai-section-title">📋 Summary <span class="ai-source-tag">${escapeHtml(data.source || "")}</span></div>
        <div class="ai-summary-text">${escapeHtml(data.summary || "No activity")}</div>
      </div>

      <div class="ai-section" style="display:flex;gap:16px;flex-wrap:wrap;">
        <div>
          <div class="ai-section-title">📊 Total Events</div>
          <span style="font-size:1.2rem;font-weight:700;font-family:var(--font-mono);color:var(--accent-cyan);">${data.total_events || 0}</span>
        </div>
        ${data.threat_level ? `<div>
          <div class="ai-section-title">⚠️ Threat Level</div>
          <span class="badge badge-${data.threat_level}">${escapeHtml(data.threat_level)}</span>
        </div>` : ""}
      </div>

      ${topIPs ? `<div class="ai-section">
        <div class="ai-section-title">🔝 Top Source IPs</div>
        <ul class="ai-actions-list">${topIPs}</ul>
      </div>` : ""}

      ${svcDist ? `<div class="ai-section">
        <div class="ai-section-title">🖥️ Service Distribution</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">${svcDist}</div>
      </div>` : ""}
    `;
  } catch (e) {
    body.innerHTML = `<div class="ai-loading" style="color:var(--accent-red)">Error: ${escapeHtml(String(e))}</div>`;
  }
}

// ── Threat Intel Modal ────────────────────────────

function closeIntelModal() {
  document.getElementById("intel-modal").classList.add("hidden");
}

document.getElementById("intel-modal").addEventListener("click", (e) => {
  if (e.target === e.currentTarget) closeIntelModal();
});

async function lookupThreatIntel(ip) {
  const modal = document.getElementById("intel-modal");
  const body = document.getElementById("intel-modal-body");

  modal.classList.remove("hidden");
  body.innerHTML = '<div class="ai-loading" style="grid-column:1/-1;"><div class="spinner"></div>Looking up IP...</div>';

  try {
    const data = await fetchJSON(`/api/intel/lookup?ip=${encodeURIComponent(ip)}`);
    if (!data) {
      body.innerHTML = '<div class="ai-loading" style="grid-column:1/-1;color:var(--accent-red)">Lookup failed</div>';
      return;
    }

    const geo = data.geo || {};
    const abuse = data.abuse || {};
    const vt = data.virustotal || {};
    const score = data.threat_score || 0;
    const scoreColor = score > 60 ? "var(--accent-red)" : score > 30 ? "var(--accent-yellow)" : "var(--accent-green)";

    body.innerHTML = `
      <div class="intel-item" style="grid-column:1/-1;">
        <div class="intel-item-title">IP Address</div>
        <div class="intel-item-value">${escapeHtml(data.ip || ip)}</div>
        <div class="intel-item-sub">${data.is_private ? "🏠 Private Network" : "🌐 Public IP"}</div>
      </div>

      <div class="intel-item">
        <div class="intel-item-title">🗺️ Geolocation</div>
        <div class="intel-item-value">${escapeHtml(geo.country || "Unknown")}</div>
        <div class="intel-item-sub">${escapeHtml(geo.city || "")}</div>
        <div class="intel-item-sub">ISP: ${escapeHtml(geo.isp || "Unknown")}</div>
      </div>

      <div class="intel-item">
        <div class="intel-item-title">⚠️ Threat Score</div>
        <div class="intel-item-value" style="color:${scoreColor};">${score}/100</div>
        <div class="threat-score-bar">
          <div class="threat-score-fill" style="width:${score}%;background:${scoreColor};"></div>
        </div>
      </div>

      <div class="intel-item">
        <div class="intel-item-title">🛡️ AbuseIPDB</div>
        ${abuse.enabled === false
          ? `<div class="intel-item-sub">${escapeHtml(abuse.message || "Not configured")}</div>`
          : `<div class="intel-item-value">${abuse.abuse_score || 0}% confidence</div>
             <div class="intel-item-sub">${abuse.total_reports || 0} reports</div>
             ${abuse.is_tor ? '<div class="intel-item-sub" style="color:var(--accent-red);">🧅 Tor Exit Node</div>' : ""}`
        }
      </div>

      <div class="intel-item">
        <div class="intel-item-title">🔬 VirusTotal</div>
        ${vt.enabled === false
          ? `<div class="intel-item-sub">${escapeHtml(vt.message || "Not configured")}</div>`
          : `<div class="intel-item-value">${vt.malicious || 0} malicious</div>
             <div class="intel-item-sub">${vt.suspicious || 0} suspicious · ${vt.harmless || 0} harmless</div>`
        }
      </div>

      <div class="intel-item">
        <div class="intel-item-title">🏢 Organization</div>
        <div class="intel-item-value">${escapeHtml(geo.org || "Unknown")}</div>
        <div class="intel-item-sub">ASN: ${escapeHtml(geo.asn || "Unknown")}</div>
      </div>
    `;
  } catch (e) {
    body.innerHTML = `<div class="ai-loading" style="grid-column:1/-1;color:var(--accent-red)">Error: ${escapeHtml(String(e))}</div>`;
  }
}

// ── Incident Status Update ────────────────────────

async function updateIncidentStatus(incidentId, newStatus) {
  try {
    await fetch(`/api/incidents/${incidentId}/status`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: newStatus }),
    });
  } catch (e) {
    console.error("Status update error:", e);
  }
}

// ── Unblock IP ─────────────────────────────────────

async function unblockIP(ip) {
  try {
    await fetch("/api/blocklist/unblock", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip }),
    });
    refresh();
  } catch (e) {
    console.error("Unblock error:", e);
  }
}

// ── Utility ────────────────────────────────────────

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = String(str);
  return div.innerHTML;
}

// ── Main Refresh Loop ──────────────────────────────

async function refresh() {
  const [
    events,
    alerts,
    blocklist,
    stats,
    timeseries,
    distribution,
    alertSummary,
    incidents,
    soarLog,
  ] = await Promise.all([
    fetchJSON("/api/events?limit=200"),
    fetchJSON("/api/alerts?limit=100"),
    fetchJSON("/api/blocklist"),
    fetchJSON("/api/stats"),
    fetchJSON(`/api/timeseries?last=${logRangeValue}`),
    fetchJSON("/api/service-distribution"),
    fetchJSON("/api/alert-summary"),
    fetchJSON("/api/incidents?limit=50"),
    fetchJSON("/api/soar/executions?limit=50"),
  ]);

  if (events) renderLogs(events);
  if (alerts) renderAlerts(alerts);
  if (blocklist) renderBlocklist(blocklist);
  updateStats(stats);
  updateTimeseriesChart(timeseries);
  updateDistributionChart(distribution);
  renderAlertSummary(alertSummary);
  renderIncidents(incidents);
  renderSOARLog(soarLog);
}

document.getElementById("log-filter").addEventListener("input", refresh);
document
  .getElementById("log-source-filter")
  .addEventListener("change", refresh);
document
  .getElementById("incident-status-filter")
  .addEventListener("change", refresh);

// Range slider for timeseries
const rangeSlider = document.getElementById("logRange");
const rangeLabel = document.getElementById("rangeValue");
rangeSlider.addEventListener("input", () => {
  logRangeValue = parseInt(rangeSlider.value, 10);
  rangeLabel.textContent = logRangeValue;
});

// Close any modal with Escape
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    closeModal();
    closeAIModal();
    closeIntelModal();
  }
});

refresh();
setInterval(refresh, REFRESH_INTERVAL);
