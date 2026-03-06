/**
 * Mini SIEM Dashboard — JavaScript
 * Real-time charts (Chart.js), tables, and auto-refresh (1s).
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

// ── Render Alerts ──────────────────────────────────

function renderAlerts(alerts) {
  const tbody = document.getElementById("alert-body");

  if (!alerts || alerts.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="7" class="empty">No alerts yet</td></tr>';
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
        </tr>`;
    })
    .join("");

  tbody.innerHTML = rows;
}

// ── Render Blocklist ───────────────────────────────

function renderBlocklist(blocklist) {
  const tbody = document.getElementById("blocklist-body");

  const entries = Object.entries(blocklist || {});
  if (entries.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="4" class="empty">No blocked IPs</td></tr>';
    return;
  }

  const rows = entries
    .map(([ip, info]) => {
      return `<tr>
            <td><strong>${escapeHtml(ip)}</strong></td>
            <td>${escapeHtml(info.blocked_at || "")}</td>
            <td style="font-family:var(--font-sans);font-size:0.78rem">${escapeHtml(info.reason || "")}</td>
            <td><button class="btn btn-danger" onclick="unblockIP('${escapeHtml(ip)}')">Unblock</button></td>
        </tr>`;
    })
    .join("");

  tbody.innerHTML = rows;
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

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeModal();
});

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
  ] = await Promise.all([
    fetchJSON("/api/events?limit=200"),
    fetchJSON("/api/alerts?limit=100"),
    fetchJSON("/api/blocklist"),
    fetchJSON("/api/stats"),
    fetchJSON(`/api/timeseries?last=${logRangeValue}`),
    fetchJSON("/api/service-distribution"),
    fetchJSON("/api/alert-summary"),
  ]);

  if (events) renderLogs(events);
  if (alerts) renderAlerts(alerts);
  if (blocklist) renderBlocklist(blocklist);
  updateStats(stats);
  updateTimeseriesChart(timeseries);
  updateDistributionChart(distribution);
  renderAlertSummary(alertSummary);
}

document.getElementById("log-filter").addEventListener("input", refresh);
document
  .getElementById("log-source-filter")
  .addEventListener("change", refresh);

// Range slider for timeseries
const rangeSlider = document.getElementById("logRange");
const rangeLabel = document.getElementById("rangeValue");
rangeSlider.addEventListener("input", () => {
  logRangeValue = parseInt(rangeSlider.value, 10);
  rangeLabel.textContent = logRangeValue;
});

refresh();
setInterval(refresh, REFRESH_INTERVAL);
