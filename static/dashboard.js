const dashboardState = window.llmguardDashboard || {};
const sessionStartedAt = dashboardState.sessionStartedAt || "";
const refreshIntervalMs = Number(dashboardState.refreshIntervalMs || 4000);
const riskPointWindowSize = 24;

const actionBreakdown = document.getElementById("action-breakdown");
const riskChart = document.getElementById("risk-chart");
const diagnosticsList = document.getElementById("diagnostics-list");
const recentLogsBody = document.getElementById("recent-logs-body");
const adminEvidenceList = document.getElementById("admin-evidence-list");
const latestEventGrid = document.getElementById("latest-event-grid");
const latestEventSummary = document.getElementById("latest-event-summary");
const latestLabelChip = document.getElementById("latest-label-chip");
const latestActionChip = document.getElementById("latest-action-chip");
const currentSessionOnly = document.getElementById("current-session-only");
const dashboardLastUpdated = document.getElementById("dashboard-last-updated");

const metricTotal = document.getElementById("metric-total");
const metricSafe = document.getElementById("metric-safe");
const metricSuspicious = document.getElementById("metric-suspicious");
const metricMalicious = document.getElementById("metric-malicious");
const metricBlocked = document.getElementById("metric-blocked");

let refreshTimerId = null;
let refreshInFlight = false;

function normalizeText(value) {
    return typeof value === "string" ? value.trim() : "";
}

function toneForAction(action) {
    switch ((action || "").toLowerCase()) {
        case "allow":
            return "safe";
        case "sanitize":
        case "log":
            return "suspicious";
        case "block":
        case "quarantine":
            return "malicious";
        default:
            return "neutral";
    }
}

function parseTimestamp(value) {
    const text = normalizeText(value);
    if (!text) {
        return null;
    }
    return new Date(text.replace(" ", "T"));
}

function isUsableRiskPoint(point) {
    return point && Number.isFinite(Number(point.risk_score));
}

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

function formatDisplayTimestamp(value) {
    const parsed = parseTimestamp(value);
    if (!parsed || Number.isNaN(parsed.getTime())) {
        return normalizeText(value) || "N/A";
    }
    return parsed.toLocaleString([], {
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
    });
}

function truncate(text, length = 120) {
    const normalized = normalizeText(text);
    if (!normalized) {
        return "";
    }
    if (normalized.length <= length) {
        return normalized;
    }
    return `${normalized.slice(0, length - 1)}...`;
}

function isBackendDiagnostic(log) {
    const response = normalizeText(log.response);
    return response.toLowerCase().includes("llm backend error");
}

function renderActionBreakdown(actionCounts) {
    actionBreakdown.innerHTML = "";
    const entries = Object.entries(actionCounts || {});
    if (entries.length === 0) {
        actionBreakdown.innerHTML = '<div class="empty-state compact">No action telemetry yet.</div>';
        return;
    }

    entries.forEach(([action, count]) => {
        const row = document.createElement("div");
        row.className = "stats-row glass-inset";
        row.innerHTML = `<span class="body-copy">${escapeHtml(action)}</span><span class="numeric-chip">${count}</span>`;
        actionBreakdown.appendChild(row);
    });
}

function normalizeRiskHistory(points) {
    const uniquePoints = new Map();
    (Array.isArray(points) ? points : [])
        .filter(isUsableRiskPoint)
        .forEach((point, index) => {
            const timestamp = normalizeText(point.timestamp);
            const id = Number(point.id);
            const score = Number(point.risk_score);
            const label = normalizeText(point.label) || "neutral";
            const action = normalizeText(point.action) || "unknown";
            const key = [
                Number.isFinite(id) ? id : `no-id-${index}`,
                timestamp,
                score.toFixed(6),
                label,
                action,
            ].join("|");
            uniquePoints.set(key, {
                id: Number.isFinite(id) ? id : null,
                timestamp,
                risk_score: score,
                label,
                action,
            });
        });

    return Array.from(uniquePoints.values())
        .sort((a, b) => {
            const aTime = parseTimestamp(a.timestamp)?.getTime() || 0;
            const bTime = parseTimestamp(b.timestamp)?.getTime() || 0;
            if (aTime !== bTime) {
                return aTime - bTime;
            }
            return (a.id || 0) - (b.id || 0);
        })
        .slice(-riskPointWindowSize);
}

function renderRiskHistory(points, { loading = false } = {}) {
    riskChart.innerHTML = "";
    const usablePoints = normalizeRiskHistory(points);

    if (usablePoints.length === 0) {
        riskChart.innerHTML = loading
            ? '<div class="empty-state compact">Loading live risk history...</div>'
            : '<div class="empty-state compact">No risk history available yet.</div>';
        return;
    }

    usablePoints.forEach((point) => {
        const wrap = document.createElement("div");
        wrap.className = "risk-bar-wrap glass-inset";
        wrap.innerHTML = `
            <div class="risk-bar ${point.label || "neutral"}" style="height: ${Math.max(8, Math.ceil(Number(point.risk_score) * 100))}%"></div>
            <span>${Number(point.risk_score).toFixed(2)}</span>
            <small class="risk-timestamp mono-text">${escapeHtml(formatDisplayTimestamp(point.timestamp))}</small>
        `;
        riskChart.appendChild(wrap);
    });
}

function renderLatestEvent(log) {
    if (!log) {
        latestEventSummary.textContent = "No log entries are available yet.";
        latestEventGrid.innerHTML = '<div class="empty-state compact">No events recorded yet.</div>';
        latestLabelChip.textContent = "no traffic";
        latestLabelChip.className = "status-chip neutral";
        latestActionChip.textContent = "waiting";
        latestActionChip.className = "status-chip neutral";
        return;
    }

    latestLabelChip.textContent = log.label || "unknown";
    latestLabelChip.className = `status-chip ${log.label || "neutral"}`;
    latestActionChip.textContent = log.action || "unknown";
    latestActionChip.className = "status-chip neutral";
    latestEventSummary.textContent = `Latest event at ${formatDisplayTimestamp(log.created_at)} with risk ${Number(log.risk_score || 0).toFixed(3)}.`;

    latestEventGrid.innerHTML = `
        <div class="glass-inset"><dt>Timestamp</dt><dd>${escapeHtml(formatDisplayTimestamp(log.created_at))}</dd></div>
        <div class="glass-inset"><dt>Prompt</dt><dd>${escapeHtml(log.prompt || "N/A")}</dd></div>
        <div class="glass-inset"><dt>Retrieved Document</dt><dd>${escapeHtml(log.retrieved_document || "N/A")}</dd></div>
        <div class="glass-inset"><dt>Sources</dt><dd>${escapeHtml((log.retrieved_sources || []).join(", ") || "N/A")}</dd></div>
        <div class="glass-inset"><dt>Label</dt><dd><span class="status-chip ${log.label || "neutral"}">${escapeHtml(log.label || "unknown")}</span></dd></div>
        <div class="glass-inset"><dt>Action</dt><dd><span class="status-chip neutral">${escapeHtml(log.action || "unknown")}</span></dd></div>
        <div class="glass-inset"><dt>Risk Score</dt><dd class="mono-text">${Number(log.risk_score || 0).toFixed(3)}</dd></div>
        <div class="glass-inset"><dt>Reason</dt><dd>${escapeHtml(log.reason || "N/A")}</dd></div>
    `;
}

function renderRecentLogs(logs) {
    recentLogsBody.innerHTML = "";
    if (!Array.isArray(logs) || logs.length === 0) {
        recentLogsBody.innerHTML = '<tr><td colspan="7"><div class="empty-state compact">No logs available yet.</div></td></tr>';
        return;
    }

    logs.forEach((log) => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td class="mono-text">${escapeHtml(formatDisplayTimestamp(log.created_at))}</td>
            <td class="table-cell-wrap">${escapeHtml(log.prompt || "N/A")}</td>
            <td class="table-cell-wrap">${escapeHtml(log.retrieved_document || "N/A")}</td>
            <td class="table-cell-wrap">${escapeHtml((log.retrieved_sources || []).join(", ") || "N/A")}</td>
            <td><span class="status-chip ${log.label || "neutral"}">${escapeHtml(log.label || "unknown")}</span></td>
            <td><span class="status-chip neutral">${escapeHtml(log.action || "unknown")}</span></td>
            <td class="mono-text">${Number(log.risk_score || 0).toFixed(3)}</td>
        `;
        recentLogsBody.appendChild(row);
    });
}

function renderEvidenceInspection(log) {
    adminEvidenceList.innerHTML = "";
    const chunks = Array.isArray(log?.retrieved_chunks) ? log.retrieved_chunks : [];

    if (chunks.length === 0) {
        adminEvidenceList.innerHTML = '<div class="empty-state">Retrieved evidence will appear here.</div>';
        return;
    }

    chunks.forEach((chunk) => {
        const sourceSet = chunk.source_set || (chunk.is_poisoned ? "poisoned" : "clean");
        const card = document.createElement("article");
        card.className = "chunk-card";
        card.innerHTML = `
            <div class="chunk-head">
                <strong>${escapeHtml(chunk.document_name || "Unknown document")}</strong>
                <span class="status-chip ${chunk.label || "neutral"}">${escapeHtml(chunk.label || "unknown")}</span>
            </div>
            <div class="chunk-meta mono-text">
                <span>${escapeHtml(chunk.source_path || "Unknown source")}</span>
                <span>${escapeHtml(sourceSet)}</span>
                <span>${chunk.is_poisoned ? "known poisoned set" : "clean set"}</span>
                <span>score ${Number(chunk.score || 0).toFixed(3)}</span>
            </div>
            <div class="chunk-body">${escapeHtml(chunk.text || "")}</div>
        `;
        adminEvidenceList.appendChild(card);
    });
}

function renderDiagnostics(logs) {
    diagnosticsList.innerHTML = "";
    const sessionStart = parseTimestamp(sessionStartedAt);
    let diagnostics = (Array.isArray(logs) ? logs : [])
        .filter(isBackendDiagnostic)
        .sort((a, b) => {
            const aTime = parseTimestamp(a.created_at)?.getTime() || 0;
            const bTime = parseTimestamp(b.created_at)?.getTime() || 0;
            return bTime - aTime;
        });

    if (currentSessionOnly.checked && sessionStart) {
        diagnostics = diagnostics.filter((log) => {
            const logTime = parseTimestamp(log.created_at);
            return logTime && logTime >= sessionStart;
        });
    }

    if (diagnostics.length === 0) {
        diagnosticsList.innerHTML = '<div class="empty-state compact">No backend diagnostics are currently recorded.</div>';
        return;
    }

    diagnostics.forEach((log) => {
        const detail = normalizeText(log.response);
        const card = document.createElement("article");
        card.className = "diagnostic-card glass-inset";
        card.innerHTML = `
            <div class="diagnostic-head">
                <span class="status-chip malicious">backend issue</span>
                <span class="mono-text">${escapeHtml(formatDisplayTimestamp(log.created_at))}</span>
            </div>
            <p class="body-copy">${escapeHtml(truncate(log.prompt || "Prompt unavailable", 100))}</p>
            <p class="diagnostic-summary">${escapeHtml(truncate(detail, 160) || "Backend issue recorded.")}</p>
            <details class="diagnostic-details">
                <summary>View details</summary>
                <div class="diagnostic-detail mono-text">${escapeHtml(detail || "No additional details available.")}</div>
            </details>
        `;
        diagnosticsList.appendChild(card);
    });
}

function setLastUpdated(text, tone = "neutral") {
    if (!dashboardLastUpdated) {
        return;
    }
    dashboardLastUpdated.textContent = text;
    dashboardLastUpdated.className = `surface-chip ${tone === "error" ? "status-chip malicious" : ""}`.trim();
}

function setDashboardLoadingState() {
    renderRiskHistory([], { loading: true });
    setLastUpdated("Refreshing live data...");
}

async function refreshDashboard() {
    if (refreshInFlight) {
        return;
    }

    refreshInFlight = true;

    try {
        const response = await fetch(`/admin/dashboard/data?_ts=${Date.now()}`, {
            headers: { Accept: "application/json" },
            cache: "no-store",
        });
        if (!response.ok) {
            throw new Error(`Dashboard refresh failed with status ${response.status}`);
        }

        const data = await response.json();
        const recentLogs = Array.isArray(data.recent_logs) ? data.recent_logs : [];

        metricTotal.textContent = String(data.total_queries || 0);
        metricSafe.textContent = String((data.label_counts || {}).safe || 0);
        metricSuspicious.textContent = String((data.label_counts || {}).suspicious || 0);
        metricMalicious.textContent = String((data.label_counts || {}).malicious || 0);
        metricBlocked.textContent = String(((data.action_counts || {}).block || 0) + ((data.action_counts || {}).quarantine || 0));

        renderActionBreakdown(data.action_counts || {});
        renderRiskHistory(data.risk_history || []);
        renderLatestEvent(recentLogs[0]);
        renderEvidenceInspection(recentLogs[0]);
        renderRecentLogs(recentLogs);
        renderDiagnostics(recentLogs);
        setLastUpdated(`Updated ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}`);
    } catch (error) {
        setLastUpdated("Live refresh unavailable", "error");
    } finally {
        refreshInFlight = false;
    }
}

currentSessionOnly.addEventListener("change", refreshDashboard);
setDashboardLoadingState();
refreshDashboard();
refreshTimerId = window.setInterval(refreshDashboard, Math.max(3000, refreshIntervalMs));
window.addEventListener("beforeunload", () => {
    if (refreshTimerId !== null) {
        window.clearInterval(refreshTimerId);
    }
});
