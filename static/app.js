const form = document.getElementById("query-form");
const promptField = document.getElementById("prompt");
const submitButton = document.getElementById("submit-button");

const warningBanner = document.getElementById("warning-banner");
const resultLabel = document.getElementById("result-label");
const resultAction = document.getElementById("result-action");
const resultRisk = document.getElementById("result-risk");
const resultDocument = document.getElementById("result-document");
const resultReason = document.getElementById("result-reason");
const resultResponse = document.getElementById("result-response");
const resultSources = document.getElementById("result-sources");
const resultChunks = document.getElementById("result-chunks");

const TECHNICAL_ERROR_MARKERS = [
    "llm backend error",
    "httpconnectionpool",
    "winerror",
    "traceback",
    "json parse",
    "connection refused",
    "max retries exceeded",
    "requests.exceptions",
];

function friendlyBackendMessage() {
    return "LLM backend temporarily unavailable. Please try again shortly.";
}

function normalizeText(value) {
    return typeof value === "string" ? value.trim() : "";
}

function containsTechnicalError(value) {
    const text = normalizeText(value).toLowerCase();
    if (!text) {
        return false;
    }
    return TECHNICAL_ERROR_MARKERS.some((marker) => text.includes(marker));
}

function actionTone(action) {
    switch ((action || "").toLowerCase()) {
        case "allow":
            return "safe";
        case "log":
        case "sanitize":
            return "suspicious";
        case "block":
        case "quarantine":
            return "malicious";
        default:
            return "neutral";
    }
}

function applyChipTone(element, value, tone) {
    element.textContent = value || "unknown";
    element.className = `status-chip ${tone}`;
}

function makeChip(text, className = "") {
    const chip = document.createElement("li");
    chip.textContent = text;
    chip.className = className || "source-chip";
    return chip;
}

function showWarning(tone, message) {
    warningBanner.className = `warning-banner ${tone}`;
    warningBanner.textContent = message;
    warningBanner.classList.remove("hidden");
}

function hideWarning() {
    warningBanner.classList.add("hidden");
    warningBanner.textContent = "";
}

function renderSources(sources) {
    resultSources.innerHTML = "";
    if (!sources || sources.length === 0) {
        resultSources.appendChild(makeChip("No retrieved sources", "source-chip empty-chip"));
        return;
    }

    sources.forEach((source) => {
        resultSources.appendChild(makeChip(source, "source-chip"));
    });
}

function buildReasonList(reasons) {
    if (!Array.isArray(reasons) || reasons.length === 0) {
        return null;
    }

    const list = document.createElement("ul");
    list.className = "chip-list";
    reasons.forEach((reason) => {
        list.appendChild(makeChip(reason, ""));
    });
    return list;
}

function renderChunks(chunks) {
    resultChunks.innerHTML = "";
    if (!chunks || chunks.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty-state";
        empty.textContent = "Retrieved chunk details will appear here.";
        resultChunks.appendChild(empty);
        return;
    }

    chunks.forEach((chunk) => {
        const card = document.createElement("article");
        card.className = "chunk-card";

        const head = document.createElement("div");
        head.className = "chunk-head";
        head.innerHTML = `
            <strong>${chunk.document_name || "Unknown document"}</strong>
            <span class="status-chip ${chunk.label || "neutral"}">${chunk.label || "unknown"}</span>
        `;

        const meta = document.createElement("div");
        meta.className = "chunk-meta mono-text";
        meta.innerHTML = `
            <span>${chunk.source_path || "Unknown source"}</span>
            <span>chunk ${(chunk.chunk_index ?? 0) + 1}</span>
            <span>retrieval ${Number(chunk.score || 0).toFixed(3)}</span>
            <span>risk ${Number(chunk.risk_score || 0).toFixed(3)}</span>
            <span>action ${chunk.action || "unknown"}</span>
        `;

        const body = document.createElement("div");
        body.className = "chunk-body";
        body.textContent = chunk.text || "";

        card.appendChild(head);
        card.appendChild(meta);
        card.appendChild(body);

        const reasonList = buildReasonList(chunk.reasons);
        if (reasonList) {
            card.appendChild(reasonList);
        }

        resultChunks.appendChild(card);
    });
}

function renderResponseText(result) {
    const responseText = normalizeText(result.response);
    if (!responseText) {
        return "No final LLM response was produced.";
    }
    if (containsTechnicalError(responseText)) {
        return friendlyBackendMessage();
    }
    return responseText;
}

function renderResult(result) {
    const label = normalizeText(result.label) || "unknown";
    const action = normalizeText(result.action) || "unknown";
    const reason = normalizeText(result.reason) || "No reason returned";
    const safeResponse = renderResponseText(result);

    applyChipTone(resultLabel, label, label);
    applyChipTone(resultAction, action, actionTone(action));
    resultRisk.textContent = Number(result.risk_score || 0).toFixed(3);
    resultDocument.textContent = result.retrieved_document || "No document retrieved";
    resultReason.textContent = reason;
    resultResponse.textContent = safeResponse;

    renderSources(result.retrieved_sources || []);
    renderChunks(result.retrieved_chunks || []);

    if (containsTechnicalError(result.response)) {
        showWarning("suspicious", friendlyBackendMessage());
        return;
    }

    if (label === "safe") {
        hideWarning();
        return;
    }

    showWarning(label, `${label.toUpperCase()} result: action=${action.toUpperCase()} | ${reason}`);
}

function extractFriendlyErrorMessage(data, fallbackText) {
    if (containsTechnicalError(data?.detail) || containsTechnicalError(fallbackText)) {
        return friendlyBackendMessage();
    }
    return "Request could not be completed. Please try again shortly.";
}

async function submitQuery(event) {
    event.preventDefault();
    const prompt = promptField.value.trim();
    if (!prompt) {
        return;
    }

    submitButton.disabled = true;
    submitButton.textContent = "Evaluating...";

    try {
        const response = await fetch("/ask", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ prompt }),
        });

        const contentType = response.headers.get("content-type") || "";
        let data = {};
        let fallbackText = "";

        if (contentType.includes("application/json")) {
            data = await response.json();
        } else {
            fallbackText = await response.text();
            data = { detail: fallbackText || "Request failed" };
        }

        if (!response.ok) {
            throw new Error(extractFriendlyErrorMessage(data, fallbackText));
        }

        renderResult(data);
    } catch (_error) {
        showWarning("malicious", friendlyBackendMessage());
        resultResponse.textContent = "Please try again shortly.";
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = "Run Secure Query";
    }
}

form.addEventListener("submit", submitQuery);
