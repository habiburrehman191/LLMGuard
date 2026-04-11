const form = document.getElementById("query-form");
const promptField = document.getElementById("prompt");
const submitButton = document.getElementById("submit-button");

const warningBanner = document.getElementById("warning-banner");
const resultLabel = document.getElementById("result-label");
const resultAction = document.getElementById("result-action");
const resultRisk = document.getElementById("result-risk");
const resultDocument = document.getElementById("result-document");
const resultPrimarySource = document.getElementById("result-primary-source");
const resultReason = document.getElementById("result-reason");
const resultEvidenceSummary = document.getElementById("result-evidence-summary");
const resultResponse = document.getElementById("result-response");
const resultSources = document.getElementById("result-sources");
const backendStatusChip = document.getElementById("backend-status-chip");
const resultBackendStatus = document.getElementById("result-backend-status");
const secondaryEvidence = document.getElementById("secondary-evidence");
const secondarySourceCount = document.getElementById("secondary-source-count");

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
const DIAGNOSTIC_REASON_MARKERS = [
    "semantic signal matched",
    "matched dangerous pattern",
    "ml classifier labeled",
    "known poisoned source set",
];

function friendlyBackendMessage() {
    return "LLM backend temporarily unavailable. Please try again shortly.";
}

function normalizeText(value) {
    return typeof value === "string" ? value.trim() : "";
}

function humanizeSourceTitle(value) {
    const text = normalizeText(value);
    if (!text) {
        return "No document retrieved";
    }

    const lastSegment = text.split(/[\\/]/).pop() || text;
    const withoutExtension = lastSegment.replace(/\.[^.]+$/, "");
    return withoutExtension
        .replace(/[_-]+/g, " ")
        .replace(/\s+/g, " ")
        .trim()
        .replace(/\b\w/g, (character) => character.toUpperCase());
}

function dedupeStrings(values) {
    const seen = new Set();
    return values.filter((value) => {
        const key = normalizeText(value);
        if (!key || seen.has(key)) {
            return false;
        }
        seen.add(key);
        return true;
    });
}

function containsTechnicalError(value) {
    const text = normalizeText(value).toLowerCase();
    return text && TECHNICAL_ERROR_MARKERS.some((marker) => text.includes(marker));
}

function userFacingReason(result) {
    const reason = normalizeText(result.reason) || "No reason returned";
    const normalized = reason.toLowerCase();
    if (DIAGNOSTIC_REASON_MARKERS.some((marker) => normalized.includes(marker))) {
        if ((result.action || "").toLowerCase() === "block") {
            return "The request was blocked because it triggered security protections.";
        }
        if ((result.action || "").toLowerCase() === "sanitize") {
            return "Potentially unsafe content was filtered before the answer was shown.";
        }
        return "Security checks adjusted how the answer was prepared.";
    }
    return reason;
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

function applyChipTone(element, text, tone) {
    element.textContent = text || "unknown";
    element.className = `status-chip ${tone}`;
}

function setBackendStatus(text, tone) {
    applyChipTone(backendStatusChip, text, tone);
    applyChipTone(resultBackendStatus, text, tone);
}

function makeChip(text, className = "source-chip") {
    const chip = document.createElement("li");
    chip.textContent = text;
    chip.className = className;
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

function renderEvidence(result) {
    const chunks = Array.isArray(result.retrieved_chunks) ? result.retrieved_chunks : [];
    const topChunk = chunks[0] || null;
    const chunkTitles = dedupeStrings(chunks.map((chunk) => normalizeText(chunk.document_name)));
    const primaryTitle = humanizeSourceTitle(topChunk?.document_name || result.retrieved_document);
    const primarySummary = normalizeText(result.evidence_summary) || "No primary source yet";
    const primaryDescriptor = topChunk
        ? (topChunk.is_poisoned ? "Retrieved policy source" : "Preferred policy source")
        : "No primary source yet";

    const secondarySources = dedupeStrings([
        ...chunkTitles
            .filter((title) => normalizeText(title) && normalizeText(title) !== normalizeText(topChunk?.document_name || ""))
            .map((title) => humanizeSourceTitle(title)),
    ]);

    resultDocument.textContent = primaryTitle;
    resultPrimarySource.textContent = primaryDescriptor;
    resultEvidenceSummary.textContent = primarySummary;
    secondarySourceCount.textContent = String(secondarySources.length);
    resultSources.innerHTML = "";

    if (secondarySources.length === 0) {
        secondaryEvidence.open = false;
        resultSources.appendChild(makeChip("No additional evidence", "source-chip empty-chip"));
        return;
    }

    secondarySources.forEach((source) => {
        resultSources.appendChild(makeChip(source));
    });
}

function sanitizedResponseText(result) {
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
    const reason = userFacingReason(result);
    const backendOffline = containsTechnicalError(result.response);

    applyChipTone(resultLabel, label, label);
    applyChipTone(resultAction, action, toneForAction(action));
    resultRisk.textContent = Number(result.risk_score || 0).toFixed(3);
    resultReason.textContent = reason;
    resultResponse.textContent = sanitizedResponseText(result);

    renderEvidence(result);

    if (backendOffline) {
        setBackendStatus("LLM Offline", "malicious");
        showWarning("suspicious", friendlyBackendMessage());
        return;
    }

    setBackendStatus("LLM Ready", "safe");
    if (label === "safe") {
        hideWarning();
    } else {
        showWarning(label, `${label.toUpperCase()} result: action=${action.toUpperCase()} | ${reason}`);
    }
}

function friendlyErrorMessage(data, fallbackText) {
    if (containsTechnicalError(data?.detail) || containsTechnicalError(fallbackText)) {
        return friendlyBackendMessage();
    }
    return "Request could not be completed. Please try again shortly.";
}

function renderOfflineState() {
    setBackendStatus("LLM Offline", "malicious");
    showWarning("suspicious", friendlyBackendMessage());
    resultResponse.textContent = "Please try again shortly.";
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
            throw new Error(friendlyErrorMessage(data, fallbackText));
        }

        renderResult(data);
    } catch (_error) {
        renderOfflineState();
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = "Run Secure Query";
    }
}

form.addEventListener("submit", submitQuery);
