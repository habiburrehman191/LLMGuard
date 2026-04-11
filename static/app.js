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

function makeChip(text, className = "") {
    const chip = document.createElement("li");
    chip.textContent = text;
    if (className) {
        chip.className = className;
    }
    return chip;
}

function renderWarning(label, action, reason) {
    warningBanner.className = `warning-banner ${label}`;
    warningBanner.textContent = `${label.toUpperCase()} result: action=${action.toUpperCase()} | ${reason}`;
    warningBanner.classList.remove("hidden");
}

function renderSources(sources) {
    resultSources.innerHTML = "";
    if (!sources || sources.length === 0) {
        resultSources.appendChild(makeChip("No retrieved sources", "empty-chip"));
        return;
    }

    sources.forEach((source) => {
        resultSources.appendChild(makeChip(source));
    });
}

function renderChunks(chunks) {
    resultChunks.innerHTML = "";
    if (!chunks || chunks.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty-state";
        empty.textContent = "No chunk metadata was returned.";
        resultChunks.appendChild(empty);
        return;
    }

    chunks.forEach((chunk) => {
        const card = document.createElement("article");
        card.className = "chunk-card";

        const head = document.createElement("div");
        head.className = "chunk-head";
        head.innerHTML = `
            <strong>${chunk.document_name}</strong>
            <span class="tag ${chunk.label}">${chunk.label}</span>
        `;

        const meta = document.createElement("div");
        meta.className = "chunk-meta mono";
        meta.innerHTML = `
            <span>${chunk.source_path}</span>
            <span>chunk ${chunk.chunk_index + 1}</span>
            <span>retrieval ${Number(chunk.score || 0).toFixed(3)}</span>
            <span>risk ${Number(chunk.risk_score || 0).toFixed(3)}</span>
            <span>action ${chunk.action}</span>
        `;

        const body = document.createElement("div");
        body.className = "chunk-body";
        body.textContent = chunk.text;

        card.appendChild(head);
        card.appendChild(meta);
        card.appendChild(body);

        if (chunk.reasons && chunk.reasons.length > 0) {
            const list = document.createElement("ul");
            list.className = "chip-list";
            chunk.reasons.forEach((reason) => {
                list.appendChild(makeChip(reason));
            });
            card.appendChild(list);
        }

        resultChunks.appendChild(card);
    });
}

function renderResult(result) {
    resultLabel.textContent = result.label || "unknown";
    resultAction.textContent = result.action || "unknown";
    resultRisk.textContent = Number(result.risk_score || 0).toFixed(3);
    resultDocument.textContent = result.retrieved_document || "No document retrieved";
    resultReason.textContent = result.reason || "No reason returned";
    resultResponse.textContent = result.response || "No final LLM response was produced.";

    renderSources(result.retrieved_sources || []);
    renderChunks(result.retrieved_chunks || []);

    if (result.label === "safe") {
        warningBanner.classList.add("hidden");
        warningBanner.textContent = "";
    } else {
        renderWarning(result.label, result.action, result.reason || "Elevated query detected");
    }
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

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.detail || "Request failed");
        }

        renderResult(data);
    } catch (error) {
        warningBanner.className = "warning-banner malicious";
        warningBanner.textContent = `REQUEST ERROR: ${error.message}`;
        warningBanner.classList.remove("hidden");
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = "Submit Query";
    }
}

form.addEventListener("submit", submitQuery);
