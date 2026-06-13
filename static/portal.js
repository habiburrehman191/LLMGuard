function fileAsBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result).split(",", 2)[1] || "");
        reader.onerror = () => reject(new Error("Could not read the selected file."));
        reader.readAsDataURL(file);
    });
}

function replaceList(container, values, emptyText) {
    container.replaceChildren();
    const items = values && values.length ? values : [emptyText];
    items.forEach((value) => {
        const item = document.createElement("li");
        item.textContent = String(value);
        container.appendChild(item);
    });
}

function renderGatewayResult(payload) {
    const result = document.querySelector("[data-assistant-result]");
    const empty = document.querySelector("[data-assistant-empty]");
    if (!result) return;
    result.hidden = false;
    result.classList.remove("state-allow", "state-block", "state-quarantine", "state-sanitize");
    result.classList.add(`state-${payload.action || "block"}`);
    if (empty) empty.hidden = true;
    const answer = payload.answer || payload.response || (payload.blocked ? "Request blocked by LLMGuard." : "No answer returned.");
    result.querySelector("[data-result-answer]").textContent = answer;
    document.getElementById("copy-answer")?.removeAttribute("disabled");
    const protectedResult = payload.mode !== "vulnerable_red_team";
    const modelSkipped = protectedResult && !payload.llm_called;
    result.querySelector("[data-result-title]").textContent = modelSkipped
        ? "Threat stopped before model execution"
        : payload.mode === "vulnerable_red_team"
            ? "Vulnerable baseline result"
            : "Protected gateway result";
    const badge = result.querySelector("[data-result-action]");
    badge.textContent = payload.action || "unknown";
    badge.className = `status-badge action-${payload.action || "unknown"} is-active`;
    result.querySelector("[data-result-label]").textContent = payload.label || "unknown";
    result.querySelector("[data-result-action-text]").textContent = payload.action || "unknown";
    result.querySelector("[data-result-risk]").textContent = `${Math.round((payload.risk_score || 0) * 100)}%`;
    result.querySelector("[data-result-source]").textContent = payload.threat_source || "none";
    result.querySelector("[data-result-stage]").textContent = payload.blocked_stage || "none";
    result.querySelector("[data-result-llm]").textContent = payload.llm_called ? "true (llm_called=true)" : "false (llm_called=false)";
    const modelGate = result.querySelector("[data-model-gate-result]");
    if (modelGate) {
        modelGate.classList.toggle("model-skipped", modelSkipped);
        modelGate.classList.toggle("model-called", Boolean(payload.llm_called));
        modelGate.querySelector("[data-model-gate-label]").textContent = modelSkipped
            ? "Qwen skipped / blocked before model call"
            : payload.llm_called
                ? "Qwen called after security gates passed"
                : "No model call recorded";
    }
    result.querySelector("[data-result-output]").textContent = payload.output_firewall_action || "not triggered";
    result.querySelector("[data-result-sanitized]").textContent = payload.sanitized ? "true" : "false";
    replaceList(result.querySelector("[data-result-sources]"), payload.sources || [], "No sources released.");
    replaceList(result.querySelector("[data-result-reasons]"), payload.reasons || [payload.reason].filter(Boolean), "No additional reasons.");
    const evidence = {
        label: payload.label,
        action: payload.action,
        risk_score: payload.risk_score,
        threat_source: payload.threat_source,
        blocked_stage: payload.blocked_stage,
        output_firewall_action: payload.output_firewall_action,
        sanitized: Boolean(payload.sanitized),
        llm_called: Boolean(payload.llm_called),
    };
    result.querySelector("[data-result-evidence]").textContent = JSON.stringify(evidence, null, 2);
    const decisions = Array.isArray(payload.tool_decisions) ? payload.tool_decisions : [];
    result.querySelector("[data-result-tools]").textContent = JSON.stringify(decisions, null, 2);
    const toolCards = result.querySelector("[data-result-tool-cards]");
    toolCards.replaceChildren();
    if (!decisions.length) {
        const emptyTool = document.createElement("p");
        emptyTool.className = "inline-note";
        emptyTool.textContent = "No tool call was requested.";
        toolCards.appendChild(emptyTool);
    } else {
        decisions.forEach((decision) => {
            const allowed = Boolean(decision.allowed);
            const card = document.createElement("article");
            card.className = `tool-decision-card ${allowed ? "allowed" : "blocked"}`;
            const title = document.createElement("strong");
            title.textContent = `${allowed ? "Allowed" : "Blocked"}: ${decision.tool_name || decision.requested_tool || "tool"}`;
            const reason = document.createElement("small");
            reason.textContent = decision.reason || "No decision reason returned.";
            card.append(title, reason);
            toolCards.appendChild(card);
        });
    }
    result.querySelector("[data-result-raw]").textContent = JSON.stringify(payload, null, 2);
}

const progressLabels = {
    prompt: "Analyzing request intent",
    rbac: "Verifying role and portal boundary",
    rag: "Filtering retrieval metadata",
    context: "Scanning authorized context",
    tool: "Authorizing tool access",
    output: "Inspecting generated output",
};

function setAssistantProgress(activeStep = "", terminalState = "") {
    const progress = document.querySelector("[data-assistant-progress]");
    if (!progress) return;
    progress.classList.remove("state-allow", "state-block", "state-quarantine", "state-sanitize");
    progress.classList.toggle("active", Boolean(activeStep || terminalState));
    if (terminalState) progress.classList.add(`state-${terminalState}`);
    progress.querySelectorAll("[data-progress-step]").forEach((step) => {
        step.classList.toggle("active", step.dataset.progressStep === activeStep);
        step.classList.toggle("complete", Boolean(terminalState) && ["allow", "sanitize"].includes(terminalState));
    });
    const label = progress.querySelector("[data-progress-label]");
    if (label) {
        label.textContent = terminalState === "allow"
            ? "Secured response released"
            : terminalState === "sanitize"
                ? "Response sanitized and released"
                : terminalState === "quarantine"
                    ? "Request quarantined for review"
                    : terminalState === "block"
                        ? "Threat blocked / Qwen skipped"
                        : progressLabels[activeStep] || "Gateway ready";
    }
}

function schedulePipelineProgress() {
    const steps = ["prompt", "rbac", "rag", "context", "tool", "output"];
    const timers = steps.map((step, index) => window.setTimeout(() => setAssistantProgress(step), index * 260));
    return () => timers.forEach((timer) => window.clearTimeout(timer));
}

const askButton = document.getElementById("portal-ask");
if (askButton) {
    const modeSelect = document.querySelector("[data-mode-select]");
    const modeIndicator = document.querySelector("[data-mode-indicator]");
    modeSelect?.addEventListener("change", () => {
        const protectedMode = modeSelect.value === "true";
        modeIndicator.textContent = protectedMode ? "Protected Mode" : "Vulnerable Red-Team Mode";
        modeIndicator.className = `status-badge ${protectedMode ? "protected-badge" : "vulnerable-badge"}`;
    });
    askButton.addEventListener("click", async () => {
        askButton.disabled = true;
        askButton.textContent = "Inspecting request...";
        setAssistantProgress("prompt");
        const clearPipelineTimers = schedulePipelineProgress();
        try {
            const scope = document.body.dataset.portalScope;
            const payload = await apiRequest(`/${scope}/ai/ask`, {
                method: "POST",
                body: JSON.stringify({
                    prompt: document.getElementById("portal-prompt").value,
                    firewall_active: modeSelect ? modeSelect.value === "true" : true,
                }),
            });
            renderGatewayResult(payload);
            setAssistantProgress("", payload.action || "allow");
        } catch (error) {
            renderGatewayResult({
                action: "block",
                label: "error",
                risk_score: 1,
                blocked: true,
                reasons: [error.message],
                llm_called: false,
                blocked_stage: "request",
            });
            setAssistantProgress("", "block");
        } finally {
            clearPipelineTimers();
            askButton.disabled = false;
            askButton.textContent = "Run through AI Gateway";
        }
    });
}

document.getElementById("copy-answer")?.addEventListener("click", async () => {
    const answer = document.querySelector("[data-result-answer]")?.textContent || "";
    if (!answer) return;
    const button = document.getElementById("copy-answer");
    try {
        await navigator.clipboard.writeText(answer);
        button.textContent = "Copied";
    } catch (_error) {
        button.textContent = "Copy unavailable";
    }
    window.setTimeout(() => { button.textContent = "Copy answer"; }, 1200);
});

document.getElementById("clear-assistant")?.addEventListener("click", () => {
    const result = document.querySelector("[data-assistant-result]");
    const empty = document.querySelector("[data-assistant-empty]");
    if (result) result.hidden = true;
    if (empty) empty.hidden = false;
    const prompt = document.getElementById("portal-prompt");
    if (prompt) prompt.value = "";
    const copyButton = document.getElementById("copy-answer");
    if (copyButton) copyButton.disabled = true;
    setAssistantProgress("");
});

document.querySelectorAll("[data-drop-zone]").forEach((zone) => {
    const input = zone.querySelector('input[type="file"]');
    ["dragenter", "dragover"].forEach((eventName) => zone.addEventListener(eventName, (event) => {
        event.preventDefault();
        zone.classList.add("dragging");
    }));
    ["dragleave", "drop"].forEach((eventName) => zone.addEventListener(eventName, (event) => {
        event.preventDefault();
        zone.classList.remove("dragging");
    }));
    zone.addEventListener("drop", (event) => {
        if (input && event.dataTransfer.files.length) input.files = event.dataTransfer.files;
    });
});

const portalUpload = document.getElementById("portal-upload");
if (portalUpload) {
    portalUpload.addEventListener("click", async () => {
        const file = document.getElementById("upload-file").files[0];
        const message = document.getElementById("upload-result");
        if (!file) {
            message.className = "form-message error";
            message.textContent = "Choose a TXT, PDF, or DOCX file.";
            return;
        }
        message.className = "form-message";
        message.textContent = "Processing controlled upload...";
        const progress = document.querySelector("[data-upload-progress]");
        progress?.classList.add("active");
        try {
            const scope = document.body.dataset.portalScope;
            const payload = await apiRequest(`/${scope}/documents/upload`, {
                method: "POST",
                body: JSON.stringify({
                    title: document.getElementById("upload-title").value || file.name,
                    filename: file.name,
                    content_base64: await fileAsBase64(file),
                }),
            });
            message.className = "form-message success";
            message.textContent = `Uploaded ${payload.source_filename || file.name}; ${payload.chunks} chunks created.`;
        } catch (error) {
            message.className = "form-message error";
            message.textContent = error.message;
        } finally {
            progress?.classList.remove("active");
        }
    });
}

function renderCompareSide(name, payload) {
    document.querySelector(`[data-compare-answer="${name}"]`).textContent = payload.answer || payload.response || (payload.blocked ? "Blocked before answer generation." : "No answer.");
    const meta = document.querySelector(`[data-compare-meta="${name}"]`);
    meta.replaceChildren();
    [
        ["Action", payload.action],
        ["Blocked stage", payload.blocked_stage || "none"],
        ["Risk score", `${Math.round((payload.risk_score || 0) * 100)}%`],
        ["Qwen called", String(Boolean(payload.llm_called))],
    ].forEach(([term, value]) => {
        const wrapper = document.createElement("div");
        const dt = document.createElement("dt");
        const dd = document.createElement("dd");
        dt.textContent = term;
        dd.textContent = value || "—";
        wrapper.append(dt, dd);
        meta.appendChild(wrapper);
    });
    document.querySelector(`[data-compare-detail="${name}"]`).textContent = JSON.stringify({
        sources: payload.sources,
        reasons: payload.reasons,
        tool_decisions: payload.tool_decisions,
        output_firewall_action: payload.output_firewall_action,
    }, null, 2);
}

const compareButton = document.getElementById("run-compare");
if (compareButton) {
    compareButton.addEventListener("click", async () => {
        const message = document.getElementById("compare-message");
        const panels = document.querySelectorAll(".compare-panel");
        compareButton.disabled = true;
        panels.forEach((panel) => panel.classList.add("loading"));
        message.textContent = "Running both gateway modes...";
        try {
            const payload = await apiRequest("/admin/compare/run", {
                method: "POST",
                body: JSON.stringify({
                    prompt: document.getElementById("compare-prompt").value,
                    user_role: document.getElementById("compare-role").value,
                    portal_scope: document.getElementById("compare-scope").value,
                    user_id: document.getElementById("compare-user-id").value || null,
                }),
            });
            renderCompareSide("vulnerable", payload.vulnerable);
            renderCompareSide("protected", payload.protected);
            document.getElementById("compare-verdict").textContent = payload.verdict;
            document.querySelector(".verdict-card")?.classList.add("decided");
            message.textContent = "";
        } catch (error) {
            message.className = "form-message error";
            message.textContent = error.message;
        } finally {
            panels.forEach((panel) => panel.classList.remove("loading"));
            compareButton.disabled = false;
        }
    });
}

const managerUpload = document.getElementById("manager-upload");
if (managerUpload) {
    managerUpload.addEventListener("click", async () => {
        const file = document.getElementById("manager-file").files[0];
        const message = document.getElementById("manager-message");
        if (!file) {
            message.className = "form-message error";
            message.textContent = "Choose a controlled file.";
            return;
        }
        try {
            message.textContent = "Uploading and chunking...";
            const progress = document.querySelector("[data-upload-progress]");
            progress?.classList.add("active");
            const payload = await apiRequest("/admin/documents/upload-manager", {
                method: "POST",
                body: JSON.stringify({
                    title: document.getElementById("manager-title").value || file.name,
                    filename: file.name,
                    content_base64: await fileAsBase64(file),
                    portal_scope: document.getElementById("manager-scope").value,
                    classification: document.getElementById("manager-classification").value,
                }),
            });
            message.className = "form-message success";
            message.textContent = `${payload.document_id} created with ${payload.chunks} chunks. Reloading inventory...`;
            window.location.reload();
        } catch (error) {
            message.className = "form-message error";
            message.textContent = error.message;
        } finally {
            document.querySelector("[data-upload-progress]")?.classList.remove("active");
        }
    });
}

document.getElementById("rebuild-index")?.addEventListener("click", async () => {
    const message = document.getElementById("index-message");
    message.textContent = "Rebuilding FAISS index...";
    try {
        const payload = await apiRequest("/admin/documents/rebuild", {method: "POST"});
        message.className = "form-message success";
        message.textContent = `Index rebuilt with ${payload.total_chunks} chunks.`;
    } catch (error) {
        message.className = "form-message error";
        message.textContent = error.message;
    }
});

document.querySelectorAll("[data-delete-document]").forEach((button) => {
    button.addEventListener("click", async () => {
        if (!window.confirm("Delete this controlled document and its database chunks?")) return;
        try {
            await apiRequest(`/admin/documents/${encodeURIComponent(button.dataset.deleteDocument)}`, {method: "DELETE"});
            window.location.reload();
        } catch (error) {
            window.alert(error.message);
        }
    });
});
