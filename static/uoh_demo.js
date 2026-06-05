const promptField = document.getElementById("demo-prompt");
const modeToggle = document.getElementById("mode-toggle");
const modeLabel = document.getElementById("mode-label");
const roleSelect = document.getElementById("role-select");
const userIdSelect = document.getElementById("user-id-select");
const roleBadge = document.getElementById("role-badge");
const askSelectedButton = document.getElementById("ask-selected");
const compareBothButton = document.getElementById("compare-both");
const singleResult = document.getElementById("single-result");
const unprotectedResponse = document.getElementById("unprotected-response");
const protectedResponse = document.getElementById("protected-response");
const unprotectedMeta = document.getElementById("unprotected-meta");
const protectedMeta = document.getElementById("protected-meta");
const toolDecision = document.getElementById("tool-decision");
const accessDecision = document.getElementById("access-decision");
const outputDecision = document.getElementById("output-decision");
const classificationBadges = document.getElementById("classification-badges");
const attackButtons = Array.from(document.querySelectorAll("[data-prompt]"));

let activeScenario = "uoh_safe_admission_question";

function normalizeText(value) {
    return typeof value === "string" ? value.trim() : "";
}

function displayResponse(payload) {
    const blocked = Boolean(payload.blocked);
    const answer = normalizeText(payload.response);
    if (blocked) {
        return `Blocked by LLMGuard.\n\nReason: ${normalizeText(payload.reason) || "Security policy blocked this request."}`;
    }
    return answer || "No final answer was produced.";
}

function qwenStatus(payload) {
    return payload.qwen_called ? "called" : "skipped";
}

function toolSummary(payload) {
    const tool = payload.tool_call || {};
    if (!tool.name) {
        return "none";
    }
    return `${tool.name} (${tool.allowed ? "allowed" : "blocked"})`;
}

function roleLabel(value) {
    return String(value || "public_user")
        .split("_")
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join(" ");
}

function renderMeta(element, payload) {
    const rows = [
        ["Label", payload.label || "unknown"],
        ["Action", payload.action || "unknown"],
        ["Risk score", Number(payload.risk_score || 0).toFixed(3)],
        ["Threat source", payload.threat_source || "none"],
        ["Reason / detector", payload.reason || "N/A"],
        ["Qwen", qwenStatus(payload)],
        ["Tool call", toolSummary(payload)],
    ];

    element.innerHTML = rows
        .map(([key, value]) => `<div><dt>${escapeHtml(key)}</dt><dd>${escapeHtml(value)}</dd></div>`)
        .join("");
}

function renderProtectedDecisionCards(payload) {
    const tool = payload.tool_call || {};
    toolDecision.textContent = tool.name
        ? `${tool.name}: ${tool.allowed ? "allowed" : "blocked"} — ${tool.reason || "No reason provided."}`
        : "No tool decision returned.";

    const access = payload.access_control || {};
    accessDecision.textContent = access.reason
        ? `${access.allowed ? "Authorized" : "Unauthorized"} — ${access.reason}`
        : "No access-control decision returned.";

    const output = payload.output_firewall || {};
    outputDecision.textContent = output.action
        ? `${output.action} — ${(output.reasons || []).join("; ") || "No leakage detected."}`
        : "No output firewall decision returned.";

    const chunks = Array.isArray(payload.retrieved_chunks) ? payload.retrieved_chunks : [];
    const unauthorized = Array.isArray(payload.unauthorized_retrievals) ? payload.unauthorized_retrievals : [];
    const classifications = new Set(chunks.map((chunk) => chunk.classification || "public"));
    unauthorized.forEach((item) => classifications.add(`${item.classification || "restricted"} blocked`));
    classificationBadges.innerHTML = classifications.size
        ? Array.from(classifications)
            .map((classification) => `<span class="classification-badge">${escapeHtml(classification)}</span>`)
            .join("")
        : "No retrieved document classifications yet.";
}

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

async function postJson(url, body) {
    const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
    });
    const payload = await response.json();
    if (!response.ok) {
        throw new Error(payload.detail || "Request failed");
    }
    return payload;
}

async function askUnprotected(prompt, scenario) {
    return postJson("/demo/ask-unprotected", {
        prompt,
        scenario,
        demo_context: "uoh",
    });
}

async function askProtected(prompt, scenario) {
    const payload = await postJson("/ask", {
        prompt,
        user_role: roleSelect.value,
        user_id: userIdSelect.value || null,
    });
    await postJson("/demo/audit", {
        prompt,
        scenario,
        mode: "protected",
        action: payload.action || "unknown",
        label: payload.label || "unknown",
        blocked: Boolean(payload.blocked),
        risk_score: Number(payload.risk_score || 0),
        threat_source: payload.threat_source || "none",
        tool_call: payload.tool_call || null,
        qwen_called: Boolean(payload.qwen_called),
        reason: payload.reason || "",
    }).catch(() => {});
    return payload;
}

function setLoading(isLoading) {
    document.body.classList.toggle("is-loading", isLoading);
    askSelectedButton.disabled = isLoading;
    compareBothButton.disabled = isLoading;
    attackButtons.forEach((button) => {
        button.disabled = isLoading;
    });
}

function renderComparison(unprotected, protectedPayload) {
    unprotectedResponse.textContent = displayResponse(unprotected);
    protectedResponse.textContent = displayResponse(protectedPayload);
    protectedResponse.classList.toggle("blocked", Boolean(protectedPayload.blocked));
    renderMeta(unprotectedMeta, unprotected);
    renderMeta(protectedMeta, protectedPayload);
    renderProtectedDecisionCards(protectedPayload);
}

async function compareBoth() {
    const prompt = promptField.value.trim();
    if (!prompt) {
        return;
    }

    setLoading(true);
    unprotectedResponse.textContent = "Running unprotected baseline assistant...";
    protectedResponse.textContent = "Running LLMGuard protected pipeline...";

    try {
        const [unprotected, protectedPayload] = await Promise.all([
            askUnprotected(prompt, activeScenario),
            askProtected(prompt, activeScenario),
        ]);
        renderComparison(unprotected, protectedPayload);
        singleResult.textContent = "Comparison complete. Review the left and right response panels.";
    } catch (error) {
        singleResult.textContent = "The demo request could not be completed. Check that the app server and local model services are running.";
    } finally {
        setLoading(false);
    }
}

async function askSelectedMode() {
    const prompt = promptField.value.trim();
    if (!prompt) {
        return;
    }

    setLoading(true);
    singleResult.textContent = "Running selected mode...";
    try {
        const payload = modeToggle.checked
            ? await askProtected(prompt, activeScenario)
            : await askUnprotected(prompt, activeScenario);
        singleResult.textContent = displayResponse(payload);
        if (modeToggle.checked) {
            protectedResponse.textContent = displayResponse(payload);
            protectedResponse.classList.toggle("blocked", Boolean(payload.blocked));
            renderMeta(protectedMeta, payload);
            renderProtectedDecisionCards(payload);
        } else {
            unprotectedResponse.textContent = displayResponse(payload);
            renderMeta(unprotectedMeta, payload);
        }
    } catch (error) {
        singleResult.textContent = "The selected mode could not complete the request.";
    } finally {
        setLoading(false);
    }
}

modeToggle.addEventListener("change", () => {
    modeLabel.textContent = modeToggle.checked ? "LLMGuard Protected" : "Unprotected AI";
    modeToggle.nextElementSibling.textContent = modeToggle.checked ? "Protected" : "Unprotected";
});

roleSelect.addEventListener("change", () => {
    roleBadge.textContent = `Selected role: ${roleLabel(roleSelect.value)}`;
    if (roleSelect.value === "student" && !userIdSelect.value) {
        userIdSelect.value = "DEMO-UOH-APP-2026-021";
    }
});

askSelectedButton.addEventListener("click", askSelectedMode);
compareBothButton.addEventListener("click", compareBoth);

attackButtons.forEach((button) => {
    button.addEventListener("click", () => {
        activeScenario = button.dataset.scenario || "uoh_custom";
        promptField.value = button.dataset.prompt || "";
        if (button.dataset.role) {
            roleSelect.value = button.dataset.role;
            roleBadge.textContent = `Selected role: ${roleLabel(roleSelect.value)}`;
        }
        compareBoth();
    });
});
