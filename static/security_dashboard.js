function applySecurityFilters() {
    const filters = {};
    document.querySelectorAll("[data-filter]").forEach((select) => {
        filters[select.dataset.filter] = select.value;
    });
    document.querySelectorAll("[data-event-row]").forEach((row) => {
        const matches = (!filters.action || row.dataset.action === filters.action)
            && (!filters.stage || row.dataset.stage === filters.stage)
            && (!filters.severity || row.dataset.severity === filters.severity)
            && (!filters.mode || row.dataset.mode === filters.mode)
            && (!filters.role || row.dataset.role === filters.role);
        row.hidden = !matches;
    });
}

document.querySelectorAll("[data-filter]").forEach((select) => select.addEventListener("change", applySecurityFilters));

const eventModal = document.getElementById("event-detail-modal");
document.querySelectorAll("[data-open-event]").forEach((button) => {
    button.addEventListener("click", () => {
        let event = {};
        try {
            event = JSON.parse(button.closest("[data-event-row]").dataset.event || "{}");
        } catch (_error) {
            event = {reason: "Event details could not be decoded."};
        }
        eventModal.querySelector('[data-detail="prompt"]').textContent = event.prompt || "—";
        eventModal.querySelector('[data-detail="role"]').textContent = event.user_role || "public_user / legacy event";
        eventModal.querySelector('[data-detail="scope"]').textContent = event.portal_scope || "global / not recorded";
        eventModal.querySelector('[data-detail="decision"]').textContent = `${event.action || "unknown"} / ${event.label || "unknown"}`;
        eventModal.querySelector('[data-detail="risk"]').textContent = `${Math.round((event.risk_score || 0) * 100)}%`;
        eventModal.querySelector('[data-detail="stage"]').textContent = event.threat_source || "none";
        eventModal.querySelector('[data-detail="qwen"]').textContent = event.response ? "called / response logged" : "not called or no response";
        eventModal.querySelector('[data-detail="output"]').textContent = event.output_firewall_action || "not triggered";
        eventModal.querySelector('[data-detail="reason"]').textContent = event.reason || "No explanation recorded.";
        eventModal.querySelector('[data-detail="technical"]').textContent = JSON.stringify({
            retrieved_sources: event.retrieved_sources || [],
            retrieved_chunks: event.retrieved_chunks || [],
            tool_name: event.tool_name,
            tool_allowed: event.tool_allowed,
            canary_markers: event.canary_markers || [],
            detector_scores: {
                rule: event.rule_score,
                semantic: event.semantic_score,
                ml: event.ml_score,
            },
        }, null, 2);
        eventModal.showModal();
    });
});
document.querySelector("[data-close-event]")?.addEventListener("click", () => eventModal.close());
eventModal?.addEventListener("click", (event) => {
    if (event.target === eventModal) eventModal.close();
});
