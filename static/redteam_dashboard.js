const runSuite = document.getElementById("run-redteam-suite");
runSuite?.addEventListener("click", async () => {
    const message = document.getElementById("redteam-message");
    runSuite.disabled = true;
    if (message) message.textContent = "Starting controlled replay suite...";
    try {
        const payload = await apiRequest("/admin/redteam/run", {method: "POST"});
        if (message) {
            message.className = "form-message success";
            message.textContent = payload.detail || "Replay suite completed.";
        }
    } catch (error) {
        if (message) {
            message.className = "form-message error";
            message.textContent = error.message;
        }
    } finally {
        runSuite.disabled = false;
    }
});
