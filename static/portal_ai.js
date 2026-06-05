const scope = document.body.dataset.portalScope;
const firewallToggle = document.getElementById("firewall-active");
const askButton = document.getElementById("portal-ask");
const promptField = document.getElementById("portal-prompt");
const answerBox = document.getElementById("portal-answer");
const uploadButton = document.getElementById("portal-upload");
const uploadTitle = document.getElementById("upload-title");
const uploadFilename = document.getElementById("upload-filename");
const uploadContent = document.getElementById("upload-content");
const uploadResult = document.getElementById("upload-result");

function endpoint(path) {
    return `/${scope}${path}`;
}

function token() {
    return window.localStorage.getItem("llmguard_token") || "";
}

async function postJson(url, body) {
    const response = await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token()}`,
        },
        body: JSON.stringify(body),
    });
    const payload = await response.json();
    if (!response.ok) {
        throw new Error(payload.detail || "Request failed");
    }
    return payload;
}

firewallToggle?.addEventListener("change", () => {
    document.body.classList.toggle("red-team-mode", !firewallToggle.checked);
});

askButton?.addEventListener("click", async () => {
    answerBox.classList.remove("error");
    answerBox.textContent = "Running portal assistant...";
    try {
        const payload = await postJson(endpoint("/ai/ask"), {
            prompt: promptField.value,
            firewall_active: firewallToggle.checked,
        });
        answerBox.textContent = JSON.stringify(payload, null, 2);
    } catch (error) {
        answerBox.classList.add("error");
        answerBox.textContent = `${error.message}\n\nLogin first and store the bearer token in localStorage as llmguard_token.`;
    }
});

uploadButton?.addEventListener("click", async () => {
    uploadResult.classList.remove("error");
    uploadResult.textContent = "Uploading synthetic document...";
    try {
        const payload = await postJson(endpoint("/documents/upload"), {
            title: uploadTitle.value,
            filename: uploadFilename.value,
            content: uploadContent.value,
        });
        uploadResult.textContent = JSON.stringify(payload, null, 2);
    } catch (error) {
        uploadResult.classList.add("error");
        uploadResult.textContent = error.message;
    }
});
