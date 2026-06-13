function storedToken() {
    return window.localStorage.getItem("llmguard_token") || "";
}

const navToggle = document.querySelector("[data-nav-toggle]");
const productNav = document.querySelector("[data-product-nav-menu]");
if (navToggle && productNav) {
    const closeNavigation = () => {
        productNav.classList.remove("mobile-open");
        navToggle.classList.remove("is-open");
        navToggle.setAttribute("aria-expanded", "false");
        navToggle.setAttribute("aria-label", "Open navigation");
    };
    navToggle.addEventListener("click", () => {
        const opening = !productNav.classList.contains("mobile-open");
        productNav.classList.toggle("mobile-open", opening);
        navToggle.classList.toggle("is-open", opening);
        navToggle.setAttribute("aria-expanded", String(opening));
        navToggle.setAttribute("aria-label", opening ? "Close navigation" : "Open navigation");
    });
    productNav.querySelectorAll("a, button").forEach((item) => item.addEventListener("click", closeNavigation));
    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") closeNavigation();
    });
}

document.querySelectorAll(".workspace-card, .portal-entry, .feature-entry, .security-kpi-grid article, .admin-kpi-grid article, .pipeline-stage, .control-plane li, .llmg-process-card, .boundary-card, .admin-module-grid a, .ndo-bento-card, .ndo-portal-card, .ndo-op-card, .ndo-benefit-grid article, .ndo-pipeline article").forEach((element, index) => {
    element.style.animationDelay = `${Math.min(index * 45, 360)}ms`;
    element.classList.add("llmg-reveal-card");
});

const revealObserver = "IntersectionObserver" in window
    ? new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
            if (entry.isIntersecting) {
                entry.target.classList.add("is-visible");
                revealObserver.unobserve(entry.target);
            }
        });
    }, {threshold: 0.12})
    : null;

document.querySelectorAll(".ndo-section-header, .ndo-bento-card, .ndo-portal-card, .ndo-op-card, .ndo-benefit-grid article, .ndo-pipeline article, .ndo-demo-flow li").forEach((element) => {
    element.classList.add("ndo-reveal");
    if (revealObserver) revealObserver.observe(element);
    else element.classList.add("is-visible");
});

const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
const neuralDefenseSpline = document.querySelector("[data-neural-defense-spline]");
if (neuralDefenseSpline && !reducedMotion.matches && neuralDefenseSpline.querySelector("[data-neural-scene-fallback]")) {
    const updateSceneTilt = (clientX, clientY) => {
        const bounds = neuralDefenseSpline.getBoundingClientRect();
        const x = Math.max(-1, Math.min(1, (clientX - bounds.left) / bounds.width * 2 - 1));
        const y = Math.max(-1, Math.min(1, (clientY - bounds.top) / bounds.height * 2 - 1));
        neuralDefenseSpline.style.setProperty("--scene-rotate-y", `${x * 7}deg`);
        neuralDefenseSpline.style.setProperty("--scene-rotate-x", `${y * -6}deg`);
        neuralDefenseSpline.style.setProperty("--scene-shift-x", `${x * 10}px`);
        neuralDefenseSpline.style.setProperty("--scene-shift-y", `${y * 8}px`);
        neuralDefenseSpline.style.setProperty("--scene-shift-x-neg", `${x * -10}px`);
        neuralDefenseSpline.style.setProperty("--scene-shift-y-neg", `${y * -8}px`);
    };
    neuralDefenseSpline.addEventListener("pointermove", (event) => updateSceneTilt(event.clientX, event.clientY));
    neuralDefenseSpline.addEventListener("pointerleave", () => {
        neuralDefenseSpline.style.removeProperty("--scene-rotate-y");
        neuralDefenseSpline.style.removeProperty("--scene-rotate-x");
        neuralDefenseSpline.style.removeProperty("--scene-shift-x");
        neuralDefenseSpline.style.removeProperty("--scene-shift-y");
        neuralDefenseSpline.style.removeProperty("--scene-shift-x-neg");
        neuralDefenseSpline.style.removeProperty("--scene-shift-y-neg");
    });
}

const demoTabs = Array.from(document.querySelectorAll("[data-demo-tab]"));
const activateDemoTab = (tab) => {
    const target = tab.dataset.demoTab;
    demoTabs.forEach((item) => {
        const active = item === tab;
        item.classList.toggle("active", active);
        item.setAttribute("aria-selected", String(active));
        item.tabIndex = active ? 0 : -1;
    });
    document.querySelectorAll("[data-demo-panel]").forEach((panel) => {
        const active = panel.dataset.demoPanel === target;
        panel.hidden = !active;
        panel.classList.toggle("active", active);
    });
};
demoTabs.forEach((tab, index) => {
    tab.addEventListener("click", () => activateDemoTab(tab));
    tab.addEventListener("keydown", (event) => {
        let nextIndex = index;
        if (event.key === "ArrowRight") nextIndex = (index + 1) % demoTabs.length;
        else if (event.key === "ArrowLeft") nextIndex = (index - 1 + demoTabs.length) % demoTabs.length;
        else if (event.key === "Home") nextIndex = 0;
        else if (event.key === "End") nextIndex = demoTabs.length - 1;
        else return;
        event.preventDefault();
        activateDemoTab(demoTabs[nextIndex]);
        demoTabs[nextIndex].focus();
    });
});

document.querySelectorAll(".security-kpi-grid article, .admin-kpi-grid article").forEach((element) => {
    element.classList.add("am-kpi-card");
});

document.querySelectorAll(".admin-sidebar a").forEach((link) => {
    link.classList.toggle("active", link.getAttribute("href") === window.location.pathname);
});

document.querySelectorAll(".security-kpi-grid strong, .admin-kpi-grid strong, .audit-summary strong").forEach((element) => {
    const target = Number(element.textContent.trim());
    if (!Number.isFinite(target) || target <= 0 || reducedMotion.matches) return;
    const started = performance.now();
    const duration = 550;
    const tick = (now) => {
        const progress = Math.min((now - started) / duration, 1);
        element.textContent = String(Math.round(target * (1 - Math.pow(1 - progress, 3))));
        if (progress < 1) window.requestAnimationFrame(tick);
    };
    window.requestAnimationFrame(tick);
});

async function apiRequest(url, options = {}) {
    const headers = new Headers(options.headers || {});
    const token = storedToken();
    if (token && !headers.has("Authorization")) {
        headers.set("Authorization", `Bearer ${token}`);
    }
    if (options.body && !headers.has("Content-Type")) {
        headers.set("Content-Type", "application/json");
    }
    const response = await fetch(url, {...options, headers});
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new Error(payload.detail || payload.message || `Request failed (${response.status})`);
    }
    return payload;
}

document.querySelectorAll("[data-logout]").forEach((button) => {
    button.addEventListener("click", async () => {
        try {
            await apiRequest("/auth/logout", {method: "POST"});
        } finally {
            window.localStorage.removeItem("llmguard_token");
            window.location.href = "/login";
        }
    });
});

const loginForm = document.getElementById("login-form");
if (loginForm) {
    const username = document.getElementById("username");
    const password = document.getElementById("password");
    const message = document.getElementById("login-message");
    const queryRole = new URLSearchParams(window.location.search).get("role");
    const presets = {
        student: ["student1", "Student@123"],
        employee: ["employee1", "Employee@123"],
        admin: ["admin1", "Admin@123"],
    };
    if (queryRole && presets[queryRole]) {
        [username.value, password.value] = presets[queryRole];
    }
    document.querySelectorAll("[data-seed-user]").forEach((button) => {
        button.addEventListener("click", () => {
            document.querySelectorAll("[data-seed-user]").forEach((item) => item.classList.toggle("selected", item === button));
            username.value = button.dataset.seedUser;
            password.value = button.dataset.seedPassword;
            username.focus();
        });
    });
    loginForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        message.className = "form-message";
        message.textContent = "Verifying local identity...";
        loginForm.classList.add("is-authenticating");
        const submitButton = loginForm.querySelector('button[type="submit"]');
        if (submitButton) {
            submitButton.disabled = true;
            submitButton.textContent = "Authenticating...";
        }
        try {
            const payload = await apiRequest("/auth/login", {
                method: "POST",
                body: JSON.stringify({username: username.value, password: password.value}),
            });
            window.localStorage.setItem("llmguard_token", payload.access_token);
            const destination = payload.role === "student"
                ? "/student/dashboard"
                : payload.role === "employee"
                    ? "/employee/dashboard"
                    : "/admin/dashboard";
            window.location.href = destination;
        } catch (error) {
            message.className = "form-message error";
            message.textContent = error.message;
            loginForm.classList.remove("is-authenticating");
            if (submitButton) {
                submitButton.disabled = false;
                submitButton.textContent = "Continue to portal";
            }
        }
    });
}

document.querySelectorAll("[data-audit-tab]").forEach((button) => {
    button.addEventListener("click", () => {
        const target = button.dataset.auditTab;
        document.querySelectorAll("[data-audit-tab]").forEach((item) => item.classList.toggle("active", item === button));
        document.querySelectorAll("[data-audit-panel]").forEach((panel) => panel.classList.toggle("active", panel.dataset.auditPanel === target));
    });
});
