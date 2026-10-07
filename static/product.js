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
    if (document.body.classList.contains("console-body")) return;
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

const consoleSidebar = document.querySelector(".console-sidebar");
const sidebarToggle = document.querySelector("[data-sidebar-toggle]");
const consoleNavigation = document.querySelector("[data-console-nav]");
if (sidebarToggle && consoleNavigation) {
    const closeConsoleNavigation = () => {
        consoleNavigation.classList.remove("mobile-open");
        consoleSidebar?.classList.remove("is-open");
        sidebarToggle.classList.remove("is-open");
        sidebarToggle.setAttribute("aria-expanded", "false");
        sidebarToggle.setAttribute("aria-label", "Open console navigation");
    };
    sidebarToggle.addEventListener("click", () => {
        const opening = !consoleNavigation.classList.contains("mobile-open");
        consoleNavigation.classList.toggle("mobile-open", opening);
        consoleSidebar?.classList.toggle("is-open", opening);
        sidebarToggle.classList.toggle("is-open", opening);
        sidebarToggle.setAttribute("aria-expanded", String(opening));
        sidebarToggle.setAttribute("aria-label", opening ? "Close console navigation" : "Open console navigation");
    });
    consoleNavigation.querySelectorAll("a").forEach((link) => link.addEventListener("click", closeConsoleNavigation));
    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") closeConsoleNavigation();
    });
}

const consoleSectionForPath = (path) => {
    if (path === "/admin/dashboard") return "dashboard";
    if (path.startsWith("/admin/applications")) return "applications";
    if (
        path.startsWith("/admin/soc") ||
        path === "/admin/security-dashboard" ||
        path.startsWith("/admin/documents") ||
        path.startsWith("/admin/audit")
    ) return "security";
    if (
        path.startsWith("/admin/evaluation") ||
        path.startsWith("/admin/compare") ||
        path.startsWith("/admin/redteam")
    ) return "evaluation";
    return "";
};

const activeConsoleSection = consoleSectionForPath(window.location.pathname);
document.querySelectorAll("[data-console-section]").forEach((link) => {
    const active = link.dataset.consoleSection === activeConsoleSection;
    link.classList.toggle("active", active);
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
});

const userMenuToggle = document.querySelector("[data-user-menu-toggle]");
const userMenu = document.querySelector("[data-user-menu]");
if (userMenuToggle && userMenu) {
    const closeUserMenu = (restoreFocus = false) => {
        userMenu.hidden = true;
        userMenuToggle.setAttribute("aria-expanded", "false");
        if (restoreFocus) userMenuToggle.focus();
    };
    userMenuToggle.addEventListener("click", (event) => {
        event.stopPropagation();
        const opening = userMenu.hidden;
        userMenu.hidden = !opening;
        userMenuToggle.setAttribute("aria-expanded", String(opening));
    });
    userMenuToggle.addEventListener("keydown", (event) => {
        if (event.key !== "ArrowDown") return;
        event.preventDefault();
        userMenu.hidden = false;
        userMenuToggle.setAttribute("aria-expanded", "true");
        userMenu.querySelector("button")?.focus();
    });
    document.addEventListener("click", (event) => {
        if (!userMenu.contains(event.target) && !userMenuToggle.contains(event.target)) closeUserMenu();
    });
    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && !userMenu.hidden) closeUserMenu(true);
    });
    userMenuToggle.closest(".console-user-menu")?.addEventListener("focusout", (event) => {
        if (event.relatedTarget && !event.currentTarget.contains(event.relatedTarget)) closeUserMenu();
    });
}

document.querySelectorAll("[data-more-filters]").forEach((button) => {
    button.addEventListener("click", () => {
        const form = button.closest("form");
        if (!form) return;
        const expanded = form.classList.toggle("show-advanced-filters");
        button.setAttribute("aria-expanded", String(expanded));
        button.textContent = expanded ? "Fewer filters" : "More filters";
    });
});

const applicationTabs = document.querySelector("[data-application-tabs]");
if (applicationTabs) {
    const tabs = Array.from(applicationTabs.querySelectorAll("[data-application-tab]"));
    const panels = Array.from(applicationTabs.querySelectorAll("[data-application-panel]"));
    const availableTabs = new Set(tabs.map((tab) => tab.dataset.applicationTab));
    const requestedHash = window.location.hash.slice(1);
    const initialTab = availableTabs.has(requestedHash)
        ? requestedHash
        : applicationTabs.dataset.initialTab || "overview";

    const activateApplicationTab = (name, updateHash = false) => {
        tabs.forEach((tab) => {
            const active = tab.dataset.applicationTab === name;
            tab.classList.toggle("active", active);
            tab.setAttribute("aria-selected", String(active));
            tab.tabIndex = active ? 0 : -1;
        });
        panels.forEach((panel) => {
            const active = panel.dataset.applicationPanel === name;
            panel.classList.toggle("active", active);
            panel.setAttribute("aria-hidden", String(!active));
        });
        if (updateHash) window.history.replaceState(null, "", `#${name}`);
    };

    applicationTabs.classList.add("is-enhanced");
    activateApplicationTab(initialTab);
    tabs.forEach((tab, index) => {
        tab.addEventListener("click", (event) => {
            event.preventDefault();
            activateApplicationTab(tab.dataset.applicationTab, true);
        });
        tab.addEventListener("keydown", (event) => {
            if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
            event.preventDefault();
            let targetIndex = index;
            if (event.key === "ArrowLeft") targetIndex = (index - 1 + tabs.length) % tabs.length;
            if (event.key === "ArrowRight") targetIndex = (index + 1) % tabs.length;
            if (event.key === "Home") targetIndex = 0;
            if (event.key === "End") targetIndex = tabs.length - 1;
            const target = tabs[targetIndex];
            activateApplicationTab(target.dataset.applicationTab, true);
            target.focus();
        });
    });
}

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

// Dashboard architecture walkthrough. Recorded status is never changed by motion.
function initLLMGuardRuntime(section) {
    if (section.dataset.runtimeInitialized) return section.llmguardRuntime;
    const stages = Array.from(section.querySelectorAll("[data-runtime-stage]"));
    const checkpoints = Array.from(section.querySelectorAll("[data-runtime-checkpoint]"));
    const paths = Array.from(section.querySelectorAll("[data-runtime-path]"));
    const motion = section.querySelector("[data-runtime-motion]");
    const toggle = section.querySelector("[data-runtime-toggle]");
    const speedButton = section.querySelector("[data-runtime-speed]");
    if (stages.length !== 7 || checkpoints.length !== 7 || !paths.length || !motion || !toggle || !speedButton) return;
    section.dataset.runtimeInitialized = "true";
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    const positions = [0.08, 0.30, 0.40, 0.55, 0.65, 0.80, 0.92];
    const point = (progress) => {
        const angle = 2 * Math.PI * progress;
        return {x: 550 + 396 * Math.cos(angle), y: 163 + 350 * .38 * Math.sin(2 * angle) * .52};
    };
    const rail = Array.from({length: 181}, (_, i) => {
        const p = point(i / 180);
        return (i ? "L" : "M") + p.x.toFixed(2) + " " + p.y.toFixed(2);
    }).join(" ") + " Z";
    paths.forEach(path => path.setAttribute("d", rail));
    checkpoints.forEach((checkpoint, i) => {
        const p = point(positions[i]), upper = p.y < 163;
        checkpoint.setAttribute("transform", "translate(" + p.x + " " + p.y + ")");
        const label = checkpoint.querySelector("[data-runtime-node-label]");
        const status = checkpoint.querySelector("[data-runtime-node-status]");
        label.setAttribute("y", upper ? -20 : 27);
        status.setAttribute("y", upper ? -36 : 42);
        label.textContent = stages[i].dataset.stageName;
        status.textContent = stages[i].dataset.stageStatus;
        checkpoint.dataset.status = stages[i].dataset.stageStatus.toLowerCase();
    });
    let frameId = null, previousTime = null, progress = positions[0], speed = 1;
    let userWantsMotion = !reducedMotion.matches, inView = true, pageActive = true, destroyed = false, activeStage = -1;
    const focusStage = (index) => {
        if (activeStage === index) return;
        activeStage = index;
        stages.forEach((stage, i) => {
            stage.classList.toggle("is-focused", i === index);
            if (i === index) stage.setAttribute("aria-current", "step"); else stage.removeAttribute("aria-current");
            checkpoints[i].classList.toggle("is-focused", i === index);
        });
        const stage = stages[index];
        section.querySelector("[data-runtime-focus]").textContent = stage.dataset.stageName;
        section.querySelector("[data-runtime-status]").textContent = stage.dataset.stageStatus;
        section.querySelector("[data-runtime-source]").textContent = stage.dataset.stageSource;
        section.querySelector("[data-runtime-detail]").textContent = stage.dataset.stageDetail;
        section.dataset.runtimeFocus = String(index + 1);
    };
    const paint = () => {
        const p = point(progress);
        motion.setAttribute("transform", "translate(" + p.x + " " + p.y + ")");
        const ring = section.querySelector(".runtime-hub-ring");
        if (ring) ring.setAttribute("transform", "rotate(" + progress * 360 + " 550 163)");
        let index = stages.length - 1;
        for (let i = 0; i < positions.length; i++) if (progress >= positions[i]) index = i;
        focusStage(index);
    };
    const canAnimate = () => !destroyed && userWantsMotion && pageActive && !document.hidden && inView && !reducedMotion.matches;
    const stopFrame = () => {
        if (frameId !== null) cancelAnimationFrame(frameId);
        frameId = null; previousTime = null; section.dataset.runtimePlaying = "false";
    };
    const render = (timestamp) => {
        frameId = null;
        if (!canAnimate()) { stopFrame(); return; }
        if (previousTime !== null) progress = (progress + Math.min((timestamp - previousTime) / 1000, .1) * speed / 18) % 1;
        previousTime = timestamp;
        paint();
        frameId = requestAnimationFrame(render);
    };
    const sync = () => {
        toggle.disabled = reducedMotion.matches;
        toggle.textContent = reducedMotion.matches ? "Reduced motion" : (userWantsMotion ? "Pause animation" : "Resume animation");
        toggle.setAttribute("aria-pressed", String(!userWantsMotion));
        section.dataset.runtimePlaying = String(canAnimate());
        if (!canAnimate()) stopFrame();
        else if (frameId === null) { previousTime = null; frameId = requestAnimationFrame(render); }
    };
    const toggleMotion = () => { userWantsMotion = !userWantsMotion; sync(); };
    const changeSpeed = () => { speed = speed === 1 ? 2 : speed === 2 ? .5 : 1; speedButton.textContent = speed + "× Speed"; };
    const stageHandlers = stages.map((stage, i) => {
        const handler = () => {
            userWantsMotion = false; sync(); progress = positions[i]; paint(); focusStage(i);
        };
        stage.addEventListener("click", handler);
        return handler;
    });
    const visibilityChanged = () => sync();
    const pageHidden = () => { pageActive = false; sync(); };
    const pageShown = () => { pageActive = true; sync(); };
    toggle.addEventListener("click", toggleMotion);
    speedButton.addEventListener("click", changeSpeed);
    document.addEventListener("visibilitychange", visibilityChanged);
    window.addEventListener("pagehide", pageHidden);
    window.addEventListener("pageshow", pageShown);
    reducedMotion.addEventListener("change", visibilityChanged);
    const observer = typeof IntersectionObserver === "function" ? new IntersectionObserver(entries => {
        inView = entries[0].isIntersecting; sync();
    }, {threshold: .1}) : null;
    observer?.observe(section);
    const controller = {
        pause() { userWantsMotion = false; sync(); },
        resume() { userWantsMotion = true; sync(); },
        destroy() {
            destroyed = true; stopFrame(); observer?.disconnect();
            toggle.removeEventListener("click", toggleMotion);
            speedButton.removeEventListener("click", changeSpeed);
            stages.forEach((stage, i) => stage.removeEventListener("click", stageHandlers[i]));
            document.removeEventListener("visibilitychange", visibilityChanged);
            window.removeEventListener("pagehide", pageHidden);
            window.removeEventListener("pageshow", pageShown);
            reducedMotion.removeEventListener("change", visibilityChanged);
            delete section.dataset.runtimeInitialized; delete section.llmguardRuntime;
        }
    };
    section.llmguardRuntime = controller;
    paint(); sync();
    return controller;
}
document.querySelectorAll("[data-runtime-loop]").forEach(initLLMGuardRuntime);

const loginForm = document.getElementById("login-form");
if (loginForm) {
    const username = document.getElementById("username");
    const password = document.getElementById("password");
    const message = document.getElementById("login-message");
    const queryRole = new URLSearchParams(window.location.search).get("role");
    const presets = {
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
            if (payload.role !== "super_admin") {
                window.localStorage.removeItem("llmguard_token");
                await apiRequest("/auth/logout", {method: "POST"});
                throw new Error("LLMGuard console access is restricted to security administrators.");
            }
            window.localStorage.setItem("llmguard_token", payload.access_token);
            window.location.href = "/admin/dashboard";
        } catch (error) {
            message.className = "form-message error";
            message.textContent = error.message;
            loginForm.classList.remove("is-authenticating");
            if (submitButton) {
                submitButton.disabled = false;
                submitButton.textContent = "Sign In to Security Console";
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

document.querySelectorAll("[data-protection-control]").forEach((form) => {
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const message = form.querySelector("[data-protection-message]");
        const button = form.querySelector('button[type="submit"]');
        const reason = form.querySelector('[name="reason"]')?.value.trim() || "";
        const protectionEnabled = form.dataset.nextEnabled === "true";
        if (!protectionEnabled && !reason) {
            message.className = "form-message error";
            message.textContent = "A reason is required when disabling protection.";
            return;
        }
        button.disabled = true;
        message.className = "form-message";
        message.textContent = "Updating application protection...";
        try {
            await apiRequest(`/admin/applications/${encodeURIComponent(form.dataset.applicationId)}/protection`, {
                method: "POST",
                body: JSON.stringify({protection_enabled: protectionEnabled, reason}),
            });
            window.location.reload();
        } catch (error) {
            message.className = "form-message error";
            message.textContent = error.message;
            button.disabled = false;
        }
    });
});
