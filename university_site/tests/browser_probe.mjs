import fs from "node:fs/promises";

const [url, widthText, heightText, outputPath, action = ""] = process.argv.slice(2);
const width = Number(widthText);
const height = Number(heightText);
const endpoint = "http://127.0.0.1:9223";

if (!url || !width || !height || !outputPath) {
  throw new Error("Usage: node browser_probe.mjs URL WIDTH HEIGHT OUTPUT [student]");
}

const target = await fetch(`${endpoint}/json/new?${encodeURIComponent("about:blank")}`, { method: "PUT" }).then((response) => response.json());
const socket = new WebSocket(target.webSocketDebuggerUrl);
let nextId = 1;
const pending = new Map();
const eventWaiters = new Map();
const runtimeExceptions = [];
const consoleErrors = [];

socket.addEventListener("message", (event) => {
  const message = JSON.parse(event.data);
  if (message.id && pending.has(message.id)) {
    const { resolve, reject } = pending.get(message.id);
    pending.delete(message.id);
    if (message.error) reject(new Error(message.error.message));
    else resolve(message.result ?? {});
  }
  const waiters = eventWaiters.get(message.method) ?? [];
  waiters.splice(0).forEach((resolve) => resolve(message.params ?? {}));
  if (message.method === "Runtime.exceptionThrown") runtimeExceptions.push(message.params);
  if (message.method === "Runtime.consoleAPICalled" && message.params?.type === "error") consoleErrors.push(message.params);
});

await new Promise((resolve, reject) => {
  socket.addEventListener("open", resolve, { once: true });
  socket.addEventListener("error", reject, { once: true });
});

const command = (method, params = {}) => new Promise((resolve, reject) => {
  const id = nextId++;
  pending.set(id, { resolve, reject });
  socket.send(JSON.stringify({ id, method, params }));
});

const waitForEvent = (method, timeout = 12_000) => Promise.race([
  new Promise((resolve) => {
    const waiters = eventWaiters.get(method) ?? [];
    waiters.push(resolve);
    eventWaiters.set(method, waiters);
  }),
  new Promise((_, reject) => setTimeout(() => reject(new Error(`Timed out waiting for ${method}`)), timeout)),
]);

await command("Page.enable");
await command("Runtime.enable");
await command("Emulation.setDeviceMetricsOverride", {
  width,
  height,
  screenWidth: width,
  screenHeight: height,
  deviceScaleFactor: 1,
  mobile: width <= 600,
});
if (action === "chatbot-reduced") {
  await command("Emulation.setEmulatedMedia", {
    media: "screen",
    features: [{ name: "prefers-reduced-motion", value: "reduce" }],
  });
}

let loaded = waitForEvent("Page.loadEventFired");
await command("Page.navigate", { url });
await loaded;
await new Promise((resolve) => setTimeout(resolve, 800));

let interactionResult = {};
const loginAndRedirect = async (username, password) => {
  loaded = waitForEvent("Page.loadEventFired");
  await command("Runtime.evaluate", {
    expression: `document.querySelector('#username').value=${JSON.stringify(username)};document.querySelector('#password').value=${JSON.stringify(password)};document.querySelector('form').requestSubmit();`,
  });
  await loaded;
  await new Promise((resolve) => setTimeout(resolve, 800));
};

const visitRoutes = async (routes) => {
  const results = [];
  for (const route of routes) {
    loaded = waitForEvent("Page.loadEventFired");
    await command("Page.navigate", { url: new URL(route, url).href });
    await loaded;
    await new Promise((resolve) => setTimeout(resolve, 180));
    const result = await command("Runtime.evaluate", {
      expression: `({path:location.pathname,title:document.title,overflow:document.documentElement.scrollWidth>innerWidth,scrollWidth:document.documentElement.scrollWidth,innerWidth})`,
      returnByValue: true,
    });
    results.push(result.result.value);
  }
  return results;
};

if (action === "student") {
  await loginAndRedirect("student.demo001", "Student@123");
  interactionResult = { loginRedirected: true };
} else if (action === "employee") {
  await loginAndRedirect("employee.lecturer", "Employee@123");
  interactionResult = { loginRedirected: true };
} else if (action === "student-journey") {
  await loginAndRedirect("student.demo001", "Student@123");
  interactionResult = { journey: await visitRoutes([
    "/portal/student/dashboard", "/portal/student/profile", "/portal/student/courses",
    "/portal/student/attendance", "/portal/student/results", "/portal/student/fees",
    "/portal/student/timetable", "/portal/student/notices", "/portal/student/documents",
  ]) };
} else if (action === "employee-journey") {
  await loginAndRedirect("employee.lecturer", "Employee@123");
  interactionResult = { journey: await visitRoutes([
    "/portal/employee/dashboard", "/portal/employee/profile", "/portal/employee/attendance",
    "/portal/employee/leave", "/portal/employee/assignments", "/portal/employee/department",
    "/portal/employee/notices", "/portal/employee/policies",
    "/portal/employee/controlled-records", "/portal/employee/directory",
    "/portal/employee/students", "/portal/employee/organogram",
  ]) };
} else if (action === "security-guard-journey") {
  await loginAndRedirect("employee.guard", "Employee@123");
  interactionResult = { journey: await visitRoutes([
    "/portal/employee/dashboard", "/portal/employee/profile", "/portal/employee/attendance",
    "/portal/employee/leave", "/portal/employee/assignments", "/portal/employee/department",
    "/portal/employee/notices", "/portal/employee/policies", "/portal/employee/controlled-records",
  ]) };
} else if (action === "public-journey") {
  interactionResult = { journey: await visitRoutes([
    "/", "/university/about", "/university/academics", "/university/departments/information-technology",
    "/university/information/examinations", "/university/information/it-services",
    "/university/information/journal-management", "/university/information/oric",
    "/university/admissions", "/university/admissions/bs-programs", "/university/admissions/eligibility",
    "/university/admissions/fee", "/university/admissions/schedule", "/university/admissions/scholarships",
    "/university/admissions/facilities", "/university/admissions/how-to-apply", "/university/policies",
    "/search?q=computer", "/portal", "/portal/student/login", "/portal/employee/login",
  ]) };
} else if (action === "home-interactions") {
  const result = await command("Runtime.evaluate", {
    expression: `(() => {
      const before = [...document.querySelectorAll('[data-slide]')].findIndex((item) => item.classList.contains('active'));
      document.querySelector('[data-slider-next]').click();
      const after = [...document.querySelectorAll('[data-slide]')].findIndex((item) => item.classList.contains('active'));
      document.querySelector('[data-announcement-close]').click();
      return { before, after, modalHidden: document.querySelector('[data-announcement-modal]').hidden };
    })()`,
    returnByValue: true,
  });
  interactionResult = result.result.value;
} else if (action === "mobile-nav") {
  const result = await command("Runtime.evaluate", {
    expression: `(() => {
      const button = document.querySelector('.nav-toggle');
      button.click();
      const menu = document.getElementById(button.getAttribute('aria-controls'));
      return { expanded: button.getAttribute('aria-expanded'), menuOpen: menu.classList.contains('open') };
    })()`,
    returnByValue: true,
  });
  interactionResult = result.result.value;
} else if (action === "login-fill") {
  const result = await command("Runtime.evaluate", {
    expression: `(() => {
      document.querySelector('[data-demo-user="student.demo001"]').click();
      return { username: document.querySelector('#username').value, passwordFilled: document.querySelector('#password').value.length > 0 };
    })()`,
    returnByValue: true,
  });
  interactionResult = result.result.value;
} else if (action.startsWith("chatbot-")) {
  const chatContext = action.replace("chatbot-", "");
  if (chatContext === "student") await loginAndRedirect("student.demo001", "Student@123");
  if (chatContext === "employee") await loginAndRedirect("employee.registrar", "Employee@123");
  const question = chatContext === "student"
    ? "What is my fee status?"
    : chatContext === "employee"
      ? "How many employees are registered?"
      : "What BS programs does the university offer?";
  const result = await command("Runtime.evaluate", {
    expression: `(async () => {
      const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
      const launcher = document.querySelector('.uoh-chat-launcher');
      launcher.click();
      await delay(100);
      const panel = document.querySelector('#uoh-chat-panel');
      const input = document.querySelector('[data-chat-input]');
      const focusedOnOpen = document.activeElement === input;
      input.value = ${JSON.stringify(question)};
      document.querySelector('[data-chat-form]').requestSubmit();
      for (let attempt = 0; attempt < 160; attempt += 1) {
        const assistantMessages = document.querySelectorAll('.uoh-chat-message.assistant').length;
        if (assistantMessages > 0 && document.querySelector('[data-chat-loading]').hidden) break;
        await delay(250);
      }
      const rect = panel.getBoundingClientRect();
      const status = document.querySelector('.uoh-chat-message.assistant:last-of-type .uoh-chat-status');
      const logo = document.querySelector('.uoh-chat-header img');
      const sourceCards = document.querySelectorAll('.uoh-chat-source-card');
      return {
        context: document.querySelector('#uoh-chat').dataset.context,
        launcherHidden: launcher.hidden,
        panelOpen: !panel.hidden,
        panel: {left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom, width: rect.width, height: rect.height},
        panelFits: rect.left >= 0 && rect.top >= 0 && rect.right <= innerWidth && rect.bottom <= innerHeight,
        focusedOnOpen,
        title: document.querySelector('#uoh-chat-title')?.textContent.trim(),
        subtitle: document.querySelector('.uoh-chat-brand small')?.textContent.trim(),
        logoLoaded: Boolean(logo?.complete && logo.naturalWidth > 0),
        logoSource: logo?.getAttribute('src'),
        suggestionCount: document.querySelectorAll('[data-chat-suggestions] button').length,
        assistantMessages: document.querySelectorAll('.uoh-chat-message.assistant').length,
        status: status?.textContent.trim(),
        sourceCards: sourceCards.length,
        feedbackButtons: document.querySelectorAll('.uoh-chat-message-actions button').length,
        historyControl: Boolean(document.querySelector('[data-chat-history]')),
        newChatControl: Boolean(document.querySelector('[data-chat-new]')),
        dialogLabelled: panel.getAttribute('aria-labelledby') === 'uoh-chat-title',
        horizontalOverflow: document.documentElement.scrollWidth > innerWidth,
        launcherAnimation: getComputedStyle(document.querySelector('.uoh-chat-launcher-ring')).animationName,
      };
    })()`,
    awaitPromise: true,
    returnByValue: true,
  });
  interactionResult = result.result.value;
}

const metricsResult = await command("Runtime.evaluate", {
  expression: `JSON.stringify({
    url: location.href,
    innerWidth,
    innerHeight,
    scrollWidth: document.documentElement.scrollWidth,
    bodyScrollWidth: document.body.scrollWidth,
    overflow: document.documentElement.scrollWidth > innerWidth,
    title: document.title
  })`,
  returnByValue: true,
});
const metrics = JSON.parse(metricsResult.result.value);
metrics.consoleExceptions = runtimeExceptions.length;
metrics.consoleErrors = consoleErrors.length;
metrics.interaction = interactionResult;
const screenshot = await command("Page.captureScreenshot", { format: "png", fromSurface: true });
await fs.writeFile(outputPath, Buffer.from(screenshot.data, "base64"));
const socketClosed = new Promise((resolve) => socket.addEventListener("close", resolve, { once: true }));
await fetch(`${endpoint}/json/close/${target.id}`);
await Promise.race([socketClosed, new Promise((resolve) => setTimeout(resolve, 500))]);
console.log(JSON.stringify(metrics));
