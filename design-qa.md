# LLMGuard Neural Defense OS Visual QA

## Direction

The active product system is an original full-width enterprise SaaS interface.
It intentionally departs from the earlier monitor-and-shield reference. The
first viewport uses an asymmetric neural policy core, orbital enforcement
rings, hostile request paths, safe packet deflection, and compact operational
telemetry.

## Design Sources

- UI/UX Pro Max research persisted in
  `design-system/llmguard-neural-defense-os/MASTER.md`.
- 21st.dev Magic was callable for SaaS hero and security dashboard pattern
  research. Returned React snippets were used only as structural inspiration;
  the implementation remains original Jinja, HTML, CSS, SVG, and JavaScript.
- No external website assets, screenshots, CSS, logos, or component code are
  included in the product.

## Viewports

- 1440px desktop landing and admin views
- 1366px laptop portal views
- 430px and 390px mobile landing/login views

## Acceptance Checks

- No horizontal viewport overflow.
- Mobile navigation remains visible and updates `aria-expanded`.
- Motion is noticeable within five seconds while reading surfaces remain stable.
- The assistant blocked state says Qwen was skipped before the model call.
- Document scans, SOC stages, risk rings, and audit timelines use restrained motion.
- `prefers-reduced-motion` disables continuous decorative movement.
- Product assets return HTTP 200 and use cache-busting version `16`.
- `/app` redirects to `/login`; the retired console is not a primary surface.
- Student and employee boundaries remain role-isolated.
- Vulnerable mode remains gated by local red-team configuration.

## Functional Evidence

Rendered QA must cover:

1. Desktop and 390px landing page.
2. Login page and mobile menu behavior.
3. Student dashboard after synthetic login.
4. Super Admin dashboard.
5. Security Dashboard and event detail controls.
6. Compare Lab.
7. A protected malicious request showing `llm_called=false`.

Temporary QA servers and browser processes must be stopped before completion.
