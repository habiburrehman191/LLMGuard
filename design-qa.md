# LLMGuard CyberSphere Reference Visual QA

## Source visual truth

- Authoritative source: the user-supplied CyberSphere dashboard screenshot.
- Source dimensions: 760 x 490 pixels.
- Defining traits reproduced: compact top header, circular icon navigation,
  near-black navy canvas, embedded 12–16px-radius panels, dense three-column
  dashboard grid, segmented gauge, blue activity bars, compact security rows,
  muted metadata, and restrained green/amber/red status accents.
- No external imagery or copied assets were used. The application-security
  artwork is a native inline SVG built specifically for LLMGuard.

## Implementation capture

- Screenshot: `reports/ui/cybersphere-dashboard-implementation.png`
- Capture dimensions: 6368 x 2936 pixels.
- Browser viewport reported by the QA session: 3184 x 1468 pixels.
- Explicit desktop breakpoint verification: 1440 x 900 CSS pixels.
- Product canvas: centered, maximum width 1500 CSS pixels.
- State: authenticated synthetic Super Admin; University of Haripur AI System
  selected; current real integration/runtime data; no fabricated events or
  counters.

## Comparison history and findings

1. Initial implementation capture showed the correct header and panel language,
   but CSS grid row stretching created an oversized vertical gap.
2. `grid-template-rows: auto 1fr` was applied to the shell and the dashboard was
   recaptured. The six panels then aligned into the intended compact 3 x 2 grid.
3. Dashboard, Applications, application detail, Security Events, Evaluation,
   and Login were inspected in the browser. The header, card radii, surface
   hierarchy, typography, pills, and controls remained consistent across pages.
4. The final dashboard capture matches the reference composition closely while
   substituting only real LLMGuard states and telemetry.

## Acceptance checks

- One compact top navigation only: Dashboard, Applications, Security, Evaluation.
- Active navigation uses the reference-style bright-blue circular treatment.
- Secure/BYPASSED status and operator identity remain visible without a sidebar.
- Dashboard uses a dense 3 x 2 panel layout with no large unused gap.
- Protection gauge represents actual available guard stages; it invents no score.
- Timeline, firewall matrix, summary, and event rows derive from stored runtime
  data and use designed compact empty states when no data exists.
- Application, Security, Evaluation, and Login surfaces share one visual system.
- Documents/ingestion remains functional but is absent from primary navigation.
- Responsive breakpoints reflow the grid and header without horizontal overflow.
- Browser console errors during authenticated route review: none.
- LLMGuard suite: 205 tests passed.
- University suite: 69 tests passed.

## Intentional differences from the source

- CyberSphere's demo threat totals and populated threat rows were not copied;
  LLMGuard renders its own real data or an honest empty state.
- The reference image card was replaced with a restrained native LLMGuard shield,
  AI-boundary, and application-security SVG rather than a stock image.
- The operator avatar uses generated initials because no real profile image is
  present in the application.
- Page labels and controls reflect LLMGuard's existing routes and security model.

## Final result

passed

---

# Exported Shared Shell Integration QA — 2026-10-07

## Scope and source visual truth

This pass implements only the shared visual system and authenticated shell.
Dashboard, Applications, application detail, Security, Evaluation and Login
content and layouts remain the existing Jinja implementation. The earlier
CyberSphere review above is retained as historical context.

- Source: `C:/Users/Habib UR Rehman/LLMGuard-New-UI/applications_system_detail/screen.png`.
- Source pixels: 1280 x 1329, interpreted at density 1.
- Tokens and font grounding: the export's HTML configuration and
  `obsidian_cyber_soc/DESIGN.md`; ambiguous narrative values defer to the HTML.
- Implementation: `reports/ui/shared-shell/desktop-applications.png`,
  1280 x 900 pixels at a 1280 x 900 CSS viewport, device scale factor 1.
- State: synthetic `admin1`, Super Admin, Applications active, actual
  Integration Pending state in an isolated test database.

## Comparison evidence

- Full-view comparison: `reports/ui/shared-shell/full-view-comparison.png`.
  Both screenshots are placed at native scale. Their different content heights
  and page compositions are intentional because page redesign is out of scope.
- Focused comparison: `reports/ui/shared-shell/header-comparison.png`.
  Both header crops are exactly 1280 x 64 pixels, stacked without scaling.
- Account menu: `reports/ui/shared-shell/desktop-account-menu.png`.
- Responsive menu: `reports/ui/shared-shell/account-menu-768.png`,
  `account-menu-375.png`, and `account-menu-320.png`; each is 900 CSS pixels tall
  at density 1. These check reflow rather than compare to an invented mobile mock.
- Login shared controls: `reports/ui/shared-shell/login-shared-controls.png`.
- Browser results: `reports/ui/shared-shell/browser-results.json`.

## Fidelity surfaces

- Fonts/typography: local Plus Jakarta Sans for shared UI, JetBrains Mono for
  technical IDs and code; UI channel badges use Plus Jakarta Sans. Semantic size tokens, readable labels and focus
  treatment. Font files and SIL Open Font Licenses are in `static/fonts/`.
- Spacing/layout: 64px sticky desktop header, 1280px content bound, 24px desktop
  padding, a 4/8/12/16/24/32px spacing scale, pill navigation, and contained menus.
  Narrow screens retain the same navigation in a horizontally scrollable row.
- Colors/tokens: navy surface tiers, #1e6bff primary, #7bd0ff secondary,
  #4edea3 healthy and #ffb4ab error colors. Existing product/portal primitives
  resolve to the same `--cs-*` palette within the console and login shell.
- Assets: existing SVG sprite and existing initials avatar are retained as
  explicitly requested. No Material Symbols CDN, new icon library, generated
  imagery, copied screenshot, Tailwind runtime or frontend build was added.
- Copy/content: username/role/status remain contextual. Exported demo metrics,
  model/storage claims, unsupported search/notification actions and hardcoded
  identity are absent. Existing page content, charts and controls are preserved.

## Comparison history

1. Desktop full-view and header comparison found the correct shared palette,
   fonts, brand, pill navigation and account treatment. Different navigation
   placement reflects the smaller set of real header controls; no unsupported
   search or notification feature was introduced.
2. [P2] The first 320px browser check found the account dropdown extended
   13.7px beyond the left viewport boundary.
3. The small-screen dropdown was anchored to the shared header. The next
   browser capture shows bounds 80–304px within a 320px viewport. At 375px,
   bounds are 135–359px. No document-level horizontal overflow remains.
4. Final desktop and narrow-screen evidence was recaptured and inspected after
   the fix and final typography changes. No actionable P0/P1/P2 shell findings
   remain. Page-specific composition differences are deferred by task scope.

## Behavior and boundary verification

- 41 Python tests passed: frontend, product frontend, SOC, application registry,
  protection controls, application credentials and the new shared header tests.
- Full LLMGuard suite passed: 209 tests in 186.229 seconds, using an isolated
  synthetic database. This includes credential actions, SOC filters and incident
  lifecycle, evaluation, replay, protection and backend security regressions.
- Six JavaScript tests passed: menu toggling, inside/outside clicks, keyboard
  focus, focus dismissal, active routes, API helper headers and existing logout.
- Browser smoke passed across 13 authenticated console routes; exactly one
  shared header and one active primary navigation link on every route.
- Actual login and logout, application detail tabs and the protection form hook
  passed in the isolated browser preview. Logout removes access (HTTP 401).
- Account keyboard handlers/focus were tested with DOM keyboard events and unit
  events: this Windows headless session did not deliver native CDP key input.
  Native OS keyboard input remains an explicit verification limitation.
- No JavaScript runtime exceptions were recorded. Desktop width 1280px and
  responsive widths 768px, 375px and 320px passed.
- The final browser pass also recorded no console error calls, duplicate
  stylesheet loads, external stylesheet dependencies or Tailwind runtime.
  All 13 authenticated routes passed the desktop overflow check. Computed-style
  fixtures confirmed blue primary, dark secondary, red destructive controls,
  36px button height and the shared revoked badge token through the real cascade.
- Shared hover rules explicitly supersede old red glows and vertical transforms.
  Scoped semantic badge rules supersede the old product/portal status colors;
  credential revoke and document delete use the common destructive treatment.
- Pre/post hashes of 206 backend, university and page-template files match.
  Only the shared header template changes; API/security code, other Jinja
  templates and the existing SVG sprite are untouched by this step.
- Whitespace and JavaScript syntax checks passed. No stage, commit or push.

## Final result

final result: passed



---

# Step 3: Exported Login Presentation QA — 2026-10-07

## Source and comparison state

- Visual source: `C:/Users/Habib UR Rehman/LLMGuard-New-UI/llmguard_soc_login/screen.png`
  and its `code.html`. Source screenshot: 1280 x 942 pixels, density 1.
- Implementation: `reports/ui/login/login-1280x942.png`, captured on `/login`
  at 1280 x 942 CSS pixels, device scale factor 1, signed out and without errors.
- Full comparison: `reports/ui/login/source-comparison.png`, 2560 x 942 pixels;
  source and implementation are placed side by side at native scale.
- Focused comparison: `reports/ui/login/card-comparison.png`, 920 x 550 pixels;
  native 460px card crops. Source card is 513px tall; implementation is 550px.
  The real sign-in heading and reserved error feedback intentionally replace
  the unsupported persistence and telemetry areas. No image scaling is used.
- The source contains a prefilled exported identity. The implementation starts
  empty and contains only the user-requested real login content; that difference
  is intentional. Authenticated shared navigation remains unchanged elsewhere.

## Fidelity surfaces

- Typography: existing locally bundled Plus Jakarta Sans, 26px brand, 15px
  sign-in heading/button, 12px labels and supporting text, 11px environment pill.
  Ordinary login content uses the UI font rather than technical monospace.
- Spacing/layout: centered 460px card, 32px desktop card padding, 12px radius,
  64px shield well, 44px inputs and submit button. Short screens use smaller
  decorative branding and spacing while retaining the same usable form controls.
- Colors/tokens: existing navy surfaces, blue primary, cyan brand accent and
  green decorative shield treatment; errors use the existing red token. Borders
  and shadows remain restrained. No new token palette or CSS system was added.
- Asset quality: existing LLMGuard sprite supplies brand, user and lock icons.
  The radar SVG geometry is reused from the export as a decorative local asset;
  it is static, hidden from assistive technology and carries no telemetry.
  No raster logo placeholders, Material Symbols, external fonts or Tailwind.
- Copy/content: LLMGuard, AI Security Firewall, Administrator Sign In,
  Username, Password, Sign In to Security Console, Controlled Research Environment
  and Restricted administrative access. Exported identity, SSO/hardware factors,
  session persistence/TTL, encryption, cluster, version, latency and node claims
  are absent. No authentication features were added.

## Findings and comparison history

1. [P2] Initial 800 x 600 layout had 673px document height. Initial environment
   pill also inherited the old product paragraph font size. Evidence was captured
   before the fix. Scoped login font specificity and a short-height spacing rule
   resolved these findings without changing shared or page-specific console CSS.
2. The final 800 x 600 capture has exactly 600px document height. Final desktop,
   source-size and mobile captures were recaptured and compared after the fix;
   no actionable P0/P1/P2 visual findings remain.
3. A repeated run in the same headless Chrome process did not deliver Tab input.
   Verification was rerun in a freshly started isolated Chrome process, with
   explicit focus emulation and focus-state waits. Native Tab through both inputs
   to submit and native Enter for both failed and successful login passed.
   The browser checker documents this fresh-process prerequisite.

## Tests and browser evidence

- Targeted login/frontend/header tests: 22 passed. Shared JavaScript tests: six
  passed. Full LLMGuard suite: 212 passed in 116.675 seconds with isolated
  synthetic databases. JavaScript syntax and `git diff --check` passed.
- Results: `reports/ui/login/browser-results.json`. Seven viewport captures:
  1280 x 942, 1440 x 900, 1280 x 720, 1024 x 768, 800 x 600, 375 x 667 and
  320 x 568. All fit without document scrolling or horizontal overflow.
- Error and focus states: `reports/ui/login/login-error.png` and
  `reports/ui/login/login-focus.png`, both at 1440 x 900, density 1.
- Real failed login presents an announced error in `#login-message` and keeps
  the submit control available. Native Enter performs both real POST requests
  to `/auth/login` with exactly the original username/password fields.
- Successful login reaches `/admin/dashboard`; HTTP-only session cookie and
  existing bearer storage are present. Actual logout returns to `/login`, clears
  bearer storage and leaves `/admin/dashboard` unauthorized (HTTP 401).
- No JavaScript exceptions/console error calls, failed static assets, broken
  image/icon references, duplicate stylesheet loads or duplicate headers.
- Preservation snapshot: 112 files unchanged, including backend/security code,
  all other templates, shared icons and `models/hybrid_firewall/logistic_regression.joblib`.
  Reversing the sole presentation string change in `product.js` reproduces its
  original SHA-256 exactly. Shared CSS outside login rules is unchanged.
- `.venv_broken/` and `.vscode/` were not touched. Existing unrelated working-tree
  edits were preserved. No staging, commit or push.

## Remaining limitations

- In-app browser could not start; visual/behavior QA used isolated Chrome CDP.
- Mobile software-keyboard behavior is not covered by the desktop browser check.
- Source differences described above follow the explicit real-authentication
  content requirements and are accepted rather than deferred visual defects.

## Implementation checklist

- Login-only markup/styles, existing hooks, real content and local assets: complete.
- Requested automated and browser checks: passed.
- Shared navigation, backend and protected files: preserved.

final result: passed

---

# Exported Dashboard Integration QA — 2026-10-07

## Scope and source

Only /admin/dashboard presentation is integrated in this step. The shared shell,
Login, Applications, Security, Evaluation and University templates are preserved.
Backend routes, security decisions, calculations and protection-state semantics
are unchanged. Existing unrelated working-tree changes are retained.

- Visual source: LLMGuard-New-UI/llmguard_soc_dashboard_autonomous_runtime_loop/code.html
  and screen.png, 1280 x 1701 pixels.
- Final implementation: reports/ui/dashboard/dashboard-1280x1701.png at the
  same CSS viewport and device scale factor 1.
- Full-view comparison: reports/ui/dashboard/full-view-comparison.png,
  2560 x 1701 pixels, source left and implementation right at native scale.
- Focused comparison: reports/ui/dashboard/runtime-comparison.png. Source crop
  (49,1065)-(1231,1502); implementation crop uses the exact browser-measured
  runtime-visual bounds (rounded outwards). Both retain native scale.
- Desktop evidence: reports/ui/dashboard/dashboard-1440-full.png,
  dashboard-1440x900.png, dashboard-1366x768.png and dashboard-1024x768.png.
- Browser state: isolated synthetic admin1 and stored synthetic security events;
  the helper refuses to seed outside reports/ui/dashboard-preview/llmguard.db.
  No preview fixture is loaded by the application or copied into its database.

## Fidelity surfaces

- Typography: existing bundled Plus Jakarta Sans for UI, JetBrains Mono for
  technical identifiers; source-size 26px page heading, blue application selector,
  15px panel titles, compact 10–12px metadata and 24px runtime heading.
- Spacing/layout: three balanced top cards, two second-row cards, full-width
  major runtime section. At 1280px the top cards are 400px wide, second-row
  cards 608px wide; 16px gaps, 12px shared card radius, 16px panel padding
  and 24px runtime padding match the exported compact panel language.
- Colors: existing near-black navy, layered navy surfaces, subtle borders,
  strong blue/cyan gauge and motion accents, green readiness, amber quarantine,
  red block. No new palette or parallel CSS system.
- Assets: existing shield, brain, radar, warning, audit and RAG sprite symbols.
  Gauge and infinity rails are native SVG/CSS. The sprite is unchanged;
  no images, stock artwork, Material Symbols, Tailwind or animation libraries.
- Copy/content: actual selected application, environment, configured channels,
  heartbeat and optional application/integration versions. All counts, action
  labels, risks and timestamps are stored-data-derived. No exported provider,
  benchmark, infrastructure, network throughput, security guarantee or fake
  incident values. The four requested summary metrics replace the export's
  unsupported threat/demo content, following the user's information architecture.

## Real data mappings

| Existing context | Dashboard use |
| --- | --- |
| application_integrations | Existing application_id GET selector, unchanged form behavior |
| selected_integration | Application identity/environment/channels, runtime/connection state, guard availability, heartbeat and optional real versions |
| security_overview | 24h blocked/quarantine totals, current open incidents, action counts from its recent six-event sample, maximum five metadata-only event rows |
| metrics | Existing route context preserved; global legacy safe totals are not mixed into the selected application's SOC metrics |

Safe Requests counts distinct safe input request IDs in the existing recent
sample; its scope is explicit. Unknown risks say Not scored. Display timestamps
are compact absolute UTC values with the full stored timestamp in datetime/title.
Trace and event links keep the existing real routes and application/request IDs.
Empty applications show no invented events, bars, latency or protection score.

## Autonomous Runtime Loop

Exactly seven SVG checkpoints and seven accessible stage buttons are implemented:

1. Request Ingress
2. Input Firewall
3. Session / Authorization
4. Context Firewall
5. Trusted Prompt + LLM
6. Output Firewall
7. Audit / Response

The infinity/racetrack rail, embedded Hybrid Engine, dashed quarantine branch,
active glow, directional marker and compact status labels preserve the source
visual language. The center and heading show the actual overall runtime state.
Latest stored stage actions map to PASS/BLOCK/SANITIZE/QUARANTINE/BYPASSED/DEGRADED.
Available recorded guard checks show READY when no recent stage event exists.
Other stages say Not reported, with an explicit source explanation. No latency,
live packet telemetry, per-request simulation or synthetic protection result
is generated by motion. The quarantine well shows the actual scoped event count.

The controller in product.js initializes once, owns one requestAnimationFrame
chain and no timers, and updates only focus/motion. It suspends when hidden,
offscreen or on pagehide; pageshow/visibility changes preserve manual pause.
Reduced motion is respected, stage selection pauses and exposes the source,
speed controls cycle 1x/2x/0.5x, and cleanup removes its observers/listeners.

## Cleanup and preservation

Old console.css dashboard gauge, radial summary, firewall matrix, application
artwork, event-row and breakpoint rules were replaced directly. The shared card,
header, input, typography and login rules remain the same. Shared event-meta
declarations were retained when separating the old dashboard block.
Inactive frontend files and old CSS files were not removed or redesigned.

A pre-step hash snapshot confirms 155 protected backend/template/asset files
unchanged, including Login, all other templates, the SVG sprite and the protected
model artifact. Removing only the added runtime module reproduces the original
product.js outside that module. .venv_broken/ and .vscode/ were not touched.
No stage, commit or push occurred.

## Findings and comparison history

1. [P2] Initial scope notes inherited the oversized legacy paragraph font.
   Dashboard-only specificity restores the intended 10px notes.
2. [P2] Initial event timestamps overflowed their row cells. Compact absolute
   UTC text retains full ISO metadata and fits the final cards.
3. [P2] Shared input specificity overrode the intended blue heading selector.
   An existing dashboard ID selector now owns only its dashboard appearance.
4. [Contract regression] The first full-suite run exposed missing optional real
   application/integration version metadata. It was restored in the boundary
   card. The original heartbeat test was kept intact and passed on rerun.
5. Final native-scale full and focused comparisons were inspected after these
   fixes. Overall protection state is also visible at the Hybrid Engine center.
   No actionable P0/P1/P2 visual findings remain within dashboard scope.

## Verification

- Dashboard/frontend targeted Python checks: 24 passed, including six new
  dashboard data/rendering cases. Heartbeat contract rerun: six passed.
- Shared/runtime Node checks: 12 passed, including six new lifecycle tests.
- Full LLMGuard suite: 218 passed with isolated synthetic databases.
- Static/product.js and dashboard browser script syntax: passed.
- git diff --check: passed. The index remains empty.
- Browser results: reports/ui/dashboard/browser-results.json.
- Viewports: 1280 x 1701, 1440 x 900, 1366 x 768, 1024 x 768,
  375 x 812 and 320 x 568. No document horizontal overflow.
- Real login, selected application GET navigation, real runtime state, populated
  stored events and truthful empty states: passed.
- Seven checkpoints/stages, moving marker, manual pause across offscreen and
  reduced-motion changes, stage selection, speed changes and no motion API
  requests: passed. Hidden/pagehide behavior is covered by lifecycle unit tests.
- One authenticated shared header, one active Dashboard nav link, three existing
  local stylesheets, valid SVG symbols, no broken images and no console errors:
  passed. Local UI font loaded successfully.
- Populated/empty captures and runtime/quarantine focus captures are retained
  under reports/ui/dashboard/ for review.

## Remaining limitations and accepted differences

Per-stage latency and telemetry for ingress/session/model/audit are not supplied
by the current dashboard context; they are not invented. Recorded stage status
and events remain a page-render snapshot; animation does not refresh security
data or imply streaming requests. Safe Requests is deliberately a recent sample,
not a new 24h backend calculation. The source's extra KPI/demo incident sections,
fake attack controls and telemetry footer are omitted under the requested scope.
The dashboard scrolls vertically like the exported design, with no horizontal
document overflow. Shared narrow-screen navigation retains its existing internal
scroll behavior because shell redesign is outside this step.

The in-app browser could not start; browser verification used isolated Chrome
CDP. Mobile touch/software-keyboard behavior was not separately tested.

## Files changed in this step

- templates/admin_dashboard.html
- static/console.css
- static/product.js
- tests/test_dashboard_frontend.py
- tests/runtime_loop.test.cjs
- tests/dashboard_browser.cjs
- tests/dashboard_browser_seed.py
- README.md
- design-qa.md

Final result: passed

# Exported Applications List Integration - Step 5

## Scope and visual source

Source: LLMGuard-New-UI/applications_system_detail/code.html and screen.png.
Only the exported applications-list header and wide card inform this step.
The source's detail tabs, policy controls, credentials and charts are outside
scope. No completed page, shared header, backend or security behavior changed.
The current registry is the sole source of application cards; no extra sample
application is introduced.

Native-scale screenshots at the source's 1280 x 1329 viewport are compared in
reports/ui/applications/source-current-full.png. The focused, unscaled card
comparison is reports/ui/applications/source-current-card.png. Desktop and
narrow-screen captures were inspected after the automated browser run.

## Fidelity surfaces

1. Layout: source-like inset heading panel and one wide layered card per real
   application. Identity remains dominant; runtime, connection and heartbeat
   occupy the right column. Three embedded guard panels and one blue action
   form the lower strip. Status and guard sections stack on narrow screens.
2. Typography: existing locally bundled Plus Jakarta Sans; shared technical
   monospace for actual identifiers and reported versions. The application name
   is larger than the source to satisfy the requested identity hierarchy.
3. Color: existing near-black navy canvas, layered panels, subtle borders,
   cyan icon accents and semantic runtime colors. List-only bypass/disabled
   treatment is amber without changing detail-page semantics or styles.
4. Surfaces: shared radius, 24px desktop padding, compact gaps, restrained
   shadow and blue primary action. No new CSS system or framework.
5. Assets: existing shield, firewall, RAG, output, database and arrow symbols.
   No stock imagery, broken assets or additional icon library.

## Real data mappings

application_integrations supplies actual name, organization, application ID,
environment and registered channel records, including disabled-channel labels.
runtime_state and connection_state are displayed directly; protection_enabled
determines Enabled/Disabled. The heartbeat retains its full ISO value in time
metadata and presents absolute UTC text; an absent heartbeat says Not received.
Optional application/integration versions come only from heartbeat metadata.
Membership in guard_stages produces VERIFIED for Input/Context/Output; missing
membership produces NOT REPORTED. A note identifies recorded guard-stage health
so verification does not imply live execution during bypass/disconnection.
The sole card action keeps /admin/applications/{application_id} unchanged.

PROTECTED is green, DEGRADED and BYPASSED amber, DISCONNECTED red, and
INTEGRATION_PENDING muted amber. No state is converted to a percentage.
The zero-record state has the requested message and no fake application/action.

## Cleanup, findings and preservation

The old two-column list/card, oversized only-child layout, fact grid and
card-owned action styles were replaced directly. Shared channel and icon rules
also used by Application Detail/Evaluation remain unchanged; list-specific
treatment is scoped. Comparing normalized CSS rules with the pre-step snapshot
found 75 changed rules, all owned by the applications list. Shared detail-grid
declarations were retained when separating their old grouped selectors.

Initial browser QA exposed a fixture transaction rollback on SystemExit; the
guarded preview helper now explicitly commits its empty-registry transaction.
A case-sensitive text assertion was corrected to inspect source text rather
than CSS-transformed uppercase text. Neither required a product/backend fix.
The existing route-copy assertion was updated only for the explicitly requested
supporting sentence; its registry and RBAC checks were retained.

Native full/focused comparisons and desktop/mobile captures have no actionable
P0/P1/P2 findings within this list-only scope. The source's demo statistics,
SSO/MFA/WebSocket claims, fake versions/policies/models, register/configuration
actions and detail content are intentionally excluded.

A pre-step hash snapshot confirms 507 protected backend/template/static files
unchanged, including Login, Dashboard/runtime, Application Detail, Security,
Evaluation, University UI, product.js, the sprite and protected model artifact.
.venv_broken/ and .vscode/ were not touched. The git index remains empty.

## Verification

- Applications/frontend, registry and heartbeat targeted Python checks: 18 passed.
- Full LLMGuard suite: 226 passed with isolated synthetic databases.
- Shared shell/runtime JavaScript regression checks: 12 passed.
- product.js and Applications browser script syntax: passed.
- git diff --check: passed.
- Browser: existing University record, actual detail navigation, all five runtime
  states, no registered applications, correct channels/protection/heartbeat,
  available/missing guard checks, one header and active Applications nav: passed.
- Viewports: 1280 x 1329, 1440 x 900, 1366 x 768, 1024 x 768,
  375 x 812 and 320 x 568. No document/card horizontal overflow.
- Valid SVG symbols, locally loaded UI font, three existing local stylesheets,
  no broken images, no failed static responses and no console errors: passed.
- Browser evidence: reports/ui/applications/browser-results.json and captures.
- Fixtures only mutate reports/ui/applications-preview/llmguard.db; the helper
  rejects other paths and is never loaded by the application.

## Remaining limitations

State, connection and guard checks remain a server-rendered snapshot; no polling
or streaming telemetry was added. Missing stage checks are not fabricated as
successes. One registered application naturally yields one card; source detail
content is not copied to fill the canvas. Mobile touch/software keyboard behavior
was not separately tested. The in-app browser could not start, so isolated Chrome
CDP provided browser verification. No stage, commit or push occurred.

## Files changed in this step

- templates/applications.html
- static/console.css (Applications-owned rules only)
- tests/test_applications_frontend.py
- tests/test_application_registry.py (requested supporting-copy assertion only)
- tests/applications_browser.cjs
- tests/applications_browser_state.py
- README.md
- design-qa.md

Final result: passed

---

# Step 6 — Application Detail only (2026-10-07)

## Visual comparison and scope

- Source: `C:/Users/Habib UR Rehman/LLMGuard-New-UI/applications_system_detail/code.html`
  and `screen.png`. Source pixels: 1280 × 1329.
- Implementation: `/admin/applications/university-of-haripur` on the isolated
  synthetic preview at `http://127.0.0.1:8766`.
- Matching viewport: 1280 × 1329 CSS pixels, deviceScaleFactor 1; implementation
  pixels: 1280 × 1329. No density rescaling. Comparison images add labels/crops only.
- State: Overview selected, protection enabled, connected, all three stages verified.
  The reference contains demo fields and combines other areas into Overview; the
  implementation deliberately uses persisted synthetic preview data and the four
  requested tab boundaries. This is a visual-language comparison, not a demo clone.
- Full-view side-by-side: `reports/ui/application-detail/comparison-full.png`.
- Focused tab/pipeline comparison: `reports/ui/application-detail/comparison-detail.png`.
- Final implementation: `reports/ui/application-detail/final-overview-1440x900.png`.
  Individual tab captures are named `{tab}-{width}x{height}.png` in the same folder.
- No raster artwork is needed in the selected detail portion. Existing local
  fonts and the shared SVG icon sprite are reused; no new icon or image assets.

## Findings, fixes, and final comparison

1. [P2, fixed] The initial tab dock retained the shared fit-content width, while
   the export uses a full-width layered dock. Set page-scoped width to 100%.
   Final combined comparison shows the matching dock and blue pill selection.
2. [P2, fixed] At 375px, metadata and credential cards clipped long values.
   Use one-column metadata and credential cards at narrow widths. All final
   tab/viewport layout assertions pass, including 320px and 375px.
3. [P2, fixed] Close inspection of the scrolled mobile audit capture found a long
   timestamp overlapping its adjacent action. Time values now use bounded block
   layout and normal wrapping. Re-captured `protection-audit-375.png` visibly
   separates Time, Action, Actor, and Reason; the final browser rerun passes.
4. [P3, fixed] Shared button specificity initially muted destructive action
   colors. Page-scoped selectors restore restrained red disable/revoke buttons.
   Browser assertion verifies the disable color; credential captures show revoke.

Post-fix visual comparison finds no remaining actionable P0/P1/P2 issues within
the requested scope. Removed source metrics, latency chart, policy switches,
masked demo secret, and RBAC matrix are intentional exclusions, not missing UI.

## Required fidelity surfaces

- Typography: local Plus Jakarta Sans and JetBrains Mono match the shared export
  typography; 24px identity heading, 15px panel titles, 12px body copy, compact
  technical labels. Mobile headings and timestamps wrap without overlap.
- Spacing/layout: 24px desktop panels, 16px section gaps, 7:5 detail grid, 12px
  panel radii, 8px row radii. Mobile stacks panels and provides a two-row tab dock.
- Colors/tokens: existing navy surface layers, blue active tabs, cyan metadata,
  restrained green verification and red destructive actions. No broad shell edits.
- Assets: shared local fonts/icons load; every rendered icon reference resolves;
  zero broken images or static responses. No placeholders or custom artwork.
- Copy/content: identity, environment, status, heartbeat, versions, channels,
  credential metadata and audit values come from existing Jinja context only.
  University authorization ownership is explicit; no fabricated telemetry or roles.

## Functionality and validation

- Retained `application`, `integration`, `credentials`, `created_credential`,
  `protection_audit`, `user`, `firewall_active`, and `asset_version` contracts.
- Retained the four tab selectors/panels and `product.js` behavior; active panel,
  selected state, ArrowRight, Home and End navigation pass. Added tab/panel ARIA links.
- Existing protection POST handler remains unchanged: native empty-reason and JS
  whitespace-reason validation, actual disable/enable, BYPASSED/PROTECTED runtime
  updates, and reason/actor audit entries all pass.
- Existing credential create/revoke POST forms remain unchanged. Creation selects
  Credentials and displays New API Secret once; later GETs and revoke responses
  contain no plaintext secret. Mobile one-time-secret layout passes. No secret is
  saved in QA screenshots, result JSON, or logs.
- Targeted Application Detail + protection + credential tests: 21 passed.
- Detail + heartbeat compatibility checks: 16 passed.
- Full LLMGuard unittest suite: 236 passed. A model copy and isolated SQLite
  databases were used because an existing pipeline test trains the classifier.
- All static JavaScript and the new browser checker pass `node --check`.
- Browser: 24 tab/viewport combinations at 1280×1329, 1440×900, 1366×768,
  1024×768, 375×812, and 320×568; no page overflow or clipped tracked content.
  One console header, real runtime states, heartbeat and channel metadata verified.
  Zero console errors, missing symbols, broken images, or failed static responses.
- Evidence: `reports/ui/application-detail/browser-results.json`, credential row
  and protection audit captures, `full-suite.log`, and `scope-check.json`.
- Baseline hashing confirms completed pages, shared CSS/JS, backend and University
  site files were unchanged during this step. Pre-existing working changes retained.
- `git diff --check` passed. No staging, commit, or push.

## Remaining limitations

- Guard failure records are not exposed by the existing detail context. Only
  recorded successes can be marked VERIFIED; absence is NOT REPORTED. FAILED is
  not inferred. Runtime state retains existing backend semantics.
- Status remains a server-rendered snapshot; heartbeat behavior is unchanged.
- Model identity is not in the context, so the flow labels Local Model without
  inventing a provider or version. No additional model profile is introduced.
- The in-app browser runtime failed to start; isolated hidden Chrome CDP supplied
  browser verification. Physical-device touch/software keyboard QA was not run.

## Files changed in this step

- `templates/application_detail.html`
- `static/application_detail.css` (new; loaded only by Application Detail)
- `tests/test_application_detail_frontend.py` (new)
- `tests/application_detail_browser.cjs` (new)
- `tests/application_detail_preview.py` (new; synthetic preview only)
- `README.md` (Application Detail documentation only)
- `design-qa.md` (this appended report; prior page reports preserved)

final result: passed

---

# Step 7A — Security Events

## Visual source and evidence

- Source: `LLMGuard-New-UI/security_operations_threat_log/code.html` and
  `screen.png` (1600×1485).
- Implementation: `http://127.0.0.1:8767/admin/soc/events`, backed by isolated,
  persisted synthetic fixtures through the existing security-event writer.
- Side-by-side comparisons: `reports/ui/security-events/comparison-full.png`
  and `comparison-events.png`. Source and implementation captured at matching
  1600×1485 CSS dimensions and device scale 1.
- Required viewport captures: 1440×900, 1366×768, 1024×768, and 375×812;
  additional mobile event-row and empty-state captures are in the same directory.

## Scope and fidelity

The Events panel carries the reference's layered navy surfaces, compact filters,
small event icons, strong category names, semantic action badges, restrained risk
indicators, subtle separators and hover states. Existing console tokens, local
Plus Jakarta Sans and JetBrains Mono, and `llmguard-icons.svg` remain in use.
All new CSS is Events-scoped. The global header and existing Security subnav are
preserved. Other SOC pages receive no Events assets.

The exported KPI strip, incident widget, trace widget, threat matrix, packet/IP
metadata, fabricated telemetry and static pagination are intentional exclusions.
Only the requested Events list is reproduced; available rows use real metadata.
No fake percentages, providers, assignees, geographic values, rules, or actions
were introduced. The rendered-count badge explicitly says events shown.

## Findings and resolution

- [P2, fixed] Inherited timestamp styling initially prevented wrapping at narrow
  widths. An Events-scoped selector now permits wrapping while preserving the
  entire stored timestamp. Required viewport and clipping checks pass on rerun.
- Post-fix comparison and mobile row inspection found no remaining actionable
  P0/P1/P2 issues within this scope. Filters stack, metadata wraps, and action,
  classification, numeric risk and Trace remain readable without page overflow.
- The approved global header retains its existing internal navigation scrolling
  on narrow screens; no shared header redesign was performed.

## Data, functionality and privacy

- Existing route, Jinja context, native GET form and all seven query names and
  values retained. `event_type` search remains exact-match; no client filtering.
- Actual event type, application name, channel, stage, action, classification,
  optional normalized risk and timestamp map directly from existing event views.
  Missing risk produces no numeric score; zero displays `0.00`.
- Long identifiers stay out of row copy. Existing Trace links retain real
  application/request IDs. Raw prompts, context, model output, content, session
  hashes, credentials and secrets do not render in the primary list.
- Existing shared More Filters handler remains unchanged. The page enhancement
  expands selected secondary filters; without JS all controls stay visible.
- Empty state and actual stored-event filtering remain server rendered. No
  mutation, detector, persistence, threshold, classification or RBAC changes.

## Validation

- Targeted Events frontend and existing SOC/security-event tests: 26 passed.
- Full LLMGuard unittest suite: 247 passed. Isolated SQLite databases and a model
  copy prevent the existing classifier-training test from touching the real model.
- Browser QA: nine persisted synthetic events, empty state, seven native GET
  filter cases covering application, stage, action, combined and exact event-type
  filters; secondary-filter state and no-JavaScript submission all passed.
- Required viewports pass page-overflow and tracked-content clipping checks.
  Existing subnav destinations and Trace links pass; one global header remains.
- Browser reports zero console errors, failed static responses or broken images;
  local fonts and every rendered SVG symbol resolve.
- JavaScript syntax and whitespace checks passed. Scope hashing confirms completed
  page files, shared CSS/JS, other SOC templates and backend files unchanged.
  The only shared-template change is two empty asset-extension blocks.
- Evidence: `reports/ui/security-events/browser-results.json`, `full-suite.log`,
  `scope-check.json`, comparisons and viewport screenshots.
- No staging, commit or push.

## Remaining limitations

- Existing backend returns at most 200 matching events without pagination or
  aggregate totals. The page does not invent either.
- Event-type search is exact-match. Date filters and additional telemetry are
  unavailable in the current contract and were not added.
- This is a server-rendered snapshot; no polling or new API behavior was added.
- Isolated Chrome CDP supplied browser verification because the in-app runtime
  was unavailable. Physical-device touch and software-keyboard QA were not run.

## Files changed in this step

- `templates/soc_events.html`
- `templates/soc_base.html` (two empty asset-extension blocks)
- `static/security_events.css` (new; Events only)
- `static/security_events.js` (new; progressive enhancement only)
- `tests/test_security_events_frontend.py` (new)
- `tests/security_events_browser.cjs` (new)
- `tests/security_events_preview.py` (new; isolated synthetic preview only)
- `README.md` (Events documentation)
- `design-qa.md` (this appended report)

final result: passed

## Step 7B — Security Incidents list only

### Evidence and scope

- Source: `C:/Users/Habib UR Rehman/LLMGuard-New-UI/security_operations_threat_log/code.html`
  and `screen.png` (1600×1485 pixels).
- Implementation: `reports/ui/security-incidents/incidents-1600x1485.png`
  (1600×1485 pixels), rendered in Edge through the browser tool.
- Full-view comparison: `reports/ui/security-incidents/comparison-full.png`.
- Focused incident comparison: `reports/ui/security-incidents/comparison-incidents.png`.
  Both comparisons were opened and visually inspected together with mobile rows.
- Source and comparison implementation use 1600×1485 CSS viewport, density 1.
  Required captures also cover 1440×900, 1366×768, 1024×768, and 375×812.
  Chromium's vertical scrollbar reduces screenshot content width at overflowing
  viewports; no content was scaled for the comparison.
- State: four persisted synthetic incidents, all three existing statuses,
  high/critical severity, two applications, and one correlated two-event case.
  Synthetic preview stores are fixed beneath the ignored QA directory and do not
  alter normal application data. True-empty and filtered-empty states were tested.

### Intentional adaptation

The export shows an Events screen with one large blue emergency incident widget,
not a standalone incident list. Per the requested scope, the implementation uses
its navy panel layers, typography hierarchy, medium radii, compact metadata and
button language for full-width incident rows. The emergency background, endpoint
actions, fabricated IDs, assignees, telemetry, IPs, countdowns, SLA, threat matrix,
trace widget, KPI strip and pagination are excluded. The approved global header
and existing Security subnav remain intact; Incidents is active.

### Required fidelity surfaces

- Typography: existing local Plus Jakarta Sans and JetBrains Mono; 26px page
  title, 15px panel title, 13px incident titles, compact metadata and secondary
  monospace IDs. Titles, timestamps and identifiers wrap without clipping.
- Spacing/layout: 20px outer panel padding, 16px row padding, 8px row gaps,
  8px row radii; desktop fields align in columns. At 1024px timestamps form a
  second row. On mobile severity/status share the top row, metadata stacks, and
  Investigate remains accessible with a 44px minimum height.
- Colors/tokens: existing `--cs-*` navy surfaces and blue navigation preserved;
  critical/high red, medium amber, low cyan. OPEN red, ACKNOWLEDGED blue and
  RESOLVED green are restrained badges displaying actual state labels.
- Assets: reuse the existing sprite only; every rendered symbol resolves, and
  browser QA finds no broken images. No generated imagery is needed.
- Copy/content: requested header and exact empty-state copy; incident titles
  derive from summary codes, categories from category metadata, application
  names from the supplied context. First/last seen and counts are actual values.
  No raw prompts, context, model output, source/chunk payloads, primary event IDs,
  request IDs or secrets appear in the primary list.

### Findings and comparison history

The first full and focused comparisons found no actionable P0/P1/P2 issues within
the user's requested compact-list adaptation. Mobile row screenshots confirm
readable severity/status and accessible Investigate actions without horizontal
overflow. The existing global navigation's internal mobile scrolling is unchanged.
No visual-fix iteration was required. An initial test-only CSS-scope parser failed
on nested media-query braces; its parser was corrected and all validation rerun.
Browser automation needed navigation waits and allowance for native GET's trailing
question mark when all filters are blank; no product changes were needed for these.

### Functionality and validation

- Native server-side GET filters preserved: `application_id`, `incident_status`,
  `severity`, `category` (exact match). Nine browser cases verify OPEN,
  ACKNOWLEDGED, RESOLVED, severity, application, category, all four combined,
  filtered empty and all fields blank. No client-side filtering.
- The scoped script deletes blank filter values from native FormData because
  the existing optional status enum rejects an empty string. Backend unchanged.
- Actual row IDs, titles, severity, status, event counts and datetime attributes
  were checked against persisted QA records. Investigate opened the exact detail
  route. The existing lifecycle controls were not changed or operated in browser QA.
- 24 targeted Python tests passed, including existing SOC/incident tests.
- Two JavaScript tests passed; JS syntax and `git diff --check` passed.
- Full LLMGuard suite: 256 tests passed, zero failures/errors/skips. SQLite
  stores, retrieval artifacts and classifier training output were isolated;
  the protected repository classifier was verified unchanged by hash.
- Browser QA: one shared header, active Incidents subnav, expected GET URLs,
  real stored values, true/filtered empty states, four required viewport checks,
  no tracked clipping or page overflow, zero console errors and valid icons.
- Scope check: 309 existing source/assets/model/test files hashed; only the
  intended existing SOC test empty-copy expectation changed among protected
  snapshot files. Completed pages, shared CSS/JS, Events assets, other SOC
  templates, backend, model and University files remain unchanged in this step.
- Results: `reports/ui/security-incidents/browser-results.json`, `full-suite.log`,
  `scope-check.json`, comparisons, viewport and filter screenshots.
- No staging, commit or push.

### Remaining limitations

- Existing context has no channel field; no channel or extra query was invented.
- Existing backend returns at most 200 matching incidents; there is no polling,
  pagination or total across records outside the supplied list.
- Current correlation rules produce high/critical incidents. Low/medium visual
  mapping was verified using presentation-only fixtures, without altering rules.
- Blank-status Apply submission relies on the scoped JavaScript to omit the
  invalid empty enum; direct unfiltered navigation and Clear remain available.
- Browser QA used Edge desktop emulation because the in-app browser was unavailable;
  physical mobile devices and other browser engines were not tested.

### Files changed in this step

- `templates/soc_incidents.html`
- `static/security_incidents.css` (new)
- `static/security_incidents.js` (new)
- `tests/test_security_incidents_frontend.py` (new)
- `tests/security_incidents.test.cjs` (new)
- `tests/security_incidents_preview.py` (new; optional synthetic QA only)
- `tests/test_soc_console.py` (one incident empty-copy expectation)
- `README.md` (incidents documentation)
- `design-qa.md` (this appended report)

final result: passed

## Step 7C — Security Incident Detail (2026-10-07)

### Scope and reference

Only `/admin/soc/incidents/{incident_id}` is redesigned. The existing shared
shell and SOC subnav remain unchanged, with Incidents active. Backend routes,
authentication, RBAC, correlation, persistence and transition rules are unchanged.

Reference: `../LLMGuard-New-UI/security_operations_threat_log/code.html` and
`screen.png`. Its security panels provide visual inspiration; its fabricated
network telemetry and emergency-response card are intentionally excluded.
The reference depicts an OPEN alert; the final implementation screenshot depicts
an actual RESOLVED synthetic incident after the verified native workflow.

Evidence under `reports/ui/security-incident-detail/`:

- `detail-1600x1485.png`: final implementation, 1600×1485 CSS viewport and PNG
  pixels, device pixel ratio 1 and visual scale 1.
- `comparison-full.png`: source and implementation at matching 1600×1485 sizes.
- `comparison-panels.png`: focused source security panels and actual summary,
  event and history panels. Crops compare visual treatment rather than geometry.
- `iteration-mobile.png`: same 320×812 CSS viewport and OPEN state before/after
  the heading fix; both tool captures are 305×774 pixels.
- `iteration-desktop.png`: initial desktop capture is partial (1440×621 pixels),
  while the later capture is 1425×891; this is not a full same-size comparison.
- `browser-results.json`, `fixture.json`, `scope-check.json`, `full-suite.log`,
  and the OPEN/RESOLVED viewport screenshots.

Browser tools scaled some required-viewport screenshot artifacts. CSS viewport
measurements, overflow and clipping checks use the requested widths, independently
of those image dimensions. The exact 1600×1485 capture avoids that scaling for
the full source comparison. Full and focused comparisons were visually inspected.

### Required fidelity surfaces

- Typography: approved local fonts and shared heading hierarchy; compact event
  titles, secondary monospace identifiers and readable timestamp text.
- Spacing/layout: layered compact summary, dense decision rows and an adjacent
  audit timeline on desktop. Panels stack on narrow screens; identifiers wrap,
  disclosure controls remain native and mobile status actions are at least 44px.
- Colors/tokens: existing navy surfaces, borders and blue navigation; restrained
  red critical/high, amber medium and cyan low severity. Actual status badges
  distinguish OPEN, ACKNOWLEDGED and RESOLVED. Resolve uses approved green.
- Assets: existing `static/llmguard-icons.svg` only, unchanged. Every referenced
  symbol resolves; there are no broken images or additional icon libraries.
- Copy/content: Security Incident, actual humanized summary code and category,
  concise metadata labels, actual audit transitions, and explicit empty states.
  No fake telemetry, owners, countdowns, risk scores or payload content.

### Findings and fixes

Initial browser review found that the shared button selector overrode Resolve's
green treatment. Increasing specificity inside the detail scope corrected it;
browser computed color is `rgb(78, 222, 163)`. Decision metadata was tightened
into wrapping groups to improve row density.

At 320px, the summary heading shared insufficient width with the privacy label.
The mobile layout now gives the heading a full row and places that label below.
The same-state mobile before/after comparison confirms the fix. Expanded 200-byte
request identifiers and the populated audit timeline were inspected at 320px.
Final full and focused comparisons have no remaining actionable P0/P1/P2 findings
within the requested adaptation. Existing global navigation scrolling is unchanged.

### Data, workflow and privacy

- Incident mapping: supplied summary code, application name/ID, category, severity,
  status, event count, incident ID, first/last seen and primary event ID. No query
  or invented field was added. Technical IDs remain secondary and wrap safely.
- Event mapping: supplied type, stage, channel, classification, action, severity,
  timestamp and optional policy code. Numeric risk is shown to two decimals;
  zero is preserved and absent risk is omitted. Native disclosures show only
  actual event/request/source/chunk identifiers.
- OPEN uses existing POST Acknowledge and Resolve forms. ACKNOWLEDGED has only
  Resolve; RESOLVED has a terminal state. No detail JavaScript or fake state
  mutation. Success copy requires `updated_status` to equal persisted status.
- History renders actual old/new status, actor and timestamp from `status_audit`,
  with a polished empty state. No actor, reason or note is fabricated.
- View Trace retains `/admin/soc/trace?application_id=...&request_id=...`, encoding
  both values. Missing request IDs produce no trace link. Back to Incidents uses
  the existing list route.
- Metadata-only rendering excludes raw prompts, retrieved context, model output,
  document bodies, credentials, secrets and personal university records. Tests
  inject extra synthetic raw fields and verify they never render.
- No exported IPs, packet captures, hosts, locations, assignees, SLA, tickets,
  containment controls or network actions were imported.

### Validation

- 28 targeted tests passed: 13 Incident Detail frontend tests plus existing SOC
  incident/status and security-event tests. Coverage includes context preservation,
  native POST/303 redirects, direct OPEN resolution, audit records, terminal 409,
  optional metadata/zero risk, encoded trace links, empty states, scoped assets,
  RBAC, authentication and unknown incidents.
- Full isolated LLMGuard suite: 269 tests passed, zero failures/errors/skips.
  SQLite stores, retrieval artifacts and classifier training outputs were isolated;
  the repository model was copied read-only and remained unchanged.
- JavaScript syntax checks passed for existing `product.js`, `security_events.js`
  and `security_incidents.js`; no JavaScript was added or changed for this step.
- Final `git diff --check` passed.
- Edge browser QA used one isolated stored synthetic incident. Native Acknowledge
  then Resolve produced OPEN → ACKNOWLEDGED → RESOLVED with correct redirect
  notices, allowed buttons and persisted actor/timestamp audit entries.
- Ten layout checks cover OPEN and RESOLVED at 1440×900, 1366×768, 1024×768,
  375×812 and 320×812. Severity/status, stacked metadata, mobile actions, event
  rows, audit and expanded identifiers remain readable without page overflow.
- Real incident/event/audit values were compared with stored records. View Trace
  opened the correct existing request trace; Back to Incidents and Investigate
  returned to the correct routes. One global header, valid icons, zero console
  errors, no raw payloads and no unsupported controls.
- Scope hashes checked 312 existing application/template/asset/model/test files.
  Only `templates/soc_incident_detail.html` changed among them. Completed pages,
  shared styles/scripts, Events/List assets, other SOC templates, backend,
  classifier and University files remain unchanged from this step's starting state.
- No staging, commit or push.

### Remaining limitations

- The export supplies security-panel inspiration rather than a standalone detail
  layout; unsupported source content is intentionally omitted.
- Audit context contains no reason/note fields; none are displayed or invented.
- This remains server-rendered stored metadata; no polling or live telemetry added.
- Browser QA uses desktop Edge emulation; physical mobile devices and other
  browser engines were not tested.

### Files changed in this step

- `templates/soc_incident_detail.html`
- `static/security_incident_detail.css` (new)
- `tests/test_security_incident_detail_frontend.py` (new)
- `tests/security_incident_detail_preview.py` (new; isolated synthetic QA only)
- `README.md` (detail documentation)
- `design-qa.md` (this appended report)

final result: passed

## Step 7D — Request Trace (2026-10-07)

### Findings and fixes

- [P2, fixed] Mobile search input/select heights were 42px despite intended
  44px sizing. The shared input min-height won the initial rule. Trace-scoped
  explicit height now gives input, select and button a measured 44px height.
  `iteration-mobile.png` compares the same long-ID trace at 375×812 before/after;
  both captures are 360×780 pixels. Final responsive checks confirm the fix.
- Initial test checks caught unsupported sprite names, corrected to existing
  `neural`/`monitor` symbols without editing the sprite. The final-decision summary
  no longer repeats a raw event-type code before chronological evidence.
- A synthetic test encountered tied Windows timestamps; distinct fixture times
  now make the intended sequence deterministic. Backend ordering remains timestamp
  then event ID, and the final decision always uses the actual last supplied event.
- The final full and focused source comparisons have no remaining actionable
  P0/P1/P2 findings within the requested visual adaptation.

### Scope, source and comparison evidence

Only `/admin/soc/trace` is redesigned. Shared header/system, Events, Incidents
list/detail, Quarantine and other completed pages remain unchanged from this
step's starting state. Native GET queries, route context, authentication/RBAC,
event persistence, detector/authorization behavior and trace semantics are intact.

Source: `../LLMGuard-New-UI/security_operations_threat_log/code.html` and
`screen.png`, specifically its Stage Trace Pipeline panel. Its visual language
is inspiration, not permission to import fabricated latency, stage records,
network telemetry or actions. The existing approved shell and local fonts prevail.

Artifacts under `reports/ui/security-trace/`:

- `blocked-1600x1485.png`: actual input-only block at 1600×1485 CSS pixels,
  device density 1; image is 1600×1485 pixels, matching the supplied source.
- `comparison-full.png`: source plus implementation at equal dimensions/density.
- `comparison-pipeline.png`: actual source/implementation pipeline crops together
  for readable typography, node, surface and copy inspection.
- `allowed-1600x1485.png`: three recorded canonical guards, connected only to
  each other; the last node has no outgoing connector.
- `iteration-mobile.png`, `before-mobile-controls.png`, `after-mobile-controls.png`:
  mobile search sizing fix at matching viewport and interaction state.
- `early-block-mobile-coverage.png`: expanded missing-record coverage at 320px.
- State/viewport captures, `capture-dimensions.json`, `browser-results.json`,
  `fixtures.json`, `full-suite.log` and `scope-check.json`.

Source and comparison both depict a blocked input decision; their datasets and
page topology differ intentionally. The export also depicts invented ingress,
session, downstream states, timings and raw export controls. The implementation
shows only its real input record. It does not clone unrelated Events widgets or
imply downstream execution. Focused crop geometry differs because those unsupported
records are omitted. Full and focused comparisons were opened and inspected together.

Browser tools scale some requested-viewport screenshot artifacts (for example,
375×812 CSS pixels yields 360×780 image pixels). Actual DOM viewport/overflow checks
use the requested widths; screenshot file dimensions are separately recorded.
The exact 1600×1485 source comparison avoids density mismatch. Initial/unsearched
captures are implementation-only evidence because the export has no such state.

### Required fidelity surfaces

- Fonts/typography: approved Plus Jakarta Sans and JetBrains Mono, shared 26px
  page heading, 15px panel titles, 12px stage/event titles and compact secondary
  metadata. Labels, long IDs and timestamps wrap without clipping.
- Spacing/layout: 20px panel padding, 18px section gaps, 8px inner card radii and
  14px node gaps. Desktop pipeline/evidence columns stack at narrower widths.
  Search becomes a single usable column; no overlapping nodes or page overflow.
- Colors/tokens: approved navy surfaces, subtle borders, blue/cyan technical
  accents and restrained node glow. ALLOW green; block/reject/failure red;
  sanitize/quarantine/restriction/bypass amber; informational actions blue.
  All labels are actual recorded values, never fabricated success percentages.
- Assets: existing sprite icons only, all references resolve, zero broken images.
  Native structural connectors link recorded nodes; no raster artwork is needed.
- Copy/content: requested header/supporting text and exact no-result message;
  concise instructional initial state, explicit persisted-evidence language,
  real stage/decision metadata and cautious missing-record copy. No live claims.

### Data and architectural truth

- Search retains `request_id` and `application_id` on native GET `/admin/soc/trace`,
  including trimming, the 200-character bound, selected app and encoded app-choice
  links. Shared request IDs require application selection; no merged trace.
- Summary derives application, actual channels, event count, first/last events,
  optional maximum numeric risk and last recorded stage/action solely from the
  supplied list. Risk zero survives; absent risk/latency generates no value.
- `stage_summary` remains the backend's three canonical identifiers: input,
  context, output. Visual labels use architecture positions 02/06/09 and guard
  names; only entries marked recorded receive nodes. All same-stage events and
  the supplied event_count remain visible. No synthetic ingress/response nodes.
- Canonical grouping is architectural, not an asserted complete execution chain.
  The chronological evidence list preserves every event in actual backend order.
  Missing records live in a separate native Recording coverage disclosure and do
  not establish execution or justify a fabricated NOT REACHED conclusion.
- An input-only block/session restriction has one input node, no outgoing connector,
  an explicit path end, and no later recorded canonical stages. No completed line
  crosses unrecorded context, retrieval or model processing.
- `other_stages` supplies Additional Security Evidence labels; matching events
  render there in the supplied chronology and remain in the full evidence list.
  Additional-only traces display no invented canonical guard.
- Explicit `university_authorization` / `protected_application_authorization`
  identifiers label University / Protected Application Authorization. These records
  remain outside LLMGuard's canonical guards; never labeled LLMGuard RBAC. The
  optional synthetic boundary fixture tests rendering, not new instrumentation.
- Metadata-only evidence renders type, stage, channel, action, classification,
  numeric risk and time. Native disclosures retain only safe event/stage/policy/
  source/chunk identifiers. Raw prompts, context, documents, model output, secrets
  and private university records never render.
- No exported packet/PCAP, IP, host, span, location, provider/vector-store branding,
  response countdown, invented latency, network action or raw-export control.
- No new JavaScript, animation, polling, API or client state mutation. Trace CSS
  uses the existing asset_version plus a page-local revision suffix for cache freshness.

### Validation and browser QA

- 30 targeted tests passed: 15 Request Trace frontend tests, seven existing SOC
  tests and eight security-event tests. Includes context/query preservation,
  empty states, early containment, actual stage/count mapping, chronology versus
  architecture, all same-stage records, zero/absent risk, bypass treatment,
  additional evidence, boundary labels, application isolation, privacy, assets,
  completed-page asset exclusion, query validation and RBAC.
- Full isolated LLMGuard suite: 284 passed, zero failures/errors/skips (151.148s).
  SQLite, retrieval and classifier outputs use disposable locations; the protected
  classifier is copied read-only, never trained or changed in the repository.
- JavaScript syntax checks passed for all 11 existing static scripts, and final
  `git diff --check` passed; no JS added/changed.
- Browser native searches covered input block, allowed later guards, sanitized
  context, output block, bypass, session restriction, additional/boundary records,
  a 200-character encoded ID, shared request IDs, application choice, wrong-app
  no-result, missing request and unsearched initial state.
- Stored event IDs/order, actions, classifications, risk and timestamps were
  compared with actual fixture records. Additional-only application choice was
  verified to show only its own evidence and no canonical node.
- Fifteen responsive checks covered long early-block, allowed and additional
  traces at 1440×900, 1366×768, 1024×768, 375×812 and 320×812. No tracked clipping,
  page overflow, node overlap or extra connector; mobile search controls are 44px.
- Expanded 320px coverage was inspected, with actual input-only termination and
  readable missing-record copy. Mobile pipeline/evidence screenshots confirm stacking.
- One global header, active Trace subnav, valid sprite symbols, zero broken images,
  zero browser console errors, privacy/excluded-content checks passed.
- A browser connection timeout interrupted a final optional capture; resetting the
  tool and opening a fresh tab restored QA. Earlier screenshots/tool observations
  remain; eight metadata cases were saved again with console verification. Final
  results are written incrementally to avoid losing evidence on a tool interruption.
- Protected-file hashes checked 315 existing application/template/asset/model/test
  files; only `templates/soc_trace.html` changed among them. Backend, completed
  pages, shared assets, University code and classifier retain starting hashes.
- No staging, commit or push.

### Remaining limitations

- Existing canonical summary includes only input/context/output. University,
  retrieval and model execution cannot be inferred when no corresponding stored
  evidence exists. The page adds no instrumentation, latency or delivered-response claim.
- Additional labels support explicitly recorded metadata; the University/retrieval
  QA fixture does not claim current production emission of those stages.
- Server-rendered stored evidence only; no live progress or polling.
- QA uses desktop Edge emulation, not physical mobile devices or other engines.
  Existing shared navigation's internal mobile scroll remains unchanged.

### Files changed in this step

- `templates/soc_trace.html`
- `static/security_trace.css` (new)
- `tests/test_security_trace_frontend.py` (new)
- `tests/security_trace_preview.py` (new; isolated synthetic QA only)
- `README.md` (Trace behavior and commands)
- `design-qa.md` (this appended report)

final result: passed

## Step 7E — Quarantine only (2026-10-07)

### Scope and visual reference

Only `/admin/soc/quarantine` presentation changed. The supplied
`security_operations_threat_log/code.html` and `screen.png` provide Security
surface, row, hierarchy and semantic-accent inspiration, rather than a dedicated
Quarantine page. The existing shared console header, SOC navigation, fonts,
sprite, authentication and RBAC remain intact. There is no global CSS change.

The page now has the requested Quarantine heading/supporting text, a count of
currently rendered records, a layered navy panel, native Application filter,
compact amber-accent rows, quiet investigation links and expandable safe IDs.
Rows are approximately 118px tall at the normalized desktop review size.
Unavailable references create no placeholder actions. The empty state uses the
requested title and supporting text without demo content.

### Real data and privacy mapping

- Existing row contract contains exactly `event_id`, `application_id`,
  `application_name`, `request_id`, `source_id`, `chunk_id`, `created_at` and
  `incident_id`. All displayed values come from these fields; no new query or
  backend aggregation was introduced.
- Category/type, stage, channel, classification, action, risk and reason are not
  supplied by this route. The neutral Quarantine record title avoids inventing
  these values or inferring them from identifiers. Amber is a presentation accent,
  not an invented severity or classification.
- Source/chunk IDs remain safe references in the native disclosure, including
  context/RAG fixtures. No source text or chunk body is displayed. The native
  disclosure works without page JavaScript.
- Native GET retains optional `application_id`, backend ordering and the existing
  200-record limit. All Applications submits the existing empty value. Clear
  filter returns to the same route. Count labels describe the rendered set only.
- Request references link to `/admin/soc/trace` with encoded `application_id` and
  `request_id`. Actual incident associations retain their existing detail links.
  Missing references produce no fake links; no event-detail route was invented.
- Rendering explicitly selects safe fields, escapes identifiers, and ignores
  additional synthetic sensitive-field sentinels even when passed to the template.
  No raw protected content, personal records, credentials or secrets appear.
- No release, restore, delete, approve, dismiss, reprocess, download or payload
  action; no fake counters, TTL, telemetry, stage/reason, network/malware concepts,
  SOC assignees or copied exported records. No polling, new API or JavaScript.

### Visual review and iteration

Artifacts are under `reports/ui/security-quarantine/`:

- `before.png`: original page with an existing isolated synthetic context record.
- `records-full.png`: complete final browser capture at 1600×1485.
- `comparison-full.png`: supplied source and implementation together at matching
  1600×1485 bounds; header/navigation differences are intentionally preserved.
- `comparison-rows.png`: focused source/implementation row and panel comparison.
- `records-{width}.png`, `empty-{width}.png`, `long-identifiers-{width}.png`:
  requested responsive checks; capture dimensions are recorded separately.
- `long-identifiers-320-full.png`: complete 320px view with native disclosure open
  and maximum-length request/source/chunk IDs wrapping cleanly.
- `browser-qa.json`, `trace-navigation.json`, fixture manifests, full-suite log and
  starting/final file-hash inventories record verification evidence.

The source and implementation were opened together and reviewed at full-page and
focused-row scale. The implementation preserves the approved navy layers, medium
radii, technical typography, restrained semantic accents and blue navigation.
Exported dashboard density/content, fake risk/telemetry and network controls are
intentionally excluded. Visual review scores: hierarchy 8/10, surface/style 8/10,
interaction clarity 9/10, responsive behavior 9/10, data/privacy fidelity 10/10.

Desktop review found inherited panel padding and a 20px native-details margin
making rows too tall. Scoped padding/margin overrides and horizontal quiet
actions reduced row height without changing shared CSS. Final captures confirm
the fix. Some viewport screenshots included browser scrollbar/scaling bounds;
the normalized comparison and mobile identifier review use complete browser
captures. These capture differences did not affect DOM viewport measurements.

### Validation

- 28 targeted checks passed: 13 new Quarantine frontend tests, seven existing
  SOC tests and eight security-event tests. Covers context/query preservation,
  real ordering/filtering, both empty states, optional links, encoded IDs,
  privacy/escaping, native disclosures, icon resolution and authentication/RBAC.
- The first run exposed one overbroad new assertion matching the requested word
  isolated, and an existing SOC trace-order fixture whose timestamps could tie.
  The assertion now checks the unsupported action Isolate Endpoint; the existing
  fixture now stores two explicit distinct timestamps. Production sorting and
  completed Trace presentation are unchanged.
- Full isolated LLMGuard suite: 297 passed, zero failures/errors/skips. Database,
  classifier output, retrieval and report artifacts use disposable locations;
  the protected repository classifier was only read/copied.
- Browser native GET checks covered all records, two application filters, Clear
  filter, filtered empty and a separate truly empty store. Displayed event IDs,
  timestamps and safe references match actual persisted fixture records.
- Fifteen responsive checks covered populated records, expanded maximum-length
  identifiers and true empty states at 1440×900, 1366×768, 1024×900, 375×812 and
  320×812. No page overflow or tracked record/metadata clipping. Search controls
  and mobile investigation links remain accessible; native disclosure confirmed.
- View Trace opened the correct application and full 200-character encoded
  request, showing its stored context event. View Incident opened the correct
  existing incident detail route. No status or quarantine action was invoked.
- One global header, active Quarantine subnav, existing valid sprite symbols,
  zero broken images and zero browser console errors. Shared mobile navigation's
  internal scroll remains unchanged.
- Final 13 Quarantine frontend checks passed after the scoped spacing adjustment.
  Syntax checks passed for all 11 existing static JavaScript files, and final
  `git diff --check` passed (existing LF/CRLF advisory warnings only).
- Hashes checked 318 existing application/template/asset/model/test files.
  Only `templates/soc_quarantine.html` and `tests/test_soc_console.py` changed;
  the latter contains the required new empty-copy assertion and timestamp-fixture
  stabilization. Completed pages, shared assets, backend, University code and
  classifier retain starting hashes. No staging, commit or push.

### Files changed in this step

- `templates/soc_quarantine.html`
- `static/security_quarantine.css` (new)
- `tests/test_security_quarantine_frontend.py` (new)
- `tests/security_quarantine_preview.py` (new; isolated synthetic QA only)
- `tests/test_soc_console.py` (empty-copy expectation and deterministic fixture)
- `README.md` (Quarantine behavior and preview commands)
- `design-qa.md` (this appended report)

### Remaining limitations

The existing route does not supply category, stage, channel, classification or
reason, so those fields are not displayed. Investigation uses existing linked
Trace/Incident metadata. Existing 200-record limit and read-only semantics remain.
QA uses synthetic stored fixtures and desktop Edge viewport emulation; no physical
mobile device or other browser engine was tested. Existing dependency warnings
remain outside this presentation scope.

final result: passed

## Step 8A — Evaluation Benchmark only (2026-10-07)

### Source audit completed before presentation edits

The current template, admin route, evaluation dataset/harness/metrics/reporting,
CLI, existing evaluation tests, README and designated final artifact were audited.
The exported `evaluation_benchmarks/code.html` and `screen.png` are visual
references only. Audit evidence is saved in
`reports/ui/evaluation-benchmark/source-audit.json`.

| Class | Actual source | Decision |
| --- | --- | --- |
| A: existing Jinja/backend | `benchmark_case_count` counts nonblank dataset lines; existing auth/portal/firewall/asset context | Preserved |
| B: real evaluation artifact | `reports/evaluation/final/benchmark.json` plus its generated `summary.md`/`cases.csv` | Read-only metadata/metric selection |
| C: documented research semantics | README and harness describe synthetic cases, seeds, modes and instrumented replay; final summary agrees with JSON | Research scope and methodology retained; no independent production certification claimed |
| D: static current-template values | Modes 6 and Runs 3 were literals matching CLI defaults, not actual run data | Replaced with verified artifact metadata |
| E: unsupported exported information | Fake overall score/interceptions, OWASP distribution, regressions/history, terminal logs/status, AutoDAN and production audit claims | Excluded |

The final artifact has schema `phase14b-v1`, synthetic-data metadata and 54 cases,
three runs with seeds 42/43/44, six implemented modes and 972 total result rows.
Dataset bytes and canonical sorted case-ID order match both artifact hashes.
The classifier hash also matched during the source audit; it was only read.
Earlier phase14a/14b/15a artifacts have different historical scores; phase15b and
the separate final-test output are not substituted for the designated final file.
No phase outputs are presented as historical trend data.

### Verified data mapping

All benchmark numbers below refer to `reports/evaluation/final/benchmark.json`.
No user-provided expected metric or exported number is used as evidence.

| Display | Artifact/source field |
| --- | --- |
| Cases 54 | Existing `benchmark_case_count`; matched `metadata.dataset_case_count` and current dataset |
| Runs 3; seeds 42,43,44 | `metadata.run_count`, `metadata.run_seeds`, checked against `repeated_runs.runs` |
| Six modes, canonical order | Present `metrics` keys; order verified against `evaluation.harness.MODE_ORDER` |
| Accuracy, Precision, Recall, F1, Clean Pass Rate 100.0% | `metrics.full_protected_pipeline` corresponding rates, each 1.0 |
| ASR, FPR, FNR 0.0% | `metrics.full_protected_pipeline` corresponding rates, each 0.0 |
| Malicious downstream 9.5% | `metrics.full_protected_pipeline.malicious_downstream_execution_rate` = 0.09523809523809523 |
| Sanitized observations 12/126; four unique cases; zero attack successes | Protected measured malicious `results` rows; all downstream rows have action sanitize and false attack_success |
| Bypassed Accuracy 22.2%, ASR 85.7%, FNR 100.0%, Clean Pass 100.0% | `metrics.bypassed` = 0.2222222222222222, 0.8571428571428571, 1.0, 1.0 |
| Matrix TP126/TN36/FP0/FN0; 162 observations | `metrics.full_protected_pipeline.confusion_matrix` and `observation_count` |
| Nine coverage categories, six cases each | `metadata.category_counts`, checked against actual dataset categories |
| Mean 39.209ms; Median 26.959ms | Protected `mean_latency_ms` 39.208716049382716 and `median_latency_ms` 26.95895 |
| Dataset/order SHA-256 | `metadata.dataset_sha256` and `case_order_sha256`, verified against dataset bytes/sorted IDs |
| Reproduction CLI | Real `evaluation.run.build_parser` flags plus stored runs/seed/modes; separate output directory |

Exact implemented modes: `rules_only`, `semantic_only`, `ml_only`, `hybrid`,
`full_protected_pipeline`, `bypassed`. Coverage uses exact dataset categories with
human-readable labels, not an invented OWASP mapping. Privilege/cross-user cases
are benign for detector scoring and evaluate University authorization separately.

### Presentation and contract

Only `/admin/evaluation` presentation is redesigned. The existing subnav component
retains Benchmark, Detector Comparison and Red Team routes, with Benchmark active.
The shared header/design system and completed pages are unchanged. New styling is
scoped under `.evaluation-benchmark-page` in `static/evaluation_benchmark.css`.
The existing icon sprite is reused without changes or another icon library.

Four compact metadata cards lead into a truthful accuracy ring, eight protected
metrics, a security/utility panel, Protected/Bypassed comparison, dataset coverage,
classification matrix, benchmark timing and a technical reproduction panel.
The matrix shows real classification observation counts, not a fabricated
robustness/history grid. Rates consistently convert proportions to percentages.

`app/benchmark_presentation.py` is a read-only presentation adapter. The existing
GET route retains its auth/RBAC and original context and adds `benchmark_report`.
This wiring changes no endpoint, security policy, evaluation execution,
calculation, dataset, threshold, seed, model or report. It reads fixed repository
paths; no HTTP parameter can select an arbitrary filesystem path. It validates
schema/synthetic metadata, dataset hashes and repeated-run metadata, then exposes
only explicit safe fields. Invalid individual rates/latency fields are omitted.

Missing/corrupt/dataset-mismatched artifacts show No verified benchmark results,
the real current dataset count and the actual CLI entrypoint. No fallback score,
fake modes or run state is supplied. The real artifact remains ignored/local and
is not copied into a tracked static snapshot.

Sanitized continuation is clearly separate from attack success. The explanatory
note is emitted only when actual stored result rows prove that all malicious
downstream observations were sanitized and attack_success is false. University
RBAC remains active in both recorded pipeline modes, with its denials excluded
from LLMGuard prevention counts.

The reproduction command is `python -m evaluation.run` with stored run/seed/mode
flags and `--output-dir reports/evaluation/reproduction`; parser validation passes.
It is inert code text, not a run button, fake log or web execution action. The
original final report is not overwritten. No new JavaScript or polling is added.

Research / Demo Evaluation, stored/read-only result wording and a concise scope
note distinguish research evidence from live telemetry or certified protection.
Timing is explicitly local instrumented boundary replay, not live University
mutations, Qwen generation, production latency or scalability evidence. Rendering
does not expose case payloads, raw prompts/context/output, secrets or personal data.

### Visual QA

Source and implementation were opened together at full-page and focused scale.
Artifacts in `reports/ui/evaluation-benchmark/` include:

- `before.png`, requested-width `benchmark-{width}.png` and `unavailable-{width}.png`.
- `benchmark-full.png`: full browser capture with the actual research panels.
- `comparison-full.png`: complete source and implementation at normalized width.
- `comparison-viewport.png`: source and implementation within source-height bounds.
- `comparison-matrix.png`: exported matrix styling versus actual observation cells.
- `mobile-metrics.png`, `mobile-comparison.png`, `mobile-reproducibility.png`:
  focused 320px views confirming readable metrics, stacked comparison and hashes.
- `browser-qa.json`, `navigation.json`, source audit, capture dimensions,
  full-suite log and starting/final hash inventories.

The source is 1280×1213. The implementation was captured at a 1280×1214 viewport;
its complete capture excludes a 15px scrollbar and is 1265×2138. Comparison output
normalizes width to 1280 (approximately 1.2% scaling). The longer actual page
accommodates verified core metrics, comparison, all categories and reproducibility
instead of the exported fake logs, historical grid and Red Team banner.

Review confirms layered dark navy panels, blue/cyan technical accents, restrained
green result values, medium radii, strong hierarchy and premium research-console
depth. Subjective QA scores: surfaces/style 8/10, hierarchy 8/10, research clarity
9/10, responsive behavior 9/10, provenance/data fidelity 10/10.

A full-page mobile capture and off-viewport clip timed out and left that tab's
capture scaling incorrect. A fresh tab in the same Edge session restored focused
captures; actual 320px metrics, comparison and wrapping hashes were then opened
and inspected. No application or CSS change was required. Final preview uses a
fresh tab with temporary viewport overrides reset.

### Validation and unchanged scope

- 35 targeted tests passed: 15 Benchmark frontend/provenance tests and 20 existing
  evaluation tests. Checks include all source mappings, percentages, exact modes,
  coverage, sanitizer evidence, observation matrix, latency, hashes/CLI parser,
  unavailable/invalid artifacts, partial data omission, privacy, icons, read-only
  behavior, completed-page asset exclusion and authentication/RBAC.
- One initial new test incorrectly expected access for an employee in the admin
  portal. Existing `require_portal` denies it; only the test expectation was fixed.
  No access rule was changed.
- Full isolated LLMGuard suite: 312 passed, zero failures/errors/skips, 180.989s.
  Classifier/retrieval/database/report outputs were isolated; final evaluation
  reports and the protected classifier retain starting hashes.
- Syntax checks passed for all 11 existing static JavaScript files. No JS added.
  `git diff --check` passed; existing LF/CRLF advisory warnings are not failures.
- Browser checks covered recorded and unavailable states at 1440×900, 1366×768,
  1024×900, 375×812 and 320×812. Every rendered rate, latency, hash, category count
  and matrix value was compared to the actual final artifact. No tracked content
  clipping or horizontal page overflow. Metric cards and comparisons stack;
  technical hashes/command wrap safely.
- Actual subnav navigation opened the unchanged Comparison and Red Team routes.
  Benchmark active state and Evaluation header active state remain correct.
- One global header, valid existing sprite symbols, zero broken images and zero
  browser console errors. Shared mobile navigation's internal scroll is preserved.
- Starting hashes checked 347 existing application/evaluation/template/asset/model/
  test/report files. Only `templates/evaluation.html`, `app/portals/admin.py` and
  `tests/test_product_frontend.py` changed among them. The admin change is only
  adapter import/context wiring; the existing test change is supporting-copy
  expectation. All evaluation inputs/artifacts, completed pages, shared CSS,
  detector/security code, University files and classifier remain unchanged.
- No staging, commit or push.

### Files changed

- `templates/evaluation.html`
- `static/evaluation_benchmark.css` (new)
- `app/benchmark_presentation.py` (new; read-only presentation adapter)
- `app/portals/admin.py` (existing GET context wiring only)
- `tests/test_evaluation_benchmark_frontend.py` (new)
- `tests/evaluation_benchmark_preview.py` (new; disposable QA stores only)
- `tests/test_product_frontend.py` (updated supporting-copy expectation)
- `README.md` (presentation/provenance/preview commands)
- `design-qa.md` (this appended report)

### Intentional omissions and remaining limitations

No provenance exists for exported regressions/deltas, OWASP mapping/distribution,
AutoDAN results, live execution status, production certification or historical
run trends. No p95/p99/throughput is shown; only supported mean/median timing is
used. Detailed detector metrics belong to the unchanged Comparison scope; other
verified report fields are omitted to keep the Benchmark focused.

The artifact describes one controlled synthetic evaluation using instrumented
boundaries. Its measurements are not current production traffic, a live model
test or proof of complete prompt-injection protection. A reproduction command
does not guarantee identical timing on another machine. Environments without the
ignored final artifact show the safe unavailable state. Browser QA uses desktop
Edge viewport emulation, not physical mobile devices or other engines. Existing
dependency deprecation/load warnings remain outside presentation scope.

final result: passed

## Step 8B — Detector Comparison (2026-10-08)

Only `/admin/compare` was redesigned. The GET/source/POST audit preceded edits:
interactive JSON POST remains `/admin/compare/run` with the existing prompt,
user-role, scope and optional synthetic user ID. It compares two gateway system
modes, not four standalone detectors. No POST, detector, threshold, dataset,
calculation, auth/RBAC, report or shared JavaScript changes.

Comparison-only CSS and a read-only allowlisted artifact adapter present four
detector cards, exact accuracy bars, a metric matrix, benchmark latency and
separate Protected Pipeline/Bypassed evidence. Existing interactive selectors,
fields, defaults, scripts and result rendering are retained in a distinct section.
The completed Benchmark's adapter and visual assets remain unchanged; its
established provenance validation is reused read-only.

All visible aggregate metrics map to
`reports/evaluation/final/benchmark.json:metrics[mode]`. Case/run/seed facts map
to `metadata.dataset_case_count`, `run_count`, `run_seeds`. Detector ASR remains
N/A when `execution_measured_malicious_count` is zero, matching the report's
`evaluation/reporting.py` formatting. Sanitized continuation counts are verified
from protected malicious measured `results` rows and never called attack success.
No exported fake history/robustness/terminal/live/model claims are included.

Edge QA covered GET, actual malicious-input POST, actual configuration rejection,
actual protected early block, expanded evidence, long synthetic user ID, subnav,
and missing-report fallback. Viewports: 1440×900, 1366×768, 1024×768, 375×812,
320×812. Every displayed metric, latency and unrounded bar source matches the
artifact. No console errors, invalid sprite symbols, broken images, duplicate
header or horizontal page overflow. Narrow matrices are focusable and keyboard
scrollable. Shared table min-width and empty result min-height were overridden
only inside Comparison. Full and focused reference/implementation frames reviewed.

Tests: 73 targeted passed (20 new Comparison, 35 Benchmark/evaluation/gateway/
frontend and 18 established Phase 14A/14B); full suite 332 passed in 155.965s,
zero failures/errors/skips. All 11 static JS syntax checks and diff whitespace
checks passed. Starting SHA-256 baseline checks 351 existing files; only Compare
template, admin GET context/import and the existing Compare heading expectation
changed. Completed pages, shared assets, final evaluation artifacts/dataset,
detectors/security, University and protected model remain unchanged.

Detailed 17-point report, exact field-to-metric provenance, test logs, browser
manifest, baseline/scope hashes, viewport captures and same-frame visual review:
`reports/ui/evaluation-compare/final-report.md` and its sibling QA artifacts.
Changed source files: template, scoped CSS, presentation adapter, GET wiring,
new targeted tests and isolated preview, existing heading assertion, README,
this appended QA entry. No staging, commit or push.

Limitations: controlled synthetic/instrumented evidence; ignored final artifact
may be absent; desktop Edge emulation only. Browser POST tests disabled bypass
and input blocking, without live Qwen or enabled bypass generation. Existing
gateway tests exercise downstream behavior using synthetic model substitutes.
Capture timeouts/emulation scale issues were resolved for final proof captures;
DOM viewport checks and screenshot pixel sizes are recorded separately.

final result: passed

## Step 8C — Red Team only (2026-10-08)

Audited the real contract before editing. The actual template is
`templates/redteam_dashboard.html`; `templates/redteam.html` and an automated
`app/redteam*` runner do not exist. Admin GET supplies stored `RedteamCase`
definitions and `runner_available=False`. The local flag is
`settings.redteam_mode or settings.app_env == "local_redteam"`; it is configuration,
not runner capability. Existing admin POST `/admin/redteam/run` returns HTTP 501
with `available:false` and no fabricated results in every flag state. Export and
cases endpoints retain their existing metadata allowlists. No backend changed.

Only Red Team presentation changed: Evaluation eyebrow/subnav, dark layered
capability panel, restrained amber NOT CONFIGURED status, separate configuration
metadata, useful real Benchmark/Comparison links, compact stored-case cards and
polished empty state. The existing disabled Run full suite button, manifest
export, JS hooks and existing script remain. No new JS, runner or controls.
Removed static category cards and Pending/Not run result placeholders. Expected
actions are clearly definitions, never observed results. Raw prompt and
metadata payloads are excluded; no duplicated aggregate benchmark metrics,
attack history, fake terminal, generation options or network terminology.

Browser QA used isolated synthetic stores: flag false with no cases; flag true
with two stored definitions, including a 180-character ID and long attack type.
Both remain NOT CONFIGURED with a disabled action. Widths 1440×900, 1366×768,
1024×768, 375×812 and 320×812 passed: correct data/flag/subnav, no private payload,
fake result, console error, invalid icon, duplicate header or page overflow.
Benchmark and Comparison links work without Red Team styles. Full source and
implementation compositions and focused capability panels were reviewed in the
same frame, at the source's 1280×1213 dimensions. Native mobile captures were
reviewed; screenshot dimensions and DOM viewport dimensions are recorded apart.

Tests: 64 targeted frontend tests passed, including 17 new Red Team tests;
20 evaluation/Phase 14A/14B regression tests passed. Full suite: 349 tests in
198.715s, zero failures/errors/skips. All 11 static JS syntax checks and
`git diff --check` passed. SHA-256 checks cover 355 existing files; only the
Red Team template and its existing frontend heading expectation changed.
Backend, completed pages, shared assets, reports, dataset, detectors, University
and protected model are unchanged from the Step 8C starting state.

Changed source: template, new scoped CSS, new targeted tests and isolated preview,
existing frontend heading assertion, relevant README text, this appended QA
entry. Detailed 15-point report, source audit, logs, hashes, browser manifest and
visual proof are in `reports/ui/evaluation-redteam/`. No stage, commit or push.

Limitations: no real Red Team runner exists; execution remains 501 by design.
Edge blocks navigation to the JSON export with ERR_BLOCKED_BY_CLIENT; isolated
HTTP tests verify its 200 response, allowlisted metadata and empty results.
No browser warning was bypassed. Desktop Edge emulation covers responsive
behavior; no physical-device testing. Full-page capture timed out, so a native
source-dimension frame provides the complete visual comparison instead.

final result: passed
