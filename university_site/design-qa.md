# University of Haripur Recreation — Design QA

## Visual truth and implementation

- Reference pages: `https://www.uoh.edu.pk/`, `https://www.uoh.edu.pk/portal`, and `https://www.uoh.edu.pk/admissions/bs-programs`.
- Local implementation: `/`, `/portal`, and `/bs-programs` on `http://127.0.0.1:8001`.
- Reference captures: `tests/visual/source-{home,portal,bs}-{1440,390}.png`.
- Local captures: `tests/visual/local-{home,portal,bs}-{1440,390}.png`.
- Comparison canvases: `tests/visual/compare-{home,portal,bs}-{1440,390}.png`.
- Capture viewports: 1440 x 900 desktop and 390 x 844 mobile, device scale factor 1.
- Compared states: homepage with admissions announcement visible, portal landing page, and BS Programs default view.

## Required surface review

- **Typography:** Segoe UI/system sans-serif is used for body and navigation copy; the institutional wordmark remains the supplied image asset so its serif lettering matches the source.
- **Spacing and layout:** utility strip, institutional header, gradient navigation, page containers, admissions columns, portal choices, and multi-column footer follow the source ordering and proportions.
- **Colors:** black utility bar, deep UoH blue, cyan navigation accents, white content backgrounds, and gold notice accents were sampled from the reference styles and assets.
- **Images:** the local site serves downloaded public UoH logos, banners, portal buttons, tiles, and footer icons; it does not iframe, proxy, or hotlink the live pages at runtime.
- **Content:** primary navigation labels, admissions program groups, eligibility/fee/schedule table structures, page headings, portal labels, and footer groupings mirror the public reference.

## Findings and fixes

1. **P2 — mobile horizontal overflow:** long admissions labels and login form min-content sizing exceeded 390 px. Removed non-wrapping rules, allowed safe word wrapping, and constrained grid/form children. Final probes report `scrollWidth === innerWidth`.
2. **P2 — BS Programs faculty sequence:** the initial two-column order differed from the live page. Faculty groups were reordered to match the reference reading order.
3. **P2 — portal proportion and spacing:** portal artwork and heading spacing were undersized after the first capture. Adjusted desktop/mobile artwork widths and content padding, then recaptured both target viewports.
4. **P3 — intentional responsive difference:** the source admissions page clips several long mobile rows. The local recreation wraps these rows to meet the explicit no-overflow and usable responsive behavior requirement.
5. **P3 — intentional safety difference:** the portal includes a small academic-demo notice and local administration link so users cannot mistake the synthetic login for real UoH authentication.
6. **P3 — dynamic carousel timing:** the active homepage banner can differ from the source capture because both carousels advance on timers; image order and controls are preserved.

No P0, P1, or P2 findings remain.

## Interaction and responsive verification

- Homepage next-slide control changed the active slide and the announcement close control hid the modal.
- Mobile navigation toggle set `aria-expanded=true` and opened the menu.
- Student demo selector filled the local login form.
- Student login redirected to `/portal/student/dashboard`; protected role checks and logout are also covered by route tests.
- Browser probes at 1440, 1366, 1280, 1024, 768, and 390 widths showed no horizontal overflow on the tested local pages.
- Final browser interaction probes reported zero runtime exceptions.

## Final result

passed

## Functional information-system completion

The visual recreation was subsequently completed as a database-backed academic
demo without changing its UoH-inspired shell. Browser journeys now cover the
public site, admissions, search, separate Student/Employee logins, all nine
Student Portal sections, all twelve authorized Lecturer portal sections, and a
Security Guard restricted-record journey.

Responsive functional captures are stored as
`tests/visual/functional-{public,student,employee}-{1440,1366,1280,1024,768,430,390,375}.png`,
with dedicated student/employee dashboard and Security Guard captures. Every
journey reported zero page-level horizontal overflow and zero uncaught runtime
exceptions. Wide institutional tables and the organogram use contained local
scroll regions where needed.
