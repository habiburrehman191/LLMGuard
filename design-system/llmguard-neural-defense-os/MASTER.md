# Design System Master File

> **LOGIC:** When building a specific page, first check `design-system/pages/[page-name].md`.
> If that file exists, its rules **override** this Master file.
> If not, strictly follow the rules below.

---

**Project:** LLMGuard
**Generated:** 2026-06-12 00:27:03
**Category:** Cybersecurity Platform

---

## Product Override

The generated research suggested a conventional enterprise gateway, but the
project brief deliberately overrides its light palette and cyberpunk excess.
LLMGuard uses a restrained dark SaaS system: deep navy surfaces, electric cyan
for active policy paths, red only for hostile traffic, amber for quarantine,
green for successful enforcement, and purple only as a minor neural accent.

The interface must feel like an enterprise security operating system rather
than a terminal, game, or crypto dashboard. Continuous motion belongs in the
hero data system, policy pipelines, scanning states, and live telemetry.
Reading surfaces remain stable. Long text uses Inter/Sora/system-ui; mono type
is reserved for counters, labels, IDs, and evidence.

### Brand Lock

- The primary product name is **LLMGuard**.
- **Neural Defense OS** appears only as a small subtitle, mode label, or
  section tagline.
- Navigation, page identity, footer, and documentation lead with LLMGuard.

### Premium Correction

UI/UX Pro Max research was applied through a disciplined modular type scale,
clear navigation grouping, 16px minimum body copy, visible SVG icon
containers, consistent card padding, restrained hover lift, and reduced dead
space. The implementation keeps Inter, Sora, Space Grotesk, and system fonts
so the interface does not depend on external font delivery.

### Project Tokens

```css
--bg-main: #02040A;
--bg-layer: #07111F;
--panel: rgba(8, 18, 34, 0.82);
--panel-strong: rgba(10, 25, 45, 0.92);
--border-soft: rgba(148, 163, 184, 0.16);
--border-cyan: rgba(34, 211, 238, 0.35);
--cyan: #22D3EE;
--red: #EF4444;
--amber: #F59E0B;
--green: #22C55E;
--purple: #8B5CF6;
--text-main: #F8FAFC;
--text-soft: #CBD5E1;
--text-muted: #94A3B8;
```

## Global Rules

### Color Palette

| Role | Hex | CSS Variable |
|------|-----|--------------|
| Primary | `#1E40AF` | `--color-primary` |
| Secondary | `#3B82F6` | `--color-secondary` |
| CTA/Accent | `#F59E0B` | `--color-cta` |
| Background | `#F8FAFC` | `--color-background` |
| Text | `#1E3A8A` | `--color-text` |

**Color Notes:** Blue data + amber highlights

### Typography

- **Heading Font:** Satoshi
- **Body Font:** General Sans
- **Mood:** premium, modern, clean, sophisticated, versatile, balanced
- **Google Fonts:** [Satoshi + General Sans](https://fonts.google.com/share?selection.family=DM+Sans:wght@400;500;700)

**CSS Import:**
```css
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;700&display=swap');
```

### Spacing Variables

| Token | Value | Usage |
|-------|-------|-------|
| `--space-xs` | `4px` / `0.25rem` | Tight gaps |
| `--space-sm` | `8px` / `0.5rem` | Icon gaps, inline spacing |
| `--space-md` | `16px` / `1rem` | Standard padding |
| `--space-lg` | `24px` / `1.5rem` | Section padding |
| `--space-xl` | `32px` / `2rem` | Large gaps |
| `--space-2xl` | `48px` / `3rem` | Section margins |
| `--space-3xl` | `64px` / `4rem` | Hero padding |

### Shadow Depths

| Level | Value | Usage |
|-------|-------|-------|
| `--shadow-sm` | `0 1px 2px rgba(0,0,0,0.05)` | Subtle lift |
| `--shadow-md` | `0 4px 6px rgba(0,0,0,0.1)` | Cards, buttons |
| `--shadow-lg` | `0 10px 15px rgba(0,0,0,0.1)` | Modals, dropdowns |
| `--shadow-xl` | `0 20px 25px rgba(0,0,0,0.15)` | Hero images, featured cards |

---

## Component Specs

### Buttons

```css
/* Primary Button */
.btn-primary {
  background: #F59E0B;
  color: white;
  padding: 12px 24px;
  border-radius: 8px;
  font-weight: 600;
  transition: all 200ms ease;
  cursor: pointer;
}

.btn-primary:hover {
  opacity: 0.9;
  transform: translateY(-1px);
}

/* Secondary Button */
.btn-secondary {
  background: transparent;
  color: #1E40AF;
  border: 2px solid #1E40AF;
  padding: 12px 24px;
  border-radius: 8px;
  font-weight: 600;
  transition: all 200ms ease;
  cursor: pointer;
}
```

### Cards

```css
.card {
  background: #F8FAFC;
  border-radius: 12px;
  padding: 24px;
  box-shadow: var(--shadow-md);
  transition: all 200ms ease;
  cursor: pointer;
}

.card:hover {
  box-shadow: var(--shadow-lg);
  transform: translateY(-2px);
}
```

### Inputs

```css
.input {
  padding: 12px 16px;
  border: 1px solid #E2E8F0;
  border-radius: 8px;
  font-size: 16px;
  transition: border-color 200ms ease;
}

.input:focus {
  border-color: #1E40AF;
  outline: none;
  box-shadow: 0 0 0 3px #1E40AF20;
}
```

### Modals

```css
.modal-overlay {
  background: rgba(0, 0, 0, 0.5);
  backdrop-filter: blur(4px);
}

.modal {
  background: white;
  border-radius: 16px;
  padding: 32px;
  box-shadow: var(--shadow-xl);
  max-width: 500px;
  width: 90%;
}
```

---

## Style Guidelines

**Style:** Premium AI Cybersecurity SaaS

**Keywords:** Dark SaaS, AI-native, restrained HUD, glassmorphism, dimensional cards, live SOC

**Best For:** AI security platforms, SOC dashboards, policy workbenches, controlled product demos

**Key Effects:** Subtle cyan glow, scan sweeps, orbital telemetry, readable motion, stable content surfaces

### Page Pattern

**Pattern Name:** Enterprise Gateway

- **Conversion Strategy:**  logo carousel,  tab switching for industries, Path selection (I am a...). Mega menu navigation. Trust signals prominent.
- **CTA Placement:** Contact Sales (Primary) + Login (Secondary)
- **Section Order:** 1. Hero (Video/Mission), 2. Solutions by Industry, 3. Solutions by Role, 4. Client Logos, 5. Contact Sales

---

## Anti-Patterns (Do NOT Use)

- ❌ Light mode
- ❌ Poor data viz

### Additional Forbidden Patterns

- ❌ **Emojis as icons** — Use SVG icons (Heroicons, Lucide, Simple Icons)
- ❌ **Missing cursor:pointer** — All clickable elements must have cursor:pointer
- ❌ **Layout-shifting hovers** — Avoid scale transforms that shift layout
- ❌ **Low contrast text** — Maintain 4.5:1 minimum contrast ratio
- ❌ **Instant state changes** — Always use transitions (150-300ms)
- ❌ **Invisible focus states** — Focus states must be visible for a11y

---

## Pre-Delivery Checklist

Before delivering any UI code, verify:

- [ ] No emojis used as icons (use SVG instead)
- [ ] All icons from consistent icon set (Heroicons/Lucide)
- [ ] `cursor-pointer` on all clickable elements
- [ ] Hover states with smooth transitions (150-300ms)
- [ ] Light mode: text contrast 4.5:1 minimum
- [ ] Focus states visible for keyboard navigation
- [ ] `prefers-reduced-motion` respected
- [ ] Responsive: 375px, 768px, 1024px, 1440px
- [ ] No content hidden behind fixed navbars
- [ ] No horizontal scroll on mobile
