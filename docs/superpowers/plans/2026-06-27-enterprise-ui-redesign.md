# Enterprise UI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restyle the whole PacketPilot web UI to an enterprise-grade hybrid look — security-console gravitas for threats/incidents, clean-SaaS polish for analytics/settings — on a slate-neutral + enterprise-blue palette, with no feature, IA, or engine changes.

**Architecture:** System-first. Retune the existing `var(--color-*)` design tokens in `ui/src/index.css` (most of the recolor propagates because every component already consumes the tokens), add a type scale + two tokens, flatten elevation. Then upgrade/add shared primitives in `ui/src/cockpit/primitives.tsx` (+ a couple new files). Then sweep each surface onto the primitives with targeted layout rework. Then revalidate every gate.

**Tech Stack:** React 18 + TypeScript + Vite 5 + Tailwind 3 (CSS-variable tokens), Vitest + RTL (jsdom), Playwright + @axe-core/playwright. No new dependencies.

## Global Constraints

- **No new dependencies.** Hand-rolled primitives only; do not add a component library.
- **Preserve the token-override theming:** components reference `var(--color-*)`; light theme is the `[data-theme="light"]` override block; never hardcode colors in components.
- **Severity ramp is the engine contract — do NOT change `--color-sev-*` hues** (`#f43f5e`/`#fb923c`/`#fbbf24`/`#2dd4bf`/`#38bdf8` dark; the AA-tuned light values). Change only neutrals + accent.
- **WCAG AA is a hard gate.** The real-browser axe suite `ui/e2e/a11y.spec.ts` (8 combos: dashboard dark/light fresh + toggled, Flows dark/light, settings, shortcuts, mobile) must stay green, including `color-contrast`. Audit per-theme via a *fresh load*, not a toggle.
- **Preserve:** the density toggle (`lib/density.ts`, `[data-density="compact"]`), the mobile-first shell (`useIsMobile`, `MobileNav`), dialog/menu a11y (`useDialogA11y`, `useMenuKeyboard`, focus traps, Escape, roving focus), and all tests: **Vitest ≥ 607 passing + coverage gate (lines/stmts/funcs ≥ 80, branches ≥ 70)**, **33 Playwright e2e**.
- **No IA/navigation changes**, no new features, no backend, no engine changes (the HTML report CSS may optionally be re-aligned to the new neutrals for parity, but that is out of scope here).
- **Two font weights only: 400 and 500** (current `font-semibold`/600 headings move to 500). Mono (`font-mono-num`) for all numerics. Min font-size 11px. Sentence case.
- **Run all commands from `ui/`** with Node 20+ on PATH (e.g. `C:\Program Files\nodejs`). The wasm bundle (`ui/src/wasm/`) must already be built (`npm run build:wasm`) for `npm run build`/`e2e`.

---

### Task 1: Retune design tokens (palette, type scale, elevation)

This single CSS change lands ~70% of the recolor with zero component edits.

**Files:**
- Modify: `ui/src/index.css:10-110` (the `:root` and `[data-theme="light"]` token blocks)
- Verify (no edit): `ui/e2e/a11y.spec.ts`

**Interfaces:**
- Produces (consumed by every later task): the token names `--color-bg`, `--color-surface`, `--color-surface-1/2/3`, `--color-surface-raised`, `--color-panel` (NEW), `--color-border`, `--color-border-strong`, `--color-grid`, `--color-text`, `--color-text-dim`, `--color-text-faint`, `--color-accent`, `--color-accent-strong`, `--color-accent-deep` (NEW), `--color-spine-violet`, the type-scale vars `--fs-display/title/heading/body/label/micro`, and the flattened `--sh-rest/hero/float`.

- [ ] **Step 1: Update the dark `:root` token values.** In `ui/src/index.css`, replace the surface/border/text/accent values (lines ~12-30) with:

```css
  /* Surfaces & structure — slate-navy */
  --color-bg: #0b1220;
  --color-surface: #0f1828;
  --color-surface-1: #0f1828;
  --color-surface-2: #141e30;
  --color-surface-3: #1b2740;
  --color-surface-raised: #202c42;
  --color-panel: #0e1a2c;            /* console panel bg (threats/incidents/flows) */
  --color-border: #223049;
  --color-border-strong: #2c3c58;
  --color-grid: #1b2740;

  /* Text */
  --color-text: #e7edf7;
  --color-text-dim: #93a1b7;
  --color-text-faint: #8b98ad;       /* AA-safe; re-verify via axe */

  /* Accent — enterprise blue (interactive/brand only; never decorative) */
  --color-accent: #3b82f6;
  --color-accent-strong: #60a5fa;
  --color-accent-deep: #1d4ed8;      /* filled-button bg, white text */
  --color-spine-violet: #7c5cff;
```

Leave the `--color-sev-*` block unchanged.

- [ ] **Step 2: Add the type-scale tokens.** Inside the same dark `:root`, after the radius scale, add:

```css
  /* Type scale (px) — apply via .t-* utilities + primitives */
  --fs-display: 22px;
  --fs-title: 18px;
  --fs-heading: 15px;
  --fs-body: 13px;
  --fs-label: 12px;
  --fs-micro: 11px;
```

- [ ] **Step 3: Flatten elevation.** Replace the three `--sh-*` values in dark `:root` with a single soft tier (console panels will use border only; SaaS cards a subtle shadow):

```css
  --sh-rest: 0 1px 2px rgba(2, 6, 16, 0.35);
  --sh-hero: 0 2px 8px -2px rgba(2, 6, 16, 0.45);
  --sh-float: 0 12px 32px -16px rgba(2, 6, 16, 0.6), 0 2px 6px -3px rgba(2, 6, 16, 0.4);
```

- [ ] **Step 4: Update the light `[data-theme="light"]` overrides.** Replace the surfaces/border/text/accent values (lines ~75-94) with:

```css
  --color-bg: #f4f7fb;
  --color-surface: #ffffff;
  --color-surface-1: #ffffff;
  --color-surface-2: #eef3f9;
  --color-surface-3: #e7edf5;
  --color-surface-raised: #ffffff;
  --color-panel: #eef3fb;
  --color-border: #d8e0ea;
  --color-border-strong: #bcc8d6;
  --color-grid: #e3e9f1;

  --color-text: #0d1b2e;
  --color-text-dim: #475569;
  --color-text-faint: #586678;       /* AA on tinted surfaces */

  --color-accent: #1d4ed8;           /* blue-700 — AA on white */
  --color-accent-strong: #2563eb;
  --color-accent-deep: #1d4ed8;
  --color-spine-violet: #6135f5;
```

Leave the light `--color-sev-*` block unchanged. Soften the light `--sh-*` similarly (keep the existing light shadow rgba style, low alpha).

- [ ] **Step 5: Build + visual smoke.** Run: `npm run build:wasm` (if `src/wasm` absent) then `npm run build`. Expected: builds clean (exit 0, no `error TS`). Start the preview and eyeball the dashboard in both themes — the recolor should already look enterprise-blue.

- [ ] **Step 6: Run the unit suite (colors are invisible to jsdom, so this just confirms no breakage).** Run: `npm run test`. Expected: all pass (≥ 607).

- [ ] **Step 7: Run the axe contrast gate — the critical check.** Run: `npm run e2e -- a11y.spec.ts`. Expected: all axe combos PASS (incl. `color-contrast`) in dark + light. **If any `color-contrast` fails, darken the offending `--color-accent` or `--color-text-faint` hex by one step and re-run until green** (this is the AA gate from the prior contrast work).

- [ ] **Step 8: Commit.**

```bash
git add ui/src/index.css
git commit -m "feat(ui): enterprise-blue + slate token palette, type scale, flat elevation"
```

---

### Task 2: `Panel` primitive (console container)

The dense, bordered, shadow-free container for threat/incident/signature/flow surfaces.

**Files:**
- Modify: `ui/src/cockpit/primitives.tsx` (add `Panel`)
- Test: `ui/src/cockpit/primitives.test.tsx` (create if absent)

**Interfaces:**
- Produces: `Panel({ title, label, count, icon, accent, right, className, bodyClassName, children })` where `accent?: Severity` draws a left severity rule; `count?: string|number`; `icon?: ReactNode`. Used by Tasks 6, 7.

- [ ] **Step 1: Write the failing test.** In `ui/src/cockpit/primitives.test.tsx`:

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { Panel } from "./primitives";

describe("Panel", () => {
  it("renders a titled console panel with a count and severity accent", () => {
    const { container } = render(
      <Panel title="Threat watchlist" count={50} accent="critical">
        <div>rows</div>
      </Panel>,
    );
    expect(screen.getByText("Threat watchlist")).toBeInTheDocument();
    expect(screen.getByText("50")).toBeInTheDocument();
    expect(screen.getByText("rows")).toBeInTheDocument();
    // severity accent applies the critical token as a left border color
    expect(container.querySelector("section")?.getAttribute("style") || "").toMatch(/--color-sev-critical|border-left/);
  });
});
```

- [ ] **Step 2: Run it — verify it fails.** Run: `npx vitest run src/cockpit/primitives.test.tsx`. Expected: FAIL (`Panel` is not exported).

- [ ] **Step 3: Implement `Panel`.** Append to `ui/src/cockpit/primitives.tsx`:

```tsx
import type { Severity } from "../types";
import { sevColor } from "./viz";

/** Dense, bordered, shadow-free console container (threats / incidents / flows). */
export function Panel({
  title, label, count, icon, accent, right, className, bodyClassName, children,
}: {
  title?: string; label?: string; count?: string | number; icon?: ReactNode;
  accent?: Severity; right?: ReactNode; className?: string; bodyClassName?: string; children: ReactNode;
}) {
  const accentColor = accent ? sevColor(accent) : undefined;
  return (
    <section
      className={cn(
        "flex min-w-0 flex-col overflow-hidden rounded-[var(--r-card)] border border-[var(--color-border)] bg-[var(--color-panel)]",
        className,
      )}
      style={accentColor ? { borderLeft: `2px solid ${accentColor}`, borderRadius: "0 var(--r-card) var(--r-card) 0" } : undefined}
    >
      {(title || label || right || icon) && (
        <header className="flex items-center gap-2 border-b border-[var(--color-border)] px-3.5 py-2.5">
          {icon && <span aria-hidden className="text-[var(--color-text-dim)]">{icon}</span>}
          <div className="min-w-0">
            {label && <div className="t-label">{label}</div>}
            {title && <h3 className="t-title text-[var(--color-text)]">{title}</h3>}
          </div>
          {count !== undefined && (
            <span className="font-mono-num t-tag text-[var(--color-text-faint)]">{count}</span>
          )}
          {right && <span className="ml-auto">{right}</span>}
        </header>
      )}
      <div className={cn("min-w-0 flex-1", bodyClassName)}>{children}</div>
    </section>
  );
}
```

(Note: `Severity`, `cn`, `sevColor`, `ReactNode` are already imported at the top of the file — do not duplicate the imports; the snippet lists them only for clarity.)

- [ ] **Step 4: Run the test — verify it passes.** Run: `npx vitest run src/cockpit/primitives.test.tsx`. Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add ui/src/cockpit/primitives.tsx ui/src/cockpit/primitives.test.tsx
git commit -m "feat(ui): add Panel console primitive"
```

---

### Task 3: Upgrade `Card`, add `StatTile` + provenance/tag chips

The airy SaaS card, the KPI tile, and the neutral/cloud chips.

**Files:**
- Modify: `ui/src/cockpit/primitives.tsx` (`Card` body padding/shadow; add `StatTile`, `Tag`, `ProvenanceChip`)
- Test: `ui/src/cockpit/primitives.test.tsx`

**Interfaces:**
- Produces: `StatTile({ label, value, sub, accent, mono })` (value defaults mono); `Tag({ children, tone })` (`tone?: "neutral"|"accent"`); `ProvenanceChip({ provider })` → `☁ <provider>`. Used by Tasks 6, 7, 9.

- [ ] **Step 1: Write the failing tests.** Append to `primitives.test.tsx`:

```tsx
import { StatTile, Tag, ProvenanceChip } from "./primitives";

describe("StatTile + chips", () => {
  it("renders a KPI tile with label and value", () => {
    render(<StatTile label="Flows" value="99,993" />);
    expect(screen.getByText("Flows")).toBeInTheDocument();
    expect(screen.getByText("99,993")).toBeInTheDocument();
  });
  it("renders a cloud provenance chip with the provider", () => {
    render(<ProvenanceChip provider="AWS" />);
    expect(screen.getByText(/AWS/)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run — verify fail.** Run: `npx vitest run src/cockpit/primitives.test.tsx`. Expected: FAIL (`StatTile` not exported).

- [ ] **Step 3: Implement.** Append to `primitives.tsx`:

```tsx
/** KPI metric tile: muted label + large mono value + optional sub line. */
export function StatTile({ label, value, sub, accent, mono = true }: {
  label: string; value: ReactNode; sub?: ReactNode; accent?: boolean; mono?: boolean;
}) {
  return (
    <div className="rounded-[var(--r-tile)] bg-[var(--color-surface-2)] px-3 py-2.5">
      <div className="t-label text-[var(--color-text-dim)]">{label}</div>
      <div className={cn("mt-0.5 text-[var(--fs-display)] font-medium leading-none", mono && "font-mono-num",
        accent ? "text-[var(--color-accent-strong)]" : "text-[var(--color-text)]")}>{value}</div>
      {sub && <div className="mt-1 t-tag text-[var(--color-text-faint)]">{sub}</div>}
    </div>
  );
}

/** Neutral or accent tag chip. */
export function Tag({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "accent" }) {
  const accent = tone === "accent";
  return (
    <span className="inline-flex items-center rounded-[var(--r-chip)] border px-1.5 py-0.5 t-tag"
      style={{
        color: accent ? "var(--color-accent-strong)" : "var(--color-text-dim)",
        borderColor: "var(--color-border)",
        backgroundColor: accent ? "color-mix(in srgb, var(--color-accent) 12%, transparent)" : "var(--color-surface-2)",
      }}>{children}</span>
  );
}

/** Offline cloud/hosting attribution chip ("☁ AWS"). */
export function ProvenanceChip({ provider }: { provider: string }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-[var(--r-chip)] border border-[var(--color-border)] px-1.5 py-0.5 t-tag text-[var(--color-text-dim)]"
      title="Offline cloud/hosting attribution (coarse hint)">☁ {provider}</span>
  );
}
```

- [ ] **Step 4: Refine `Card` for the SaaS register.** In the existing `Card` (top of file), change the `<section>` className to add a subtle shadow and ensure the SaaS padding: `"card flex min-w-0 flex-col shadow-[var(--sh-rest)]"`. (The `.card` class already supplies bg/border/radius; this adds the soft shadow that distinguishes SaaS cards from console panels.)

- [ ] **Step 5: Run — verify pass.** Run: `npx vitest run src/cockpit/primitives.test.tsx`. Expected: PASS.

- [ ] **Step 6: Commit.**

```bash
git add ui/src/cockpit/primitives.tsx ui/src/cockpit/primitives.test.tsx
git commit -m "feat(ui): StatTile, Tag, ProvenanceChip; soft shadow on SaaS Card"
```

---

### Task 4: `Toolbar`, `SectionHeader`, and enterprise table CSS utilities

The data-grid styling (applied to the existing virtualized table — no rewrite) + a section toolbar.

**Files:**
- Modify: `ui/src/index.css` (add `.pp-table*` utility classes under `@layer components` or plain CSS)
- Modify: `ui/src/cockpit/primitives.tsx` (add `Toolbar`, `SectionHeader`)
- Test: `ui/src/cockpit/primitives.test.tsx`

**Interfaces:**
- Produces: `Toolbar({ children, className })` (flex row, gap, used above grids); `SectionHeader({ title, count, right })`. CSS classes: `.pp-table` (full-width, collapse, `--fs-body`), `.pp-table thead th` (sticky, `--color-surface-2` bg, `--color-text-faint`, uppercase `--fs-label`), `.pp-table tbody tr` (hairline top border `--color-border`, hover `--color-surface-2`), `.pp-table td` (padding 7px 10px). Used by Tasks 7, 6.

- [ ] **Step 1: Add the table utilities to `index.css`** (after the existing `.t-*`/`.card` utilities):

```css
.pp-table { width: 100%; border-collapse: collapse; font-size: var(--fs-body); }
.pp-table thead th { position: sticky; top: 0; z-index: 1; background: var(--color-surface-2);
  color: var(--color-text-faint); font-weight: 400; text-transform: uppercase; letter-spacing: .04em;
  font-size: var(--fs-label); text-align: left; padding: 7px 10px; }
.pp-table tbody tr { border-top: 1px solid var(--color-border); }
.pp-table tbody tr:hover { background: var(--color-surface-2); }
.pp-table td { padding: 7px 10px; color: var(--color-text); }
```

- [ ] **Step 2: Write the failing test.** Append to `primitives.test.tsx`:

```tsx
import { Toolbar, SectionHeader } from "./primitives";

describe("Toolbar + SectionHeader", () => {
  it("renders a section header with title and count", () => {
    render(<SectionHeader title="Flows" count="1,024" />);
    expect(screen.getByText("Flows")).toBeInTheDocument();
    expect(screen.getByText("1,024")).toBeInTheDocument();
  });
  it("renders toolbar children", () => {
    render(<Toolbar><button>Filter</button></Toolbar>);
    expect(screen.getByRole("button", { name: "Filter" })).toBeInTheDocument();
  });
});
```

- [ ] **Step 3: Run — verify fail.** Run: `npx vitest run src/cockpit/primitives.test.tsx`. Expected: FAIL.

- [ ] **Step 4: Implement.** Append to `primitives.tsx`:

```tsx
/** Section toolbar — search / filters / actions row above a data grid. */
export function Toolbar({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn("flex flex-wrap items-center gap-2", className)}>{children}</div>;
}

/** Consistent section title + count + right actions. */
export function SectionHeader({ title, count, right }: { title: string; count?: string | number; right?: ReactNode }) {
  return (
    <div className="flex items-center gap-2 pb-2">
      <h2 className="t-title text-[var(--color-text)]">{title}</h2>
      {count !== undefined && <span className="font-mono-num t-tag text-[var(--color-text-faint)]">{count}</span>}
      {right && <span className="ml-auto">{right}</span>}
    </div>
  );
}
```

- [ ] **Step 5: Run — verify pass.** Run: `npx vitest run src/cockpit/primitives.test.tsx`. Expected: PASS.

- [ ] **Step 6: Build to confirm the CSS compiles.** Run: `npm run build`. Expected: clean.

- [ ] **Step 7: Commit.**

```bash
git add ui/src/index.css ui/src/cockpit/primitives.tsx ui/src/cockpit/primitives.test.tsx
git commit -m "feat(ui): Toolbar, SectionHeader, enterprise .pp-table utilities"
```

---

### Task 5: Sweep the app shell

**Files:**
- Modify: `ui/src/components/layout/AppShell.tsx`, `ui/src/cockpit/CommandBar.tsx`, `ui/src/cockpit/ThreatRail.tsx`, `ui/src/components/layout/MobileNav.tsx`

**Interfaces:** Consumes Task 1 tokens. No new exports.

- [ ] **Step 1: Restyle the rail + top bar to the new tokens.** In `CommandBar.tsx` / `AppShell.tsx` / `ThreatRail.tsx`: ensure the rail uses `bg-[var(--color-surface)]` with a `border-[var(--color-border)]` divider; the active nav item gets a 2px `bg-[var(--color-accent)]` left indicator + accent icon color; inactive icons `text-[var(--color-text-dim)]`. The top bar: `bg-[var(--color-surface)]`, hairline bottom border, the capture chip as a `Tag`/status-dot, the `Export` button filled with `bg-[var(--color-accent-deep)] text-white`, secondary actions ghost. Replace any `font-semibold` with `font-medium`. Remove glow/`--sh-hero` from chrome.

- [ ] **Step 2: Mirror the changes in `MobileNav.tsx`** (drawer + bottom tab bar) — same token usage, active tab uses the accent, preserve `useIsMobile` gating and the existing roles/labels.

- [ ] **Step 3: Run the shell tests.** Run: `npx vitest run src/components/layout/AppShell.test.tsx src/cockpit/CommandBar.test.tsx src/components/layout/MobileNav.test.tsx src/cockpit/ThreatRail.test.tsx`. Expected: PASS — if an assertion checks a class string that changed, update it to the new markup (keep behavioral assertions).

- [ ] **Step 4: Visual + a11y check.** Build, open the preview, verify the shell in dark + light + mobile width. Run: `npm run e2e -- a11y.spec.ts`. Expected: axe green.

- [ ] **Step 5: Commit.**

```bash
git add ui/src/components/layout/AppShell.tsx ui/src/cockpit/CommandBar.tsx ui/src/cockpit/ThreatRail.tsx ui/src/components/layout/MobileNav.tsx
git commit -m "feat(ui): restyle app shell (rail, top bar, mobile nav) to enterprise tokens"
```

---

### Task 6: Sweep the Dashboard

**Files:**
- Modify: `ui/src/components/Dashboard.tsx`, `ui/src/cockpit/KpiCluster.tsx`, and the threat/incident panels (`ThreatRail`/watchlist render, `IncidentHero.tsx`, `components/triage/SignatureMatchesPanel.tsx`, `CertHealthPanel.tsx`, `DomainThreatsPanel.tsx`)

**Interfaces:** Consumes `Panel`, `StatTile`, `Card`, `SectionHeader`, `Tag`, `ProvenanceChip`.

- [ ] **Step 1: Convert KPIs to `StatTile`.** In `KpiCluster.tsx`, render each KPI via `<StatTile label=… value=… />`; the Critical tile uses `accent`/a sev tint. Keep the same metrics/order.
- [ ] **Step 2: Convert threat/incident/signature/cert/domain sections to console `Panel`.** Wrap each in `<Panel title=… count=… icon=… accent=…>`; the Threat watchlist and Signature tables get `className="pp-table"`. Keep the existing rows/handlers (`onSelect`, `onJump`, carve). Use `ProvenanceChip` for `cloud:*` tags and `SeverityChip` as today.
- [ ] **Step 3: Keep analytics sections as SaaS `Card`** (ProtocolMix, Sunburst, TopPorts, TopTalkers, HttpOverview, PacketDistributions, DNS/Downloads/LocalHosts/EncryptedDns, AiSummary) — they already use `Card`; ensure the new soft shadow + section headers read cleanly. Tighten the analytics grid gaps via the density tokens.
- [ ] **Step 4: Run the dashboard + card tests.** Run: `npx vitest run src/components/Dashboard.test.tsx src/cockpit/KpiCluster.test.tsx src/cockpit/IncidentHero.test.tsx src/components/triage`. Expected: PASS — update class-coupled assertions to the new markup; keep behavior assertions.
- [ ] **Step 5: Visual + a11y.** Build, preview the full dashboard in dark + light; run `npm run e2e -- a11y.spec.ts`. Expected: axe green (dashboard fresh dark/light + toggled).
- [ ] **Step 6: Commit.**

```bash
git add ui/src/components/Dashboard.tsx ui/src/cockpit/KpiCluster.tsx ui/src/cockpit/IncidentHero.tsx ui/src/components/triage
git commit -m "feat(ui): dashboard — console Panels for threats/incidents, StatTiles, SaaS cards"
```

---

### Task 7: Sweep Flows (the data-grid)

**Files:**
- Modify: `ui/src/views/FlowsView.tsx` (filter bar → `Toolbar`), `ui/src/components/flows/FlowsTable.tsx` (apply `.pp-table` styling), `ui/src/components/flows/FilterProfiles.tsx`, `ui/src/components/flows/RuleSetsMenu.tsx`

**Interfaces:** Consumes `Panel`, `Toolbar`, `SectionHeader`, `.pp-table`. **Preserve TanStack virtualization and keyboard operability** (the `flows-a11y.spec.ts` sort/row-open tests).

- [ ] **Step 1: Wrap the Flows table in a `Panel`** and put the search + category/severity/proto filters + saved-filters in a `Toolbar` above it. Keep all filter state/handlers.
- [ ] **Step 2: Apply enterprise table styling.** Give the table the `pp-table` class (or port the rules onto the virtualized header/rows): sticky elevated header, hairline rows, hover, mono numerics, inline `SeverityChip`/JA3 columns. Do **not** change the virtualization (row measurement/windowing) or the `role="row"`/`tabIndex`/`aria-selected` keyboard behavior.
- [ ] **Step 3: Run the Flows tests.** Run: `npx vitest run src/views/FlowsView.test.tsx src/components/flows`. Expected: PASS (update class assertions only).
- [ ] **Step 4: a11y + keyboard.** Run: `npm run e2e -- a11y.spec.ts flows-a11y.spec.ts`. Expected: axe green (Flows dark/light) + keyboard sort/row-open pass.
- [ ] **Step 5: Commit.**

```bash
git add ui/src/views/FlowsView.tsx ui/src/components/flows
git commit -m "feat(ui): Flows enterprise data-grid (Panel + Toolbar + pp-table), virtualization intact"
```

---

### Task 8: Sweep Recent + Compare

**Files:**
- Modify: `ui/src/components/recent/RecentView.tsx`, `ui/src/views/CompareView.tsx`

- [ ] **Step 1: Recent — bordered console rows.** Render captures as `.pp-table`/bordered rows inside a `Panel` (not floaty cards), with cached stats + reopen; keep handlers and the `packetpilot:annotations`/recent logic.
- [ ] **Step 2: Compare — restyle the diff** with the new tokens; severity deltas use the (unchanged) ramp; wrap columns in `Card`/`Panel` as fits.
- [ ] **Step 3: Run tests.** Run: `npx vitest run src/components/recent/RecentView.test.tsx src/views/CompareView.test.tsx`. Expected: PASS (update class assertions).
- [ ] **Step 4: Visual.** Preview both in dark + light.
- [ ] **Step 5: Commit.**

```bash
git add ui/src/components/recent/RecentView.tsx ui/src/views/CompareView.tsx
git commit -m "feat(ui): restyle Recent (console rows) and Compare to enterprise tokens"
```

---

### Task 9: Sweep Settings + dialogs

**Files:**
- Modify: `ui/src/cockpit/SettingsDialog.tsx`, `ui/src/components/layout/LoadCaptureDialog.tsx`, `ui/src/cockpit/AiConsent.tsx`, `ui/src/cockpit/ReputationConsent.tsx`, `ui/src/cockpit/DomainConsent.tsx`, `ui/src/cockpit/PacketInspector.tsx`, `ui/src/cockpit/DetailFlyout.tsx`, `ui/src/cockpit/ExportMenu.tsx`, `ui/src/components/flows/RuleSetsMenu.tsx`

- [ ] **Step 1: Settings → clean SaaS form.** Sectioned groups, labels, generous spacing, the new accent on the primary action; inputs use `bg-[var(--color-surface-2)]` + hairline border + focus ring `--color-accent`. **Do not touch** `useDialogA11y` (focus trap/Escape) or the field wiring.
- [ ] **Step 2: Restyle the other dialogs/menus/flyout/inspector** to the new tokens; menus keep `useMenuKeyboard` roving focus + `role=menu/menuitem`; the flyout keeps its sections. Replace `font-semibold` → `font-medium`.
- [ ] **Step 3: Run tests.** Run: `npx vitest run src/cockpit/SettingsDialog.test.tsx src/cockpit/SettingsDialog.tauri.test.tsx src/components/layout/LoadCaptureDialog.test.tsx src/cockpit/PacketInspector.test.tsx src/cockpit/DetailFlyout.test.tsx src/cockpit/ExportMenu.test.tsx src/components/flows/RuleSetsMenu.test.tsx src/cockpit/AiConsent.test.tsx`. Expected: PASS (update class assertions; keep a11y/behavior assertions).
- [ ] **Step 4: a11y.** Run: `npm run e2e -- a11y.spec.ts`. Expected: axe green (settings + shortcuts combos).
- [ ] **Step 5: Commit.**

```bash
git add ui/src/cockpit/SettingsDialog.tsx ui/src/components/layout/LoadCaptureDialog.tsx ui/src/cockpit/AiConsent.tsx ui/src/cockpit/ReputationConsent.tsx ui/src/cockpit/DomainConsent.tsx ui/src/cockpit/PacketInspector.tsx ui/src/cockpit/DetailFlyout.tsx ui/src/cockpit/ExportMenu.tsx ui/src/components/flows/RuleSetsMenu.tsx
git commit -m "feat(ui): restyle Settings, dialogs, menus, flyout, inspector to enterprise tokens"
```

---

### Task 10: Full revalidation + regenerate the sample screenshot path

**Files:** none (verification only); fix any fallout in the files above.

- [ ] **Step 1: Coverage gate.** Run: `npm run test:coverage`. Expected: all pass; lines/stmts/funcs ≥ 80, branches ≥ 70. Fix any coverage dips by covering new primitive branches.
- [ ] **Step 2: Build.** Run: `npm run build`. Expected: clean (no `error TS`).
- [ ] **Step 3: Full e2e incl. axe both themes.** Run: `npm run e2e`. Expected: 33 passing (incl. all axe color-contrast combos dark + light + mobile). Fix any AA failure by darkening the accent/faint token (Task 1) and re-running.
- [ ] **Step 4: Desktop build (same frontend).** From `ui/`: `npx tauri build --no-bundle`. Expected: compiles (the restyle is frontend-only; this confirms the vite build the desktop embeds).
- [ ] **Step 5: Manual visual pass.** Preview every view in dark, light, and mobile width; confirm the hybrid reads (console panels vs SaaS cards), severity still pops, and nothing glows.
- [ ] **Step 6: Final commit (if any fixes).**

```bash
git add -A ui/src
git commit -m "test(ui): revalidate enterprise redesign — vitest/coverage, e2e+axe, build, desktop"
```

---

## Self-Review

- **Spec coverage:** §3 tokens → Task 1; §3.2 type scale → Task 1; §4 primitives (`Panel`/`Card`/`StatTile`/`DataTable`-as-utilities/`Toolbar`/`SectionHeader`/chips) → Tasks 2–4; §5 per-surface (shell/dashboard/flows/recent/compare/settings/mobile) → Tasks 5–9; §6 constraints → Global Constraints + per-task a11y/test steps; §8 testing → Tasks 1,5–10; §9 risks (phasing, AA gate, severity contract, fresh-load verify) → addressed in steps. No gaps.
- **Placeholders:** none — token values, primitive code, and per-file targets are concrete; the sweep tasks name exact files + the primitive to apply + the verification command.
- **Type consistency:** `Panel`/`StatTile`/`Tag`/`ProvenanceChip`/`Toolbar`/`SectionHeader` signatures defined in Tasks 2–4 match their use in Tasks 5–9; `.pp-table` class name consistent (Task 4 → 6/7); severity tokens never renamed.
