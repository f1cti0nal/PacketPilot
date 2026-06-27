# Enterprise UI redesign — design

*Status: design · 2026-06-27 · Scope: web UI (and desktop, same React frontend) · Pre-launch polish.*

## 1. Goal

Elevate PacketPilot's web UI from the current "futuristic cockpit" look to a **complete, enterprise-grade
design** before the web launch. Same product, same information, a more authoritative and consistent visual
system. No new features, no navigation/IA changes.

## 2. Direction (the four anchors, approved)

- **Aesthetic — hybrid.** Dark, dense **security-console** gravitas for the threat/incident surfaces;
  clean, airy **SaaS** polish for analytics/charts and settings. Two registers on one page, deliberately.
- **Scope — whole app, one cohesive pass.** App shell (rail + top bar + ⌘K), Dashboard, Flows, Recent,
  Compare, Settings, dialogs, and the mobile shell.
- **Depth — restyle + targeted layout rework.** Refresh the entire visual layer; rework specific section
  layouts where it elevates the enterprise feel. Keep the component architecture.
- **Palette — enterprise blue.** Deep blue/indigo accent on slate/graphite neutrals. **Color is reserved
  for severity** (the engine's critical/high/medium/low/info ramp) and a single interactive accent —
  nothing decorates. The approved mockup is the reference.

**Sequencing — system-first:** define the token + primitive foundation once, then sweep every surface onto
it. Because components already consume `var(--color-*)`, most of the recolor propagates from `index.css`.

## 3. Design system

The existing token *names* are kept (so components inherit automatically); their *values* change, plus a few
additions. All values are defined for both themes via the existing `[data-theme="light"]` override
architecture (`lib/theme.ts`) and remain compatible with the density toggle (`lib/density.ts`).

### 3.1 Color tokens

**Neutrals + accent change; the severity ramp stays byte-identical to the engine contract** (so the UI,
the HTML report, and `model::severity` never drift).

Dark (`:root`):

| Token | Now | New | Role |
|---|---|---|---|
| `--color-bg` | `#070b11` | `#0b1220` | page canvas (deep slate-navy) |
| `--color-surface` / `-1` | `#0d121b` | `#0f1828` | in-flow card |
| `--color-surface-2` | `#121a26` | `#141e30` | raised card / table header |
| `--color-surface-3` | `#1a2230` | `#1b2740` | popover / hover |
| `--color-surface-raised` | `#222d3e` | `#202c42` | floating |
| `--color-panel` | *(new)* | `#0e1a2c` | **console panel** bg (threats/incidents/flows) |
| `--color-border` | `#243042` | `#223049` | hairline |
| `--color-border-strong` | `#2c3a4e` | `#2c3c58` | emphasized divider |
| `--color-grid` | `#1e2733` | `#1b2740` | chart gridlines |
| `--color-text` | `#e6edf6` | `#e7edf7` | primary |
| `--color-text-dim` | `#94a3b8` | `#93a1b7` | secondary |
| `--color-text-faint` | `#8b98ad` | `#8b98ad` | captions — **keep AA-safe value; re-verify by axe** |
| `--color-accent` | `#38bdf8` | `#3b82f6` | interactive/brand (blue-500) |
| `--color-accent-strong` | `#5fd0ff` | `#60a5fa` | accent hover/emphasis |
| `--color-accent-deep` | *(new)* | `#1d4ed8` | filled-button bg (white text) |
| `--color-spine-violet` | `#7c5cff` | `#7c5cff` | retained (incident spine viz only) |
| `--color-sev-*` | *engine* | **unchanged** | severity ramp (contract) |

Light (`[data-theme="light"]`): canvas `#f4f7fb`, surfaces white/`#eef3f9`/`#e7edf5`, panel `#eef3fb`,
border `#d8e0ea`/`#bcc8d6`, text `#0d1b2e`/`#475569`, **accent `#1d4ed8`** (blue-700 — clears WCAG AA on
white) / strong `#2563eb` / deep `#1d4ed8`. Severity stays the current AA-tuned light values
(`--color-sev-critical #c5183f`, etc.).

> **AA is a hard gate.** The accent and `--color-text-faint` values above are targets; each must clear
> WCAG AA (≥4.5:1) on its background in *both* themes, verified by the real-browser axe suite
> (`e2e/a11y.spec.ts`, 8 combos) on a fresh per-theme load. Adjust the hex if axe flags it.

### 3.2 Typography scale (new tokens)

Currently sizes are ad-hoc Tailwind classes + px. Introduce a defined scale and apply it via primitives.

| Token | px | Use |
|---|---|---|
| `--fs-display` | 22 | page/section hero numbers |
| `--fs-title` | 18 | view titles |
| `--fs-heading` | 15 | card / panel titles |
| `--fs-body` | 13 | dense data-UI default |
| `--fs-label` | 12 | labels, table headers |
| `--fs-micro` | 11 | chips, captions (never below 11) |

**Two weights only: 400 and 500.** The current `font-semibold` (600) headings move to 500 for a lighter,
more refined enterprise feel. Monospace (`font-mono-num`) for **all** numerics — IPs, ports, scores,
counts, timestamps.

### 3.3 Spacing, radius, elevation, motion

- Spacing keeps the density tokens (`--density-gap*`, `--density-pad`); the redesign tightens the
  *comfortable* defaults slightly and standardizes section gaps.
- Radius keeps `--r-card 12px` / `--r-tile 8px` / `--r-chip 6px` / `--r-micro 4px`.
- **Elevation: flatten.** Replace the heavy glow shadows (`--sh-rest/hero/float`) with hairline borders +
  one subtle shadow tier; console panels use border only (no shadow), SaaS cards use a single soft shadow.
  This is the biggest "less cockpit, more enterprise" lever.
- Motion: keep transitions short and functional (hover/focus 120–160ms); remove decorative glow/pulse
  except the single live "Analyzing" indicator.

## 4. Shared primitives

Most exist in `cockpit/primitives.tsx`; this upgrades them and adds the missing ones. Each is a small,
single-purpose unit with a clear interface.

| Primitive | What it is | Used by |
|---|---|---|
| `Panel` (console) | bordered container, dense header (icon + title + count + right-slot actions), optional severity left-accent, no shadow | ThreatWatchlist, IncidentHero, SignatureMatchesPanel, CertHealthPanel, DomainThreatsPanel, the Flows table shell |
| `Card` (SaaS) | 12px radius, soft border + subtle shadow, airy padding, title row | ProtocolMix, ProtocolSunburst, TopPorts, TopTalkers, HttpOverview, PacketDistributions, DnsResolutions, Downloads, LocalHosts, EncryptedDns, AiSummary, CarvedFiles |
| `StatTile` | KPI metric: muted label + large mono value + optional sub/delta | KpiCluster |
| `DataTable` | enterprise grid: sticky/elevated header, hairline rows, hover, mono numerics, severity chips, keyboard-operable sortable headers (preserve existing a11y) | FlowsTable, plus the watchlist/signature tables |
| `Toolbar` | section toolbar: search + filter chips + actions, used above data grids | FlowsView filter bar |
| `SectionHeader` | consistent title + count + actions row | every section |
| `SeverityChip` / `Tag` / `ProvenanceChip` | tinted-bg + same-family text chips; `☁ <provider>` cloud + `ioc` provenance | tables, threat cards |

**Hybrid assignment rule:** *threat/incident/signature/flow* surfaces use `Panel` + `DataTable` (console);
*analytics/overview/settings* surfaces use `Card` (SaaS). This is the single rule that produces the hybrid.

## 5. Per-surface treatment

- **App shell (`AppShell`, `CommandBar`, `ThreatRail`, `MobileNav`):** slim icon rail with a blue active
  indicator; clean top bar = mark + capture chip (status dot) + search affordance + theme/density/settings
  + ⌘K hint + Export. Tighten the rail/top-bar chrome to the new tokens. Keep the mobile drawer + bottom
  tab bar behavior; restyle only.
- **Dashboard (`Dashboard.tsx`):** keep the zone order (KPI → AI summary → incident hero → watchlist →
  graph → heatmap → analytics grid → stacked panels). Convert KPIs to `StatTile`s; threat/incident/
  signature/cert/domain sections to console `Panel`s; analytics cards to SaaS `Card`s. Targeted layout
  rework: a tighter, more scannable analytics grid and clearer section headers.
- **Flows (`FlowsView`, `FlowsTable`):** the surface where enterprise table craft matters most — a real
  data-grid: elevated sticky header, hairline zebra-free rows, mono numerics, inline severity chips,
  per-flow TLS/JA3 columns, a proper `Toolbar` (search + category/severity/proto filters + saved filters).
  Preserve virtualization (TanStack) and keyboard operability.
- **Recent (`RecentView`):** console list of captures as bordered rows (not floaty cards), with cached
  stats + reopen.
- **Compare (`CompareView`):** two-column diff styled with the new tokens; severity deltas use the ramp.
- **Settings + dialogs (`SettingsDialog`, `LoadCaptureDialog`, consent dialogs, `PacketInspector`,
  `DetailFlyout`, menus):** clean SaaS forms — sectioned, labelled, generous spacing; keep the dialog a11y
  hooks (`useDialogA11y`, focus trap, Escape) and menu keyboard nav untouched.

## 6. Constraints / non-goals

**Preserve (hard):** the light/dark token-override architecture; the density toggle; **WCAG AA contrast in
both themes** (the axe e2e suite is the gate); the mobile-first shell; keyboard a11y (dialog/menu hooks,
roving focus); the 607 vitest + coverage gate (80/70) + 33 Playwright e2e — update only assertions coupled
to specific classes/markup; the engine severity contract; no new heavy dependencies (hand-rolled
primitives, no component library).

**Non-goals:** no new features, no engine changes (beyond optionally re-aligning the report CSS to the new
neutrals for parity), no navigation/IA restructure, no backend.

## 7. Implementation approach (phased)

1. **Tokens** — rewrite `index.css` token values (dark + light) + add `--color-panel`, `--color-accent-deep`,
   the type-scale tokens; flatten elevation. Build + axe AA both themes. *Most of the recolor lands here.*
2. **Primitives** — upgrade/add `Panel`, `Card`, `StatTile`, `DataTable`, `Toolbar`, `SectionHeader`, chips
   in `cockpit/primitives.tsx` (+ small new files). Unit-test the new primitives.
3. **Sweep surfaces** — apply primitives + targeted layout rework per surface (shell → Dashboard → Flows →
   Recent → Compare → Settings → mobile), fixing tests as markup shifts.
4. **Validate** — full local gates: `npm run test:coverage`, `npm run e2e` (incl. axe in both themes),
   `npm run build`, desktop `tauri build`; a manual visual pass in both themes + mobile.

The implementation **plan** (next step) sequences these into reviewable tasks.

## 8. Testing & validation

- Keep vitest green; where a test asserts a specific class/structure that the restyle changes, update the
  assertion to the new markup (behavioral assertions stay).
- The real-browser **axe** suite (`e2e/a11y.spec.ts`) re-verifies WCAG A/AA + **color-contrast** across
  dashboard (dark/light, fresh + toggled), Flows (dark/light), settings, shortcuts, and mobile — this is
  the contrast gate; audit per-theme via a fresh load (not toggle), per the prior AA work.
- Add structural tests for the new primitives (`Panel`, `StatTile`, `DataTable`, `Toolbar`).
- Visual smoke via the preview in both themes + mobile width.

## 9. Risks

- **Large surface area** → many test touch-ups; mitigate by phasing (tokens first lands ~70% with zero
  markup change) and running the suite per phase.
- **AA regressions** — the accent/faint hues must be axe-verified per theme on fresh load; the AA work was
  hard-won, treat axe as the gate.
- **Visual regressions / HMR drift** during the sweep — verify in a fresh preview, not a hot-reloaded tab.
- **Severity contract** — do not change `--color-sev-*` hues; they mirror the engine.
