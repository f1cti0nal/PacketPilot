# SNI-domain reputation — Sub-project C (AI context) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a domains section to the shared AI context (`buildContext`) so the exec summary and chat can name risky/notable SNI domains — the final piece of "SNI-domain everywhere."

**Architecture:** One focused addition to `ui/src/lib/ai/context.ts` (mirroring the `threatLine`/`## Top threat IPs` pattern) + a one-line disclosure update to `ui/src/cockpit/AiConsent.tsx`. Both AI paths (`generateSummary`, `askChat`) already call `buildContext(output)`, so no `run.ts`/transport change. No engine/B change, no new deps.

**Tech Stack:** React 18 + TypeScript; Vitest (pure TS string-building).

## Global Constraints

- **Privacy invariant:** `buildContext` reads ONLY `output.summary` rollups (its contract: "never raw packets/payloads/flows"). The domains section reads ONLY `output.summary.domain_threats` (host/flows/bytes/reputation — all pre-computed). No new data source, no new recipient.
- **No new AI consent gate** — folded into the existing AI consent; only the `AiConsent.tsx` disclosure copy changes. (Distinct from B's `pp.rep.domain-consent`, which gates sending to VirusTotal.)
- **The section is unconditional** (no `domainEnabled()` gate) — `summary.domain_threats` is always engine-populated; B already shows it in the dashboard unconditionally.
- **Bounded output** — malicious-first selection, ≤ ~10–15 lines; the existing `ctx.length < 20000` test must keep passing.
- **No engine / B / `run.ts` / transport / WASM change.** Pure `context.ts` + `AiConsent.tsx` (+ tests).
- **`npm run test:coverage` gate stays green** (80/70) under the locked toolchain (vitest 1.6.1; do NOT `npm install`).
- **Stage specific files** on commit (never `git add -A`). TOOLCHAIN: node/npx at `/c/Program Files/nodejs`.

## Reference: the existing code C mirrors (verbatim, verified)

```ts
// ui/src/lib/ai/context.ts
const TOP_INCIDENTS = 10, TOP_THREATS = 20, TOP_N = 10;
function fmtBytes(n: number): string { /* GB/MB/KB/B */ }
function threatLine(t: IpThreat): string {
  const tags = t.tags.length ? ` tags:[${t.tags.join(",")}]` : "";
  const ev = t.evidence.length ? ` — ${t.evidence.slice(0, 3).join("; ")}` : "";
  const rep = t.reputation?.length
    ? ` — reputation: ${t.reputation.map((r) => `${r.source}:${r.status}`).join(", ")}`
    : "";
  return `- ${t.ip} (${t.ip_class}) — ${t.severity} ${t.score}/100${t.ioc ? " IOC" : ""}${tags}${ev}${rep}`;
}
// buildContext(output): assembles "# PacketPilot analysis summary" → capture line → "## Severity"
//   → "## Incidents" → "## Top threat IPs" (threats.slice(0, TOP_THREATS)) → "## Traffic categories"
//   → "## Top talkers". Reads only output.summary.*. Returns lines.join("\n").
//   The "## Top threat IPs" block:
//     const threats = s.ip_threats ?? [];
//     if (threats.length) {
//       lines.push("## Top threat IPs");
//       for (const t of threats.slice(0, TOP_THREATS)) lines.push(threatLine(t));
//       lines.push("");
//     }
// ui/src/types.ts:136 — DomainThreat { host: string; flows: number; bytes: number; reputation?: ReputationVerdict[] }
// ui/src/types.ts:109 — RepStatus = "malicious"|"benign"|"clean"|"unknown"|"notfound"|"unavailable"
// ui/src/cockpit/AiConsent.tsx — discloses "...top incidents and threat IPs with their evidence (never raw packets...)"
```

---

### Task 1: Domains section in `buildContext` + tests

**Files:**
- Modify: `ui/src/lib/ai/context.ts` (add `domainLine` + the `## Notable domains (SNI)` section; import `DomainThreat`)
- Test: `ui/src/lib/ai/context.test.ts` (add domain-section cases; extend `makeOutput`)

**Interfaces:**
- Consumes: `DomainThreat` (`ui/src/types.ts`), the module-private `fmtBytes`, `TOP_N`.
- Produces: a `## Notable domains (SNI)` markdown block in `buildContext`'s output, malicious-first.

- [ ] **Step 1: Write the failing tests** — add to `ui/src/lib/ai/context.test.ts`. First READ the file to reuse its `makeOutput` fixture + imports; add `domain_threats` to the fixture's summary (or build a focused output). Add:

```ts
import type { DomainThreat } from "../../types";

const vt = (status: string) => ({
  source: "virustotal", status, malicious: status === "malicious",
  score: status === "malicious" ? 90 : null, tags: [], link: null, fetched_at: 0,
});
const dom = (host: string, bytes: number, rep?: ReturnType<typeof vt>[]): DomainThreat => ({
  host, flows: 1, bytes, reputation: rep,
});

describe("buildContext — domains", () => {
  it("renders a Notable domains section, labels malicious, and lists malicious-first", () => {
    const out = makeOutput();
    out.summary.domain_threats = [
      dom("cdn.example.com", 5_000_000),                 // high traffic, no verdict
      dom("c2.evil.test", 1_000, [vt("malicious")]),     // low traffic, malicious
      dom("quota.example", 2_000, [vt("unavailable")]),  // quota placeholder — NOT malicious
    ];
    const ctx = buildContext(out);
    expect(ctx).toContain("## Notable domains (SNI)");
    expect(ctx).toContain("c2.evil.test");
    expect(ctx).toContain("MALICIOUS (virustotal)");
    // quota-unavailable shows its status but is never labeled MALICIOUS
    expect(ctx).toContain("quota.example");
    expect(ctx).toContain("virustotal:unavailable");
    // malicious-first: the low-traffic malicious domain precedes the high-traffic clean one
    expect(ctx.indexOf("c2.evil.test")).toBeLessThan(ctx.indexOf("cdn.example.com"));
    // privacy + bounds still hold
    expect(ctx).not.toContain("payload");
    expect(ctx.length).toBeLessThan(20000);
  });

  it("omits the section when there are no domains", () => {
    const out = makeOutput();
    out.summary.domain_threats = [];
    expect(buildContext(out)).not.toContain("## Notable domains (SNI)");
  });
});
```

> NOTE: match `makeOutput`/`buildContext` to their real import names in the file. If the fixture's summary already has `domain_threats`, override it per-test as shown. The `ReputationVerdict` shape is `{ source, status, malicious, score, tags, link, fetched_at }` — keep the `vt` helper consistent with `ui/src/types.ts`.

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/lib/ai/context.test.ts` → FAIL (no `## Notable domains (SNI)`).

- [ ] **Step 3: Implement** — in `ui/src/lib/ai/context.ts`:

(a) add `DomainThreat` to the existing `../../types` import.

(b) add the formatter near `threatLine`:

```ts
function domainLine(d: DomainThreat): string {
  const verdicts = d.reputation ?? [];
  const malSources = verdicts.filter((r) => r.status === "malicious").map((r) => r.source);
  if (malSources.length) {
    return `- ${d.host} — ${fmtBytes(d.bytes)}, ${d.flows} flows — MALICIOUS (${malSources.join(", ")})`;
  }
  const rep = verdicts.length
    ? ` — reputation: ${verdicts.map((r) => `${r.source}:${r.status}`).join(", ")}`
    : "";
  return `- ${d.host} — ${fmtBytes(d.bytes)}, ${d.flows} flows${rep}`;
}
```

(c) in `buildContext`, insert the section immediately AFTER the `## Top threat IPs` block (the one ending in `lines.push("")`) and BEFORE the `## Traffic categories` block:

```ts
  const domains = s.domain_threats ?? [];
  if (domains.length) {
    const isMal = (d: DomainThreat) => (d.reputation ?? []).some((r) => r.status === "malicious");
    const malicious = domains.filter(isMal);
    const rest = domains.filter((d) => !isMal(d)).slice(0, TOP_N);
    const shown = [...malicious, ...rest];
    lines.push("## Notable domains (SNI)");
    for (const d of shown) lines.push(domainLine(d));
    lines.push("");
  }
```

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/lib/ai/context.test.ts` → PASS. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 5: Commit**

```bash
git add ui/src/lib/ai/context.ts ui/src/lib/ai/context.test.ts
git commit -m "feat(ai): name risky/notable SNI domains in the AI context (malicious-first)"
```

---

### Task 2: AI consent disclosure + coverage gate

**Files:**
- Modify: `ui/src/cockpit/AiConsent.tsx` (disclosure copy)
- Test: extend an existing `AiConsent` test if present (else rely on the gate).

- [ ] **Step 1: Update the disclosure copy** — READ `ui/src/cockpit/AiConsent.tsx`; in the privacy paragraph, add "domains contacted" to the disclosed list. Concretely, change the phrase listing what's sent so it reads (adapt to the exact existing wording):

> "Your analysis **summary** — severity counts, top incidents, threat IPs (with evidence), and the domains contacted (never raw packets, payloads, or the capture file) — will be sent to …"

Keep the existing "(never raw packets, payloads, or the capture file)" clause intact and the rest of the component unchanged.

- [ ] **Step 2: Keep any AiConsent test green** — if `ui/src/cockpit/AiConsent.test.tsx` exists and asserts on the copy, update its expectation to match (`grep -rl "AiConsent" ui/src --include=*.test.tsx`). Run it: `cd ui && npx vitest run src/cockpit/AiConsent.test.tsx` (if it exists) → PASS. If no such test exists, no test change is needed (copy-only change).

- [ ] **Step 3: Run the full gate under the LOCKED toolchain** — `cd ui && export PATH="/c/Program Files/nodejs:$PATH"`:

```bash
git diff --stat package.json package-lock.json
git checkout -- package.json package-lock.json 2>/dev/null || true
npm ci
node -p "require('./node_modules/vitest/package.json').version"   # 1.6.1
npm run build:wasm
npm run build; echo "build EXIT: $?"          # EXIT 0, 0 TS errors
npm run test:coverage; echo "cov EXIT: $?"    # EXIT 0; All files >= 80/70 — paste the line
```
Do NOT `npm install`. (`build:wasm` is included for parity with the locked CI flow; C adds no WASM, but the gitignored `ui/src/wasm/` must exist for `npm run build`.)

- [ ] **Step 4: Fill any gap** — if a metric dips because of the new `context.ts` code, add a focused test (e.g. a `domainLine`-via-`buildContext` case for the no-reputation branch). Re-run step 3.

- [ ] **Step 5: Commit**

```bash
git add ui/src/cockpit/AiConsent.tsx
# + any AiConsent test you updated
git commit -m "feat(ai): disclose domains-contacted in the AI consent dialog"
```

---

## Self-Review

**1. Spec coverage:** `domainLine` + the `## Notable domains (SNI)` malicious-first section (T1) → spec §1-2; the `AiConsent.tsx` disclosure (T2) → spec §3; tests (T1) → spec Testing; the coverage gate (T2) → Global Constraints. Privacy invariant (summary-only), no new consent, unconditional section, bounded output, no engine/run.ts change — all honored. ✓

**2. Placeholder scan:** every code step has complete code. The NOTEs (reuse the real `makeOutput`/`buildContext` import names; match the exact `AiConsent` wording; update an `AiConsent` test only if it exists) are concrete in-repo verifications, not placeholders. ✓

**3. Type consistency:** `DomainThreat { host, flows, bytes, reputation? }` (consumed from `types.ts`) used in `domainLine` + the section + the test fixture. `fmtBytes`/`TOP_N` reused from `context.ts`. `RepStatus` `"malicious"`/`"unavailable"` strings match `types.ts`. The malicious-first predicate `(d.reputation ?? []).some(r => r.status === "malicious")` matches B's `DomainThreatsPanel` rule. ✓
