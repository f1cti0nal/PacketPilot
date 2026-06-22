# SNI-domain reputation — Sub-project C (AI context) — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-22
**Branch:** `feat/sni-domain-ai`
**Parent feature:** "SNI-domain everywhere" — A (engine, SHIPPED PR #16) → B (UI + consent, SHIPPED PR #17) → **C (AI context, this spec)**. C is the final piece; it consumes A's `summary.domain_threats` contract.

## Goal

Add a domains section to the AI analysis context so the executive summary and the chat assistant can name risky and notable SNI domains the capture contacted — completing "SNI-domain everywhere" (engine → UI → AI).

## Architecture

One focused addition to the single shared context builder `ui/src/lib/ai/context.ts` (`buildContext`), mirroring the existing `threatLine`/`## Top threat IPs` pattern, plus a one-line disclosure update to `ui/src/cockpit/AiConsent.tsx`. Both AI paths — `generateSummary` (exec summary) and `askChat` (chat), in `ui/src/lib/ai/run.ts` — already call `buildContext(output)`, so the domains text reaches both with **no `run.ts` or transport change**. No engine change, no change to B's UI/consent surfaces.

**Tech stack:** React 18 + TS; Vitest. (Pure TS string-building; no Rust, no WASM, no new deps.)

## Global Constraints

- **Privacy invariant preserved.** `buildContext` derives ONLY from `output.summary` rollups — "never raw packets/payloads/flows" (the function's contract comment + the `context.test.ts` assertions: `.not.toContain("payload")`, bounded length). The domains section reads ONLY `output.summary.domain_threats` (host/flows/bytes/reputation — all pre-computed rollups). No new data source, no new recipient (the same model already receives the rest of the summary).
- **No new AI consent gate.** Sending domains to the model is folded into the existing AI consent (`AiConsent.tsx`); the disclosure copy is updated to name domains. (This is distinct from B's `pp.rep.domain-consent`, which gates sending domains to *VirusTotal* — a different recipient. C adds no new toggle/consent.)
- **The section is unconditional** (no `domainEnabled()` gate): `summary.domain_threats` is always engine-populated (network-free SNI aggregation), and B already shows it in the dashboard unconditionally — so the AI context mirrors what the user already sees. Reputation verdicts appear only if the user ran B's domain pass.
- **Bounded output.** The section is capped (malicious-first selection, ≤ ~10–15 lines) so the context stays compact; the existing `ctx.length < 20000` test must keep passing.
- **No engine / B / `run.ts` / transport change.** Pure `context.ts` + `AiConsent.tsx` (+ tests).
- **`npm run test:coverage` gate stays green** (80/70), verified under the locked toolchain (vitest 1.6.1).
- **Stage specific files** on commit (never `git add -A`).

## Reference: the pattern C mirrors (verified)

```ts
// ui/src/lib/ai/context.ts
//   const TOP_INCIDENTS = 10, TOP_THREATS = 20, TOP_N = 10;
//   fmtBytes(n)                          — GB/MB/KB/B formatter
//   threatLine(t: IpThreat): string      — "- {ip} ({class}) — {sev} {score}/100{IOC}{tags}{ev}{rep}"
//        where rep = " — reputation: " + t.reputation.map(r => `${r.source}:${r.status}`).join(", ")
//   buildContext(output): assembles "# PacketPilot analysis summary", capture line, "## Severity",
//        "## Incidents", "## Top threat IPs" (threats.slice(0, TOP_THREATS)), "## Traffic categories",
//        "## Top talkers" — reads only output.summary.* — returns the joined markdown string.
// ui/src/lib/ai/run.ts — generateSummary + askChat both embed buildContext(output) as message content.
// ui/src/cockpit/AiConsent.tsx — discloses "severity counts, top incidents and threat IPs with their
//        evidence (never raw packets, payloads, or the capture file)".
// ui/src/types.ts:136 — DomainThreat { host, flows, bytes, reputation?: ReputationVerdict[] }; Summary.domain_threats?
// ui/src/types.ts:109 — RepStatus = "malicious"|"benign"|"clean"|"unknown"|"notfound"|"unavailable"
```

## Components

### 1. `domainLine(d: DomainThreat): string` — `ui/src/lib/ai/context.ts`

Mirrors `threatLine`, simpler (domains have no severity/score):

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

The explicit `MALICIOUS (source)` marker (vs. just `source:malicious`) makes the risk signal unambiguous for the model. A quota `unavailable` verdict renders as `reputation: virustotal:unavailable` — informative, never "malicious" (mirrors B's malicious-only highlight rule).

### 2. `## Notable domains (SNI)` section — `buildContext`

Inserted after the `## Top threat IPs` block, before `## Traffic categories`. **Selection: malicious-first.**

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

All domains with a `malicious` verdict appear first (they are the security-relevant ones and may be low-traffic — a bytes-only top-N could cut off a small C2 beacon), followed by up to `TOP_N` (10) more ranked by the engine's existing bytes-descending order. Bounded: malicious domains are rare and `domain_threats` is itself engine-capped at 50.

### 3. Consent disclosure — `ui/src/cockpit/AiConsent.tsx`

Add "domains contacted" to the disclosed list, e.g. change "top incidents and threat IPs with their evidence" → "top incidents, threat IPs (with evidence), and the domains contacted". The summary already sends destination IPs (`top_talkers`, `ip_threats`); SNI domains are the same "who you talked to" class, so disclosing them keeps the consent honest. No new toggle.

## Data flow & error handling

`buildContext(output)` reads `output.summary.domain_threats` (already part of the derived summary) → the markdown string flows, unchanged, into both `generateSummary`'s user message and `askChat`'s system message → the existing tauri/proxy/direct transports, under the existing AI consent. No `domain_threats` (no TLS SNI, or an old capture without the `#[serde(default)]` field) → the section is simply omitted (`if (domains.length)`); never throws. Empty `reputation` → the line shows host + traffic only.

## Testing

Extend `ui/src/lib/ai/context.test.ts` (reuse/extend the existing `makeOutput` fixture):

- **Section presence:** a capture with `domain_threats` → the context contains `## Notable domains (SNI)` and each shown host.
- **Malicious labeling:** a domain with a `virustotal` `malicious` verdict → its line contains `MALICIOUS (virustotal)`; a domain with only an `unavailable` verdict → its line contains `virustotal:unavailable` and NOT `MALICIOUS`.
- **Malicious-first ordering:** a low-traffic malicious domain ordered ahead of a higher-traffic non-malicious one in the rendered context.
- **Privacy/bounds preserved:** `.not.toContain("payload")` and `ctx.length < 20000` still hold with domains present.
- **Empty:** no `domain_threats` → no `## Notable domains` header, no throw.
- Coverage ≥ 80/70 under the locked toolchain (vitest 1.6.1).

## Out of scope

- A separate AI-domain consent/toggle (folded into the existing AI consent).
- Any `run.ts` / transport / engine / B-UI change.
- Per-domain scoring, severity/incident coupling, non-VT domain providers (settled in A/B).

## File manifest

**Modify:** `ui/src/lib/ai/context.ts` (`domainLine` + the `## Notable domains (SNI)` section), `ui/src/cockpit/AiConsent.tsx` (disclosure copy), `ui/src/lib/ai/context.test.ts` (domain-section tests).
**No engine, no `run.ts`, no WASM, no new deps.**
