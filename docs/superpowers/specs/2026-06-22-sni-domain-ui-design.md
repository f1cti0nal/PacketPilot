# SNI-domain reputation — Sub-project B (UI + consent) — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-22
**Branch:** `feat/sni-domain-ui`
**Parent feature:** "SNI-domain everywhere" — A (engine, SHIPPED PR #16) → **B (UI + consent, this spec)** → C (AI context). B consumes A's contract.

## Goal

Surface the engine's `summary.domain_threats` in a domains panel and add an opt-in VirusTotal domain-reputation pass — making risky domains visible, mirroring the IP-reputation UI half for domains.

## Architecture

Pure UI + one thin Tauri command, mirroring the IP-reputation surfaces (`lib/reputation/settings.ts` facade, `lib/reputation/{virustotal,orchestrator}.ts`, `wasmEngine.applyReputationWasm`, `ReputationConsent`, the `reputation_lookup` Tauri command, `App.tsx` `runReputation`/`triggerReputationGate`, `ThreatsPanel`) keyed by domain. Consumes A's contract: `summary.domain_threats: DomainThreat[]`, the WASM `apply_domain_reputation` export, the native `lookup_domain_reputation_native`. **VirusTotal-only.** No engine change. A `build:wasm` makes the wrapper resolve (the A export is already on `main`).

**Tech stack:** React 18 + TS + Tailwind (cockpit conventions); Rust (`src-tauri`) for the one command; Vitest + RTL.

## Global Constraints

- **No engine change** — consume A's `summary.domain_threats` + the existing `apply_domain_reputation` WASM export + `lookup_domain_reputation_native`.
- **VirusTotal-only** for domains (AbuseIPDB/GreyNoise are IP-only).
- **Domain lookups are a SEPARATE opt-in, OFF by default** — `pp.rep.domain-enabled` + `pp.rep.domain-consent`, distinct from `pp.rep.enabled`/`pp.rep.consent`. Enabling IP reputation must NOT enable domain lookups. A separate domain consent prompt.
- **Cap domain lookups to the top ~15 hosts by traffic** (bytes) per capture (protect the VT budget + latency); the rest render in the panel without a verdict.
- **"Risky" highlight only on a `status === "malicious"` verdict** — a quota `unavailable` placeholder (A attaches one on budget exhaustion) shows in the chip but never flags a domain as risky.
- **No new runtime dependencies.** Match cockpit styling; reuse `ReputationChip`.
- **`npm run test:coverage` gate stays green** (80/70). Verify under the locked toolchain (`npm ci` → `npm run build:wasm` → `npm run build` → `npm run test:coverage`; vitest 1.6.1) before completion.
- **Stage specific files** on commit (never `git add -A`).

## Design Decisions (resolved)

1. **Panel:** top domains by traffic, risky highlighted (not risky-only). 2. **No severity coupling** (display-only). 3. **VT-only.** 4. **Separate `pp.rep.domain-consent`, off by default.** 5. **Lookup cap = top ~15 by traffic.** 6. **A separate domain consent prompt** (names the domains, shows the count, states VT).

## Reference: the IP pattern B mirrors (verified)

```ts
// lib/reputation/settings.ts — repEnabled()/setRepEnabled (pp.rep.enabled); consentGiven()/giveConsent (pp.rep.consent); getKey("virustotal"); getProxyUrl()
// lib/reputation/virustotal.ts:23 — virustotalVerdictIp(http, key, ip, now) → ReputationVerdict   (NO domain fn yet)
// lib/reputation/orchestrator.ts — lookupReputation(http, ips, keys, now)
// lib/wasmEngine.ts:74 — applyReputationWasm(outputJson, verdicts) → AnalysisOutput
// src-tauri/src/lib.rs:118 — fn reputation_lookup(ips: Vec<String>) -> Result<String,String>  (registered :268)
// cockpit/ReputationConsent.tsx — ReputationConsent({ ipCount, providers, onProceed, onCancel })
// App.tsx:218 runReputation(output); :244 triggerReputationGate(output) (consentGiven ? run : open prompt)
```

## Components

### 1. TS types — `ui/src/types.ts`
```ts
export interface DomainThreat {
  host: string;
  flows: number;
  bytes: number;
  reputation?: ReputationVerdict[];
}
// on Summary:
domain_threats?: DomainThreat[];
```

### 2. Settings facade — `lib/reputation/settings.ts`
Add (mirroring `repEnabled`/`consentGiven`, off by default):
```ts
domainEnabled(): boolean        // "pp.rep.domain-enabled" === "1"
setDomainEnabled(b): void
domainConsentGiven(): boolean   // "pp.rep.domain-consent" === "1"
giveDomainConsent(): void
```
Reuses `getKey("virustotal")` + `getProxyUrl()`.

### 3. Domain orchestration — `lib/reputation/`
- `virustotal.ts`: `virustotalVerdictDomain(http, key, domain, now): Promise<ReputationVerdict>` (mirror `virustotalVerdictIp`, VT `domains/{domain}` endpoint).
- `orchestrator.ts`: `lookupDomainReputation(http, hosts: string[], vtKey: string, now): Promise<Record<string, ReputationVerdict[]>>` — VT-only; reuse the proxy + IndexedDB cache (key `virustotal|<host>`) + budget.

### 4. WASM wrapper + Tauri command
- `lib/wasmEngine.ts`: `applyDomainReputationWasm(outputJson, verdicts): Promise<AnalysisOutput>` (mirror `applyReputationWasm`, calling the wasm `apply_domain_reputation`).
- `src-tauri/src/lib.rs`: `#[tauri::command] fn domain_reputation_lookup(hosts: Vec<String>) -> Result<String, String>` (mirror `reputation_lookup`, calling `ppcap_core::lookup_domain_reputation_native` with the keychain VT key + cache dir + now); register it in `generate_handler!`.

### 5. App wiring — `App.tsx`
- `runDomainReputation(output)`: `const hosts = (output.summary.domain_threats ?? []).slice(0, 15).map(d => d.host)` (already traffic-ranked by A) → desktop `invoke("domain_reputation_lookup", { hosts })` / browser `lookupDomainReputation(proxyHttp(getProxyUrl()), hosts, getKey("virustotal"), now)` → `applyDomainReputationWasm(JSON.stringify(output), verdicts)` → `setSummary`.
- `triggerDomainReputationGate(output)`: per new capture (alongside `triggerReputationGate`), if `domainEnabled()` and `domain_threats` is non-empty: run if `domainConsentGiven()`, else set a `domainConsentPrompt` state → render the domain consent dialog (Proceed → `giveDomainConsent()` + run).

### 6. Consent dialog
A new sibling component `DomainConsent({ domainCount, onProceed, onCancel })` (mirrors `ReputationConsent`'s markup/props) — names that SNI **domains** will be sent, shows the `domainCount` about to go out, and states VirusTotal. Kept separate from `ReputationConsent` so the more-sensitive domain opt-in reads as its own explicit decision.

### 7. UI panel — `DomainThreatsPanel` + `DomainCard`
Render `summary.domain_threats` (traffic-ranked) as cards: `host` + `flows` + `humanBytes(bytes)` + the `ReputationChip` popover (reuses the transparency primitive — it already renders per-provider verdicts incl. `unavailable`). **Highlight a card as risky only when `reputation?.some(v => v.status === "malicious")`** (or `suspicious`), so a quota `unavailable` never false-flags. Mounted in `Dashboard` beside `ThreatsPanel`; empty `domain_threats` → the panel is hidden.

## Data flow & error handling

`summary.domain_threats` flows from A. Consent-gated, VT-only lookup → `applyDomainReputationWasm` (browser) / the enriched summary (desktop) → `setSummary`. Declined consent or a failed lookup → `reputation` stays empty/`unavailable`; the panel still shows the local (always-available) domain list; never crashes. A capture with no SNI → no panel.

## Testing

- **`virustotalVerdictDomain` + `lookupDomainReputation`** (mocked `HttpGet`): parses a VT domain 200/404; cache hit on the 2nd call; the cap is applied by the caller.
- **`applyDomainReputationWasm`** round-trip (built wasm or a mocked wasm seam).
- **`DomainThreatsPanel`/`DomainCard`**: traffic-ranked render; risky highlight ONLY on a `malicious` verdict; a quota `unavailable` verdict shows but is NOT highlighted; empty → hidden.
- **Domain consent gate**: enabled + no consent → prompt shown + no lookup; Proceed → `giveDomainConsent` + lookup fires.
- **Settings facade**: the new keys default off.
- Coverage ≥ 80/70; verify under the locked toolchain incl. `build:wasm` (the wasm export must be in the bundle).

## Out of scope

- **C (AI context):** a domains section in `buildContext` — the next sub-project.
- Severity/incident coupling; non-VT domain providers; richer per-domain scoring.

## File manifest

**Modify:** `ui/src/types.ts` (DomainThreat + Summary field), `ui/src/lib/reputation/settings.ts` (domain keys), `ui/src/lib/reputation/virustotal.ts` (`virustotalVerdictDomain`), `ui/src/lib/reputation/orchestrator.ts` (`lookupDomainReputation`), `ui/src/lib/wasmEngine.ts` (`applyDomainReputationWasm`), `ui/src-tauri/src/lib.rs` (`domain_reputation_lookup` + register), `ui/src/cockpit/SettingsDialog.tsx` (domain checkbox), `ui/src/App.tsx` (run/trigger + consent prompt + panel mount), `ui/src/components/Dashboard.tsx` (mount the panel).
**Create:** `ui/src/components/triage/DomainThreatsPanel.tsx` (+ `DomainCard`), a domain consent dialog (or a `ReputationConsent` variant), + co-located tests.
**No `ppcap-core` change.**
