# SNI-domain reputation — Sub-project B (UI + consent) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface `summary.domain_threats` in a domains panel and add an opt-in VirusTotal domain-reputation pass, mirroring the IP-reputation UI half for domains.

**Architecture:** Pure UI + one Tauri command, mirroring the IP reputation surfaces keyed by domain. Consumes sub-project A's contract (`summary.domain_threats`, the WASM `apply_domain_reputation` export, `lookup_domain_reputation_native`). VT-only; separate opt-in off by default.

**Tech Stack:** React 18 + TS + Tailwind; Rust (`src-tauri`) for one command; Vitest + RTL.

## Global Constraints

- **No engine change** — consume A's `summary.domain_threats`, the existing WASM `apply_domain_reputation`, and `lookup_domain_reputation_native`.
- **VirusTotal-only** for domains.
- **Separate opt-in, OFF by default:** `pp.rep.domain-enabled` + `pp.rep.domain-consent` (distinct from `pp.rep.enabled`/`pp.rep.consent`). A separate `DomainConsent` prompt.
- **Cap domain lookups to the top 15 by traffic** (the engine pre-ranks `domain_threats` by bytes — take the first 15).
- **"Risky" highlight only on a `status === "malicious"` verdict** — A's quota `unavailable` placeholder must never flag a domain.
- **No new runtime deps.** Reuse `ProviderVerdictList` (transparency primitive) for the per-provider verdict display. Match cockpit styling.
- **`npm run test:coverage` gate stays green** (80/70). Verify under the locked toolchain (`npm ci` → `npm run build:wasm` → `npm run build` → `npm run test:coverage`; vitest 1.6.1). The `apply_domain_reputation` WASM export is already on `main` (from A) — `build:wasm` brings it into the bundle.
- **TOOLCHAIN:** node/npx at `/c/Program Files/nodejs`; cargo at `/c/Users/ravid/.cargo/bin`; the src-tauri build needs MinGW (`/c/Users/ravid/opt/mingw64/bin`). Do NOT `npm install`. Stage specific files (never `git add -A`).

## Reference: the IP pattern B mirrors (verbatim)

```ts
// lib/reputation/settings.ts — repEnabled/setRepEnabled (pp.rep.enabled), consentGiven/giveConsent (pp.rep.consent), getProxyUrl, getKey("virustotal"), browserKeys, Provider, PROVIDERS
// lib/reputation/http.ts — type HttpGet = (url, headers) => Promise<{status,body}>; proxyHttp(proxyUrl); unavailable(source, now)
// lib/reputation/virustotal.ts — a module-private parse(body,status,link,now); export virustotalVerdictIp(http,key,ip,now) → http(`.../ip_addresses/${ip}`, {"x-apikey":key})
// lib/reputation/orchestrator.ts — module-private TTL, quotaUnavailable; makeBudget/trySpend (./budget); getReputation/putReputation (../recent); lookupReputation(http, ips, keys, now)
// lib/wasmEngine.ts:10 import {... apply_reputation as wasmApplyReputation ...} from "../wasm/ppcap_wasm.js"; ensureWasm(); applyReputationWasm(outputJson, verdicts)
// src-tauri/src/lib.rs:117 reputation_lookup(ips) — key_for("virustotal"), ReputationKeys, lookup_reputation_native; handler list :258-272
// cockpit/ReputationConsent.tsx — ReputationConsent({ ipCount, providers, onProceed, onCancel })
// App.tsx:218 runReputation; :244 triggerReputationGate; :123 consentPrompt useState; :524 dialog render; call sites :276/:304/:333 (after applyCapture, guarded by lastRepSourceRef)
// components/triage/ThreatsPanel.tsx — ThreatCard + ThreatsPanel({threats}); uses ProviderVerdictList, humanBytes, humanNumber
// components/Dashboard.tsx — `const s = ...summary`; a 12-col grid (:110-124)
```

---

### Task 1: TS types + settings facade

**Files:**
- Modify: `ui/src/types.ts` (DomainThreat + Summary field), `ui/src/lib/reputation/settings.ts` (domain keys)
- Test: `ui/src/lib/reputation/settings.test.ts` (add cases)

**Interfaces:**
- Produces: `DomainThreat { host, flows, bytes, reputation? }`; `Summary.domain_threats?`; `domainEnabled()/setDomainEnabled()`, `domainConsentGiven()/giveDomainConsent()`.

- [ ] **Step 1: Write the failing test** — add to `ui/src/lib/reputation/settings.test.ts`:

```ts
import { describe, it, expect, beforeEach } from "vitest";
import { domainEnabled, setDomainEnabled, domainConsentGiven, giveDomainConsent } from "./settings";

describe("domain reputation settings", () => {
  beforeEach(() => localStorage.clear());
  it("defaults off and round-trips", () => {
    expect(domainEnabled()).toBe(false);
    expect(domainConsentGiven()).toBe(false);
    setDomainEnabled(true);
    expect(domainEnabled()).toBe(true);
    expect(localStorage.getItem("pp.rep.domain-enabled")).toBe("1");
    giveDomainConsent();
    expect(domainConsentGiven()).toBe(true);
  });
  it("is independent of the IP enable/consent keys", () => {
    localStorage.setItem("pp.rep.enabled", "1");
    localStorage.setItem("pp.rep.consent", "1");
    expect(domainEnabled()).toBe(false); // enabling IP rep does NOT enable domains
    expect(domainConsentGiven()).toBe(false);
  });
});
```

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/lib/reputation/settings.test.ts` → FAIL (fns undefined).

- [ ] **Step 3: Implement** — (a) in `ui/src/types.ts`, add the interface (near `IpThreat`/`ReputationVerdict`) and the Summary field:

```ts
export interface DomainThreat {
  host: string;
  flows: number;
  bytes: number;
  reputation?: ReputationVerdict[];
}
```
On the `Summary` interface, add: `domain_threats?: DomainThreat[];`

(b) in `ui/src/lib/reputation/settings.ts`, append:

```ts
export function domainEnabled(): boolean { return localStorage.getItem("pp.rep.domain-enabled") === "1"; }
export function setDomainEnabled(b: boolean): void { localStorage.setItem("pp.rep.domain-enabled", b ? "1" : "0"); }
export function domainConsentGiven(): boolean { return localStorage.getItem("pp.rep.domain-consent") === "1"; }
export function giveDomainConsent(): void { localStorage.setItem("pp.rep.domain-consent", "1"); }
```

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/lib/reputation/settings.test.ts` → PASS. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 5: Commit**

```bash
git add ui/src/types.ts ui/src/lib/reputation/settings.ts ui/src/lib/reputation/settings.test.ts
git commit -m "feat(domain-rep): DomainThreat TS type + domain enable/consent settings"
```

---

### Task 2: TS domain orchestration

**Files:**
- Modify: `ui/src/lib/reputation/virustotal.ts` (`virustotalVerdictDomain`), `ui/src/lib/reputation/orchestrator.ts` (`lookupDomainReputation`)
- Test: `ui/src/lib/reputation/virustotal.test.ts` + `orchestrator.test.ts` (add cases; create if absent)

**Interfaces:**
- Produces: `virustotalVerdictDomain(http, key, domain, now): Promise<ReputationVerdict>`; `lookupDomainReputation(http, hosts: string[], vtKey: string, now): Promise<Record<string, ReputationVerdict[]>>`.

- [ ] **Step 1: Write the failing test** — add to `ui/src/lib/reputation/virustotal.test.ts` (mock `HttpGet` as a fn):

```ts
import { describe, it, expect } from "vitest";
import { virustotalVerdictDomain } from "./virustotal";

const vtBody = (m: number) => JSON.stringify({ data: { attributes: { last_analysis_stats: { malicious: m, suspicious: 0, harmless: 5, undetected: 0 }, tags: [] } } });

describe("virustotalVerdictDomain", () => {
  it("parses a malicious domain", async () => {
    const http = async () => ({ status: 200, body: vtBody(3) });
    const v = await virustotalVerdictDomain(http, "k", "evil.example", 0);
    expect(v.status).toBe("malicious");
    expect(v.link).toContain("/domain/evil.example");
  });
  it("maps 404 to notfound", async () => {
    const http = async () => ({ status: 404, body: "" });
    expect((await virustotalVerdictDomain(http, "k", "x.example", 0)).status).toBe("notfound");
  });
});
```

And, for the orchestrator, add to `ui/src/lib/reputation/orchestrator.test.ts` a case that the cap-respecting caller passes only hosts (the cap is applied by App). Minimal:

```ts
import { describe, it, expect, vi } from "vitest";
import { lookupDomainReputation } from "./orchestrator";

vi.mock("../recent", () => ({ getReputation: vi.fn(async () => null), putReputation: vi.fn(async () => {}) }));

describe("lookupDomainReputation", () => {
  it("returns empty without a VT key", async () => {
    const http = async () => ({ status: 200, body: "{}" });
    expect(await lookupDomainReputation(http, ["a.example"], "", 0)).toEqual({});
  });
  it("looks up each host via VT (cache miss → fetch)", async () => {
    const http = vi.fn(async () => ({ status: 200, body: JSON.stringify({ data: { attributes: { last_analysis_stats: { malicious: 1, suspicious: 0, harmless: 9, undetected: 0 }, tags: [] } } }) }));
    const out = await lookupDomainReputation(http, ["evil.example"], "k", 0);
    expect(out["evil.example"][0].status).toBe("malicious");
    expect(http).toHaveBeenCalledTimes(1);
  });
});
```

> NOTE: if `orchestrator.test.ts` already mocks `../recent`/`./budget`, reuse its mocks instead of re-declaring.

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/lib/reputation/virustotal.test.ts src/lib/reputation/orchestrator.test.ts` → FAIL.

- [ ] **Step 3: Implement** — (a) in `virustotal.ts`, after `virustotalVerdictIp`, add (reusing the module-private `parse`):

```ts
export async function virustotalVerdictDomain(http: HttpGet, key: string, domain: string, now: number): Promise<ReputationVerdict> {
  const res = await http(`https://www.virustotal.com/api/v3/domains/${domain}`, { "x-apikey": key });
  return parse(res.body, res.status, `https://www.virustotal.com/gui/domain/${domain}`, now);
}
```

(b) in `orchestrator.ts`, add (reusing the module-private `TTL`/`quotaUnavailable`, the imported `makeBudget`/`trySpend`, `getReputation`/`putReputation`, and `virustotalVerdictDomain`):

```ts
import { virustotalVerdictDomain } from "./virustotal";

/** Domain reputation — VirusTotal only. `hosts` should already be capped/ordered by the caller. */
export async function lookupDomainReputation(
  http: HttpGet,
  hosts: string[],
  vtKey: string,
  now: number,
): Promise<Record<string, ReputationVerdict[]>> {
  const out: Record<string, ReputationVerdict[]> = {};
  if (!vtKey) return out;
  const budget = makeBudget();
  for (const host of hosts) {
    const cached = await getReputation("virustotal", host, now, TTL.virustotal);
    let v: ReputationVerdict;
    if (cached) {
      v = cached;
    } else if (trySpend(budget, "virustotal")) {
      v = await virustotalVerdictDomain(http, vtKey, host, now);
      await putReputation("virustotal", host, v);
    } else {
      v = quotaUnavailable("virustotal", now);
    }
    out[host] = [v];
  }
  return out;
}
```

(Add `virustotalVerdictDomain` to the existing `./virustotal` import in orchestrator.ts.)

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/lib/reputation/virustotal.test.ts src/lib/reputation/orchestrator.test.ts` → PASS. tsc clean.

- [ ] **Step 5: Commit**

```bash
git add ui/src/lib/reputation/virustotal.ts ui/src/lib/reputation/orchestrator.ts ui/src/lib/reputation/virustotal.test.ts ui/src/lib/reputation/orchestrator.test.ts
git commit -m "feat(domain-rep): virustotalVerdictDomain + lookupDomainReputation (VT-only)"
```

---

### Task 3: WASM wrapper + Tauri command

**Files:**
- Modify: `ui/src/lib/wasmEngine.ts` (`applyDomainReputationWasm`), `ui/src-tauri/src/lib.rs` (`domain_reputation_lookup` + register)
- Test: `ui/src/lib/wasmEngine.domain.test.ts` (mock the wasm module)

**Interfaces:**
- Consumes: the wasm `apply_domain_reputation` export (from A, already on `main`); `ppcap_core::lookup_domain_reputation_native`.
- Produces: `applyDomainReputationWasm(outputJson, verdicts): Promise<AnalysisOutput>`; Tauri `domain_reputation_lookup(hosts)`.

- [ ] **Step 1: Write the failing test** — `ui/src/lib/wasmEngine.domain.test.ts` (mock the whole wasm module so no real wasm is needed):

```ts
import { describe, it, expect, vi } from "vitest";

vi.mock("../wasm/ppcap_wasm.js", () => ({
  default: vi.fn(async () => {}),
  analyze: vi.fn(), extract_packets: vi.fn(), apply_reputation: vi.fn(),
  apply_domain_reputation: vi.fn((o: string) => o), // echo the output json
  export_csv: vi.fn(), export_stix: vi.fn(),
}));
vi.mock("./data", () => ({ loadFlows: vi.fn(), flowRowFromWasm: vi.fn() }));

import { applyDomainReputationWasm } from "./wasmEngine";

describe("applyDomainReputationWasm", () => {
  it("calls the wasm export and parses the result", async () => {
    const out = await applyDomainReputationWasm(JSON.stringify({ summary: { domain_threats: [] } }), {});
    expect((out as any).summary.domain_threats).toEqual([]);
  });
});
```

> NOTE: the `vi.mock("../wasm/ppcap_wasm.js")` factory must provide EVERY named export `wasmEngine.ts` imports (analyze, extract_packets, apply_reputation, apply_domain_reputation, export_csv, export_stix) + the default. Match the file's actual import list.

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/lib/wasmEngine.domain.test.ts` → FAIL (export not defined).

- [ ] **Step 3: Implement** — (a) `ui/src/lib/wasmEngine.ts`: add `apply_domain_reputation as wasmApplyDomainReputation,` to the `from "../wasm/ppcap_wasm.js"` import, then add:

```ts
export async function applyDomainReputationWasm(
  outputJson: string,
  verdicts: Record<string, ReputationVerdict[]>,
): Promise<AnalysisOutput> {
  await ensureWasm();
  const updated = wasmApplyDomainReputation(outputJson, JSON.stringify(verdicts)) as string;
  return JSON.parse(updated) as AnalysisOutput;
}
```

(b) `ui/src-tauri/src/lib.rs`: add the command (mirror `reputation_lookup`, VT-only):

```rust
#[tauri::command]
fn domain_reputation_lookup(hosts: Vec<String>) -> Result<String, String> {
    let keys = ppcap_core::ReputationKeys {
        abuseipdb: None,
        greynoise: None,
        virustotal: key_for("virustotal")?,
    };
    if keys.virustotal.is_none() {
        return Ok("{}".to_string());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let cache_dir = dirs::cache_dir().unwrap_or_else(std::env::temp_dir).join("packetpilot");
    let verdicts = ppcap_core::lookup_domain_reputation_native(&hosts, &keys, &cache_dir, now);
    serde_json::to_string(&verdicts).map_err(|e| e.to_string())
}
```

Add `domain_reputation_lookup,` to the `tauri::generate_handler![ … ]` list (after `reputation_lookup`).

- [ ] **Step 4: Verify** —
  - `cd ui && npx vitest run src/lib/wasmEngine.domain.test.ts` → PASS.
  - Rebuild wasm + confirm the export ships: `cd ui && export PATH="/c/Program Files/nodejs:/c/Users/ravid/.cargo/bin:$PATH" && npm run build:wasm && grep -c apply_domain_reputation src/wasm/ppcap_wasm.js` → ≥ 1.
  - `cd ui/src-tauri && export PATH="/c/Users/ravid/opt/mingw64/bin:/c/Users/ravid/.cargo/bin:$PATH" && cargo build` → compiles clean.

- [ ] **Step 5: Commit** (Rust source + TS; NOT the gitignored `ui/src/wasm/`):

```bash
git add ui/src/lib/wasmEngine.ts ui/src/lib/wasmEngine.domain.test.ts ui/src-tauri/src/lib.rs
git commit -m "feat(domain-rep): applyDomainReputationWasm wrapper + domain_reputation_lookup Tauri command"
```

---

### Task 4: UI — `DomainConsent` + `DomainThreatsPanel`/`DomainCard`

**Files:**
- Create: `ui/src/cockpit/DomainConsent.tsx`, `ui/src/components/triage/DomainThreatsPanel.tsx` + `DomainThreatsPanel.test.tsx`

**Interfaces:**
- Consumes: `DomainThreat` (Task 1); `ProviderVerdictList` (`../transparency/ProviderVerdictList`); the `humanBytes`/`humanNumber` helpers `ThreatsPanel` imports.
- Produces: `DomainConsent({ domainCount, onProceed, onCancel })`; `DomainThreatsPanel({ domains: DomainThreat[] })`.

- [ ] **Step 1: Write the failing test** — `ui/src/components/triage/DomainThreatsPanel.test.tsx`:

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { DomainThreatsPanel } from "./DomainThreatsPanel";
import type { DomainThreat } from "../../types";

const dom = (o: Partial<DomainThreat>): DomainThreat => ({ host: "a.example", flows: 1, bytes: 1, ...o });

describe("DomainThreatsPanel", () => {
  it("renders nothing when there are no domains", () => {
    const { container } = render(<DomainThreatsPanel domains={[]} />);
    expect(container).toBeEmptyDOMElement();
  });
  it("renders domain hosts and flags malicious ones only", () => {
    render(<DomainThreatsPanel domains={[
      dom({ host: "evil.example", reputation: [{ source: "virustotal", status: "malicious", malicious: true, score: 90, tags: [], link: null, fetched_at: 0 }] }),
      dom({ host: "quota.example", reputation: [{ source: "virustotal", status: "unavailable", malicious: false, score: null, tags: ["quota"], link: null, fetched_at: 0 }] }),
      dom({ host: "plain.example" }),
    ]} />);
    expect(screen.getByText("evil.example")).toBeInTheDocument();
    expect(screen.getByText("plain.example")).toBeInTheDocument();
    // exactly one "malicious" flag (the unavailable/quota domain is NOT flagged)
    expect(screen.getAllByText("malicious").length).toBe(1);
  });
});
```

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/components/triage/DomainThreatsPanel.test.tsx` → FAIL (module not found).

- [ ] **Step 3: Implement** —

`ui/src/cockpit/DomainConsent.tsx` (mirror `ReputationConsent`):

```tsx
export function DomainConsent({ domainCount, onProceed, onCancel }:
  { domainCount: number; onProceed: () => void; onCancel: () => void }) {
  return (
    <div role="dialog" aria-label="Domain reputation consent" className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="max-w-md rounded-lg bg-[var(--color-surface)] p-5 text-[var(--color-text)]">
        <h2 className="text-sm font-semibold">Send {domainCount} domain{domainCount === 1 ? "" : "s"} to VirusTotal?</h2>
        <p className="mt-2 text-xs text-[var(--color-text-faint)]">
          The top {domainCount} TLS SNI hostname{domainCount === 1 ? "" : "s"} this capture contacted will be sent to VirusTotal
          to check reputation. Payloads and the capture itself never leave this device.
        </p>
        <div className="mt-4 flex justify-end gap-2">
          <button className="t-tag" onClick={onCancel}>Cancel</button>
          <button className="t-tag font-semibold" onClick={onProceed}>Proceed</button>
        </div>
      </div>
    </div>
  );
}
```

`ui/src/components/triage/DomainThreatsPanel.tsx` (mirror `ThreatsPanel`/`ThreatCard`, simpler — no severity/score). Use the SAME import paths `ThreatsPanel.tsx` uses for `humanBytes`/`humanNumber` (copy them from that file's imports):

```tsx
import { Globe } from "lucide-react";
import type { DomainThreat } from "../../types";
import { humanBytes, humanNumber } from "../../lib/format"; // match ThreatsPanel's actual import path
import { ProviderVerdictList } from "../transparency/ProviderVerdictList";

function DomainCard({ domain }: { domain: DomainThreat }) {
  const malicious = (domain.reputation ?? []).some((v) => v.status === "malicious");
  return (
    <li
      className="flex flex-col gap-2.5 rounded-lg border bg-[var(--color-surface-2)] p-3"
      style={{ borderColor: malicious ? "color-mix(in srgb, var(--color-sev-critical) 50%, var(--color-border))" : "var(--color-border)" }}
    >
      <div className="flex flex-wrap items-center gap-2">
        <Globe size={13} className="shrink-0 text-[var(--color-text-faint)]" aria-hidden />
        <span className="font-mono-num min-w-0 flex-1 truncate text-sm font-semibold text-[var(--color-text)]">{domain.host}</span>
        {malicious && (
          <span className="t-tag font-semibold" style={{ color: "var(--color-sev-critical)" }}>malicious</span>
        )}
      </div>
      <div className="flex items-center gap-3 text-xs text-[var(--color-text-dim)]">
        <span><span className="font-mono-num text-[var(--color-text)]">{humanNumber(domain.flows)}</span> flows</span>
        <span><span className="font-mono-num text-[var(--color-text)]">{humanBytes(domain.bytes)}</span></span>
      </div>
      {domain.reputation && domain.reputation.length > 0 && <ProviderVerdictList verdicts={domain.reputation} />}
    </li>
  );
}

/** Top SNI domains by traffic, with VirusTotal reputation when looked up. Hidden when empty. */
export function DomainThreatsPanel({ domains }: { domains: DomainThreat[] }) {
  if (!domains || domains.length === 0) return null;
  const top = domains.slice(0, 12);
  return (
    <section data-component="DomainThreatsPanel" aria-label="Domains" className="rounded-lg border border-border bg-surface p-4 shadow-sm">
      <div className="mb-3 flex items-baseline justify-between gap-2">
        <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-[var(--color-text-dim)]">
          <Globe size={15} className="text-[var(--color-accent)]" /> Domains
        </h2>
        <span className="font-mono-num text-xs text-[var(--color-text-faint)]">{humanNumber(domains.length)} seen</span>
      </div>
      <ul className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
        {top.map((d) => <DomainCard key={d.host} domain={d} />)}
      </ul>
    </section>
  );
}
```

> NOTE: open `ThreatsPanel.tsx` to copy the EXACT import path for `humanBytes`/`humanNumber` (the example `../../lib/format` may differ). If `ProviderVerdictList`'s path differs, match the real one (it's a transparency primitive).

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/components/triage/DomainThreatsPanel.test.tsx` → PASS. tsc clean.

- [ ] **Step 5: Commit**

```bash
git add ui/src/cockpit/DomainConsent.tsx ui/src/components/triage/DomainThreatsPanel.tsx ui/src/components/triage/DomainThreatsPanel.test.tsx
git commit -m "feat(domain-rep): DomainConsent + DomainThreatsPanel (malicious-only highlight)"
```

---

### Task 5: App wiring + Dashboard mount

**Files:**
- Modify: `ui/src/App.tsx` (run/trigger/consent + state + dialog + 3 call sites), `ui/src/components/Dashboard.tsx` (mount the panel)

**Interfaces:**
- Consumes: `domainEnabled`/`domainConsentGiven`/`giveDomainConsent` (T1); `lookupDomainReputation` (T2); `applyDomainReputationWasm` (T3); `DomainConsent` + `DomainThreatsPanel` (T4); the existing `getProxyUrl`/`getKey`/`proxyHttp`/`IS_TAURI`/`setSummary`.

- [ ] **Step 1: App imports + state** — in `ui/src/App.tsx`:
  - Add to the `./lib/reputation/settings` import: `domainEnabled, domainConsentGiven, giveDomainConsent, getKey`. Add `lookupDomainReputation` to the `./lib/reputation/orchestrator` import. Add `applyDomainReputationWasm` to the `./lib/wasmEngine` import. Add `import { DomainConsent } from "./cockpit/DomainConsent";`.
  - Add state near `consentPrompt`: `const [domainConsentPrompt, setDomainConsentPrompt] = useState<{ output: AnalysisOutput; domainCount: number } | null>(null);`

- [ ] **Step 2: `runDomainReputation` + `triggerDomainReputationGate`** — add next to `runReputation`/`triggerReputationGate`:

```tsx
  const runDomainReputation = useCallback(async (output: AnalysisOutput): Promise<void> => {
    if (!domainEnabled()) return;
    const hosts = (output.summary.domain_threats ?? []).slice(0, 15).map((d) => d.host);
    if (hosts.length === 0) return;
    let verdicts: Record<string, import("./types").ReputationVerdict[]> = {};
    if (IS_TAURI) {
      const { invoke } = await import("@tauri-apps/api/core");
      verdicts = JSON.parse(await invoke<string>("domain_reputation_lookup", { hosts })) as typeof verdicts;
    } else {
      const proxy = getProxyUrl();
      const vtKey = getKey("virustotal");
      if (!proxy || !vtKey) return;
      const now = Math.floor(Date.now() / 1000);
      verdicts = await lookupDomainReputation(proxyHttp(proxy), hosts, vtKey, now);
    }
    if (Object.keys(verdicts).length === 0) return;
    const enriched = await applyDomainReputationWasm(JSON.stringify(output), verdicts);
    setSummary({ status: "ready", data: enriched });
  }, []);

  const triggerDomainReputationGate = useCallback((output: AnalysisOutput) => {
    if (!domainEnabled()) return;
    const domains = output.summary.domain_threats ?? [];
    if (domains.length === 0) return;
    if (domainConsentGiven()) {
      void runDomainReputation(output);
    } else {
      setDomainConsentPrompt({ output, domainCount: Math.min(15, domains.length) });
    }
  }, [runDomainReputation]);
```

- [ ] **Step 3: Dialog render + call sites** — (a) render the dialog near the `ReputationConsent` render:

```tsx
    {domainConsentPrompt && (
      <DomainConsent
        domainCount={domainConsentPrompt.domainCount}
        onProceed={() => {
          giveDomainConsent();
          const out = domainConsentPrompt.output;
          setDomainConsentPrompt(null);
          void runDomainReputation(out);
        }}
        onCancel={() => setDomainConsentPrompt(null)}
      />
    )}
```

(b) at EACH of the 3 `triggerReputationGate(<out>);` call sites (the `lastRepSourceRef` blocks after applyCapture), add a line right after it: `triggerDomainReputationGate(<out>);` (same argument — `out` / `nextSummary`).

- [ ] **Step 4: Mount the panel** — in `ui/src/components/Dashboard.tsx`, add the import `import { DomainThreatsPanel } from "./triage/DomainThreatsPanel";` and render it as a full-width section after the 12-col grid block (it returns null when empty, so unconditional is safe):

```tsx
        <DomainThreatsPanel domains={s.domain_threats ?? []} />
```

- [ ] **Step 5: Verify** — `cd ui && npx vitest run src/App.test.tsx src/components/Dashboard.test.tsx` (whichever exist; `grep -rl "App.test\|Dashboard" ui/src --include=*.test.tsx`) → existing tests stay green (domain pass is off by default → no behavior change). `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 6: Commit**

```bash
git add ui/src/App.tsx ui/src/components/Dashboard.tsx
git commit -m "feat(domain-rep): consent-gated domain reputation pass + Dashboard panel mount"
```

---

### Task 6: Settings checkbox + coverage gate

**Files:**
- Modify: `ui/src/cockpit/SettingsDialog.tsx` (the domain-enable checkbox)
- Add focused tests if a gate dips below the bar.

- [ ] **Step 1: Settings checkbox** — in `ui/src/cockpit/SettingsDialog.tsx`: add a `domainEnabled`/`setDomainEnabled` import from `../lib/reputation/settings`; add state `const [domainEnabledState, setDomainEnabledState] = useState(domainEnabled());`; render a 2nd checkbox in the reputation section (after the "Enable reputation lookups" checkbox):

```tsx
        <label className="mt-3 flex items-center gap-2 text-xs">
          <input type="checkbox" checked={domainEnabledState} onChange={(e) => setDomainEnabledState(e.target.checked)} /> Enable domain reputation lookups (sends SNI hostnames to VirusTotal)
        </label>
```

and in `save()`, after `setRepEnabled(enabled);`, add `setDomainEnabled(domainEnabledState);`.

- [ ] **Step 2: Realign + rebuild wasm + run gates** — `cd ui && export PATH="/c/Program Files/nodejs:/c/Users/ravid/.cargo/bin:$PATH"`:

```bash
git diff --stat package.json package-lock.json
git checkout -- package.json package-lock.json 2>/dev/null || true
npm ci
node -p "require('./node_modules/vitest/package.json').version"   # 1.6.1
npm run build:wasm
npm run build; echo "build EXIT: $?"          # EXIT 0, 0 error TS
npm run test:coverage; echo "cov EXIT: $?"    # EXIT 0; All files >= 80/70 — paste it
```
Do NOT `npm install`.

- [ ] **Step 3: Fill gaps** — if `DomainThreatsPanel`/`orchestrator`/`virustotal` domain code or the SettingsDialog dips a metric, add a real behavior test (e.g. DomainConsent Proceed/Cancel; a SettingsDialog test toggling the domain checkbox). Re-run step 2.

- [ ] **Step 4: Commit**

```bash
git add ui/src/cockpit/SettingsDialog.tsx
# + any added tests
git commit -m "feat(domain-rep): settings checkbox + hold the coverage gate"
```

---

## Self-Review

**1. Spec coverage:** types + settings (T1) → spec §1-2; orchestration (T2) → §3; wasm wrapper + Tauri (T3) → §4; DomainConsent + DomainThreatsPanel (T4) → §6-7; App run/trigger/consent + Dashboard mount (T5) → §5; settings checkbox + gate (T6) → §3 settings + testing. Separate consent off-by-default, top-15 cap, malicious-only highlight, VT-only, no engine change — all covered. C (AI) out of scope. ✓

**2. Placeholder scan:** every code step has complete code. The NOTEs (copy the exact `humanBytes`/`humanNumber` + `ProviderVerdictList` import paths from `ThreatsPanel.tsx`; match the wasm mock to the real import list; reuse existing test mocks) are concrete in-repo verifications, not placeholders. ✓

**3. Type consistency:** `DomainThreat { host, flows, bytes, reputation? }` (T1) used in T2 (n/a), T4 (panel), T5 (run collects `.host`). `lookupDomainReputation(http, hosts, vtKey, now)` (T2) ⇄ T5 call. `applyDomainReputationWasm(outputJson, verdicts)` (T3) ⇄ T5. `domainEnabled`/`domainConsentGiven`/`giveDomainConsent` (T1) ⇄ T5/T6. `DomainConsent({ domainCount, onProceed, onCancel })` (T4) ⇄ T5. Tauri `domain_reputation_lookup(hosts)` (T3) ⇄ T5. All consistent. ✓
