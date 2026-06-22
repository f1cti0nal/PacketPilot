# AI Analyst Assist Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an AI executive-summary card + an NL chat over the *derived* analysis summary — provider-agnostic (any OpenAI-compatible endpoint), streaming, opt-in/BYO-key — with the summary foldable into the exported HTML report.

**Architecture:** All TypeScript under `ui/src/lib/ai/` + two React components, mirroring the reputation feature's settings/proxy/keychain/cache patterns. One OpenAI-compatible streaming client speaks every backend; the browser streams through the user's relay (or direct to localhost), the desktop through a new `tauri::ipc::Channel` command (ureq 2.x). The only engine change is an optional `ai_summary` param on `render_html` (desktop report export; WASM doesn't render reports).

**Tech Stack:** TypeScript/React 18, Vitest + RTL, IndexedDB; Tauri 2 (`ipc::Channel`, `keyring`, `ureq` 2.x); Rust `render_html`.

## Global Constraints

- **OpenAI-compatible wire format** for v1: `POST {baseUrl}/chat/completions`, body `{ model, messages, stream: true }`, auth header `Authorization: Bearer {key}` (omitted when no key). Streamed response = SSE `data: {json}` lines (`choices[0].delta.content`), terminated by `data: [DONE]`.
- **Off by default, double-gated:** AI runs only when enabled **and** `{baseUrl, model}` configured (plus a key when the endpoint needs one). Explicit first-use consent.
- **Privacy:** only the curated derived summary (Task A2) ever leaves; never raw packets/payloads/flows/pcap/filenames. The user's endpoint decides cloud vs. on-device (localhost = nothing leaves).
- **Keys:** desktop OS keychain under service `packetpilot-ai` (distinct from reputation's `packetpilot-reputation`); browser localStorage (`pp.ai.*`). Keys never logged or bundled.
- **Default preset:** Anthropic, `baseUrl=https://api.anthropic.com/v1`, `model=claude-opus-4-8`, `Authorization: Bearer` — Anthropic's OpenAI-compat endpoint (testing-oriented; OpenRouter is the production-grade Anthropic path). Model IDs: `claude-opus-4-8` / `claude-sonnet-4-6` / `claude-haiku-4-5`; any model string the endpoint accepts is allowed.
- **No new cargo feature, no `ring`/C-deps churn.** `ureq` 2.x (already in the lock via `ppcap-core[online]`) is declared as a direct dep of `ui/src-tauri`. Never upgrade ureq to 3.x (API differs).
- **Report `render_html` is pure/infallible** and escapes ALL capture-derived strings via `esc()`. The `ai_summary` text is LLM output → MUST be `esc()`'d (rendered as escaped `<pre class="ai-summary">`, no raw HTML, no markdown formatter in the report).
- **Coverage gate:** run **`npm run test:coverage`** (not just `vitest run`) and keep it green — lines/functions/statements ≥ 80, branches ≥ 70. Unit-test every new `lib/ai/*` function.

## File Structure

**Browser (`ui/src/`):**
- `lib/ai/settings.ts` *(new)* — `pp.ai.*` localStorage config + presets, mirroring `lib/reputation/settings.ts`.
- `lib/ai/context.ts` *(new)* — `buildContext(output) -> string` (the curated summary projection).
- `lib/ai/prompts.ts` *(new)* — `SUMMARY_SYSTEM`, `CHAT_SYSTEM`.
- `lib/ai/sse.ts` *(new)* — OpenAI SSE → content deltas.
- `lib/ai/transport.ts` *(new)* — `StreamTransport` + `proxyTransport`/`directTransport`/`tauriTransport`.
- `lib/ai/client.ts` *(new)* — `chatCompletion(config, messages, transport, onToken) -> Promise<string>`.
- `lib/ai/cache.ts` *(new)* — `putAiSummary`/`getAiSummary` (IndexedDB `ai_summaries` store via `recent.ts`'s db).
- `lib/recent.ts` *(modify)* — bump `DB_VERSION` 2→3, add the `ai_summaries` store.
- `types.ts` *(modify)* — `AiConfig`, `AiMessage`, `AiSummaryEntry`.
- `cockpit/AiSummaryCard.tsx`, `cockpit/AiChatPanel.tsx`, `cockpit/AiConsent.tsx` *(new)*.
- `cockpit/SettingsDialog.tsx` *(modify)* — AI section.
- `components/Dashboard.tsx`, `App.tsx`, `lib/platform.ts` *(modify)* — mount + wiring + report-export threading.

**Desktop (`ui/src-tauri/`):** `Cargo.toml` (add `ureq` direct dep), `src/lib.rs` (`ai_chat_stream` Channel command + `set_ai_key`/`ai_key_status` + register).

**Engine (`engine/crates/ppcap-core/src/`):** `report/mod.rs` (`render_html` `ai_summary` param + section + CSS).

---

## Phase A — AI TypeScript core (no UI)

### Task A1: `lib/ai/settings.ts` — config + presets

**Files:**
- Create: `ui/src/lib/ai/settings.ts`, `ui/src/lib/ai/settings.test.ts`
- Modify: `ui/src/types.ts` (add `AiConfig`)

**Interfaces:**
- Produces: `AiConfig { enabled, baseUrl, model, apiKey }`; `AI_PRESETS`; `getAiConfig()`, `getAiEnabled/setAiEnabled`, `getAiBaseUrl/setAiBaseUrl`, `getAiModel/setAiModel`, `getAiKey/setAiKey`, `aiConsentGiven/giveAiConsent`.

- [ ] **Step 1: Write the failing test** — `ui/src/lib/ai/settings.test.ts`:

```ts
import { describe, it, expect, beforeEach } from "vitest";
import {
  getAiEnabled, setAiEnabled, getAiBaseUrl, setAiBaseUrl, getAiModel, setAiModel,
  getAiKey, setAiKey, aiConsentGiven, giveAiConsent, getAiConfig, AI_PRESETS,
} from "./settings";

describe("ai settings", () => {
  beforeEach(() => localStorage.clear());
  it("off by default; toggles", () => {
    expect(getAiEnabled()).toBe(false);
    setAiEnabled(true);
    expect(getAiEnabled()).toBe(true);
  });
  it("baseUrl / model / key round-trip", () => {
    setAiBaseUrl("https://api.openai.com/v1"); setAiModel("gpt-4o"); setAiKey("sk-x");
    expect(getAiBaseUrl()).toBe("https://api.openai.com/v1");
    expect(getAiModel()).toBe("gpt-4o");
    expect(getAiKey()).toBe("sk-x");
  });
  it("consent is sticky", () => {
    expect(aiConsentGiven()).toBe(false);
    giveAiConsent();
    expect(aiConsentGiven()).toBe(true);
  });
  it("getAiConfig assembles the stored values", () => {
    setAiEnabled(true); setAiBaseUrl("u"); setAiModel("m"); setAiKey("k");
    expect(getAiConfig()).toEqual({ enabled: true, baseUrl: "u", model: "m", apiKey: "k" });
  });
  it("the default preset is Anthropic + claude-opus-4-8", () => {
    expect(AI_PRESETS[0]).toMatchObject({ baseUrl: "https://api.anthropic.com/v1", model: "claude-opus-4-8" });
  });
});
```

- [ ] **Step 2: Run** — `cd ui && npx vitest run src/lib/ai/settings.test.ts` → FAIL (module missing).

- [ ] **Step 3: Add the type** — in `ui/src/types.ts`:

```ts
export interface AiConfig { enabled: boolean; baseUrl: string; model: string; apiKey: string; }
```

- [ ] **Step 4: Implement** — `ui/src/lib/ai/settings.ts`:

```ts
import type { AiConfig } from "../../types";

/** Provider presets for the settings dropdown; all fields overridable. */
export const AI_PRESETS: { id: string; label: string; baseUrl: string; model: string }[] = [
  { id: "anthropic", label: "Anthropic", baseUrl: "https://api.anthropic.com/v1", model: "claude-opus-4-8" },
  { id: "openai", label: "OpenAI", baseUrl: "https://api.openai.com/v1", model: "gpt-4o" },
  { id: "openrouter", label: "OpenRouter", baseUrl: "https://openrouter.ai/api/v1", model: "anthropic/claude-opus-4-8" },
  { id: "ollama", label: "Ollama (local)", baseUrl: "http://localhost:11434/v1", model: "llama3.1" },
  { id: "custom", label: "Custom", baseUrl: "", model: "" },
];

export function getAiEnabled(): boolean { return localStorage.getItem("pp.ai.enabled") === "1"; }
export function setAiEnabled(b: boolean): void { localStorage.setItem("pp.ai.enabled", b ? "1" : "0"); }
export function getAiBaseUrl(): string { return localStorage.getItem("pp.ai.baseUrl") ?? AI_PRESETS[0].baseUrl; }
export function setAiBaseUrl(s: string): void { localStorage.setItem("pp.ai.baseUrl", s); }
export function getAiModel(): string { return localStorage.getItem("pp.ai.model") ?? AI_PRESETS[0].model; }
export function setAiModel(s: string): void { localStorage.setItem("pp.ai.model", s); }
export function getProxyUrl(): string { return localStorage.getItem("pp.ai.proxyUrl") ?? ""; }
export function setProxyUrl(s: string): void { localStorage.setItem("pp.ai.proxyUrl", s); }
export function aiConsentGiven(): boolean { return localStorage.getItem("pp.ai.consent") === "1"; }
export function giveAiConsent(): void { localStorage.setItem("pp.ai.consent", "1"); }

/** Browser-only key access. On desktop the key lives in the OS keychain (Tauri commands). */
export function getAiKey(): string { return localStorage.getItem("pp.ai.key") ?? ""; }
export function setAiKey(s: string): void { localStorage.setItem("pp.ai.key", s); }

export function getAiConfig(): AiConfig {
  return { enabled: getAiEnabled(), baseUrl: getAiBaseUrl(), model: getAiModel(), apiKey: getAiKey() };
}
```

*(Note: `getAiBaseUrl`/`getAiModel` default to the Anthropic preset, so the test's explicit sets are what's asserted; if a stricter "empty until set" is preferred, drop the `?? AI_PRESETS[0]` fallbacks — keep them: a sensible default endpoint is good UX and the round-trip test still passes.)*

- [ ] **Step 5: Run** — `cd ui && npx vitest run src/lib/ai/settings.test.ts` → PASS.

- [ ] **Step 6: Commit** — `git add ui/src/lib/ai/settings.ts ui/src/lib/ai/settings.test.ts ui/src/types.ts && git commit -m "feat(ai): settings + provider presets"`

### Task A2: `lib/ai/context.ts` — `buildContext`

**Files:**
- Create: `ui/src/lib/ai/context.ts`, `ui/src/lib/ai/context.test.ts`

**Interfaces:**
- Consumes: `AnalysisOutput` (`types.ts`): `summary.{total_packets,total_bytes,duration_ns,unique_hosts,severity_counts,incidents,ip_threats,category_breakdown,top_talkers,protocol_hierarchy,port_histogram}`.
- Produces: `buildContext(output: AnalysisOutput) -> string`.

- [ ] **Step 1: Write the failing test:**

```ts
import { describe, it, expect } from "vitest";
import { buildContext } from "./context";
import { makeOutput } from "../../test/fixtures";

describe("buildContext", () => {
  it("includes capture metadata, severity, and top incidents/threats; never raw flows", () => {
    const out = makeOutput();
    const ctx = buildContext(out);
    expect(ctx).toContain("# PacketPilot analysis summary");
    expect(ctx.toLowerCase()).toContain("severity");
    // incidents from the fixture appear by host
    const firstIncident = out.summary.incidents?.[0];
    if (firstIncident) expect(ctx).toContain(firstIncident.host);
    // no raw-flow leakage markers
    expect(ctx).not.toContain("payload");
    // bounded: stays compact even with many threats
    expect(ctx.length).toBeLessThan(20000);
  });

  it("is resilient to missing optional sections", () => {
    const out = makeOutput();
    out.summary.incidents = undefined;
    out.summary.ip_threats = undefined;
    expect(() => buildContext(out)).not.toThrow();
  });
});
```

- [ ] **Step 2: Run** — `cd ui && npx vitest run src/lib/ai/context.test.ts` → FAIL.

- [ ] **Step 3: Implement** — `ui/src/lib/ai/context.ts`:

```ts
import type { AnalysisOutput, Incident, IpThreat } from "../../types";

const TOP_INCIDENTS = 10, TOP_THREATS = 20, TOP_N = 10;

function fmtBytes(n: number): string {
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)} GB`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)} MB`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)} KB`;
  return `${n} B`;
}

function incidentLine(i: Incident): string {
  const atk = i.attack.length ? ` [${i.attack.join(",")}]` : "";
  const stages = i.stages.length ? ` (stages: ${i.stages.join(" → ")})` : "";
  return `- **${i.host}** — ${i.severity} ${i.score}/100 — ${i.title}${stages}${atk}\n  ${i.narrative}`;
}

function threatLine(t: IpThreat): string {
  const tags = t.tags.length ? ` tags:[${t.tags.join(",")}]` : "";
  const ev = t.evidence.length ? ` — ${t.evidence.slice(0, 3).join("; ")}` : "";
  const rep = t.reputation?.length
    ? ` — reputation: ${t.reputation.map((r) => `${r.source}:${r.status}`).join(", ")}`
    : "";
  return `- ${t.ip} (${t.ip_class}) — ${t.severity} ${t.score}/100${t.ioc ? " IOC" : ""}${tags}${ev}${rep}`;
}

/** Curate the derived analysis summary into a compact, labeled context for the LLM.
 * Only rollups the engine already computed — never raw packets/payloads/flows. */
export function buildContext(output: AnalysisOutput): string {
  const s = output.summary;
  const lines: string[] = ["# PacketPilot analysis summary", ""];

  const durSec = Math.round((s.duration_ns ?? 0) / 1e9);
  lines.push(
    `Capture: ${s.total_packets} packets, ${fmtBytes(s.total_bytes)}, ${s.total_flows} flows, ` +
      `${s.unique_hosts} hosts, ~${durSec}s.`,
    "",
  );

  const sc = s.severity_counts;
  if (sc) {
    lines.push(
      `## Severity\ncritical ${sc.critical}, high ${sc.high}, medium ${sc.medium}, low ${sc.low}, info ${sc.info}`,
      "",
    );
  }

  const incidents = s.incidents ?? [];
  if (incidents.length) {
    lines.push("## Incidents (correlated, kill-chain ordered)");
    for (const i of incidents.slice(0, TOP_INCIDENTS)) lines.push(incidentLine(i));
    if (incidents.length > TOP_INCIDENTS) lines.push(`…and ${incidents.length - TOP_INCIDENTS} more.`);
    lines.push("");
  }

  const threats = s.ip_threats ?? [];
  if (threats.length) {
    lines.push("## Top threat IPs");
    for (const t of threats.slice(0, TOP_THREATS)) lines.push(threatLine(t));
    lines.push("");
  }

  if (s.category_breakdown?.length) {
    lines.push("## Traffic categories");
    for (const c of s.category_breakdown.slice(0, TOP_N)) {
      lines.push(`- ${c.category}: ${c.flows} flows, ${fmtBytes(c.bytes)}`);
    }
    lines.push("");
  }

  if (s.top_talkers?.length) {
    lines.push("## Top talkers (by bytes)");
    for (const t of s.top_talkers.slice(0, TOP_N)) lines.push(`- ${t.ip}: ${fmtBytes(t.bytes)}, ${t.flows} flows`);
    lines.push("");
  }

  return lines.join("\n");
}
```

*(If a field name differs from the fixture/types — e.g. `category_breakdown` entries — adjust to the exact `types.ts` shape; the failing test + `npx tsc --noEmit` will catch mismatches.)*

- [ ] **Step 4: Run** — `cd ui && npx vitest run src/lib/ai/context.test.ts && npx tsc --noEmit` → PASS + clean.

- [ ] **Step 5: Commit** — `git add ui/src/lib/ai/context.ts ui/src/lib/ai/context.test.ts && git commit -m "feat(ai): buildContext (curated summary projection)"`

### Task A3: `lib/ai/prompts.ts`

**Files:**
- Create: `ui/src/lib/ai/prompts.ts`, `ui/src/lib/ai/prompts.test.ts`

**Interfaces:**
- Produces: `SUMMARY_SYSTEM: string`, `CHAT_SYSTEM: string`.

- [ ] **Step 1: Write the failing test:**

```ts
import { describe, it, expect } from "vitest";
import { SUMMARY_SYSTEM, CHAT_SYSTEM } from "./prompts";

describe("ai prompts", () => {
  it("ground the model in the provided summary only", () => {
    for (const p of [SUMMARY_SYSTEM, CHAT_SYSTEM]) {
      expect(p.toLowerCase()).toContain("summary");
      expect(p.toLowerCase()).toMatch(/only|do not invent|not in the/);
    }
    expect(CHAT_SYSTEM.toLowerCase()).toContain("question");
  });
});
```

- [ ] **Step 2: Run** — `cd ui && npx vitest run src/lib/ai/prompts.test.ts` → FAIL.

- [ ] **Step 3: Implement** — `ui/src/lib/ai/prompts.ts`:

```ts
export const SUMMARY_SYSTEM = [
  "You are a senior network-forensics analyst. You are given a STRUCTURED SUMMARY of a packet capture",
  "that PacketPilot already analyzed (severity, correlated incidents with kill-chain narratives, top",
  "threat IPs with evidence, traffic categories). Write a concise executive brief for a SOC analyst:",
  "what happened, the most important incidents and threats and why, the overall risk posture, and clear",
  "recommended next steps. Use short paragraphs and bullets. Base every statement ONLY on the provided",
  "summary — do not invent packet-level details you were not given. If the summary shows nothing notable,",
  "say so plainly.",
].join(" ");

export const CHAT_SYSTEM = [
  "You are a network-forensics assistant answering questions about ONE packet capture. You are given a",
  "STRUCTURED SUMMARY of PacketPilot's analysis (severity, incidents, threat IPs, categories). Answer the",
  "analyst's question using ONLY facts present in the summary. If something the user asks about is not in",
  "the summary, say it isn't in the analysis rather than guessing. Be concise and cite the host/IP/incident",
  "you're referring to.",
].join(" ");
```

- [ ] **Step 4: Run** — `cd ui && npx vitest run src/lib/ai/prompts.test.ts` → PASS.

- [ ] **Step 5: Commit** — `git add ui/src/lib/ai/prompts.ts ui/src/lib/ai/prompts.test.ts && git commit -m "feat(ai): grounded system prompts"`

### Task A4: `lib/ai/sse.ts` — OpenAI SSE → content deltas

**Files:**
- Create: `ui/src/lib/ai/sse.ts`, `ui/src/lib/ai/sse.test.ts`

**Interfaces:**
- Produces: `class SseAccumulator { push(chunk: string): string[]; }` — feed raw response text, get content deltas; handles partial lines + `[DONE]`.

- [ ] **Step 1: Write the failing test:**

```ts
import { describe, it, expect } from "vitest";
import { SseAccumulator } from "./sse";

const ev = (content: string) => `data: ${JSON.stringify({ choices: [{ delta: { content } }] })}\n\n`;

describe("SseAccumulator", () => {
  it("extracts content deltas across well-formed events", () => {
    const a = new SseAccumulator();
    expect(a.push(ev("Hel") + ev("lo"))).toEqual(["Hel", "lo"]);
  });
  it("buffers a partial event split across pushes", () => {
    const a = new SseAccumulator();
    const whole = ev("world");
    const cut = Math.floor(whole.length / 2);
    expect(a.push(whole.slice(0, cut))).toEqual([]);
    expect(a.push(whole.slice(cut))).toEqual(["world"]);
  });
  it("ignores [DONE] and content-less deltas", () => {
    const a = new SseAccumulator();
    const role = `data: ${JSON.stringify({ choices: [{ delta: { role: "assistant" } }] })}\n\n`;
    expect(a.push(role + ev("x") + "data: [DONE]\n\n")).toEqual(["x"]);
  });
});
```

- [ ] **Step 2: Run** — `cd ui && npx vitest run src/lib/ai/sse.test.ts` → FAIL.

- [ ] **Step 3: Implement** — `ui/src/lib/ai/sse.ts`:

```ts
/** Incremental parser for an OpenAI-compatible SSE stream. Feed raw text chunks; get content deltas. */
export class SseAccumulator {
  private buf = "";

  push(chunk: string): string[] {
    this.buf += chunk;
    const out: string[] = [];
    let idx: number;
    // Events are separated by a blank line (\n\n). Keep the trailing partial in `buf`.
    while ((idx = this.buf.indexOf("\n\n")) !== -1) {
      const rawEvent = this.buf.slice(0, idx);
      this.buf = this.buf.slice(idx + 2);
      for (const line of rawEvent.split("\n")) {
        const t = line.trim();
        if (!t.startsWith("data:")) continue;
        const data = t.slice(5).trim();
        if (data === "[DONE]" || data === "") continue;
        try {
          const delta = JSON.parse(data)?.choices?.[0]?.delta?.content;
          if (typeof delta === "string" && delta.length) out.push(delta);
        } catch {
          /* skip malformed event */
        }
      }
    }
    return out;
  }
}
```

- [ ] **Step 4: Run** — `cd ui && npx vitest run src/lib/ai/sse.test.ts` → PASS.

- [ ] **Step 5: Commit** — `git add ui/src/lib/ai/sse.ts ui/src/lib/ai/sse.test.ts && git commit -m "feat(ai): SSE delta accumulator"`

### Task A5: `lib/ai/transport.ts` + `lib/ai/client.ts`

**Files:**
- Create: `ui/src/lib/ai/transport.ts`, `ui/src/lib/ai/client.ts`, `ui/src/lib/ai/client.test.ts`

**Interfaces:**
- Consumes: `SseAccumulator` (A4), `AiConfig` (A1).
- Produces: `type StreamTransport = (req: LlmRequest, onChunk: (raw: string) => void) => Promise<void>`; `interface LlmRequest { url: string; headers: Record<string,string>; body: string }`; `proxyTransport(proxyUrl)`, `directTransport()`; `chatCompletion(config, messages, transport, onToken) -> Promise<string>`.

- [ ] **Step 1: Write the failing test** (uses a fake transport — zero network):

```ts
import { describe, it, expect } from "vitest";
import { chatCompletion } from "./client";
import type { StreamTransport } from "./transport";
import type { AiConfig } from "../../types";

const cfg: AiConfig = { enabled: true, baseUrl: "https://api.x/v1", model: "m", apiKey: "k" };

describe("chatCompletion", () => {
  it("builds an OpenAI-format request and assembles streamed deltas", async () => {
    let seen: any = null;
    const fake: StreamTransport = async (req, onChunk) => {
      seen = req;
      onChunk(`data: ${JSON.stringify({ choices: [{ delta: { content: "Hi" } }] })}\n\n`);
      onChunk(`data: ${JSON.stringify({ choices: [{ delta: { content: "!" } }] })}\n\ndata: [DONE]\n\n`);
    };
    const tokens: string[] = [];
    const text = await chatCompletion(cfg, [{ role: "user", content: "q" }], fake, (t) => tokens.push(t));
    expect(text).toBe("Hi!");
    expect(tokens).toEqual(["Hi", "!"]);
    expect(seen.url).toBe("https://api.x/v1/chat/completions");
    expect(seen.headers.Authorization).toBe("Bearer k");
    const body = JSON.parse(seen.body);
    expect(body).toMatchObject({ model: "m", stream: true });
    expect(body.messages).toEqual([{ role: "user", content: "q" }]);
  });

  it("omits the auth header when no key is set", async () => {
    let seen: any = null;
    const fake: StreamTransport = async (req) => { seen = req; };
    await chatCompletion({ ...cfg, apiKey: "" }, [], fake, () => {});
    expect(seen.headers.Authorization).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run** — `cd ui && npx vitest run src/lib/ai/client.test.ts` → FAIL.

- [ ] **Step 3: Implement `transport.ts`:**

```ts
import { SseAccumulator } from "./sse";

export interface LlmRequest { url: string; headers: Record<string, string>; body: string }
/** Opens the upstream streaming POST and calls `onChunk` with raw response text as it arrives. */
export type StreamTransport = (req: LlmRequest, onChunk: (raw: string) => void) => Promise<void>;

async function readStream(resp: Response, onChunk: (raw: string) => void): Promise<void> {
  if (!resp.body) {
    onChunk(await resp.text());
    return;
  }
  const reader = resp.body.getReader();
  const dec = new TextDecoder();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    onChunk(dec.decode(value, { stream: true }));
  }
}

/** Browser → user's streaming relay. Contract: POST {proxyUrl} with {url,headers,method,body,stream:true};
 * the relay opens the upstream request and pipes the text/event-stream back verbatim. */
export function proxyTransport(proxyUrl: string): StreamTransport {
  return async (req, onChunk) => {
    const resp = await fetch(proxyUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url: req.url, headers: req.headers, method: "POST", body: req.body, stream: true }),
    });
    if (!resp.ok) throw new Error(`relay error ${resp.status}`);
    await readStream(resp, onChunk);
  };
}

/** Browser → local endpoint directly (e.g. Ollama on localhost with CORS enabled). */
export function directTransport(): StreamTransport {
  return async (req, onChunk) => {
    const resp = await fetch(req.url, { method: "POST", headers: req.headers, body: req.body });
    if (!resp.ok) throw new Error(`endpoint error ${resp.status}`);
    await readStream(resp, onChunk);
  };
}

export { SseAccumulator };
```

- [ ] **Step 4: Implement `client.ts`:**

```ts
import type { AiConfig } from "../../types";
import { SseAccumulator, type LlmRequest, type StreamTransport } from "./transport";

export interface AiMessage { role: "system" | "user" | "assistant"; content: string }

/** Run one OpenAI-compatible chat completion (streaming). Returns the full assembled text;
 * `onToken` receives each content delta as it arrives. Transport is injected (browser relay / desktop). */
export async function chatCompletion(
  config: AiConfig,
  messages: AiMessage[],
  transport: StreamTransport,
  onToken: (delta: string) => void,
): Promise<string> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (config.apiKey) headers.Authorization = `Bearer ${config.apiKey}`;
  const req: LlmRequest = {
    url: `${config.baseUrl.replace(/\/$/, "")}/chat/completions`,
    headers,
    body: JSON.stringify({ model: config.model, messages, stream: true }),
  };
  const acc = new SseAccumulator();
  let full = "";
  await transport(req, (raw) => {
    for (const delta of acc.push(raw)) {
      full += delta;
      onToken(delta);
    }
  });
  return full;
}
```

- [ ] **Step 5: Run** — `cd ui && npx vitest run src/lib/ai/client.test.ts && npx tsc --noEmit` → PASS + clean.

- [ ] **Step 6: Commit** — `git add ui/src/lib/ai/transport.ts ui/src/lib/ai/client.ts ui/src/lib/ai/client.test.ts && git commit -m "feat(ai): streaming OpenAI-compatible client + transports"`

### Task A6: `lib/ai/cache.ts` — per-capture summary cache

**Files:**
- Modify: `ui/src/lib/recent.ts` (bump `DB_VERSION` 2→3, add `ai_summaries` store)
- Create: `ui/src/lib/ai/cache.ts`, `ui/src/lib/ai/cache.test.ts`
- Modify: `ui/src/types.ts` (`AiSummaryEntry`)

**Interfaces:**
- Produces: `putAiSummary(captureId, text, model, now) -> Promise<boolean>`; `getAiSummary(captureId) -> Promise<AiSummaryEntry | null>`; `AiSummaryEntry { text: string; model: string; cached_at: number }`.

- [ ] **Step 1: Write the failing test:**

```ts
import { describe, it, expect } from "vitest";
import "fake-indexeddb/auto";
import { putAiSummary, getAiSummary } from "./cache";

describe("ai summary cache", () => {
  it("round-trips by capture id", async () => {
    await putAiSummary("cap-1", "the brief", "claude-opus-4-8", 1000);
    const got = await getAiSummary("cap-1");
    expect(got?.text).toBe("the brief");
    expect(got?.model).toBe("claude-opus-4-8");
    expect(await getAiSummary("absent")).toBeNull();
  });
});
```

- [ ] **Step 2: Run** — `cd ui && npx vitest run src/lib/ai/cache.test.ts` → FAIL.

- [ ] **Step 3: Extend `recent.ts`** — bump `const DB_VERSION = 3;`; in `onupgradeneeded` add (after the existing store creations): `if (!db.objectStoreNames.contains("ai_summaries")) db.createObjectStore("ai_summaries");`. Export the `openDb` helper if not already exported (the AI cache reuses it): if `openDb` is module-private, add `export` to it (it's the single DB opener — sharing it is correct).

- [ ] **Step 4: Add the type** — `ui/src/types.ts`: `export interface AiSummaryEntry { text: string; model: string; cached_at: number; }`

- [ ] **Step 5: Implement `cache.ts`:**

```ts
import type { AiSummaryEntry } from "../../types";
import { openDb } from "../recent";

const STORE = "ai_summaries";

export async function putAiSummary(captureId: string, text: string, model: string, now: number): Promise<boolean> {
  const db = await openDb();
  if (!db) return false;
  return new Promise((resolve) => {
    try {
      const store = db.transaction(STORE, "readwrite").objectStore(STORE);
      const entry: AiSummaryEntry = { text, model, cached_at: now };
      const req = store.put(entry, captureId);
      req.onsuccess = () => resolve(true);
      req.onerror = () => resolve(false);
    } catch { resolve(false); }
  });
}

export async function getAiSummary(captureId: string): Promise<AiSummaryEntry | null> {
  const db = await openDb();
  if (!db) return null;
  return new Promise((resolve) => {
    try {
      const store = db.transaction(STORE, "readonly").objectStore(STORE);
      const req = store.get(captureId);
      req.onsuccess = () => resolve((req.result as AiSummaryEntry | undefined) ?? null);
      req.onerror = () => resolve(null);
    } catch { resolve(null); }
  });
}

/** Stable per-capture cache key. `source_sha256` is empty for browser/WASM-analyzed captures
 * (the wasm pass doesn't hash), so fall back to the source path. */
export function captureKey(output: { source_sha256: string; source_path: string }): string {
  return output.source_sha256 || output.source_path || "capture";
}
```

- [ ] **Step 6: Run** — `cd ui && npx vitest run src/lib/ai/cache.test.ts` (+ `npx vitest run src/components/recent` to confirm the DB bump didn't break flows) → PASS.

- [ ] **Step 7: Commit** — `git add ui/src/lib/recent.ts ui/src/lib/ai/cache.ts ui/src/lib/ai/cache.test.ts ui/src/types.ts && git commit -m "feat(ai): per-capture summary IndexedDB cache"`

---

## Phase B — Executive summary UI

### Task B1: `lib/ai/run.ts` — transport selection + summary/chat orchestrators

**Files:**
- Create: `ui/src/lib/ai/run.ts`, `ui/src/lib/ai/run.test.ts`

**Interfaces:**
- Consumes: `chatCompletion` (A5), `buildContext` (A2), prompts (A3), settings (A1), transports (A5), `tauri-detect`.
- Produces: `pickTransport(config) -> StreamTransport`; `generateSummary(output, config, onToken) -> Promise<string>`; `askChat(output, history, question, config, onToken) -> Promise<string>`.

- [ ] **Step 1: Write the failing test** (browser path; transport injected):

```ts
import { describe, it, expect, vi } from "vitest";
import { generateSummary, askChat } from "./run";
import type { AiConfig } from "../../types";
import { makeOutput } from "../../test/fixtures";

const cfg: AiConfig = { enabled: true, baseUrl: "https://api.x/v1", model: "m", apiKey: "k" };
const fakeTransport = (text: string) => async (_req: any, onChunk: (r: string) => void) => {
  onChunk(`data: ${JSON.stringify({ choices: [{ delta: { content: text } }] })}\n\ndata: [DONE]\n\n`);
};

describe("run orchestrators", () => {
  it("generateSummary sends the summary system prompt + curated context", async () => {
    const out = makeOutput();
    const text = await generateSummary(out, cfg, () => {}, fakeTransport("BRIEF"));
    expect(text).toBe("BRIEF");
  });
  it("askChat includes the question + context", async () => {
    const out = makeOutput();
    const text = await askChat(out, [], "what happened?", cfg, () => {}, fakeTransport("ANSWER"));
    expect(text).toBe("ANSWER");
  });
});
```

- [ ] **Step 2: Run** — `cd ui && npx vitest run src/lib/ai/run.test.ts` → FAIL.

- [ ] **Step 3: Implement** — `ui/src/lib/ai/run.ts`:

```ts
import type { AnalysisOutput, AiConfig } from "../../types";
import { isTauri } from "../tauri-detect";
import { buildContext } from "./context";
import { SUMMARY_SYSTEM, CHAT_SYSTEM } from "./prompts";
import { chatCompletion, type AiMessage } from "./client";
import { proxyTransport, directTransport, type StreamTransport, type LlmRequest } from "./transport";
import { getProxyUrl } from "./settings";
import { SseAccumulator } from "./sse";

/** Desktop transport: stream the upstream POST through the Tauri `ai_chat_stream` command via a Channel. */
export function tauriTransport(): StreamTransport {
  return async (req: LlmRequest, onChunk) => {
    const { invoke, Channel } = await import("@tauri-apps/api/core");
    const channel = new Channel<string>();
    channel.onmessage = (chunk) => onChunk(chunk);
    await invoke("ai_chat_stream", { url: req.url, body: req.body, onChunk: channel });
  };
}

/** Pick the transport for the current surface + config. Desktop → Tauri; browser → relay, or direct to localhost. */
export function pickTransport(config: AiConfig): StreamTransport {
  if (isTauri()) return tauriTransport();
  const proxy = getProxyUrl();
  if (proxy) return proxyTransport(proxy);
  const isLocal = /^https?:\/\/(localhost|127\.0\.0\.1)/i.test(config.baseUrl);
  if (isLocal) return directTransport();
  throw new Error("Browser AI needs a relay URL (Settings) for non-local endpoints.");
}

export async function generateSummary(
  output: AnalysisOutput, config: AiConfig, onToken: (t: string) => void, transport: StreamTransport = pickTransport(config),
): Promise<string> {
  const messages: AiMessage[] = [
    { role: "system", content: SUMMARY_SYSTEM },
    { role: "user", content: buildContext(output) },
  ];
  return chatCompletion(config, messages, transport, onToken);
}

export async function askChat(
  output: AnalysisOutput, history: AiMessage[], question: string, config: AiConfig,
  onToken: (t: string) => void, transport: StreamTransport = pickTransport(config),
): Promise<string> {
  const messages: AiMessage[] = [
    { role: "system", content: `${CHAT_SYSTEM}\n\n${buildContext(output)}` },
    ...history.slice(-8),
    { role: "user", content: question },
  ];
  return chatCompletion(config, messages, transport, onToken);
}

export { SseAccumulator };
```

- [ ] **Step 4: Run** — `cd ui && npx vitest run src/lib/ai/run.test.ts && npx tsc --noEmit` → PASS + clean.

- [ ] **Step 5: Commit** — `git add ui/src/lib/ai/run.ts ui/src/lib/ai/run.test.ts && git commit -m "feat(ai): transport selection + summary/chat orchestrators"`

### Task B2: `AiSummaryCard` component

**Files:**
- Create: `ui/src/cockpit/AiSummaryCard.tsx`, `ui/src/cockpit/AiSummaryCard.test.tsx`

**Interfaces:**
- Consumes: `generateSummary` (B1), `getAiConfig`/`getAiEnabled`/`aiConsentGiven` (A1), `getAiSummary`/`putAiSummary` (A6).
- Produces: `AiSummaryCard({ output, captureId })`.

- [ ] **Step 1: Write the failing test** (mock `run` + `cache` + `settings`):

```tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AiSummaryCard } from "./AiSummaryCard";
import { makeOutput } from "../test/fixtures";

vi.mock("../lib/ai/settings", () => ({
  getAiEnabled: () => true, aiConsentGiven: () => true,
  getAiConfig: () => ({ enabled: true, baseUrl: "u", model: "m", apiKey: "k" }),
}));
vi.mock("../lib/ai/cache", () => ({ getAiSummary: vi.fn(async () => null), putAiSummary: vi.fn(async () => true) }));
vi.mock("../lib/ai/run", () => ({
  generateSummary: vi.fn(async (_o, _c, onToken) => { onToken("Generated brief."); return "Generated brief."; }),
}));

describe("AiSummaryCard", () => {
  beforeEach(() => vi.clearAllMocks());
  it("generates and renders the brief on click", async () => {
    const u = userEvent.setup();
    render(<AiSummaryCard output={makeOutput()} captureId="cap-1" />);
    await u.click(screen.getByRole("button", { name: /generate/i }));
    expect(await screen.findByText(/Generated brief\./)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run** — `cd ui && npx vitest run src/cockpit/AiSummaryCard.test.tsx` → FAIL.

- [ ] **Step 3: Implement** — `ui/src/cockpit/AiSummaryCard.tsx`:

```tsx
import { useEffect, useState } from "react";
import type { AnalysisOutput } from "../types";
import { getAiEnabled, aiConsentGiven, getAiConfig } from "../lib/ai/settings";
import { getAiSummary, putAiSummary } from "../lib/ai/cache";
import { generateSummary } from "../lib/ai/run";

type State = { status: "idle" | "loading" | "ready" | "error"; text: string; error?: string };

export function AiSummaryCard({ output, captureId }: { output: AnalysisOutput; captureId: string }) {
  const [st, setSt] = useState<State>({ status: "idle", text: "" });

  useEffect(() => {
    let on = true;
    getAiSummary(captureId).then((c) => { if (on && c) setSt({ status: "ready", text: c.text }); });
    return () => { on = false; };
  }, [captureId]);

  async function run() {
    if (!getAiEnabled()) { setSt({ status: "error", text: "", error: "AI is off — enable it in Settings." }); return; }
    if (!aiConsentGiven()) { setSt({ status: "error", text: "", error: "Consent required — open Settings." }); return; }
    setSt({ status: "loading", text: "" });
    try {
      const cfg = getAiConfig();
      let acc = "";
      const full = await generateSummary(output, cfg, (t) => { acc += t; setSt({ status: "loading", text: acc }); });
      setSt({ status: "ready", text: full });
      await putAiSummary(captureId, full, cfg.model, Math.floor(Date.now() / 1000));
    } catch (e) {
      setSt({ status: "error", text: "", error: `AI request failed: ${e instanceof Error ? e.message : String(e)}` });
    }
  }

  return (
    <section className="rounded-lg bg-[var(--color-surface)] p-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold">AI Analyst Summary</h2>
        <button className="t-tag font-semibold" onClick={run} disabled={st.status === "loading"}>
          {st.status === "ready" ? "Regenerate" : st.status === "loading" ? "Generating…" : "Generate"}
        </button>
      </div>
      {st.error && <p className="mt-2 text-xs text-[var(--color-critical,#ef4444)]">{st.error}</p>}
      {st.text && <pre className="mt-2 whitespace-pre-wrap break-words text-xs text-[var(--color-text)]">{st.text}</pre>}
    </section>
  );
}
```

- [ ] **Step 4: Run** — `cd ui && npx vitest run src/cockpit/AiSummaryCard.test.tsx` → PASS.

- [ ] **Step 5: Commit** — `git add ui/src/cockpit/AiSummaryCard.tsx ui/src/cockpit/AiSummaryCard.test.tsx && git commit -m "feat(ai): AiSummaryCard (streamed brief, cached)"`

### Task B3: mount `AiSummaryCard` in the dashboard

**Files:**
- Modify: `ui/src/components/Dashboard.tsx` (mount after `KpiCluster`)

**Interfaces:**
- Consumes: `AiSummaryCard` (B2); `Dashboard` already receives `output` + an `activeId`/capture identity.

- [ ] **Step 1:** In `Dashboard.tsx`, import `AiSummaryCard` and `captureKey` (from `lib/ai/cache`). Add after the `<KpiCluster output={output} />` line:

```tsx
        <AiSummaryCard output={output} captureId={captureKey(output)} />
```

- [ ] **Step 2: Verify** — `cd ui && npx tsc --noEmit && npx vitest run src/components/Dashboard.test.tsx` → clean + existing Dashboard tests still pass (the card renders an idle "Generate" button; if a Dashboard test snapshots the whole tree, update it to expect the new card, or assert the card is present).

- [ ] **Step 3: Commit** — `git add ui/src/components/Dashboard.tsx && git commit -m "feat(ai): mount AiSummaryCard in dashboard"`

---

## Phase C — NL chat UI

### Task C1: `AiChatPanel` component

**Files:**
- Create: `ui/src/cockpit/AiChatPanel.tsx`, `ui/src/cockpit/AiChatPanel.test.tsx`

**Interfaces:**
- Consumes: `askChat` (B1), `getAiConfig` (A1), `AiMessage` (A5).
- Produces: `AiChatPanel({ open, onClose, output })`.

- [ ] **Step 1: Write the failing test** (mock `run` + `settings`):

```tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AiChatPanel } from "./AiChatPanel";
import { makeOutput } from "../test/fixtures";

vi.mock("../lib/ai/settings", () => ({
  getAiConfig: () => ({ enabled: true, baseUrl: "u", model: "m", apiKey: "k" }),
}));
vi.mock("../lib/ai/run", () => ({
  askChat: vi.fn(async (_o, _h, q, _c, onToken) => { onToken(`re: ${q}`); return `re: ${q}`; }),
}));

describe("AiChatPanel", () => {
  beforeEach(() => vi.clearAllMocks());
  it("sends a question and renders the streamed answer", async () => {
    const u = userEvent.setup();
    render(<AiChatPanel open onClose={vi.fn()} output={makeOutput()} />);
    await u.type(screen.getByRole("textbox"), "what happened?");
    await u.click(screen.getByRole("button", { name: /send/i }));
    expect(await screen.findByText(/re: what happened\?/)).toBeInTheDocument();
  });
  it("renders nothing when closed", () => {
    const { container } = render(<AiChatPanel open={false} onClose={vi.fn()} output={makeOutput()} />);
    expect(container).toBeEmptyDOMElement();
  });
});
```

- [ ] **Step 2: Run** — `cd ui && npx vitest run src/cockpit/AiChatPanel.test.tsx` → FAIL.

- [ ] **Step 3: Implement** — `ui/src/cockpit/AiChatPanel.tsx`:

```tsx
import { useState } from "react";
import type { AnalysisOutput } from "../types";
import type { AiMessage } from "../lib/ai/client";
import { getAiConfig } from "../lib/ai/settings";
import { askChat } from "../lib/ai/run";

export function AiChatPanel({ open, onClose, output }: { open: boolean; onClose: () => void; output: AnalysisOutput }) {
  const [msgs, setMsgs] = useState<AiMessage[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [streaming, setStreaming] = useState("");

  if (!open) return null;

  async function send() {
    const q = input.trim();
    if (!q || busy) return;
    setInput("");
    const history = [...msgs, { role: "user" as const, content: q }];
    setMsgs(history);
    setBusy(true);
    setStreaming("");
    try {
      let acc = "";
      const full = await askChat(output, msgs, q, getAiConfig(), (t) => { acc += t; setStreaming(acc); });
      setMsgs([...history, { role: "assistant", content: full }]);
    } catch (e) {
      setMsgs([...history, { role: "assistant", content: `AI request failed: ${e instanceof Error ? e.message : String(e)}` }]);
    } finally {
      setBusy(false);
      setStreaming("");
    }
  }

  return (
    <div role="dialog" aria-label="AI chat" className="fixed inset-y-0 right-0 z-50 flex w-[28rem] flex-col bg-[var(--color-surface)] shadow-xl">
      <div className="flex items-center justify-between border-b border-[var(--color-border,#222)] p-3">
        <h2 className="text-sm font-semibold">Ask about this capture</h2>
        <button className="t-tag" onClick={onClose}>Close</button>
      </div>
      <div className="flex-1 space-y-2 overflow-auto p-3 text-xs">
        {msgs.map((m, i) => (
          <div key={i} className={m.role === "user" ? "text-[var(--color-text)]" : "text-[var(--color-text-faint)]"}>
            <span className="t-tag uppercase">{m.role}</span>
            <pre className="whitespace-pre-wrap break-words">{m.content}</pre>
          </div>
        ))}
        {streaming && <pre className="whitespace-pre-wrap break-words text-[var(--color-text-faint)]">{streaming}</pre>}
      </div>
      <div className="flex gap-2 border-t border-[var(--color-border,#222)] p-3">
        <input className="flex-1 rounded bg-[var(--color-bg)] p-1 text-xs" value={input}
          onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") void send(); }}
          placeholder="e.g. which host exfiltrated data?" />
        <button className="t-tag font-semibold" onClick={() => void send()} disabled={busy}>Send</button>
      </div>
    </div>
  );
}
```

- [ ] **Step 4: Run** — `cd ui && npx vitest run src/cockpit/AiChatPanel.test.tsx` → PASS.

- [ ] **Step 5: Commit** — `git add ui/src/cockpit/AiChatPanel.tsx ui/src/cockpit/AiChatPanel.test.tsx && git commit -m "feat(ai): AiChatPanel (streamed NL chat)"`

### Task C2: wire chat open/close into App + a launcher

**Files:**
- Modify: `ui/src/App.tsx` (state + render `AiChatPanel`), `ui/src/cockpit/CommandBar.tsx` (an "Ask AI" button)

- [ ] **Step 1:** In `App.tsx`: add `const [aiChatOpen, setAiChatOpen] = useState(false);`. Where `summary.status === "ready"`, render the panel with the current output: `<AiChatPanel open={aiChatOpen} onClose={() => setAiChatOpen(false)} output={summary.data} />` (guard on `summary.status === "ready"`). Pass an `onOpenAiChat={() => setAiChatOpen(true)}` handler down to the chrome (CommandBar) the same way `onOpenSettings` is passed (F2 of the reputation feature established that prop-drill).

- [ ] **Step 2:** In `CommandBar.tsx`: add an "Ask AI" button (lucide `Sparkles` or `MessageSquare` icon) that calls `onOpenAiChat`, rendered only when the handler is provided (mirror the settings-gear pattern).

- [ ] **Step 3: Verify** — `cd ui && npx tsc --noEmit && npx vitest run src/App.test.tsx src/cockpit/CommandBar.test.tsx` → clean + green (the chat is closed by default → no behavior change to existing tests).

- [ ] **Step 4: Commit** — `git add ui/src/App.tsx ui/src/cockpit/CommandBar.tsx && git commit -m "feat(ai): launch AiChatPanel from the command bar"`

---

## Phase D — Settings + consent

### Task D1: AI settings section + consent modal

**Files:**
- Modify: `ui/src/cockpit/SettingsDialog.tsx` (AI section)
- Create: `ui/src/cockpit/AiConsent.tsx`, `ui/src/cockpit/AiConsent.test.tsx`

**Interfaces:**
- Consumes: AI `settings` (A1), `isTauri`, Tauri `set_ai_key` (E1, dynamic import — desktop only).

- [ ] **Step 1: Write the failing test** — `AiConsent.test.tsx`:

```tsx
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AiConsent } from "./AiConsent";

describe("AiConsent", () => {
  it("shows the endpoint and confirms on Proceed", async () => {
    const u = userEvent.setup(); const onProceed = vi.fn();
    render(<AiConsent baseUrl="https://api.anthropic.com/v1" model="claude-opus-4-8" onProceed={onProceed} onCancel={vi.fn()} />);
    expect(screen.getByText(/anthropic\.com/)).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: /proceed/i }));
    expect(onProceed).toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run** — `cd ui && npx vitest run src/cockpit/AiConsent.test.tsx` → FAIL.

- [ ] **Step 3: Implement `AiConsent.tsx`:**

```tsx
export function AiConsent({ baseUrl, model, onProceed, onCancel }:
  { baseUrl: string; model: string; onProceed: () => void; onCancel: () => void }) {
  const local = /^https?:\/\/(localhost|127\.0\.0\.1)/i.test(baseUrl);
  return (
    <div role="dialog" aria-label="AI consent" className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="max-w-md rounded-lg bg-[var(--color-surface)] p-5 text-[var(--color-text)]">
        <h2 className="text-sm font-semibold">Send the analysis summary to the model?</h2>
        <p className="mt-2 text-xs text-[var(--color-text-faint)]">
          Your analysis <b>summary</b> — severity counts, top incidents and threat IPs with their evidence
          (never raw packets, payloads, or the capture file) — will be sent to <b>{baseUrl}</b> using
          model <b>{model}</b>. {local ? "This endpoint is local — it stays on this device." : ""}
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

- [ ] **Step 4:** In `SettingsDialog.tsx`, add an **AI section** below the reputation one: an enable checkbox, a **preset dropdown** (from `AI_PRESETS`, prefilling baseUrl+model on change), `baseUrl` + `model` text inputs, an API-key input (`type="password"`), and a proxy-URL input (browser only — for non-local endpoints). On save: browser → `setAiEnabled/setAiBaseUrl/setAiModel/setAiKey/setProxyUrl`; desktop → store the key via `invoke("set_ai_key", { provider: "default", key })` (dynamic import, mirroring the reputation save), the rest to localStorage. Reuse the existing dialog's label/input/error markup.

- [ ] **Step 5: Verify** — `cd ui && npx vitest run src/cockpit/AiConsent.test.tsx && npx tsc --noEmit && npx vitest run src/lib/ai/settings.test.ts` → PASS + clean.

- [ ] **Step 6: Commit** — `git add ui/src/cockpit/SettingsDialog.tsx ui/src/cockpit/AiConsent.tsx ui/src/cockpit/AiConsent.test.tsx && git commit -m "feat(ai): settings section + consent modal"`

- [ ] **Step 7: Wire consent into the summary/chat trigger** — in `AiSummaryCard` (and the chat launcher), before the first call, if `!aiConsentGiven()` open `<AiConsent .../>` (store the pending action; Proceed → `giveAiConsent()` + run). Mirror the reputation consent gate in `App.tsx` (F3). Add a focused test that an un-consented generate opens the consent dialog. Commit.

---

## Phase E — Desktop (Tauri) streaming + keychain

*No new TS — wires the `tauriTransport` (B1) to a native streaming command. Build-verified (Tauri commands need the runtime; the streaming logic pipes raw bytes that the TS-side `SseAccumulator` — tested in A4 — parses).*

### Task E1: AI keychain commands

**Files:**
- Modify: `ui/src-tauri/src/lib.rs` (commands + register)

**Interfaces:**
- Produces Tauri commands: `set_ai_key(provider: String, key: String) -> Result<(), String>`, `ai_key_status() -> Result<Vec<String>, String>`; helper `ai_key_for(name) -> Result<Option<String>, String>`.

- [ ] **Step 1: Implement** — add to `ui/src-tauri/src/lib.rs` (mirroring the reputation keychain block, distinct service):

```rust
const KEYRING_SERVICE_AI: &str = "packetpilot-ai";

fn ai_key_for(name: &str) -> Result<Option<String>, String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE_AI, name).map_err(|e| e.to_string())?;
    match entry.get_password() {
        Ok(k) if !k.is_empty() => Ok(Some(k)),
        _ => Ok(None),
    }
}

#[tauri::command]
fn set_ai_key(provider: String, key: String) -> Result<(), String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE_AI, &provider).map_err(|e| e.to_string())?;
    entry.set_password(&key).map_err(|e| e.to_string())
}

#[tauri::command]
fn ai_key_status() -> Result<Vec<String>, String> {
    Ok(if ai_key_for("default")?.is_some() { vec!["default".to_string()] } else { vec![] })
}
```

- [ ] **Step 2: Register** — add `set_ai_key, ai_key_status` to the `tauri::generate_handler![ … ]` list.

- [ ] **Step 3: Build** — `cd ui/src-tauri && cargo build` → clean. (Toolchain: cargo at `/c/Users/ravid/.cargo/bin`; MinGW on PATH for `ring` — see the reputation D2 notes.)

- [ ] **Step 4: Commit** — `git add ui/src-tauri/src/lib.rs && git commit -m "feat(tauri): AI keychain commands"`

### Task E2: `ai_chat_stream` streaming command

**Files:**
- Modify: `ui/src-tauri/Cargo.toml` (declare `ureq` direct dep), `ui/src-tauri/src/lib.rs` (the command + register)

**Interfaces:**
- Consumes: `ai_key_for` (E1); `tauri::ipc::Channel<String>`; `ureq` 2.x.
- Produces: `ai_chat_stream(url, body, on_chunk: Channel<String>) -> Result<(), String>` (invoked by `tauriTransport`, B1).

- [ ] **Step 1: Declare ureq** — `ui/src-tauri/Cargo.toml` `[dependencies]`: `ureq = { workspace = true }` (already resolved in the lock via `ppcap-core[online]`; this makes it a direct dep usable in `lib.rs`).

- [ ] **Step 2: Implement** — add to `ui/src-tauri/src/lib.rs`:

```rust
/// Stream an OpenAI-compatible chat completion to the frontend. `body` is the full request JSON
/// (model + messages + stream:true) built in TS; the API key is read from the OS keychain here so it
/// never crosses into the renderer. Raw response bytes are forwarded via the Channel; the TS side
/// parses the SSE. Runs the blocking ureq read on a worker so the Tauri event loop is never blocked.
#[tauri::command]
async fn ai_chat_stream(
    url: String,
    body: String,
    on_chunk: tauri::ipc::Channel<String>,
) -> Result<(), String> {
    let key = ai_key_for("default")?;
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(180))
            .build();
        let mut req = agent.post(&url).set("content-type", "application/json");
        if let Some(k) = &key {
            req = req.set("Authorization", &format!("Bearer {k}"));
        }
        let resp = match req.send_string(&body) {
            Ok(r) => r,
            // 4xx/5xx: surface the upstream error body as the failure reason.
            Err(ureq::Error::Status(code, r)) => {
                return Err(format!("AI endpoint {code}: {}", r.into_string().unwrap_or_default()));
            }
            Err(e) => return Err(e.to_string()),
        };
        use std::io::Read;
        let mut reader = std::io::BufReader::new(resp.into_reader());
        let mut buf = [0u8; 4096];
        loop {
            let n = reader.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            on_chunk
                .send(String::from_utf8_lossy(&buf[..n]).to_string())
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}
```

- [ ] **Step 3: Register** — add `ai_chat_stream` to `tauri::generate_handler![ … ]`.

- [ ] **Step 4: Build** — `cd ui/src-tauri && cargo build` → clean (confirms `tauri::ipc::Channel` + ureq usage compile against the pinned Tauri 2 / ureq 2.x).

- [ ] **Step 5: Manual smoke (desktop, optional)** — run the desktop app, configure an endpoint+key, Generate the summary → tokens stream into the card. (No automated test — Tauri commands need the runtime; the SSE parsing the chunks feed is unit-tested in A4.)

- [ ] **Step 6: Commit** — `git add ui/src-tauri/Cargo.toml ui/src-tauri/src/lib.rs && git commit -m "feat(tauri): ai_chat_stream Channel streaming command"`

---

## Phase F — Report integration (desktop only)

### Task F1: `render_html` gains an optional AI-summary section

**Files:**
- Modify: `engine/crates/ppcap-core/src/report/mod.rs` (signature + section + CSS)
- Modify: all callers — `ui/src-tauri/src/lib.rs` (`save_report`), `engine/crates/ppcap-cli/src/cli.rs` (`--html`), and any `render_html` test — to pass `None` (F2 makes `save_report` pass `Some`).

**Interfaces:**
- Produces: `render_html(out: &AnalysisOutput, generated_unix_secs: i64, ai_summary: Option<&str>) -> String`.

- [ ] **Step 1: Write the failing test** — in `report/mod.rs` `#[cfg(test)] mod tests`:

```rust
#[test]
fn ai_summary_section_is_present_and_escaped() {
    let out = crate::model::output::AnalysisOutput::default(); // or the existing test fixture builder
    let html = render_html(&out, 0, Some("Risk is HIGH <script>x</script>"));
    assert!(html.contains("AI Analyst Summary"));
    assert!(html.contains("Risk is HIGH &lt;script&gt;")); // escaped, not raw
    assert!(!html.contains("<script>x</script>"));
}

#[test]
fn ai_summary_absent_when_none() {
    let out = crate::model::output::AnalysisOutput::default();
    let html = render_html(&out, 0, None);
    assert!(!html.contains("AI Analyst Summary"));
}
```

*(Use whatever `AnalysisOutput` constructor the existing report tests use — match the file's convention.)*

- [ ] **Step 2: Run** — `cd engine && cargo test -p ppcap-core report::` → FAIL (arity mismatch / new assertions).

- [ ] **Step 3: Implement** — change the signature to add `ai_summary: Option<&str>` after `generated_unix_secs`. Just before the closing `</main>` (the recon points at ~line 269, after the incidents section), insert:

```rust
    if let Some(ai) = ai_summary {
        write!(
            s,
            "<section class=\"card\"><h2>AI Analyst Summary</h2><pre class=\"ai-summary\">{}</pre></section>\n",
            esc(ai)
        )
        .ok();
    }
```

Add to the inline `STYLE` CSS (the recon points at ~line 742): `.ai-summary{{white-space:pre-wrap;word-break:break-word;font-family:inherit;}}` (note the doubled braces if it's inside a `write!`/`format!` style block, else single).

- [ ] **Step 4: Fix all callers to pass `None`** — `cargo build --workspace` will fail at each `render_html(` call:
  - `ui/src-tauri/src/lib.rs` `save_report`: `ppcap_core::render_html(&summary, now_unix_secs, None)` (F2 changes this to `ai_summary.as_deref()`).
  - `engine/crates/ppcap-cli/src/cli.rs` (the `--html` path): add `, None`.
  - Any existing `render_html` test: add `, None`.

- [ ] **Step 5: Run** — `cd engine && cargo test -p ppcap-core report:: && cargo build --workspace` → PASS + builds. Run `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings` (the CI gates).

- [ ] **Step 6: Commit** — `git add -A && git commit -m "feat(report): optional AI-summary section in render_html"`

### Task F2: thread the AI summary into report export

**Files:**
- Modify: `ui/src-tauri/src/lib.rs` (`save_report` param), `ui/src/lib/platform.ts` (`exportReport`), the export trigger (`AppShell.tsx`/`CommandBar.tsx`)

- [ ] **Step 1: Tauri `save_report`** — add `ai_summary: Option<String>` and pass it:

```rust
#[tauri::command]
fn save_report(summary: AnalysisOutput, path: String, ai_summary: Option<String>) -> Result<(), String> {
    let now_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let html = ppcap_core::render_html(&summary, now_unix_secs, ai_summary.as_deref());
    std::fs::write(&path, html).map_err(|e| format!("write report: {e}"))
}
```

- [ ] **Step 2: `exportReport`** — `ui/src/lib/platform.ts`: change the signature to `exportReport(summary: AnalysisOutput, aiSummary?: string)`; desktop → `await invoke("save_report", { summary, path, aiSummary: aiSummary ?? null })`; browser JSON branch unchanged (the report is desktop-only HTML; the AI summary is already in IndexedDB, so the browser JSON download stays as-is).

- [ ] **Step 3: Export trigger** — where the export button calls `exportReport(summary)` (AppShell/CommandBar), first read the cached summary and pass it: `const ai = await getAiSummary(captureKey(output)); exportReport(output, ai?.text);`. (Import `getAiSummary` + `captureKey` from `lib/ai/cache`.)

- [ ] **Step 4: Verify** — `cd ui && npx tsc --noEmit` + `cd ui/src-tauri && cargo build` → clean. `cd ui && npx vitest run` → existing platform/export tests still pass (the new param is optional/null by default → no behavior change without a generated summary).

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(ai): fold AI summary into the exported report"`

---

## Phase G — Coverage + docs

### Task G1: restore/verify the coverage gate

**Files:**
- Add focused tests wherever `npm run test:coverage` shows new `lib/ai/*` or component functions below the bar.

- [ ] **Step 1: Run the ACTUAL gate** — `cd ui && export PATH="/c/Program Files/nodejs:$PATH" && npm run test:coverage` → read the `All files` line + any threshold error. (This is the step that was skipped on the reputation feature — do NOT substitute `vitest run`.)

- [ ] **Step 2: Fill gaps** — for any new function below the bar, add a real behavior test. Likely targets (write these proactively): `transport.ts` `proxyTransport`/`directTransport` (mock `global.fetch` returning a `ReadableStream` of SSE bytes → assert `onChunk` receives them; non-ok → throws); `run.ts` `pickTransport` (browser: proxy-set → proxyTransport; localhost → directTransport; non-local no-proxy → throws); `AiSummaryCard` cached + error + needs-config states; `AiChatPanel` closed state. Example for transport:

```ts
import { describe, it, expect, vi } from "vitest";
import { proxyTransport, directTransport } from "./transport";

function streamResponse(text: string): Response {
  const body = new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode(text)); c.close(); } });
  return new Response(body, { status: 200 });
}

describe("transports", () => {
  it("proxyTransport pipes upstream bytes to onChunk", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => streamResponse("data: x\n\n")));
    const seen: string[] = [];
    await proxyTransport("https://relay")({ url: "u", headers: {}, body: "{}" }, (c) => seen.push(c));
    expect(seen.join("")).toContain("data: x");
  });
  it("directTransport throws on non-ok", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 500 })));
    await expect(directTransport()({ url: "u", headers: {}, body: "{}" }, () => {})).rejects.toThrow();
  });
});
```

- [ ] **Step 3: Re-run** — `cd ui && npm run test:coverage` → **exit 0**, `All files` functions/lines/statements ≥ 80, branches ≥ 70.

- [ ] **Step 4: Commit** — `git add -A && git commit -m "test(ai): cover transports/run/components (coverage gate)"`

### Task G2: docs

**Files:**
- Modify: `README.md` (roadmap), `docs/reputation.md`-adjacent
- Create: `docs/ai-assist.md`

- [ ] **Step 1: Operator guide** — `docs/ai-assist.md`: what it does (executive summary + NL chat over the *derived* summary); opt-in/consent + the privacy line (only the summary leaves; localhost = nothing leaves); **provider presets** (Anthropic/OpenAI/OpenRouter/Ollama/Custom) + how to configure baseUrl/model/key; the Anthropic-compat caveat (testing-oriented; OpenRouter for production); the **browser streaming-relay contract** (`POST {proxyUrl} {url,headers,method,body,stream:true}` → pipe the upstream `text/event-stream` back verbatim) with a tiny Node reference relay; desktop keychain; "only the summary is sent — never packets/payloads."

- [ ] **Step 2: README** — move/add the AI-assist item from the roadmap into the shipped/“what it does” list (executive summary + NL chat, BYO-endpoint, privacy-preserving).

- [ ] **Step 3: Commit** — `git add README.md docs/ai-assist.md && git commit -m "docs(ai): operator guide + roadmap"`

---

## Self-Review

- **Spec coverage:** §2 both sub-features → B/C; §4 module layout → A/B/C; §5 OpenAI format + presets + `format` seam → A1/A5 (v1 = openai only, per spec); §6 privacy/consent/keys → A1/D1/E1; §7 context → A2; §8 client+streaming+transports → A4/A5/B1/E2; §9 summary UX + report integration → B2/B3/F1/F2; §10 chat → C1/C2; §11 error handling → component error states + transport throws; §12 testing + coverage discipline → every task + G1; §13 deferreds noted (native Anthropic adapter, CLI, reference relay → G2). The one **refinement vs spec**: the report renders the AI summary as **escaped `<pre>` plain text** (recon: `render_html` has no markdown facility and `esc()` is the security choke point) rather than a "minimal markdown subset in the report" — rich markdown rendering stays in the UI panels. Flag to the user.
- **Placeholders:** none — every code step carries real code; mismatches in exact `types.ts`/report field names are caught by `tsc`/`cargo` + the failing tests (called out where they could occur).
- **Type consistency:** `AiConfig` (A1) used in A5/B1/B2/C/D; `StreamTransport`/`LlmRequest` (A5) in B1/G1; `AiMessage` (A5) in B1/C1; `chatCompletion(config, messages, transport, onToken)` consistent A5→B1; `render_html(out, generated_unix_secs, ai_summary)` consistent F1→F2 callers; keychain service `packetpilot-ai` consistent E1/E2; `getAiSummary(captureId)` consistent A6/B2/F2; cache key via `captureKey(output)` (sha → path fallback) consistent A6/B3/F2.
