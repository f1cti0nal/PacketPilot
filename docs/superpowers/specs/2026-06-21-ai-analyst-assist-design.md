# AI analyst assist — design

- **Date:** 2026-06-21
- **Status:** Approved (design); pending implementation plan
- **Branch:** `feat/ai-analyst-assist` (to be created off `main`)

## 1. Context & motivation

PacketPilot lands the analyst on a triage dashboard with explainable severity, per-IP threat cards,
behavioral findings, and per-host **incidents** that already carry a deterministic plain-English
`narrative` + kill-chain `stages` ([`model/incident.rs`](../../engine/crates/ppcap-core/src/model/incident.rs)).
This adds **Phase 5 — AI analyst assist**: a capture-level **executive summary** that synthesizes the whole
analysis into an analyst-readable brief, and an **NL chat** that answers free-form questions grounded in
the computed summary. The headline differentiator none of the comparison tools (Wireshark/Arkime/Brim/NDR)
offer — and exactly what this environment is built for.

The local-first thesis is preserved by construction: the LLM sees only the **derived summary** (never raw
packets/payloads), it is **opt-in**, **bring-your-own-key**, and — because the backend is a **user-configured
endpoint** — the user decides cloud vs. fully-local (point it at Ollama and nothing leaves the device).

## 2. Scope

**In scope**
- Both capabilities: a one-shot **executive summary** and an interactive **NL chat**, grounded in the
  curated analysis summary.
- A **provider-agnostic** LLM client speaking the **OpenAI-compatible Chat Completions** wire format
  (`POST {baseUrl}/chat/completions`), so any backend works: Anthropic (compat endpoint), OpenAI,
  OpenRouter, Ollama, LM Studio, vLLM, … The user configures `{ baseUrl, model, apiKey }`.
- **Streaming** (token-by-token) responses: desktop via a Tauri `Channel`; browser via a streaming relay.
- **Report integration**: the generated summary folds into the exported HTML report via one optional
  `render_html` param.
- Surfaces: **Desktop + Browser** (the UI). Reuses the reputation BYO-key / OS-keychain / browser-proxy /
  settings/consent infrastructure.

**Out of scope (non-goals)**
- **CLI** AI (`ppcap analyze --ai-summary`) — a clean follow-up; chat is inherently a UI experience.
- A **native Anthropic Messages-API** adapter — the `format` seam exists; v1 implements `openai` only (§5).
- Sending raw packets/payloads/flows or the pcap to any model — only the curated summary (§7) ever leaves.
- New detectors, pipeline, or cargo features; no `ring`/C-deps. The only engine change is one optional
  `render_html` param (§9).
- Multi-model orchestration, agents/tools, RAG over external corpora.

## 3. Decisions (approved)

| # | Decision | Rationale |
|---|---|---|
| D1 | Ship **both** sub-features (executive summary + NL chat) in v1. | The roadmap names both; they share all plumbing. |
| D2 | **Provider-agnostic** via the OpenAI-compatible Chat Completions format; user configures endpoint+model+key. | One wire format covers every cloud + local backend; the user owns cloud-vs-local. |
| D3 | **UI-only TypeScript** + one minimal engine touch (the `render_html` param). | Smallest surface; reuses reputation plumbing; no cargo feature / C-deps. |
| D4 | **Streaming** responses in v1. | Chat UX expectation; desktop `Channel`, browser streaming relay. |
| D5 | **Report integration** in v1 via an optional `render_html(ai_summary)` param. | Clean, consistently-styled report section beats UI-side HTML injection. |
| D6 | Default preset **Anthropic + `claude-opus-4-8`** via its OpenAI-compat endpoint; a `format` seam for a native adapter later. | "Default to latest, most capable Claude"; compat works today, native is a follow-up. |

## 4. Architecture & module layout

**All TypeScript, plus one optional engine param.** New `ui/src/lib/ai/`:

| File | Responsibility |
|---|---|
| `client.ts` | The OpenAI-compatible client: `chatCompletion(config, messages, onToken?) -> Promise<string>`. Streams via `onToken`. Transport is injected (browser relay / desktop Tauri command / direct-to-local). |
| `transport.ts` | `LlmTransport` — `stream(url, headers, body, onChunk) -> Promise<void>`. Impls: `proxyTransport(proxyUrl)` (browser, streaming relay), `tauriTransport()` (desktop, `Channel`), `directTransport()` (local Ollama when CORS permits). |
| `sse.ts` | Parse OpenAI SSE chunks (`data: {…}\n\n`, `[DONE]`) → assembled text deltas. |
| `context.ts` | `buildContext(output: AnalysisOutput) -> string` — the curated, top-N summary projection (§7). |
| `prompts.ts` | `SUMMARY_SYSTEM`, `CHAT_SYSTEM` (grounding instructions). |
| `settings.ts` | `{ enabled, baseUrl, model, apiKey, consent }` + provider presets, mirroring `reputation/settings.ts`. |

**UI:** `cockpit/AiSummaryPanel.tsx` (the brief), `cockpit/AiChat.tsx` (the chat), AI fields added to the
settings dialog (`SettingsDialog.tsx`) + a first-use `AiConsent` modal (mirrors `ReputationConsent`).

**Desktop (Tauri):** a streaming command `ai_chat(request, channel)` (native HTTP → SSE → `Channel` chunks) +
keychain commands `set_ai_key`/`ai_key_status` (mirror the reputation keychain commands, distinct keyring
service `packetpilot-ai`).

**Engine (the one touch):** `render::render_html(…, ai_summary: Option<&str>)` renders an "AI Analyst
Summary" section when `Some`; threaded through the Tauri `save_report` command and the WASM render export.

**Reused as-is / extended:** the browser **proxy relay** (extended to a streaming mode, §8.3); the
keychain command pattern; the settings/consent pattern; `tauri-detect.ts`.

**Data flow:**
```
AnalysisOutput (already in the UI)
  → buildContext()  →  compact summary text
  → messages = [system] + (chat history) + [context (+ user question)]
  → chatCompletion(config, messages, onToken)
        desktop: ai_chat Tauri command (native HTTP, key from keychain) → Channel
        browser: streaming proxy relay (or direct to localhost)
  → streamed text → render (summary panel / chat bubble)
  → (on export) ai_summary passed into render_html → report section
```

## 5. Provider config, presets & the `format` seam

**Wire format (v1):** OpenAI Chat Completions — `POST {baseUrl}/chat/completions`, body
`{ model, messages, stream }`, auth `Authorization: Bearer <key>`. Response (non-stream) `choices[0].message.content`;
(stream) SSE `data:` chunks with `choices[0].delta.content`.

**Presets (settings dropdown; all fields overridable):**

| Preset | baseUrl | default model | notes |
|---|---|---|---|
| **Anthropic** (default) | `https://api.anthropic.com/v1` | `claude-opus-4-8` | OpenAI-compat endpoint; `Authorization: Bearer`. ⚠️ Anthropic flags its compat layer as **testing-oriented, not production** — fine for this opt-in assist; a native Messages adapter is the follow-up. |
| OpenAI | `https://api.openai.com/v1` | `gpt-4o` | |
| OpenRouter | `https://openrouter.ai/api/v1` | `anthropic/claude-opus-4-8` | proxies many providers incl. Anthropic, production-grade |
| Ollama (local) | `http://localhost:11434/v1` | `llama3.1` | no key; browser may reach it directly (set `OLLAMA_ORIGINS`) → no relay |
| Custom | (blank) | (blank) | any OpenAI-compatible endpoint |

**Model IDs (latest Claude, per environment):** `claude-opus-4-8` (most capable), `claude-sonnet-4-6`,
`claude-haiku-4-5`. The user may set any model string the chosen endpoint accepts.

**`format` seam:** each preset carries `format: "openai"`. v1 implements only `openai`. A future
`format: "anthropic"` adapter (native `/v1/messages`, `x-api-key`, Messages request/SSE shape) is a clean
addition behind the same `LlmTransport`/`client` boundary, with no UI change.

## 6. Privacy & consent

- **Off by default, double-gated:** runs only when enabled **and** a `{baseUrl, model}` is configured (plus
  a key when the endpoint needs one).
- **The user owns egress.** A localhost endpoint keeps everything on-device; a cloud endpoint sends only the
  derived summary (§7) to the chosen provider. The consent modal reflects the configured endpoint:
  > *"Your analysis **summary** — severity counts, top incidents and threat IPs with their evidence (never
  > raw packets, payloads, or the capture file) — will be sent to **{baseUrl}** using model **{model}**."*
  > *(localhost → "…stays on this device.")*
- **Never sent:** raw packets, payloads, full flow rows, the pcap bytes, filenames. **Sent:** only §7.
- Keys: desktop OS keychain (service `packetpilot-ai`); browser localStorage (the user's own machine). Keys
  never appear in logs or the JS bundle.

## 7. Context curation (`buildContext`)

A compact, **labeled markdown-ish text block** (token-efficient + LLM-readable), top-N-bounded to a few
thousand tokens. Built **once** per capture and reused for the summary and as the chat system context.

**Included** (each list truncated to top-N):
- Capture metadata — duration, total packets/bytes, unique hosts, first/last timestamp.
- Severity counts (critical→info).
- **Incidents** (headline) — host, severity/score, title, the deterministic `narrative`, `stages`, ATT&CK ids.
- **Top IP threats** — ip, class, severity/score, ioc, tags, ATT&CK, evidence lines, reputation verdicts when present.
- Category breakdown; top talkers (by bytes); protocol hierarchy; top ports.

**Deliberate (vs reputation):** the context **includes internal/private IPs** — they are the subject of the
analysis (you can't discuss "10.0.0.5 beaconed out" without them). Acceptable because it is the user's *own*
capture, consent-gated, and the user picks the endpoint (local keeps it on-device). The reputation pass
withheld internal IPs only because they went to *third-party* services — a different, correct call there.

## 8. The OpenAI-compatible client + streaming

### 8.1 Request
`chatCompletion(config, messages, onToken)` posts `{ model: config.model, messages, stream: true }` to
`{config.baseUrl}/chat/completions` with `Authorization: Bearer {key}` (omitted when no key). `messages` is
`[{role:"system", content: systemPrompt}, …history, {role:"user", content}]`.

### 8.2 Streaming parse
`sse.ts` consumes the response body stream, splits on `\n\n`, parses each `data: {json}` (ignoring
`data: [DONE]`), extracts `choices[0].delta.content`, and calls `onToken(delta)`. Non-stream fallback reads
`choices[0].message.content`. Malformed/empty → resolves with whatever accumulated + surfaces an error.

### 8.3 Transports
- **Desktop (`tauriTransport`)** — `invoke` the `ai_chat` command with a Tauri 2 **`Channel<string>`**; the
  Rust side opens the native HTTPS POST, reads the upstream SSE, and sends each chunk down the channel. Key
  read from the keychain inside the command (never crosses into JS).
- **Browser (`proxyTransport`)** — POST to the user's **streaming relay**: body `{ url, headers, method:"POST",
  body, stream:true }`; the relay opens the upstream request and **pipes the `text/event-stream` back
  verbatim**; the browser reads it with `fetch` + `ReadableStream`. *(This is a more capable relay than the
  reputation buffered one; documented with a reference relay in §13.)*
- **Direct (`directTransport`)** — for a `localhost` endpoint where CORS permits (Ollama with `OLLAMA_ORIGINS`),
  the browser streams directly with no relay.

Transport selection: desktop → tauri; browser + localhost-and-CORS-ok → direct; else → proxy (requires a
configured relay URL, else a clear "configure a relay" error).

## 9. Executive summary UX + report integration

- **`AiSummaryPanel`** — a dashboard card. *Generate* → `buildContext` → `chatCompletion(SUMMARY_SYSTEM …)`,
  streaming the markdown brief into the card. The result is **cached per capture** (keyed by capture id, in
  the existing IndexedDB/recent infra) so revisiting doesn't re-bill; a *Regenerate* button forces a refresh.
- **Report integration** — `render_html` gains `ai_summary: Option<&str>`; when present it renders a styled
  "AI Analyst Summary" section. The summary is LLM output, so it is **HTML-escaped first** (never injected
  as raw HTML), then given a **minimal markdown-subset** formatting pass (paragraphs/line-breaks, `**bold**`,
  `-` bullets, `#` headings) by a small Rust formatter — anything else renders as escaped text. Threaded
  through Tauri `save_report(summary, path, ai_summary)` and the WASM render export. The UI passes the
  currently-generated summary (or `None`) into the export call. `None` → report is byte-identical to today
  (back-compat).

## 10. NL chat UX

- **`AiChat`** — a slide-over/tab: a messages list + input. Each question → `chatCompletion(CHAT_SYSTEM,
  [context, …recentHistory, question], onToken)`, streaming the assistant reply into a new bubble.
- **History bounded** to the last N turns to stay within budget; the curated context is the system message
  (sent each turn — it's small). The `CHAT_SYSTEM` prompt instructs: answer **only** from the provided
  summary; if a detail isn't in the summary, say so plainly; never invent packet-level facts.
- Per-capture chat state (cleared on capture swap, like other per-capture UI).

## 11. Error handling

AI failures never touch the analysis — the dashboard and all triage keep working.
- Network / 401 / 429 / 5xx / timeout → inline error in the panel or chat bubble ("AI request failed: …").
- Streaming error mid-response → show the partial text + an error note.
- Unconfigured (no endpoint/model, or no key when required) → the panel prompts to open settings; no call.
- Unreachable endpoint (browser CORS without a working relay; Ollama not running) → "couldn't reach {baseUrl}
  — check your relay/endpoint."
- Off by default + consent gate → zero calls without enable + consent.

## 12. Testing

- **TS units:** `buildContext` (fixture `AnalysisOutput` → expected curated text; top-N truncation; no raw
  flows); `chatCompletion` (mocked `LlmTransport` → correct OpenAI request shape; assembles streamed deltas;
  error statuses → graceful error); `sse.ts` (canned chunks incl. `[DONE]` + split-across-boundary → text);
  AI `settings` (round-trip, presets prefill, off-by-default); prompt content (grounding instructions present).
- **Component (RTL):** `AiSummaryPanel` (generate → streamed brief renders; cached; error/needs-config
  states), `AiChat` (question → reply; bounded history; grounding), settings dialog (preset + field round-trip),
  `AiConsent` (gate).
- **Engine (the one Rust touch):** `render_html` with `Some(ai_summary)` renders the section; `None` omits it
  (back-compat) — a focused Rust test.
- **Coverage discipline (lesson from the reputation feature):** this adds substantial new TS, so each new
  `lib/ai/*` function is unit-tested, and **`npm run test:coverage`** (not just `vitest run`) is run to
  confirm the 80/70 gate (lines/functions/statements ≥80, branches ≥70) stays green **before** claiming done.
  See [[verify-ui-coverage-gate]].

## 13. Deferred / follow-ups
- **Native Anthropic Messages adapter** (`format: "anthropic"`) for production-grade Anthropic — the seam
  exists (§5).
- **CLI** `ppcap analyze --ai-summary` (one-shot brief).
- A **reference streaming relay** (a tiny Node/serverless example that pipes SSE) shipped in `docs/` — the
  browser path needs the user to run one for cloud endpoints; document the contract + example.
- Tool/function-calling so the model can drill into specific flows on request (would require sending more
  than the curated summary — a deliberate future privacy decision).

## 14. Sources
- Anthropic OpenAI SDK compatibility (endpoint, `Authorization: Bearer`, testing-oriented caveat, native
  `/v1/messages`): https://platform.claude.com/docs/en/api/openai-sdk
- OpenAI Chat Completions + SSE streaming format (the universal wire format).
- Reuse: `ui/src/lib/reputation/{settings,http}.ts`, `ui/src-tauri/src/lib.rs` (keychain commands),
  `engine/crates/ppcap-core/src/report/mod.rs` (`render_html`).
