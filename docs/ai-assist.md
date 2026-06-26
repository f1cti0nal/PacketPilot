# AI Analyst Assist — Operator Guide

AI Analyst Assist turns the *derived* analysis summary — severity counts, top incidents, ranked
threat IPs with their evidence — into a **natural-language executive brief** and an **interactive
NL chat** session. It does not read raw packets, flows, or payloads; the LLM sees only what the
engine already computed.

> Off by default. Requires an API key (or local Ollama). No key is ever bundled.

---

## What it does

### Executive summary
One click generates a 3–5 paragraph narrative brief: what threat patterns appear, what the
kill-chain looks like, which IPs are highest priority, and what to investigate next. The brief
appears in the **AI Analyst Summary** card on the triage dashboard and is cached in IndexedDB
(Desktop: SQLite) so subsequent opens are instant.

### Natural-language chat
The **Ask** panel (command bar or ⌘K → "Ask") opens a sidebar chat where the analyst can
question the data in plain English:

> *"Which internal host initiated the lateral movement?"*
> *"Summarise the TLS anomalies — is there any DGA pattern?"*
> *"Write a short IR ticket body for this incident."*

The LLM is given the same curated summary context for every question. There is no conversation
memory between sessions — chat history lives only in the current page load.

---

## Privacy — what leaves the device

**Only the summary ever leaves.** The context sent to the LLM contains:

- Packet/flow/byte/host *counts*
- Severity bucket totals
- Top incident narratives (from the engine's explainable-severity output)
- Per-IP threat scores, tags, MITRE ATT&CK mappings, and evidence strings

**What is never sent:** raw packets, payloads, full flow tables, pcap file contents or filename,
internal IP addresses beyond what appears in the engine's own threat report cards, or any data
not already shown on the triage dashboard.

If the endpoint is `localhost` or `127.0.0.1` (e.g. Ollama), **nothing leaves the device at all**
— the request stays on the loopback interface.

---

## Opt-in and consent

1. Open **Settings** → **AI Analyst** → check *Enable AI analysis*.
2. The first time you click **Generate**, a consent modal shows:
   - The base URL the request will go to
   - The model name
   - Whether it is local (loopback — stays on device) or remote
   - A one-line summary of what will be sent
3. Click **Proceed** once per session to continue. Clicking **Cancel** aborts with no network call.

Consent is a one-time acknowledgement stored locally (`pp.ai.consent`) in `localStorage`
(Browser) or the OS profile (Desktop). The consent dialog always shows the **current** endpoint
and model at the moment you click Generate, so you always see where data will go.

---

## Provider presets

Choose a preset in **Settings → AI Analyst → Preset**. All fields are editable after selecting.

| Preset | Base URL | Default model |
|---|---|---|
| Anthropic | `https://api.anthropic.com/v1` | `claude-opus-4-8` |
| OpenAI | `https://api.openai.com/v1` | `gpt-4o` |
| OpenRouter | `https://openrouter.ai/api/v1` | `anthropic/claude-opus-4-8` |
| Ollama (local) | `http://localhost:11434/v1` | `llama3.1` |
| Custom | *(user-supplied)* | *(user-supplied)* |

**Anthropic-compat caveat:** the client uses the OpenAI-compatible `/chat/completions` streaming
endpoint (SSE, `data: [DONE]` terminator). The Anthropic-preset base URL is correct for the
Anthropic Messages API when accessed through an OpenAI-compat shim (e.g. OpenRouter), but the
native `api.anthropic.com` endpoint uses a different wire format. For production use, either:

- Use **OpenRouter** with an Anthropic model (fully supported, handles the wire format).
- Use **Ollama** for local models that expose an OpenAI-compat API.
- Use any other OpenAI-compat API endpoint.

The Anthropic preset is kept for convenience and testing; it will work only if an OpenAI-compat
shim is placed in front of the Anthropic API.

---

## Configuring keys and the base URL

### Desktop (Tauri)

Keys are stored in the **OS keychain** via the Tauri keyring — never in plaintext on disk.
Configure in **Settings → AI Analyst → API Key**. On save the key is stored with
`set_ai_key("default", ...)` and retrieved at runtime; it never appears in `localStorage`.

### Browser

Keys and the proxy URL are stored in `localStorage` on the user's own machine. Configure in
**Settings → AI Analyst → API Key** and **Proxy URL**.

---

## Browser streaming-relay contract

Browsers cannot complete cross-origin SSE requests directly to provider APIs. The browser AI
pass therefore relays through a **user-supplied streaming relay URL** stored in `localStorage`.

**Contract:** the app sends `POST {proxyUrl}` with a JSON body:

```json
{
  "url": "<llm-endpoint-url>",
  "headers": { "authorization": "Bearer sk-...", "content-type": "application/json" },
  "method": "POST",
  "body": "<serialised-chat-completions-request>",
  "stream": true
}
```

The relay opens the upstream request and **pipes the `text/event-stream` back verbatim** — every
SSE chunk is forwarded byte-for-byte as the response body. The response `Content-Type` should be
`text/event-stream`.

> ⚠ **CORS preflight is mandatory.** The browser POSTs `application/json`, so it sends an `OPTIONS`
> preflight first. The relay **must** answer `OPTIONS` with `access-control-allow-origin`,
> `access-control-allow-methods: POST, OPTIONS`, and **`access-control-allow-headers: content-type`**
> — otherwise the real POST is never sent and the relay appears to "do nothing". (A relay that only
> handles POST is the most common broken relay.)

**Ready-to-run reference relays live in [`relay/`](../relay/):** `relay/ai-relay.mjs` (zero-dep
Node ≥ 18) and `relay/ai-relay.worker.js` (Cloudflare Worker). See [`relay/README.md`](../relay/README.md).

```sh
node relay/ai-relay.mjs        # → http://localhost:8788
```

Minimal correct relay (note the `OPTIONS` branch the naive version omits):

```js
// ai-relay.mjs  —  node ai-relay.mjs   (env: PORT, ALLOW_ORIGIN, AI_API_KEY)
import http from "http";
const ALLOW = process.env.ALLOW_ORIGIN ?? "*";
const KEY = process.env.AI_API_KEY ?? "";

http.createServer(async (req, res) => {
  res.setHeader("access-control-allow-origin", ALLOW);
  res.setHeader("access-control-allow-methods", "POST, OPTIONS");
  res.setHeader("access-control-allow-headers", "content-type");
  if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }  // ← the preflight
  if (req.method !== "POST") { res.writeHead(405); res.end(); return; }

  const { url, headers = {}, method = "POST", body } = JSON.parse(await readBody(req));
  if (!/^https?:\/\//i.test(url ?? "")) { res.writeHead(400); res.end(); return; }
  if (KEY) headers.authorization = `Bearer ${KEY}`;             // optional: keep the key off the browser

  const upstream = await fetch(url, { method, headers, body });
  res.writeHead(upstream.status, {                              // forward the REAL status (401/429/…)
    "content-type": upstream.headers.get("content-type") ?? "text/event-stream",
    "cache-control": "no-cache",
  });
  for await (const chunk of upstream.body) res.write(chunk);    // stream verbatim, do not buffer
  res.end();
}).listen(Number(process.env.PORT ?? 8788), () => console.log("AI relay on :8788"));

function readBody(req) {
  return new Promise(r => { let b = ""; req.on("data", c => b += c); req.on("end", () => r(b)); });
}
```

Point **Settings → AI Analyst → Proxy URL** to `http://localhost:8788` (or wherever the relay runs).

**Security note:** the user's API key transits their own relay on their own machine — no third party.
Set `ALLOW_ORIGIN` to your app's exact origin so other sites can't use your relay, and set
`AI_API_KEY` to inject the key server-side (then leave the Settings → API Key field blank) so it
never lives in the browser. CLI and Desktop are not browser-sandboxed and do not need a relay.

### Local endpoint (no relay needed)

If the Base URL is `http://localhost:…` or `http://127.0.0.1:…` (e.g. Ollama), the browser makes
the request directly without a relay. No Proxy URL is required in this case.

---

## Caching

Generated summaries are cached locally (IndexedDB in the browser, SQLite in the desktop app)
keyed by capture SHA-256 (or source path when the hash is unavailable). The cache entry stores
the full text and the model name. On subsequent opens the cached brief loads instantly without
calling the LLM.

There is no automatic expiry — cached summaries persist until the browser storage is cleared or
the app data folder is reset. Re-generating a summary always overwrites the cache entry.

---

## Supported LLM API format

The client uses the **OpenAI Chat Completions streaming format**:

- `POST /v1/chat/completions` with `{"model": "…", "messages": […], "stream": true}`
- SSE response: `data: {"choices":[{"delta":{"content":"…"}}]}\n\n`
- Stream terminator: `data: [DONE]\n\n`

Any endpoint that speaks this wire format is compatible — Ollama, LM Studio, vLLM, Anyscale,
together.ai, OpenRouter, and OpenAI all work out of the box.
