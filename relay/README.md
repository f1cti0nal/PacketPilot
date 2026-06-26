# PacketPilot AI relay

A tiny streaming proxy for the **browser** AI Analyst. The CLI and desktop apps don't need it.

## Why you need it

A browser can't call a cloud LLM provider (Anthropic / OpenAI / OpenRouter) directly:

- the provider's API doesn't send CORS headers, so the browser blocks the request; and
- your API key would be exposed to the web page.

This relay runs on **your** machine (or your own Worker). The browser sends it the request; the
relay forwards it to the provider and streams the `text/event-stream` response back. Your key never
has to leave your control — and (optionally) never even reaches the browser (see *Hardening*).

> Not needed for: a **localhost** model (Ollama at `http://localhost:11434/v1`) — the browser talks
> to it directly. Or the **desktop app** / **CLI**, which aren't browser-sandboxed.

## Run it

### Node (local, zero dependencies — needs Node ≥ 18)

```sh
node relay/ai-relay.mjs
# PacketPilot AI relay → http://localhost:8788 (allow-origin: *)
```

Then in PacketPilot: **Settings → AI Analyst → Proxy URL** = `http://localhost:8788`.

### Cloudflare Worker (hosted, free tier — for a deployed PacketPilot)

```sh
npm create cloudflare@latest my-relay      # or: wrangler init
# replace the worker source with relay/ai-relay.worker.js, then:
wrangler deploy
```

Set **Proxy URL** to your `https://<worker>.workers.dev`.

## Configuration (env vars)

| var | default | meaning |
|---|---|---|
| `PORT` | `8788` | listen port (Node only) |
| `ALLOW_ORIGIN` | `*` | CORS origin to allow. **Set this to your app's exact origin** to stop other sites from using your relay (e.g. `http://localhost:5180`, or your deployed origin). |
| `AI_API_KEY` | — | optional. If set, the relay **injects** this as the `Authorization` bearer, so the key never lives in the browser — leave **Settings → API Key** blank. |

## The contract (if you write your own)

PacketPilot's browser build sends:

```
POST <your relay>      content-type: application/json
{
  "url": "https://api.openai.com/v1/chat/completions",
  "headers": { "content-type": "application/json", "authorization": "Bearer sk-..." },
  "method": "POST",
  "body": "{\"model\":\"...\",\"messages\":[...],\"stream\":true}",
  "stream": true
}
```

Your relay must:

1. **Answer the CORS preflight** — the browser sends `OPTIONS` first (the POST is `application/json`),
   so respond `204` with `access-control-allow-origin`, `access-control-allow-methods: POST, OPTIONS`,
   and **`access-control-allow-headers: content-type`**. (Forgetting this is the #1 reason a relay
   "doesn't work" — the real POST never gets sent.)
2. **Forward** `body` to `url` with `headers` (or your injected key) and `method`.
3. **Stream the response body back verbatim**, chunk by chunk — don't buffer, or tokens won't appear
   live. Forward the upstream **status** too, so a 401/429 surfaces as a real error.

## Security

- The relay can call **any** `url` you POST to it (restricted to `http(s)`). Don't expose it on a
  public IP without `ALLOW_ORIGIN` locked down (and ideally network/auth restrictions) — otherwise
  it's an open proxy.
- Prefer `AI_API_KEY` (server-side injection) so the key is never stored in the browser.
- Only the derived analysis **summary** is ever sent (PacketPilot never sends raw packets/payloads).
