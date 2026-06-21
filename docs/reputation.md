# Reputation Enrichment — Operator Guide

Online reputation enrichment is an **opt-in, post-analysis pass** that corroborates public IPs on
the per-IP threat cards using crowd-sourced intelligence from AbuseIPDB, GreyNoise, and VirusTotal.
It is off by default and requires at least one provider API key to do anything.

---

## What it does

After local analysis completes, the reputation pass:

1. Selects distinct **public IPs** from the analysis summary (RFC 1918, loopback, CGNAT, multicast,
   link-local, and documentation-range IPs are never looked up).
2. Orders them by current card severity — most-suspicious first — so that scarce quota (GreyNoise
   in particular) lands on the IPs that matter.
3. Checks the local cache; only cache misses hit the network.
4. Maps each provider response to a `ReputationVerdict` and folds it into the per-IP threat card
   via `apply_reputation` — a single-sourced, pure, network-free function shared across CLI,
   Desktop, and Browser.

**Severity effect (bounded and explainable):**

- One malicious verdict floors the card to High (≥ 60 pts); two or more agreeing providers floor
  it to Critical (≥ 90 pts).
- A GreyNoise `benign` or RIOT attribution suppresses one severity band — *only* when the IP has
  no local IOC match and no confirmed behavioral finding (brute-force, beacon, etc.).
- `Clean`, `Unknown`, `NotFound`, and `Unavailable` verdicts are recorded on the card for
  transparency but contribute zero points and never trigger suppression.
- Every adjustment pushes a human-readable evidence string, consistent with the existing
  "every point is explained" severity model.

---

## Keys — bring your own

No API key is bundled. Each provider is active only when its key is present.

### CLI — environment variables

```sh
export ABUSEIPDB_API_KEY=<your-key>
export GREYNOISE_API_KEY=<your-key>
export VIRUSTOTAL_API_KEY=<your-key>
```

Keys are read at startup; unset or empty variables cause that provider to be silently skipped.

### Desktop (Tauri)

Keys are stored in the OS keychain via the Tauri keyring — never in plaintext on disk. Configure
them in the Settings dialog (per-provider toggles). A first-use consent modal summarises which
external IPs will be sent before the first lookup runs.

### Browser

Keys and the proxy URL are stored in `localStorage` on the user's own machine. Configure them in
the Settings panel. The browser also requires a **proxy URL** (see next section).

---

## CLI usage

```sh
# Enable reputation enrichment (prints a notice and continues if no key is set):
ppcap analyze capture.pcap --reputation

# Also look up SNI domains via VirusTotal (opt-in sub-toggle):
ppcap analyze capture.pcap --reputation --reputation-domains
```

If `--reputation` is passed but no key is set, the CLI prints a notice and continues with the
local-only analysis result.

---

## Browser proxy contract

Browsers cannot complete cross-origin requests to the provider APIs (no
`Access-Control-Allow-Origin`). The browser reputation pass therefore relays through a
**user-supplied proxy URL** stored in `localStorage`. The proxy is off by default and entirely
under the user's control.

**Contract:** the app sends `POST {proxyUrl}` with a JSON body:

```json
{ "url": "<provider-endpoint>", "headers": { "<header-name>": "<value>", "...": "..." } }
```

The proxy forwards the request server-side and responds with:

```json
{ "status": 200, "body": "<raw-response-body-string>" }
```

`body` must be a string (the raw provider response), not a parsed object.

**Minimal Node.js relay example:**

```js
// relay.mjs  —  node relay.mjs
import http from "http";
import https from "https";

http.createServer(async (req, res) => {
  const { url, headers } = JSON.parse(await body(req));
  const upstream = await fetch(url, { headers });
  const text = await upstream.text();
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ status: upstream.status, body: text }));
}).listen(8787, () => console.log("relay on :8787"));

function body(req) {
  return new Promise(r => { let b = ""; req.on("data", c => b += c); req.on("end", () => r(b)); });
}
```

Point the browser settings to `http://localhost:8787` (or wherever the relay runs).

**Security note:** the user's own API key transits their own relay; no third party is involved.
CLI and Desktop are server-side by nature and do not need a proxy.

---

## Quotas and cache TTLs

| Provider   | Free quota          | Default daily budget | Cache TTL |
|------------|---------------------|----------------------|-----------|
| AbuseIPDB  | 1 000 / day (UTC)   | 950                  | 18 h      |
| VirusTotal | 500 / day + 4 / min | 480                  | 12 h      |
| GreyNoise  | ~10 / day           | 9                    | 24 h      |

Budget defaults are conservative (free quota minus a safety margin). Cache hits cost nothing
against the quota; only live fetches decrement the daily counter.

When a provider's budget is exhausted for the session, remaining indicators are surfaced in the
UI as **"N not looked up (quota)"** — never silently dropped.

**Cache storage:** on-disk JSON under the platform cache directory (CLI / Desktop); IndexedDB
(Browser). The cache is private, local, and single-user — results are never exported, shared, or
re-served to other users.

---

## Terms of service and privacy

- **Bring-your-own keys:** no key is ever bundled. VirusTotal's free key is non-commercial only;
  you must supply your own key to comply with their ToS.
- **Private cache:** cached verdicts are local only and are never redistributed or republished,
  consistent with the ToS of all three providers.
- **GreyNoise:** for internal/non-commercial use only. Never feed cached GreyNoise data into
  model training (ToS §3.2(7)). If you intend commercial shipping, confirm the durable-cache TTL
  with GreyNoise before deploying.
- **What leaves the device:** only bare public IP strings (e.g. `203.0.113.7`) and, when
  `--reputation-domains` is active, SNI domain strings. Raw packets, payloads, internal IPs,
  pcap filenames, and flow contents never leave the device.
- **Double-gated off by default:** the pass runs only when reputation is explicitly enabled *and*
  at least one provider key is present. No silent network calls are ever made.

---

## Build note — `online` cargo feature

The native reputation adapters live behind the `online` cargo feature in `ppcap-core`. Enabling
it pulls `ureq` (rustls TLS backend, ring crypto), which requires a **C compiler** at build time.
The default offline engine build keeps this dependency absent; the CI C-compiler-free gate is
scoped to the `ppcap-core` default feature set.

```sh
# Build CLI with reputation support:
cargo build -p ppcap-cli --release --features ppcap-core/online
```

`apply_reputation` itself is always compiled (no feature gate) and is wasm-safe — it is a pure
function with no network I/O, so the Browser build gets the same scoring logic via the WASM
export without pulling the native HTTP stack.
