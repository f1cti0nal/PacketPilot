# Online reputation connectors — design

- **Date:** 2026-06-21
- **Status:** Approved (design); pending implementation plan
- **Branch:** `feat/reputation-connectors` (to be created off `main`)

## 1. Context & motivation

PacketPilot enriches flows with a local `IpClass` classifier + an **offline** threat feed (`ThreatFeed`),
and scores every flow with a transparent weighted severity (`score::score_flow`). The roadmap's first
optional item is **online reputation connectors** — AbuseIPDB, GreyNoise, VirusTotal — to corroborate
(or *suppress*) verdicts on public peers with live, crowd-sourced intelligence.

The seam already exists by design: `enrich::ReputationProvider` (trait) + `ReputationVerdict { source,
malicious, score, tags }` + a `NoopReputation` default held (dead) on `Enricher`, with code comments
anticipating "a future `enrich::online` cargo feature." This design makes that seam real **without
breaking the local-first privacy thesis**: the pass is opt-in, sends only bare public-IP / domain
strings (never raw packets), caches aggressively, and contributes to severity through a **bounded,
explainable** uplift consistent with the existing "every point is explained" scorer.

## 2. Scope

**In scope**
- A native Rust `enrich::online` module (cargo feature `online`) with three provider adapters behind the
  existing `ReputationProvider` trait, a keyed on-disk cache, per-provider rate-limiting + quota budgeting,
  and indicator selection/prioritization.
- A **single-sourced, network-free** `apply_reputation(summary, verdicts) -> summary` that folds verdicts
  into the per-IP `IpThreat` cards with a bounded, explainable severity adjustment.
- Surfaces: **CLI** (`--reputation` flag), **Desktop** (Tauri command, native HTTP), **Browser** (TypeScript
  `reputation.ts` over an opt-in user-supplied proxy URL; verdicts applied via a WASM export of the *same*
  `apply_reputation`).
- Caching: on-disk (native) + IndexedDB (browser, reusing `recent.ts`); per-provider TTL.
- UI: a reputation row on the per-IP threat cards, an enrichment-status line, and a first-use consent modal.

**Out of scope (non-goals)**
- Per-flow re-scoring or changes to `score_flow` / the flows table. Reputation applies at the **per-IP card**
  granularity only (§9).
- Any change to the streaming decode/flow/classify hot path. Reputation is a strictly post-analysis pass.
- A bundled/shared API key, a hosted proxy, or a server component. Keys are **bring-your-own**; the browser
  proxy is user-supplied and off by default.
- Paid provider tiers / bulk endpoints (GreyNoise GNQL, VT premium). Free-tier contracts only; the design
  degrades gracefully under their quotas.
- Domain reputation beyond VirusTotal (AbuseIPDB/GreyNoise have no domain endpoint). SNI-domain lookups are
  an opt-in sub-toggle routed to VT only.

## 3. Decisions (approved)

| # | Decision | Rationale |
|---|---|---|
| D1 | **All three surfaces** get reputation: CLI + Desktop call providers directly; Browser via opt-in proxy URL. | Power users batch on the CLI; the browser is the zero-install path. |
| D2 | **Browser reaches providers through a user-supplied proxy URL**, off by default. | Browsers cannot complete the cross-origin request (see §7.4); CLI/Desktop need no proxy. |
| D3 | **All three providers**, each active iff its key is configured. | Complementary signals; graceful subset operation. |
| D4 | **Architecture B**: native reputation in Rust, browser in TS, the severity re-score single-sourced via a pure WASM `apply_reputation`. | Respects the runtime split; keeps the scoring rule from drifting across surfaces. |
| D5 | **Per-IP-card granularity**; reputation never re-scores individual flows. | Verdicts are a property of the peer, which the card represents; keeps the change bounded. |
| D6 | **Bounded, explainable uplift**; consensus(≥2)→Critical floor; single malicious→at most High floor; GreyNoise benign/RIOT as a *gated* suppressor. | No single external API becomes a black-box override; protects FP-averse detectors. |

## 4. Data contract

### 4.1 `ReputationVerdict` (extended)

The current bare `malicious: bool` conflates **clean** with **no-data** — and all three providers have a
distinct "not found / never analyzed" state that must **not** be read as innocence (§7). The verdict gains
an explicit status, a freshness stamp, and a drill-down link:

```rust
pub enum RepStatus {
    Malicious,  // provider asserts malicious → raises severity
    Benign,     // provider asserts KNOWN-benign attribution → suppression-worthy (GreyNoise benign / RIOT only)
    Clean,      // analyzed, no adverse signal, but no positive benign attribution (AbuseIPDB 0 reports, VT all-harmless) → 0 pts, never suppresses
    Unknown,    // analyzed but inconclusive (VT no harmless majority, GreyNoise classification=unknown)
    NotFound,   // provider has no record (HTTP 404 / NotFoundError) — NOT "clean"
    Unavailable // lookup failed/skipped: error, bad key, quota exhausted, offline
}

pub struct ReputationVerdict {
    pub source: &'static str,      // "abuseipdb" | "greynoise" | "virustotal"
    pub status: RepStatus,
    pub malicious: bool,           // == (status == Malicious); retained for serialization back-compat
    pub score: Option<u8>,         // 0..=100; Some(0) when Clean; None when Unknown/NotFound/Unavailable
    pub tags: Vec<String>,
    pub link: Option<String>,      // provider report page for the indicator (evidence drill-down)
    pub fetched_at: i64,           // unix seconds; drives cache TTL + "as of" display
}
```

### 4.2 `IpThreat` (additions)

```rust
// model::summary::IpThreat gains:
pub reputation: Vec<ReputationVerdict>,  // per-provider verdicts for this IP (empty when pass didn't run)
// existing fields (severity, score, ioc, tags, attack, evidence) are adjusted in place by apply_reputation
```

### 4.3 Wire JSON (snake_case, matching engine convention)

```jsonc
// Indicators request (UI → Tauri command / proxy)  — ONLY these leave the device
{ "ips": ["203.0.113.7", "198.51.100.9"], "domains": ["auth.example.com"] }   // domains present iff opted in

// ReputationVerdict (engine/Tauri/proxy → UI)
{ "source": "abuseipdb", "status": "malicious", "malicious": true, "score": 96,
  "tags": ["ssh", "brute-force", "Data Center/Web Hosting/Transit"],
  "link": "https://www.abuseipdb.com/check/203.0.113.7", "fetched_at": 1750500000 }
```

The browser passes `verdicts` (keyed by indicator) into the WASM `apply_reputation(summary_json,
verdicts_json) -> summary_json` exactly as the native path passes them to the Rust fn.

## 5. Architecture & data flow

Reputation is a **post-analysis pass** over the distinct external indicators of a completed analysis —
never in the streaming hot path:

```
analysis summary ─▶ select distinct PUBLIC IPs (+ opt-in SNI domains)
                 ─▶ order by current card severity (most-suspicious first)   [§6.3]
                 ─▶ cache lookup (hit = instant/offline)
                 ─▶ cache miss = provider fetch, within per-provider quota budget   [§8]
                 ─▶ normalize each response → ReputationVerdict   [§7]
                 ─▶ apply_reputation(summary, verdicts)   ← single-sourced, pure, network-free   [§9]
                 ─▶ updated IpThreat cards (verdict + evidence + bounded uplift/suppression)
```

**Single-sourced scoring.** `enrich::online::apply_reputation(summary, verdicts) -> summary` is one pure
Rust function. CLI and Tauri call it directly; the browser calls the *same* function compiled into
`ppcap-wasm` and exported as `apply_reputation`. This is the anti-drift guarantee that justifies Approach B.

**Module layout:**

| Concern | Native (CLI + Desktop) | Browser |
|---|---|---|
| Provider adapters (fetch + normalize) | `ppcap-core::enrich::online::{abuseipdb,greynoise,virustotal}` (feature `online`; `ureq`+`rustls`, no C deps) | `ui/src/lib/reputation/{abuseipdb,greynoise,virustotal}.ts` (fetch via proxy URL) |
| Cache | on-disk JSON store, atomic write (`dirs::cache_dir()/packetpilot/reputation.json`) | IndexedDB store (reuse `recent.ts` infra) |
| Rate-limit / quota budget | `enrich::online::budget` (token bucket + daily counter) | `ui/src/lib/reputation/budget.ts` |
| Severity re-score | `enrich::online::apply_reputation` (native call) | **same fn** via `ppcap-wasm` `apply_reputation` export |
| Display | shared React components (`cockpit/ThreatRail.tsx`, `IpThreat` views) | same shared components |

- **CLI:** `--reputation` runs the pass after analyze; `--reputation-domains` adds SNI; keys from env
  (`ABUSEIPDB_API_KEY`, `GREYNOISE_API_KEY`, `VIRUSTOTAL_API_KEY`) or `config.toml`.
- **Desktop:** a Tauri command `reputation_lookup(indicators) -> verdicts` does fetch+cache+normalize in
  native Rust; the frontend then displays. Re-score runs natively (no WASM on desktop).
- **Browser:** `reputation.ts` does fetch-via-proxy + IndexedDB cache + normalize → calls WASM
  `apply_reputation`.

The one accepted duplication is the **provider adapters** (Rust + TS) — transport-specific by nature. The
scoring rule, which must not drift, is shared.

## 6. Indicator selection, privacy & budgeting

### 6.1 What is looked up
Only `IpClass::Public` addresses (reuse `enrich::classify_ip`). Skip Private/RFC1918, Loopback, LinkLocal,
CGNAT, Multicast, Documentation/RFC5737, Reserved — both a privacy guarantee and a quota saver (providers
return nothing useful for non-routable IPs; AbuseIPDB's `isPublic=false` confirms this). SNI **domains** are
an opt-in sub-toggle (default off), routed to **VirusTotal only**.

### 6.2 The privacy contract

| Never leaves the device | May leave the device — only when opted in |
|---|---|
| Raw packets, payloads, flow contents | A bare external IP string (e.g. `203.0.113.7`) |
| Internal/private IPs, the pcap bytes, filename | Optionally, an SNI domain string |

- **Off by default, double-gated:** runs only when reputation is enabled **and** ≥1 provider key is present.
  No silent network calls.
- **Informed consent on first use:** the UI states *"N external IPs will be sent to <active providers> to
  check reputation"* before the first lookup.
- **Auditability:** the result view shows which indicators were sent and to which providers.

### 6.3 Quota budgeting & prioritization (consequence of §7 quotas)
Free-tier quotas vary by three orders of magnitude (AbuseIPDB 1000/day, VT 500/day @ 4/min, **GreyNoise
~10/day**). A real capture with dozens–hundreds of distinct public IPs will exhaust GreyNoise immediately.
Therefore:

- Indicators are looked up in **priority order: descending current card severity/score** (most-suspicious
  external IPs first), so scarce GreyNoise calls land on the IPs that matter.
- Each provider has a **daily budget** (default = its free quota minus a safety margin; configurable). The
  cache counts against nothing; only live fetches consume budget.
- When a provider's budget/quota is reached, remaining indicators are surfaced as **"N not looked up
  (quota)"** — never silently dropped (matches the project's no-silent-caps ethos).

## 7. Provider adapters & normalization

All adapters map a provider response into `ReputationVerdict`. *Verified against official docs
(2026-06-21), with adversarial corrections applied.* CORS posture is an **operational assumption, not
vendor-documented** — none of the three documents CORS; treat "no `Access-Control-Allow-Origin`" as an
empirical fact to confirm, with the proxy requirement standing regardless (§7.4).

### 7.1 AbuseIPDB (API v2) — IP only
- **Endpoint:** `GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90`
  — pin `maxAgeInDays=90` so cached `abuseConfidenceScore` stays comparable.
- **Auth:** header `Key: <api-key>` (literally named `Key`, bare value, no `Bearer`) + `Accept: application/json`.
- **score:** `data.abuseConfidenceScore` (0–100) maps **directly**, no rescaling.
- **status:** `>= 75` ⇒ `Malicious`; `25..75` ⇒ `Unknown` (suspicious); `0 && totalReports==0` ⇒ `Clean`
  (no abuse reports — display only; does **not** suppress).
  `data.isWhitelisted` is a **soft down-weight only** (docs: "generally should not be used as a basis for
  action"); guard `isWhitelisted == null` (null ≠ false).
- **tags:** `usageType`, `isTor`→`tor`, `countryCode`, `domain`/`isp`; category IDs from `reports[]` (18=Brute-Force,
  22=SSH, 14=Port Scan, 4=DDoS) **only when `verbose`** (omit `verbose` by default for small payloads).
- **Envelope:** data under `data{}`; errors `{ errors: [{detail, status}] }`.
- **Quota:** 1000/day (UTC reset); 429 on exhaustion with `Retry-After`; read `X-RateLimit-Remaining`.

### 7.2 GreyNoise (Community API) — IP only, the FP suppressor
- **Endpoint:** `GET https://api.greynoise.io/v3/community/{ip}` (IP in path; no query params).
- **Auth:** header `key: <api-key>` (lowercase, bare value).
- **status (gate on `classification`, never on `noise`):** `classification=="malicious"` ⇒ `Malicious`;
  `classification=="benign" OR riot==true` ⇒ `Benign` (primary FP suppressor); `classification=="unknown"`
  ⇒ `Unknown`; **HTTP 404 with body** (`message: "IP not observed…"`) ⇒ `NotFound`.
- **score (synthesized; no numeric field):** Malicious 90–100; `unknown && noise` ~50; `benign||riot` 0–10;
  NotFound 0.
- **tags:** `classification`, `name` (actor/org), `riot`→`business-service`, `noise`→`internet-scanner`.
  **RIOT is not an allow-list** — suppress on it but never render "verified safe."
- **Quota:** *tiny* — ~10 lookups/day (unauth) / 50 searches/week (community). Drives §6.3 budgeting and a
  24h+ TTL. A **403** is a Cloudflare WAF edge block (send a real key + sane User-Agent), distinct from 401/429.

### 7.3 VirusTotal (API v3) — IP **and** domain (one parser, identical fields)
- **Endpoints:** `GET https://www.virustotal.com/api/v3/ip_addresses/{ip}` ·
  `…/api/v3/domains/{domain}`.
- **Auth:** header `x-apikey: <api-key>` (lowercase, bare value).
- **status:** `data.attributes.last_analysis_stats.malicious > 0` ⇒ `Malicious`; stats present with
  `malicious==0 && suspicious==0` and a harmless majority ⇒ `Clean` (display only, no suppression);
  **`last_analysis_stats` absent** ⇒ `NotFound` (`error.code=="NotFoundError"`) / `Unknown` — never coerce
  to clean.
- **score:** `round(100 * malicious / Σ(actual stats keys present))` — sum the keys that exist (engine count
  varies 60–90+). **Never** derive score from `reputation` (signed, unbounded community vote).
- **tags:** `attributes.tags` direct; synthesize from `last_analysis_results.{engine}.category`/`.result`;
  `country`, `as_owner` as context tags.
- **Envelope:** `{ data: { id, type, attributes } }`; errors `{ error: { code, message } }`
  (`NotFoundError`, `QuotaExceededError`).
- **Quota:** **4 req/min AND 500/day** (4/min is binding — queue/throttle); 429 ⇒ `QuotaExceededError`.
  Free key is **non-commercial only** ⇒ **require the user's own key** (already our BYO model).

### 7.4 Why the browser needs the proxy
The binding technical reason is **operational**: a browser `fetch` (or a WASM call delegating to `fetch`) to
these hosts does not complete cross-origin (no `Access-Control-Allow-Origin` observed; vendors document only
server-side use). The user-supplied proxy (D2) forwards the request server-side. The user's own key transits
their own proxy — acceptable, since it is their key and their relay. CLI/Desktop are server-side already and
need no proxy.

## 8. Caching, rate-limiting, quota

- **Cache key** `(provider, indicator)`, value `ReputationVerdict + fetched_at`. **Native:** single
  atomic-write JSON store under the platform cache dir. **Browser:** IndexedDB object store (reuse
  `recent.ts`). On a fetch failure, a stale entry is served **flagged stale** rather than nothing.
- **TTL (freshness judgment; no vendor maximum stated):** AbuseIPDB 12–24h, VirusTotal 6–24h, GreyNoise 24h+.
  Defaults configurable.
- **Rate-limit:** per-provider token-bucket tuned under each free tier (VT ≤4/min the tightest), bounded
  concurrency, exponential backoff honoring `Retry-After` on 429.
- **Quota budget:** per §6.3; cache hits are free; live fetches decrement a daily counter; over-budget
  indicators are surfaced, not dropped.

## 9. Severity uplift (`apply_reputation`)

Pure, deterministic, network-free; mirrors `score_flow`'s idiom — every adjustment pushes an evidence string
and the card's score reconciles to its evidence. Applies **only to public-IP cards**.

**Constants (single source, documented):**
```
PTS_REP_MALICIOUS = 25   // per malicious provider
REP_UPLIFT_CAP    = 25   // total reputation uplift ceiling (multiple providers cannot exceed one "soft IOC")
```

**Rules (per `IpThreat` card):**
1. **Raise.** For each provider with `status==Malicious`, add `PTS_REP_MALICIOUS` (total capped at
   `REP_UPLIFT_CAP`), with evidence `reputation: <source> malicious <score>% [tags] (+N)`.
   - ≥1 malicious provider ⇒ **floor to High** (`score = max(score, 60)`), evidence `floor: reputation
     malicious forces High (>= 60)`.
   - **≥2 providers agree malicious** ⇒ **floor to Critical** (`score = max(score, 90)`), evidence
     `floor: 2+ providers agree malicious forces Critical (>= 90)`.
2. **Suppress (FP reduction).** If ≥1 provider has `status==Benign` (a *positive* known-benign attribution —
   in practice GreyNoise `classification=benign` or `riot=true`; AbuseIPDB/VT "clean" is `Clean`, **not**
   `Benign`, and does not suppress) **and** the card has **no local IOC** (`ioc==false`) **and** the host has
   **no behavioral Finding/Incident** attributed to it, downgrade one severity band (clamp score into the
   lower band's range), evidence `reputation: <source> benign '<name>' — known benign (-1 band)`. Never
   below Info.
3. **Guardrails (load-bearing):**
   - The **local feed outranks online reputation** — a hard local-IOC match or a confirmed behavioral
     Finding (BruteForce/Beacon/DataExfil/Lateral/…) can **never** be suppressed by a provider Benign.
   - Online reputation **never forces Critical alone**; only provider *consensus* does, and a single malicious
     verdict floors only to High.
4. `Clean`/`Unknown`/`NotFound`/`Unavailable` verdicts are recorded on the card (for transparency +
   drill-down) but contribute **0** points and trigger **no** floor/suppression. Only `Malicious` raises and
   only `Benign` suppresses.

`apply_reputation` cross-references `summary.findings`/`incidents` by host to enforce the suppression guard.

## 10. Config / keys / opt-in (off by default, double-gated everywhere)

| Surface | Keys | Enable | Proxy |
|---|---|---|---|
| CLI | env (`ABUSEIPDB_API_KEY`/`GREYNOISE_API_KEY`/`VIRUSTOTAL_API_KEY`) or `config.toml` | `--reputation` (`--reputation-domains` for SNI) | n/a |
| Desktop | OS keychain (Tauri keyring) — never plaintext | Settings toggles per provider + consent prompt | n/a |
| Browser | localStorage (user's own key, own machine) | Settings toggles + consent prompt | required `proxyUrl` (localStorage) |

A provider is active **iff** its key is present **and** reputation is enabled.

## 11. UI surfacing
- Per-IP cards (`ThreatRail`/`IpThreat`) gain a **reputation row**: provider chips (malicious %/benign/
  unknown), tags, an "as of `fetched_at`" stamp, a deep link to the provider report page, and the uplift/
  suppression evidence folded into the existing evidence list.
- An **enrichment-status** line: providers run, IPs looked up, cache hits, and any "N not looked up (quota)"
  / "provider unavailable" notes.
- A **first-use consent modal** (§6.2).
- Lookups run **async after** the instant local triage, with a skeleton/loading state on the cards.

## 12. Error handling — enrichment failures never touch triage
- Provider error / 429 / 401 / quota ⇒ that verdict is `Unavailable`; the card notes it; analysis is never
  blocked.
- Bad/missing key ⇒ provider inactive (not an error); surfaced in settings.
- Offline ⇒ cached-only; no calls; core analysis unaffected.
- Per-request timeout + total-pass budget. The pass is fully decoupled from the core pipeline.

## 13. Testing
- **Rust:** `apply_reputation` units — uplift cap, consensus→Critical, single→High, suppression gating
  (**never suppress a local IOC / behavioral Finding**), `Unknown`/`NotFound` contribute 0, evidence
  reconciliation; public-only indicator selection; per-provider adapters against **recorded fixture JSON**
  (success + 404/not-found + error envelopes) via the `ReputationProvider` trait — **no live network**;
  cache TTL + atomic-write; rate-limiter + quota-budget ordering.
- **TS:** `reputation/*.ts` normalization (fixture → `ReputationVerdict`), fetch-via-proxy with mocked
  `fetch`, IndexedDB cache (jsdom), consent gating, budget/priority ordering.
- **Cross-surface parity test:** an identical `(summary, verdicts)` vector → assert native Rust
  `apply_reputation` **==** WASM `apply_reputation` output. The anti-drift guard for Approach B.
- **CI:** no live-network tests (keys absent); deterministic fixtures only.

## 14. Terms-of-service & privacy compliance
- **Caching:** a private, local, single-user cache with a conservative TTL is the defensible posture for all
  three. None states a maximum cache duration; none permits **redistribution/republishing** of results — so
  the cache is never re-served, exported, or shared, and provenance is preserved.
- **GreyNoise:** internal/non-commercial use only; **never feed cached GreyNoise data into model training**
  (ToS §3.2(7)); keep the cache short-lived and local. Confirm durable-cache TTL with GreyNoise before any
  paid/commercial shipping.
- **VirusTotal:** free key is **non-commercial only** ⇒ BYO key is mandatory (we never bundle one); no
  redistribution of verdicts.
- **AbuseIPDB:** no resale/republish of API data; local caching for your own quota is the community norm.

## 15. Open questions / future
- **Paid tiers / bulk** (GreyNoise GNQL, VT premium) for high-IP-count captures — out of scope now; the
  budgeting in §6.3 is what makes free tiers usable meanwhile.
- **More domain reputation** (beyond VT) if a second domain-capable provider is added.
- **Shared proxy convenience** (a documented serverless template) to lower the browser opt-in friction —
  documentation, not code.

## 16. Sources (verified 2026-06-21)
- AbuseIPDB: docs.abuseipdb.com, abuseipdb.com/api.html, /pricing, /faq.html, /legal
- GreyNoise: docs.greynoise.io (community-api, using-the-greynoise-api, riot-data, api-v3-whats-new-vs-v2),
  github.com/GreyNoise-Intelligence/api.greynoise.io, greynoise.io/terms
- VirusTotal: docs.virustotal.com (ip-object, domains-object, authentication, public-vs-premium-api,
  api-overview, historic-terms-of-service, errors)
