# SNI-domain reputation — Sub-project A (Engine) — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-22
**Branch:** `feat/sni-domain-engine`
**Parent feature:** "SNI-domain everywhere" — split into **A (engine, this spec)** → B (UI + domain consent) → C (AI context). A emits the data contract that B and C consume.

## Goal

Aggregate TLS SNI hostnames into a per-capture domain list and add a VirusTotal domain-reputation path — the engine spine that lets the UI (B) show a domains panel and the AI (C) name risky domains.

## Architecture

Mirrors the existing reputation engine (`IpThreat` / `apply_reputation` / `lookup_reputation`) keyed by **domain** instead of IP. Two layers:
- **Always-on, network-free:** a `DomainThreat` model + `summary.domain_threats` rollup (folded from the per-flow `FlowRecord.sni` the decoder already extracts) + a pure `apply_domain_reputation` scoring fold. This works offline and powers the AI context (C) with zero data leaving the machine.
- **`online`-feature-gated:** the VirusTotal domain lookup (the already-written but dead `verdict_domain`), reusing the existing indicator-agnostic cache + budget.

Cross-surface: a WASM `apply_domain_reputation` export + a native≡WASM parity test, so B's browser path is locked to the engine. The CLI `--reputation` pass is extended to look up + apply domains natively.

**Tech stack:** Rust (`ppcap-core`, `ppcap-wasm`, `ppcap-cli`). No new deps beyond what the `online` feature already pulls.

## Global Constraints

- **`apply_domain_reputation` is pure, network-free, and wasm-safe** — the SINGLE source of the domain-enrichment rule (in `enrich/reputation.rs`, NOT behind any feature), exactly like `apply_reputation`. Native callers, the WASM export, and the CLI all call the same fn; a cross-surface parity test asserts native ≡ WASM.
- **Network lookups stay behind the native-only `online` cargo feature** (`enrich/online/`), reusing the existing `HttpGet` trait + cache + budget. VT-only for domains.
- **SNI aggregation is always-on and network-free** (no feature gate) — folded in the stats stage.
- **`summary.domain_threats` is `#[serde(default)]`** — no schema-version bump; old cached captures still deserialize.
- **No severity/incident coupling** — a malicious-domain verdict is displayed (B) but does NOT raise a host's severity or an incident. The incident-correlation engine is untouched.
- **Bounded:** `domain_threats` is capped at the top **50** hosts by bytes; SNI hosts are normalized lowercase, deduped, and IP-literal / empty SNI is skipped.
- **The C-compiler-free CI gate stays scoped to `cargo tree -p ppcap-core`** (the offline default graph); the `online` feature's `ring`/`cc` dependency is the accepted exception (don't re-broaden the gate).
- Engine CI gates pass: `cargo fmt`, `cargo clippy --workspace --all-targets -D warnings`, `cargo test --workspace`, `cargo test --features online`.

## Reference: existing structures (verified)

```rust
// model/summary.rs:107
pub struct IpThreat { /* ip-keyed; … reputation: Vec<ReputationVerdict> */ }
// enrich/reputation.rs:62
pub fn apply_reputation(summary: &mut Summary, verdicts: &BTreeMap<String, Vec<ReputationVerdict>>);
// enrich/online/virustotal.rs:106  (exists, currently dead code)
pub fn verdict_domain(http: &dyn HttpGet, key: &str, domain: &str, now: i64) -> ReputationVerdict;
// enrich/online/cache.rs:14  — already indicator-agnostic
fn key(source: &str, indicator: &str) -> String { format!("{source}|{indicator}") }
// enrich/online/mod.rs:121 / :241  — IP-only today
pub fn lookup_reputation(...); pub fn lookup_reputation_native(...);
// ppcap-wasm/src/lib.rs:165 — the export pattern to mirror
pub fn apply_reputation(output_json: &str, verdicts_json: &str) -> Result<String, JsValue>;
// per-flow SNI already extracted: FlowRecord.sni (model/flow.rs); decode/mod.rs sniff_tls_client_hello
```

## Components

### 1. Model — `model/summary.rs`
```rust
pub struct DomainThreat {
    pub host: String,
    pub flows: u64,
    pub bytes: u64,
    #[serde(default)]
    pub reputation: Vec<ReputationVerdict>,
}
// in struct Summary:
#[serde(default)]
pub domain_threats: Vec<DomainThreat>,
```
No `score`/`severity` (it's a traffic-ranked panel, not a scored card).

### 2. Aggregation — `stats/mod.rs`
In `StatsAccumulator`, add a `HashMap<String, (u64 /*flows*/, u64 /*bytes*/)>` keyed by normalized SNI host. In the per-flow observe path, when `FlowRecord.sni` is `Some(host)` and `host` is a valid domain (non-empty, contains `.`, not an IP literal), accumulate `flows += 1`, `bytes += flow bytes`, on the lowercased host. In `finish()`, materialize into `Vec<DomainThreat>` (empty `reputation`), sort by `bytes` desc (tie-break host asc for determinism), truncate to 50.

### 3. Pure fold — `enrich/reputation.rs`
```rust
pub fn apply_domain_reputation(
    summary: &mut Summary,
    verdicts: &BTreeMap<String, Vec<ReputationVerdict>>,
);
```
For each `DomainThreat`, if `verdicts` has its `host`, set `domain.reputation = verdicts[host].clone()`. Pure, network-free, deterministic. No severity change. (Mirrors `apply_reputation`'s host-keyed lookup; simpler — no score uplift.)

### 4. Online lookup — `enrich/online/` (behind `online`)
A domain lookup path (e.g. `lookup_domain_reputation(http, hosts: &[String], key, now, cache, budget) -> BTreeMap<String, Vec<ReputationVerdict>>`) that, for each host, checks the cache (key `virustotal|<host>`), and on miss calls `verdict_domain` (VT) under the existing per-provider budget, caching the result. Reuses the existing cache + budget structs unchanged (their keys are already `source|indicator`).

### 5. Cross-surface — `ppcap-wasm/src/lib.rs`
A `#[wasm_bindgen] pub fn apply_domain_reputation(output_json, verdicts_json) -> Result<String, JsValue>` mirroring the IP `apply_reputation` export (parse `AnalysisOutput` + the host→verdicts map → call the core fn → return JSON). A cross-surface parity test (extend `ui/src/test/reputation-parity.fixture.json` with a `domain_threats` + `domain_verdicts` + `expected_domain` block, asserted by both `engine/.../tests/reputation_parity.rs` and `ui/src/lib/reputation/parity.test.ts`). **The TS parity side requires `npm run build:wasm` after adding the export** so the rebuilt `ui/src/wasm/` carries `apply_domain_reputation` (CI's ui job rebuilds wasm).

### 6. CLI — `ppcap-cli`
Extend the existing `--reputation` pass: after the IP lookup+apply, also collect `summary.domain_threats[].host`, run the domain lookup (online), and `apply_domain_reputation`. Same flag, no new surface.

## Data flow & error handling

Decode → per-flow `sni` → stats aggregation → `summary.domain_threats` (always). With `--reputation` (CLI) or the UI domain pass (B): top domains → VT lookup (budget-bounded, cached) → `apply_domain_reputation`. A failed/absent lookup leaves `reputation` empty (the fold is a no-op for missing hosts); never panics. Old captures without `domain_threats` deserialize via `#[serde(default)]`.

## Testing

- **Aggregation unit tests:** dedup + lowercase; IP-literal/empty SNI skipped; bytes/flows tally; sort-by-bytes + top-50 cap + deterministic tie-break; capture with no TLS → empty.
- **`apply_domain_reputation` tests:** fold by host (malicious + neutral verdicts); host not in verdicts → unchanged; empty verdicts → no-op.
- **Online lookup tests:** a fake `HttpGet` returns canned VT domain JSON → asserts `verdict_domain` parsing + cache hit on the second call + budget honored (no network).
- **Parity:** the extended fixture asserts native `apply_domain_reputation` ≡ WASM export.
- Engine gates: fmt, clippy `-D warnings`, `test --workspace`, `test --features online`, C-free gate (`ppcap-core`).

## Out of scope (later sub-projects / follow-ups)

- **B (UI):** `DomainThreatsPanel` + `DomainThreat` TS type + the **`pp.rep.domain-consent`** opt-in (off by default; separate from IP consent) + the TS domain orchestrator (`virustotalVerdictDomain` + a domain lookup path) + the WASM/Tauri consumption.
- **C (AI):** a domains section in `buildContext`.
- Severity/incident coupling; non-VT domain providers; per-domain richer scoring.

## File manifest

**Modify:** `engine/crates/ppcap-core/src/model/summary.rs` (`DomainThreat` + `Summary.domain_threats`), `engine/crates/ppcap-core/src/stats/mod.rs` (aggregation), `engine/crates/ppcap-core/src/enrich/reputation.rs` (`apply_domain_reputation` + export), `engine/crates/ppcap-core/src/enrich/online/mod.rs` (domain lookup; behind `online`), `engine/crates/ppcap-wasm/src/lib.rs` (WASM export), `engine/crates/ppcap-cli/src/cli.rs` (domain pass), `engine/crates/ppcap-core/tests/reputation_parity.rs` + `ui/src/lib/reputation/parity.test.ts` + `ui/src/test/reputation-parity.fixture.json` (parity).
**No UI surface, no consent, no AI** (those are B and C).
