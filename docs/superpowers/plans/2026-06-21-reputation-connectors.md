# Online Reputation Connectors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in AbuseIPDB / GreyNoise / VirusTotal IP reputation that folds into PacketPilot's per-IP threat cards via a bounded, explainable severity adjustment — across CLI, Desktop, and Browser — without raw packets ever leaving the device.

**Architecture:** A pure, network-free `apply_reputation(summary, verdicts)` in `ppcap-core` is the single source of the scoring rule; native callers (CLI/Tauri) call it directly and the browser calls the *same* function compiled into `ppcap-wasm`. Network lookups live behind a native-only `online` cargo feature (Rust `ureq` adapters + cache + budget) for CLI/Desktop; the browser performs lookups in TypeScript through a user-supplied proxy and applies verdicts via the WASM export. The full design is [docs/superpowers/specs/2026-06-21-reputation-connectors-design.md](../specs/2026-06-21-reputation-connectors-design.md).

**Tech Stack:** Rust (ppcap-core/ppcap-cli/ppcap-wasm, `ureq` + rustls), Tauri 2 (Rust commands, `keyring`), TypeScript/React 18 + Vite, Vitest + RTL, IndexedDB.

## Global Constraints

*Every task's requirements implicitly include this section. Values copied verbatim from the spec.*

- **No C deps.** The HTTP/TLS client must be pure Rust (`ureq` with rustls). Never add `*-sys` / OpenSSL crates.
- **`apply_reputation` is always-compiled and network-free.** It lives in `ppcap-core` *outside* the `online` feature and MUST compile for `wasm32` so the browser gets identical scoring. Only the provider adapters + HTTP + cache + budget are behind `#[cfg(feature = "online")]`.
- **Off by default, double-gated.** Reputation runs only when the user enables it **and** ≥1 provider key is present. A provider is active **iff** its key is set. No silent network calls.
- **Only bare public-IP / domain strings leave the device.** Never raw packets, payloads, internal IPs, pcap bytes, or filenames. Look up only `IpClass::is_external()` addresses.
- **Single-sourced scoring.** Native Rust `apply_reputation` and the WASM export produce byte-identical output for the same input (enforced by a cross-surface parity test).
- **Bounded, explainable uplift.** `PTS_REP_MALICIOUS = 25` per malicious provider, total capped at `REP_UPLIFT_CAP = 25`. ≥1 malicious ⇒ floor High (score ≥ 60); ≥2 agree ⇒ floor Critical (score ≥ 90). GreyNoise benign/RIOT ⇒ `status=Benign` ⇒ downgrade one band, **only** when the card has no local IOC and no behavioral finding. `Clean`/`Unknown`/`NotFound`/`Unavailable` contribute 0.
- **Wire JSON is snake_case** (matches the engine convention). Browser ↔ WASM/proxy payloads keyed by indicator string.
- **ToS:** cache is private/local-only, never redistributed; conservative TTL (AbuseIPDB 12–24h, VT 6–24h, GreyNoise 24h+); never feed GreyNoise data into model training; VT/all keys are bring-your-own (never bundled).
- **Pins:** `wasm-bindgen = "=0.2.125"` (must match the installed `wasm-bindgen-cli`).

## File Structure

**Engine (`engine/crates/ppcap-core/src/`):**
- `enrich/reputation.rs` *(new, always compiled)* — `RepStatus`, extended `ReputationVerdict`, `apply_reputation`, scoring constants. The keystone.
- `enrich/online/mod.rs` *(new, `#[cfg(feature="online")]`)* — `HttpGet` trait + `UreqClient`, `RepError`, `ReputationKeys`, the cache, the budget, and the `lookup_reputation` orchestrator.
- `enrich/online/abuseipdb.rs`, `greynoise.rs`, `virustotal.rs` *(new, gated)* — one pure `*_verdict(http, key, ip)` parser each, unit-tested against fixture JSON.
- `enrich/mod.rs` *(modify)* — re-export the reputation types from `reputation`; declare the `online` module; keep `ReputationProvider`/`NoopReputation`.
- `model/summary.rs` *(modify)* — add `IpThreat.reputation: Vec<ReputationVerdict>` (`#[serde(default)]`).
- `lib.rs` *(modify)* — `pub use` the reputation types + `apply_reputation`; (gated) re-export `lookup_reputation`.
- `Cargo.toml` + `engine/Cargo.toml` *(modify)* — the `online` feature + `ureq` dep.

**CLI (`engine/crates/ppcap-cli/`):** `Cargo.toml` (enable `online`), `src/cli.rs` (`--reputation` flag, env keys, run the pass).

**WASM (`engine/crates/ppcap-wasm/`):** `Cargo.toml` (block features), `src/lib.rs` (`apply_reputation` export).

**Desktop (`ui/src-tauri/`):** `Cargo.toml` (enable `online`, add `keyring`), `src/lib.rs` (`reputation_lookup` command + registration).

**Browser (`ui/src/`):**
- `lib/reputation/{types,abuseipdb,greynoise,virustotal,cache,budget,orchestrator,apply}.ts` *(new)*
- `lib/recent.ts` *(modify)* — reputation IndexedDB store.
- `types.ts` *(modify)* — `RepStatus`, `ReputationVerdict`, `IpThreat.reputation`.
- `cockpit/ThreatRail.tsx` *(modify)* — reputation chip; `cockpit/ReputationChip.tsx` *(new)*.
- `cockpit/SettingsDialog.tsx`, `cockpit/ReputationConsent.tsx` *(new)* — keys/proxy/toggles + consent.
- `App.tsx` *(modify)* — run the pass after `applyCapture` (desktop vs browser branch).

**Tests:** colocated Rust `#[cfg(test)]` modules + fixture JSON under `engine/crates/ppcap-core/src/enrich/online/fixtures/`; Vitest `*.test.ts(x)` colocated; shared parity fixture under `ui/src/test/`.

---

## Phase A — Engine core: reputation types + `apply_reputation` (pure, WASM-safe)

*No network. This is the scoring brain every surface shares. Fully TDD'd.*

### Task A1: `RepStatus` + extended `ReputationVerdict` in `enrich/reputation.rs`

**Files:**
- Create: `engine/crates/ppcap-core/src/enrich/reputation.rs`
- Modify: `engine/crates/ppcap-core/src/enrich/mod.rs` (declare module + re-export; remove the old `ReputationVerdict` struct)
- Test: in-file `#[cfg(test)] mod tests`

**Interfaces:**
- Produces: `RepStatus` (enum), `ReputationVerdict { source: String, status: RepStatus, malicious: bool, score: Option<u8>, tags: Vec<String>, link: Option<String>, fetched_at: i64 }`.

- [ ] **Step 1: Write the failing test** — append to the new file:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_serde_roundtrip_snake_case() {
        let v = ReputationVerdict {
            source: "abuseipdb".to_string(),
            status: RepStatus::Malicious,
            malicious: true,
            score: Some(96),
            tags: vec!["ssh".to_string(), "brute-force".to_string()],
            link: Some("https://www.abuseipdb.com/check/203.0.113.7".to_string()),
            fetched_at: 1_750_500_000,
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("\"status\":\"malicious\""));
        let back: ReputationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn status_default_is_unknown() {
        assert_eq!(RepStatus::default(), RepStatus::Unknown);
    }
}
```

- [ ] **Step 2: Write the module** — prepend to `enrich/reputation.rs`:

```rust
//! Always-compiled reputation types + the pure, network-free severity folding.
//!
//! Provider adapters + HTTP live behind the `online` feature in [`crate::enrich::online`];
//! THIS module compiles everywhere (incl. `wasm32`) so the browser applies verdicts via the
//! WASM `apply_reputation` export and gets the SAME scoring as native callers.

use crate::model::severity::Severity;
use crate::model::summary::Summary;
use std::collections::{BTreeMap, HashSet};

/// Per-provider reputation status. Distinguishes "no data" from "clean" so absence is never
/// read as innocence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RepStatus {
    /// Provider asserts malicious → raises severity.
    Malicious,
    /// Provider asserts KNOWN-benign attribution → suppression-worthy (GreyNoise benign / RIOT).
    Benign,
    /// Analyzed, no adverse signal, but no positive benign attribution → 0 pts, never suppresses.
    Clean,
    /// Analyzed but inconclusive.
    Unknown,
    /// Provider has no record (HTTP 404 / NotFoundError) — NOT "clean".
    NotFound,
    /// Lookup failed/skipped: error, bad key, quota exhausted, offline.
    Unavailable,
}

impl Default for RepStatus {
    fn default() -> Self {
        RepStatus::Unknown
    }
}

/// One provider's verdict for one indicator. `source` is a `String` (not `&'static str`) so it
/// round-trips through JSON on the WASM boundary.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReputationVerdict {
    /// `"abuseipdb" | "greynoise" | "virustotal"`.
    pub source: String,
    pub status: RepStatus,
    /// `== matches!(status, RepStatus::Malicious)`. Retained for wire back-compat / convenience.
    pub malicious: bool,
    /// 0..=100; `Some(0)` when `Clean`; `None` when `Unknown`/`NotFound`/`Unavailable`.
    pub score: Option<u8>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Provider report page for the indicator (evidence drill-down).
    #[serde(default)]
    pub link: Option<String>,
    /// Unix seconds the verdict was fetched (cache freshness / "as of" display).
    #[serde(default)]
    pub fetched_at: i64,
}
```

- [ ] **Step 3: Wire the module + remove the old struct** — in `enrich/mod.rs`: delete the existing `pub struct ReputationVerdict { ... }` (the `&'static str` one), add `pub mod reputation;` and `pub use reputation::{apply_reputation, RepStatus, ReputationVerdict};` near the other `pub use`s. Leave `ReputationProvider` + `NoopReputation` (their `lookup_*` returning `Option<ReputationVerdict>` still type-checks against the new struct).

- [ ] **Step 4: Run** — `cd engine && cargo test -p ppcap-core enrich::reputation` → Expected: 2 passed (after Task A3 compiles `apply_reputation`; if A3 not yet written, temporarily stub `pub fn apply_reputation(_: &mut Summary, _: &BTreeMap<String, Vec<ReputationVerdict>>) {}` and the imports resolve). Expected the serde test passes.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(reputation): RepStatus + extended ReputationVerdict (always-compiled)"`

### Task A2: `IpThreat.reputation` field

**Files:**
- Modify: `engine/crates/ppcap-core/src/model/summary.rs:107-123` (IpThreat)
- Test: in-file `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `ReputationVerdict` (A1).
- Produces: `IpThreat.reputation: Vec<ReputationVerdict>`.

- [ ] **Step 1: Write the failing test** — add to summary.rs tests:

```rust
#[test]
fn ipthreat_reputation_defaults_empty_on_old_json() {
    // An older summary row written before the field existed must still deserialize.
    let json = r#"{"ip":"203.0.113.7","ip_class":"public","severity":"low","score":20,
        "flows":3,"bytes":1000,"ioc":false,"tags":["public"],"attack":[],"evidence":[]}"#;
    let row: IpThreat = serde_json::from_str(json).unwrap();
    assert!(row.reputation.is_empty());
}
```

- [ ] **Step 2: Add the field** — in `IpThreat`, after `pub evidence: Vec<String>,`:

```rust
    /// Per-provider online reputation verdicts (empty unless the reputation pass ran).
    /// `#[serde(default)]` keeps older summaries (written before this field) readable.
    #[serde(default)]
    pub reputation: Vec<crate::enrich::ReputationVerdict>,
```

- [ ] **Step 3: Fix construction sites** — `cargo build -p ppcap-core` will fail where `IpThreat { .. }` is built without `reputation` (in `stats/mod.rs`, the row builder near line 493). Add `reputation: Vec::new(),` to that literal.

- [ ] **Step 4: Run** — `cd engine && cargo test -p ppcap-core summary::` → Expected: PASS.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(reputation): IpThreat.reputation field (serde default)"`

### Task A3: `apply_reputation` — raise path (malicious uplift + floors)

**Files:**
- Modify: `engine/crates/ppcap-core/src/enrich/reputation.rs`
- Test: in-file tests

**Interfaces:**
- Produces: `pub fn apply_reputation(summary: &mut Summary, verdicts: &BTreeMap<String, Vec<ReputationVerdict>>)`; private `fn downgrade_one_band(Severity, u16) -> (Severity, u16)`.

- [ ] **Step 1: Write the failing tests** — add a test helper + raise-path tests:

```rust
#[cfg(test)]
mod apply_tests {
    use super::*;
    use crate::enrich::IpClass;
    use crate::model::summary::{IpThreat, Summary, ProtoCounts, SeverityCounts};

    fn verdict(source: &str, status: RepStatus, score: Option<u8>) -> ReputationVerdict {
        ReputationVerdict {
            source: source.to_string(), status, malicious: status == RepStatus::Malicious,
            score, tags: vec![], link: None, fetched_at: 0,
        }
    }

    fn card(ip: &str, class: IpClass, sev: Severity, score: u16, ioc: bool) -> IpThreat {
        IpThreat {
            ip: ip.to_string(), ip_class: class, severity: sev, score, flows: 1, bytes: 100,
            ioc, tags: vec![], attack: vec![], evidence: vec![], reputation: vec![],
        }
    }

    fn summary_with(threats: Vec<IpThreat>, findings: Vec<crate::model::finding::Finding>) -> Summary {
        Summary {
            total_packets: 0, total_bytes: 0, captured_bytes: 0, total_flows: 0, decode_errors: 0,
            non_ip_frames: 0, proto: ProtoCounts::default(), first_ts_ns: None, last_ts_ns: None,
            duration_ns: 0, unique_hosts: 0, top_talkers: vec![], protocol_hierarchy: vec![],
            port_histogram: vec![], time_histogram: vec![], time_bucket_secs: 1,
            category_breakdown: vec![], severity_counts: SeverityCounts::default(),
            ip_threats: threats, findings, incidents: vec![],
        }
    }

    fn map(pairs: Vec<(&str, Vec<ReputationVerdict>)>) -> BTreeMap<String, Vec<ReputationVerdict>> {
        pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    #[test]
    fn single_malicious_floors_to_high() {
        let mut s = summary_with(vec![card("203.0.113.7", IpClass::Public, Severity::Low, 20, false)], vec![]);
        apply_reputation(&mut s, &map(vec![("203.0.113.7", vec![verdict("abuseipdb", RepStatus::Malicious, Some(96))])]));
        let c = &s.ip_threats[0];
        assert_eq!(c.severity, Severity::High);
        assert!(c.score >= 60);
        assert_eq!(c.reputation.len(), 1);
        assert!(c.evidence.iter().any(|e| e.contains("reputation: abuseipdb malicious")));
        assert!(c.evidence.iter().any(|e| e == "floor: reputation malicious forces High (>= 60)"));
    }

    #[test]
    fn consensus_two_malicious_floors_to_critical() {
        let mut s = summary_with(vec![card("203.0.113.7", IpClass::Public, Severity::Medium, 40, false)], vec![]);
        apply_reputation(&mut s, &map(vec![("203.0.113.7", vec![
            verdict("abuseipdb", RepStatus::Malicious, Some(96)),
            verdict("virustotal", RepStatus::Malicious, Some(80)),
        ])]));
        let c = &s.ip_threats[0];
        assert_eq!(c.severity, Severity::Critical);
        assert!(c.score >= 90);
        assert!(c.evidence.iter().any(|e| e.contains("2+ providers agree malicious")));
    }

    #[test]
    fn internal_card_is_untouched() {
        let mut s = summary_with(vec![card("10.0.0.5", IpClass::Private, Severity::Low, 20, false)], vec![]);
        apply_reputation(&mut s, &map(vec![("10.0.0.5", vec![verdict("abuseipdb", RepStatus::Malicious, Some(96))])]));
        assert_eq!(s.ip_threats[0].severity, Severity::Low);
        assert!(s.ip_threats[0].reputation.is_empty());
    }
}
```

- [ ] **Step 2: Run to verify it fails** — `cd engine && cargo test -p ppcap-core enrich::reputation::apply_tests` → Expected: FAIL (`apply_reputation` not yet defined or stub does nothing).

- [ ] **Step 3: Implement** — replace any stub with the real fn (raise + neutral; suppress added in A4) in `reputation.rs`:

```rust
/// Points one malicious provider contributes (a "soft IOC" — see `score::PTS_IOC`).
const PTS_REP_MALICIOUS: u16 = 25;
/// Ceiling on total reputation uplift — multiple providers cannot exceed one soft IOC in points;
/// consensus escalates via the Critical FLOOR, not via runaway points.
const REP_UPLIFT_CAP: u16 = 25;

/// Fold per-indicator reputation verdicts into the per-IP threat cards. Pure + deterministic;
/// mirrors `score::score_flow`'s idiom (bounded points, an evidence line per adjustment). Applies
/// ONLY to public-IP cards. `verdicts` is keyed by the card's `ip` string.
pub fn apply_reputation(
    summary: &mut Summary,
    verdicts: &BTreeMap<String, Vec<ReputationVerdict>>,
) {
    // Hosts with a behavioral finding can never be suppressed (local detectors outrank online
    // benign attribution). Key on src_ip AND dst_ip.
    let finding_hosts: HashSet<&str> = summary
        .findings
        .iter()
        .flat_map(|f| std::iter::once(f.src_ip.as_str()).chain(f.dst_ip.as_deref()))
        .collect();

    for card in summary.ip_threats.iter_mut() {
        if !card.ip_class.is_external() {
            continue;
        }
        let Some(vs) = verdicts.get(&card.ip) else { continue };
        if vs.is_empty() {
            continue;
        }
        card.reputation = vs.clone();

        let mal_count = vs.iter().filter(|v| v.status == RepStatus::Malicious).count();
        let has_benign = vs.iter().any(|v| v.status == RepStatus::Benign);

        if mal_count >= 1 {
            let points = (PTS_REP_MALICIOUS * mal_count as u16).min(REP_UPLIFT_CAP);
            card.score = (card.score + points).min(100);
            for v in vs.iter().filter(|v| v.status == RepStatus::Malicious) {
                let pct = v.score.map(|s| format!(" {s}%")).unwrap_or_default();
                let tags = if v.tags.is_empty() { String::new() } else { format!(" [{}]", v.tags.join(",")) };
                card.evidence.push(format!("reputation: {} malicious{}{} (+{})", v.source, pct, tags, points));
            }
            let mut sev = Severity::from_score(card.score);
            if sev < Severity::High {
                sev = Severity::High;
                card.score = card.score.max(60);
                card.evidence.push("floor: reputation malicious forces High (>= 60)".to_string());
            }
            if mal_count >= 2 {
                sev = Severity::Critical;
                card.score = card.score.max(90);
                card.evidence.push("floor: 2+ providers agree malicious forces Critical (>= 90)".to_string());
            }
            card.severity = sev;
            if !card.tags.iter().any(|t| t == "reputation") {
                card.tags.push("reputation".to_string());
            }
        } else if has_benign && !card.ioc && !finding_hosts.contains(card.ip.as_str()) {
            // Suppress path implemented in Task A4.
            suppress(card, vs);
        }
        // Clean / Unknown / NotFound / Unavailable: attached above; no score/severity change.
    }

    // A reputation uplift can reorder the table — re-sort (mirrors `stats.finish()` ordering).
    summary.ip_threats.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then(b.severity.rank().cmp(&a.severity.rank()))
            .then(b.flows.cmp(&a.flows))
            .then(a.ip.cmp(&b.ip))
    });
}

fn downgrade_one_band(sev: Severity, score: u16) -> (Severity, u16) {
    match sev {
        Severity::Critical => (Severity::High, score.min(84)),
        Severity::High => (Severity::Medium, score.min(59)),
        Severity::Medium => (Severity::Low, score.min(34)),
        Severity::Low => (Severity::Info, score.min(14)),
        Severity::Info => (Severity::Info, score),
    }
}

// Placeholder until Task A4 fills it in.
fn suppress(_card: &mut crate::model::summary::IpThreat, _vs: &[ReputationVerdict]) {}
```

- [ ] **Step 4: Run** — `cd engine && cargo test -p ppcap-core enrich::reputation::apply_tests` → Expected: PASS (3 raise/guard tests).

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(reputation): apply_reputation raise path (single->High, consensus->Critical)"`

### Task A4: `apply_reputation` — suppress path (GreyNoise benign, guarded)

**Files:**
- Modify: `engine/crates/ppcap-core/src/enrich/reputation.rs`
- Test: in-file tests

**Interfaces:**
- Consumes: `downgrade_one_band` (A3).
- Produces: real `fn suppress(card, vs)`.

- [ ] **Step 1: Write the failing tests** — add to `apply_tests`:

```rust
    fn benign(source: &str, name: &str) -> ReputationVerdict {
        ReputationVerdict {
            source: source.to_string(), status: RepStatus::Benign, malicious: false,
            score: Some(5), tags: vec![name.to_string()], link: None, fetched_at: 0,
        }
    }

    fn finding(src_ip: &str) -> crate::model::finding::Finding {
        crate::model::finding::Finding {
            kind: crate::model::finding::FindingKind::Beacon, severity: Severity::High, score: 70,
            title: "t".to_string(), src_ip: src_ip.to_string(), dst_ip: None, dst_port: None,
            attack: vec![], evidence: vec![], interval_ns: None, jitter_cv: None, contacts: None,
        }
    }

    #[test]
    fn benign_downgrades_one_band_when_unguarded() {
        let mut s = summary_with(vec![card("203.0.113.9", IpClass::Public, Severity::Medium, 40, false)], vec![]);
        apply_reputation(&mut s, &map(vec![("203.0.113.9", vec![benign("greynoise", "Shodan.io")])]));
        let c = &s.ip_threats[0];
        assert_eq!(c.severity, Severity::Low);
        assert!(c.score <= 34);
        assert!(c.evidence.iter().any(|e| e.contains("known benign")));
    }

    #[test]
    fn benign_never_suppresses_a_card_with_local_ioc() {
        let mut s = summary_with(vec![card("203.0.113.9", IpClass::Public, Severity::High, 65, true)], vec![]);
        apply_reputation(&mut s, &map(vec![("203.0.113.9", vec![benign("greynoise", "Shodan.io")])]));
        assert_eq!(s.ip_threats[0].severity, Severity::High);
    }

    #[test]
    fn benign_never_suppresses_a_host_with_behavioral_finding() {
        let mut s = summary_with(
            vec![card("203.0.113.9", IpClass::Public, Severity::High, 70, false)],
            vec![finding("203.0.113.9")],
        );
        apply_reputation(&mut s, &map(vec![("203.0.113.9", vec![benign("greynoise", "Shodan.io")])]));
        assert_eq!(s.ip_threats[0].severity, Severity::High);
    }
```

- [ ] **Step 2: Run to verify it fails** — `cd engine && cargo test -p ppcap-core enrich::reputation::apply_tests::benign` → Expected: FAIL (suppress is a no-op stub).

- [ ] **Step 3: Implement `suppress`** — replace the placeholder:

```rust
/// Downgrade a card one severity band on a positive known-benign attribution (GreyNoise
/// benign / RIOT). Caller has already verified: no local IOC, no behavioral finding.
fn suppress(card: &mut crate::model::summary::IpThreat, vs: &[ReputationVerdict]) {
    let b = vs.iter().find(|v| v.status == RepStatus::Benign);
    let (src, name) = b
        .map(|v| (v.source.as_str(), v.tags.first().map(String::as_str).unwrap_or("known benign")))
        .unwrap_or(("reputation", "known benign"));
    card.evidence.push(format!("reputation: {src} benign '{name}' — known benign (-1 band)"));
    let (sev, score) = downgrade_one_band(card.severity, card.score);
    card.severity = sev;
    card.score = score;
}
```

- [ ] **Step 4: Run** — `cd engine && cargo test -p ppcap-core enrich::reputation` → Expected: PASS (all raise + suppress tests).

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(reputation): apply_reputation suppress path (guarded GreyNoise benign)"`

### Task A5: neutral statuses attach without effect + re-sort proof

**Files:**
- Modify: `engine/crates/ppcap-core/src/enrich/reputation.rs` (tests only)

- [ ] **Step 1: Write the tests** — add to `apply_tests`:

```rust
    #[test]
    fn unknown_and_notfound_attach_but_dont_move_score() {
        let mut s = summary_with(vec![card("203.0.113.7", IpClass::Public, Severity::Low, 20, false)], vec![]);
        apply_reputation(&mut s, &map(vec![("203.0.113.7", vec![
            verdict("greynoise", RepStatus::NotFound, None),
            verdict("virustotal", RepStatus::Unknown, None),
        ])]));
        let c = &s.ip_threats[0];
        assert_eq!(c.severity, Severity::Low);
        assert_eq!(c.score, 20);
        assert_eq!(c.reputation.len(), 2);
    }

    #[test]
    fn uplifted_card_resorts_to_top() {
        let mut s = summary_with(vec![
            card("203.0.113.1", IpClass::Public, Severity::High, 70, false),
            card("203.0.113.2", IpClass::Public, Severity::Low, 20, false),
        ], vec![]);
        // The low card gets consensus-malicious -> Critical, must rise to index 0.
        apply_reputation(&mut s, &map(vec![("203.0.113.2", vec![
            verdict("abuseipdb", RepStatus::Malicious, Some(96)),
            verdict("greynoise", RepStatus::Malicious, Some(90)),
        ])]));
        assert_eq!(s.ip_threats[0].ip, "203.0.113.2");
        assert_eq!(s.ip_threats[0].severity, Severity::Critical);
    }
```

- [ ] **Step 2: Run** — `cd engine && cargo test -p ppcap-core enrich::reputation` → Expected: PASS (logic already supports these; no impl change).

- [ ] **Step 3: Commit** — `git add -A && git commit -m "test(reputation): neutral statuses + re-sort coverage"`

### Task A6: public exports

**Files:**
- Modify: `engine/crates/ppcap-core/src/lib.rs`

- [ ] **Step 1: Add exports** — in the `pub use crate::enrich::{...}` block (near line 54), add `apply_reputation, RepStatus, ReputationVerdict` (and keep `BTreeMap` available to callers — it's `std`). Confirm `pub use` compiles.

- [ ] **Step 2: Run** — `cd engine && cargo build -p ppcap-core && cargo test -p ppcap-core` → Expected: full suite green (325+ tests).

- [ ] **Step 3: Confirm wasm-safety** — `cd engine/crates/ppcap-wasm && cargo build --release` → Expected: builds (proves `apply_reputation` + types compile for `wasm32` with no `online` feature).

- [ ] **Step 4: Commit** — `git add -A && git commit -m "feat(reputation): export apply_reputation + types from ppcap-core"`

---

## Phase B — Engine `online` module (native, feature-gated): HTTP, adapters, cache, budget, orchestrator

*All of Phase B is behind `#[cfg(feature = "online")]`. Run its tests with `--features online`. The browser does NOT use this code (it has TS adapters); it keeps the WASM binary lean.*

### Task B1: `online` cargo feature + `ureq` dep + module skeleton

**Files:**
- Modify: `engine/Cargo.toml` (`[workspace.dependencies]`)
- Modify: `engine/crates/ppcap-core/Cargo.toml` (`[dependencies]` + `[features]`)
- Modify: `engine/crates/ppcap-wasm/Cargo.toml` (block features)
- Create: `engine/crates/ppcap-core/src/enrich/online/mod.rs`
- Modify: `engine/crates/ppcap-core/src/enrich/mod.rs` (declare gated module)

**Interfaces:**
- Produces: `pub trait HttpGet`, `pub struct HttpResponse { status: u16, body: String }`, `pub enum RepError`, `#[cfg(test)] struct FakeHttp`.

- [ ] **Step 1: Add the workspace dep** — in `engine/Cargo.toml` `[workspace.dependencies]`:

```toml
# Pure-Rust HTTP client (rustls TLS, no C deps) for online reputation lookups.
# NOTE: pin to 2.x — its response API is `.call()?.into_string()?`. ureq 3.x changed this
# (`.body_mut().read_to_string()`); if cargo resolves 3.x, either pin "=2.x" or update UreqClient.
ureq = { version = "2", default-features = false, features = ["tls"] }
```

- [ ] **Step 2: Gate it in ppcap-core** — in `engine/crates/ppcap-core/Cargo.toml`, add under `[dependencies]` then a new `[features]` section (AFTER `[dependencies]`):

```toml
[dependencies]
# ... existing deps unchanged ...
ureq = { workspace = true, optional = true }

[features]
default = []
# Native-only online reputation lookups (AbuseIPDB / GreyNoise / VirusTotal). Pulls ureq.
online = ["dep:ureq"]
```

- [ ] **Step 3: Block features in wasm** — in `engine/crates/ppcap-wasm/Cargo.toml`, make the ppcap-core dep explicit:

```toml
ppcap-core = { path = "../ppcap-core", default-features = false, features = [] }
```

- [ ] **Step 4: Write the module skeleton** — `engine/crates/ppcap-core/src/enrich/online/mod.rs`:

```rust
//! Native-only online reputation lookups (feature `online`). Provider adapters map each API's
//! response into `ReputationVerdict`; a keyed on-disk cache + per-provider daily budget keep the
//! free tiers usable. The pure scoring fold lives in `crate::enrich::reputation` (always compiled).

use std::net::IpAddr;

pub mod abuseipdb;
pub mod greynoise;
pub mod virustotal;
mod budget;
mod cache;

pub use budget::Budget;
pub use cache::ReputationCache;

/// Minimal HTTP response surface the adapters need.
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// Transport errors (the adapter turns these into a `RepStatus::Unavailable` verdict).
#[derive(Debug)]
pub enum RepError {
    Network(String),
}

/// A blocking HTTP GET. Real impl is `UreqClient`; tests inject a fake. Adapters depend on the
/// trait, never on `ureq` directly, so they unit-test with zero network.
pub trait HttpGet {
    fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse, RepError>;
}

/// The three provider API keys; a provider is active iff its key is `Some`.
#[derive(Debug, Clone, Default)]
pub struct ReputationKeys {
    pub abuseipdb: Option<String>,
    pub greynoise: Option<String>,
    pub virustotal: Option<String>,
}

impl ReputationKeys {
    /// True when no provider is configured (the pass is a no-op).
    pub fn is_empty(&self) -> bool {
        self.abuseipdb.is_none() && self.greynoise.is_none() && self.virustotal.is_none()
    }
}

#[cfg(test)]
pub(crate) struct FakeHttp {
    /// (status, body) returned for every call; the URL is captured for assertions.
    pub response: (u16, String),
    pub last_url: std::cell::RefCell<String>,
}

#[cfg(test)]
impl HttpGet for FakeHttp {
    fn get(&self, url: &str, _headers: &[(&str, &str)]) -> Result<HttpResponse, RepError> {
        *self.last_url.borrow_mut() = url.to_string();
        Ok(HttpResponse { status: self.response.0, body: self.response.1.clone() })
    }
}

#[cfg(test)]
impl FakeHttp {
    pub fn new(status: u16, body: &str) -> Self {
        FakeHttp { response: (status, body.to_string()), last_url: std::cell::RefCell::new(String::new()) }
    }
}

/// Helper: is this address worth a lookup (public/routable)?
pub(crate) fn is_lookupable(ip: IpAddr) -> bool {
    crate::enrich::classify_ip(ip).is_external()
}
```

- [ ] **Step 5: Declare the gated module** — in `enrich/mod.rs`: `#[cfg(feature = "online")] pub mod online;`

- [ ] **Step 6: Verify both builds** — Run:
  - `cd engine && cargo build -p ppcap-core` → Expected: builds, no `ureq` (default features).
  - `cd engine && cargo build -p ppcap-core --features online` → Expected: builds with `ureq` (will warn about empty submodules until B2–B6; create empty `abuseipdb.rs`/`greynoise.rs`/`virustotal.rs`/`budget.rs`/`cache.rs` with a `// stub` line to satisfy the `mod` decls, or write them in order B2→B6 before this passes).
  - `cd engine/crates/ppcap-wasm && cargo build --release` → Expected: builds, no ureq.

- [ ] **Step 7: Commit** — `git add -A && git commit -m "feat(reputation): online feature + ureq dep + HttpGet skeleton"`

### Task B2: AbuseIPDB adapter

**Files:**
- Create: `engine/crates/ppcap-core/src/enrich/online/abuseipdb.rs`
- Test: in-file

**Interfaces:**
- Consumes: `HttpGet`, `ReputationVerdict`, `RepStatus`.
- Produces: `pub fn verdict(http: &dyn HttpGet, key: &str, ip: IpAddr, now: i64) -> ReputationVerdict`.

- [ ] **Step 1: Write the failing tests:**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::online::FakeHttp;
    use crate::enrich::RepStatus;
    use std::net::IpAddr;

    fn ip() -> IpAddr { "203.0.113.7".parse().unwrap() }

    #[test]
    fn high_confidence_is_malicious() {
        let body = r#"{"data":{"abuseConfidenceScore":96,"totalReports":42,"isWhitelisted":false,
            "usageType":"Data Center/Web Hosting/Transit","isTor":false,"countryCode":"NL"}}"#;
        let v = verdict(&FakeHttp::new(200, body), "k", ip(), 1234);
        assert_eq!(v.status, RepStatus::Malicious);
        assert!(v.malicious);
        assert_eq!(v.score, Some(96));
        assert_eq!(v.source, "abuseipdb");
        assert_eq!(v.fetched_at, 1234);
        assert!(v.tags.iter().any(|t| t.contains("Data Center")));
        assert_eq!(v.link.as_deref(), Some("https://www.abuseipdb.com/check/203.0.113.7"));
    }

    #[test]
    fn zero_reports_is_clean_not_malicious() {
        let body = r#"{"data":{"abuseConfidenceScore":0,"totalReports":0}}"#;
        let v = verdict(&FakeHttp::new(200, body), "k", ip(), 0);
        assert_eq!(v.status, RepStatus::Clean);
        assert!(!v.malicious);
        assert_eq!(v.score, Some(0));
    }

    #[test]
    fn rate_limited_is_unavailable() {
        let v = verdict(&FakeHttp::new(429, "{}"), "k", ip(), 0);
        assert_eq!(v.status, RepStatus::Unavailable);
        assert_eq!(v.score, None);
    }
}
```

- [ ] **Step 2: Run** — `cd engine && cargo test -p ppcap-core --features online abuseipdb` → Expected: FAIL (no `verdict`).

- [ ] **Step 3: Implement:**

```rust
//! AbuseIPDB API v2 `/check` adapter (IP only). Header auth `Key: <key>`; score is the native
//! `abuseConfidenceScore` (0..=100). See spec §7.1.

use super::{HttpGet, RepError};
use crate::enrich::{RepStatus, ReputationVerdict};
use std::net::IpAddr;

#[derive(serde::Deserialize)]
struct Resp {
    data: Data,
}
#[derive(serde::Deserialize)]
struct Data {
    #[serde(rename = "abuseConfidenceScore")]
    abuse_confidence_score: u8,
    #[serde(rename = "totalReports", default)]
    total_reports: u64,
    #[serde(rename = "usageType", default)]
    usage_type: Option<String>,
    #[serde(rename = "isTor", default)]
    is_tor: Option<bool>,
    #[serde(rename = "countryCode", default)]
    country_code: Option<String>,
}

const SOURCE: &str = "abuseipdb";

fn unavailable(now: i64) -> ReputationVerdict {
    ReputationVerdict {
        source: SOURCE.to_string(), status: RepStatus::Unavailable, malicious: false,
        score: None, tags: vec![], link: None, fetched_at: now,
    }
}

/// Look up one IP. Network errors / non-200 / parse failures degrade to `Unavailable`.
pub fn verdict(http: &dyn HttpGet, key: &str, ip: IpAddr, now: i64) -> ReputationVerdict {
    let url = format!("https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90");
    let resp = match http.get(&url, &[("Key", key), ("Accept", "application/json")]) {
        Ok(r) => r,
        Err(RepError::Network(_)) => return unavailable(now),
    };
    if resp.status != 200 {
        return unavailable(now);
    }
    let Ok(parsed) = serde_json::from_str::<Resp>(&resp.body) else {
        return unavailable(now);
    };
    let d = parsed.data;
    let score = d.abuse_confidence_score;
    let status = if score >= 75 {
        RepStatus::Malicious
    } else if score >= 25 {
        RepStatus::Unknown
    } else if d.total_reports == 0 {
        RepStatus::Clean
    } else {
        RepStatus::Unknown
    };
    let mut tags = Vec::new();
    if let Some(u) = d.usage_type { tags.push(u); }
    if d.is_tor == Some(true) { tags.push("tor".to_string()); }
    if let Some(c) = d.country_code { tags.push(c); }
    ReputationVerdict {
        source: SOURCE.to_string(),
        status,
        malicious: status == RepStatus::Malicious,
        score: Some(score),
        tags,
        link: Some(format!("https://www.abuseipdb.com/check/{ip}")),
        fetched_at: now,
    }
}
```

- [ ] **Step 4: Run** — `cd engine && cargo test -p ppcap-core --features online abuseipdb` → Expected: PASS (3).

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(reputation): AbuseIPDB adapter"`

### Task B3: GreyNoise adapter

**Files:**
- Create: `engine/crates/ppcap-core/src/enrich/online/greynoise.rs`
- Test: in-file

**Interfaces:**
- Produces: `pub fn verdict(http: &dyn HttpGet, key: &str, ip: IpAddr, now: i64) -> ReputationVerdict`.

- [ ] **Step 1: Write the failing tests:**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::online::FakeHttp;
    use crate::enrich::RepStatus;
    use std::net::IpAddr;
    fn ip() -> IpAddr { "203.0.113.7".parse().unwrap() }

    #[test]
    fn classification_malicious() {
        let body = r#"{"ip":"203.0.113.7","noise":true,"riot":false,"classification":"malicious",
            "name":"unknown","link":"https://viz.greynoise.io/ip/203.0.113.7","last_seen":"2026-06-20"}"#;
        let v = verdict(&FakeHttp::new(200, body), "k", ip(), 0);
        assert_eq!(v.status, RepStatus::Malicious);
        assert!(v.malicious);
    }

    #[test]
    fn benign_actor_suppresses() {
        let body = r#"{"ip":"203.0.113.7","noise":true,"riot":false,"classification":"benign",
            "name":"Shodan.io","link":"x","last_seen":"2026-06-20"}"#;
        let v = verdict(&FakeHttp::new(200, body), "k", ip(), 0);
        assert_eq!(v.status, RepStatus::Benign);
        assert!(v.tags.iter().any(|t| t == "Shodan.io"));
    }

    #[test]
    fn riot_is_benign_context() {
        let body = r#"{"ip":"8.8.8.8","noise":false,"riot":true,"classification":"unknown","name":"Google"}"#;
        let v = verdict(&FakeHttp::new(200, body), "k", ip(), 0);
        assert_eq!(v.status, RepStatus::Benign);
        assert!(v.tags.iter().any(|t| t == "business-service"));
    }

    #[test]
    fn not_found_404_is_notfound_not_clean() {
        let body = r#"{"ip":"203.0.113.7","noise":false,"riot":false,"message":"IP not observed..."}"#;
        let v = verdict(&FakeHttp::new(404, body), "k", ip(), 0);
        assert_eq!(v.status, RepStatus::NotFound);
    }

    #[test]
    fn forbidden_403_is_unavailable() {
        let v = verdict(&FakeHttp::new(403, ""), "k", ip(), 0);
        assert_eq!(v.status, RepStatus::Unavailable);
    }
}
```

- [ ] **Step 2: Run** — `cd engine && cargo test -p ppcap-core --features online greynoise` → Expected: FAIL.

- [ ] **Step 3: Implement:**

```rust
//! GreyNoise Community API `/v3/community/{ip}` adapter (IP only). Header auth `key: <key>`.
//! `classification` is the verdict gate; benign/RIOT are the false-positive suppressors. 404 is a
//! real "not observed" body, NOT clean. See spec §7.2.

use super::{HttpGet, RepError};
use crate::enrich::{RepStatus, ReputationVerdict};
use std::net::IpAddr;

#[derive(serde::Deserialize, Default)]
struct Resp {
    #[serde(default)]
    noise: bool,
    #[serde(default)]
    riot: bool,
    #[serde(default)]
    classification: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    link: Option<String>,
}

const SOURCE: &str = "greynoise";

fn simple(status: RepStatus, score: Option<u8>, now: i64) -> ReputationVerdict {
    ReputationVerdict {
        source: SOURCE.to_string(), status, malicious: status == RepStatus::Malicious,
        score, tags: vec![], link: None, fetched_at: now,
    }
}

pub fn verdict(http: &dyn HttpGet, key: &str, ip: IpAddr, now: i64) -> ReputationVerdict {
    let url = format!("https://api.greynoise.io/v3/community/{ip}");
    let resp = match http.get(&url, &[("key", key)]) {
        Ok(r) => r,
        Err(RepError::Network(_)) => return simple(RepStatus::Unavailable, None, now),
    };
    match resp.status {
        404 => return simple(RepStatus::NotFound, Some(0), now),
        200 => {}
        _ => return simple(RepStatus::Unavailable, None, now),
    }
    let Ok(r) = serde_json::from_str::<Resp>(&resp.body) else {
        return simple(RepStatus::Unavailable, None, now);
    };

    let (status, score) = if r.classification == "malicious" {
        (RepStatus::Malicious, Some(95))
    } else if r.classification == "benign" || r.riot {
        (RepStatus::Benign, Some(5))
    } else {
        (RepStatus::Unknown, Some(if r.noise { 50 } else { 0 }))
    };

    let mut tags = Vec::new();
    if !r.name.is_empty() && r.name != "unknown" { tags.push(r.name); }
    if r.riot { tags.push("business-service".to_string()); }
    if r.noise { tags.push("internet-scanner".to_string()); }

    ReputationVerdict {
        source: SOURCE.to_string(),
        status,
        malicious: status == RepStatus::Malicious,
        score,
        tags,
        link: r.link.or_else(|| Some(format!("https://viz.greynoise.io/ip/{ip}"))),
        fetched_at: now,
    }
}
```

- [ ] **Step 4: Run** — `cd engine && cargo test -p ppcap-core --features online greynoise` → Expected: PASS (5).

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(reputation): GreyNoise adapter (benign/RIOT suppressors)"`

### Task B4: VirusTotal adapter (IP + domain, one parser)

**Files:**
- Create: `engine/crates/ppcap-core/src/enrich/online/virustotal.rs`
- Test: in-file

**Interfaces:**
- Produces: `pub fn verdict_ip(http, key, ip, now) -> ReputationVerdict`; `pub fn verdict_domain(http, key, domain, now) -> ReputationVerdict`.

- [ ] **Step 1: Write the failing tests:**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::online::FakeHttp;
    use crate::enrich::RepStatus;
    use std::net::IpAddr;
    fn ip() -> IpAddr { "203.0.113.7".parse().unwrap() }

    #[test]
    fn malicious_engines_flag() {
        let body = r#"{"data":{"id":"203.0.113.7","type":"ip_address","attributes":{
            "last_analysis_stats":{"malicious":8,"suspicious":2,"harmless":70,"undetected":10,"timeout":0},
            "tags":["malware"],"as_owner":"EvilCorp","country":"NL"}}}"#;
        let v = verdict_ip(&FakeHttp::new(200, body), "k", ip(), 0);
        assert_eq!(v.status, RepStatus::Malicious);
        assert_eq!(v.score, Some(9)); // round(100*8/90)
        assert!(v.tags.iter().any(|t| t == "malware"));
    }

    #[test]
    fn all_harmless_is_clean() {
        let body = r#"{"data":{"attributes":{"last_analysis_stats":
            {"malicious":0,"suspicious":0,"harmless":85,"undetected":5,"timeout":0}}}}"#;
        let v = verdict_ip(&FakeHttp::new(200, body), "k", ip(), 0);
        assert_eq!(v.status, RepStatus::Clean);
        assert_eq!(v.score, Some(0));
    }

    #[test]
    fn not_found_is_notfound() {
        let v = verdict_ip(&FakeHttp::new(404, r#"{"error":{"code":"NotFoundError"}}"#), "k", ip(), 0);
        assert_eq!(v.status, RepStatus::NotFound);
    }

    #[test]
    fn domain_uses_same_parser() {
        let body = r#"{"data":{"attributes":{"last_analysis_stats":
            {"malicious":3,"suspicious":0,"harmless":60,"undetected":7,"timeout":0}}}}"#;
        let v = verdict_domain(&FakeHttp::new(200, body), "k", "evil.example.com", 0);
        assert_eq!(v.status, RepStatus::Malicious);
        assert_eq!(v.link.as_deref(), Some("https://www.virustotal.com/gui/domain/evil.example.com"));
    }
}
```

- [ ] **Step 2: Run** — `cd engine && cargo test -p ppcap-core --features online virustotal` → Expected: FAIL.

- [ ] **Step 3: Implement:**

```rust
//! VirusTotal API v3 adapter for IP (`/ip_addresses/{ip}`) and domain (`/domains/{d}`). Header
//! auth `x-apikey: <key>`. Score is the malicious ratio over the engine stats actually present —
//! never the signed `reputation` field. Missing stats / 404 ⇒ not "clean". See spec §7.3.

use super::{HttpGet, RepError};
use crate::enrich::{RepStatus, ReputationVerdict};
use std::net::IpAddr;

#[derive(serde::Deserialize)]
struct Resp {
    data: DataObj,
}
#[derive(serde::Deserialize)]
struct DataObj {
    attributes: Attrs,
}
#[derive(serde::Deserialize, Default)]
struct Attrs {
    #[serde(default)]
    last_analysis_stats: Option<Stats>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    as_owner: Option<String>,
    #[serde(default)]
    country: Option<String>,
}
#[derive(serde::Deserialize, Default)]
struct Stats {
    #[serde(default)]
    malicious: u32,
    #[serde(default)]
    suspicious: u32,
    #[serde(default)]
    harmless: u32,
    #[serde(default)]
    undetected: u32,
}

const SOURCE: &str = "virustotal";

fn simple(status: RepStatus, score: Option<u8>, now: i64) -> ReputationVerdict {
    ReputationVerdict {
        source: SOURCE.to_string(), status, malicious: status == RepStatus::Malicious,
        score, tags: vec![], link: None, fetched_at: now,
    }
}

fn parse(body: &str, status_code: u16, link: String, now: i64) -> ReputationVerdict {
    match status_code {
        404 => return simple(RepStatus::NotFound, None, now),
        200 => {}
        _ => return simple(RepStatus::Unavailable, None, now),
    }
    let Ok(r) = serde_json::from_str::<Resp>(body) else {
        return simple(RepStatus::Unavailable, None, now);
    };
    let Some(st) = r.data.attributes.last_analysis_stats else {
        return simple(RepStatus::Unknown, None, now); // analyzed-but-no-stats ⇒ unknown, not clean
    };
    let total = (st.malicious + st.suspicious + st.harmless + st.undetected).max(1);
    let score = ((100u32 * st.malicious) / total) as u8;
    let status = if st.malicious > 0 {
        RepStatus::Malicious
    } else if st.suspicious == 0 && st.harmless > 0 {
        RepStatus::Clean
    } else {
        RepStatus::Unknown
    };
    let mut tags = r.data.attributes.tags;
    if let Some(o) = r.data.attributes.as_owner { tags.push(o); }
    if let Some(c) = r.data.attributes.country { tags.push(c); }
    ReputationVerdict {
        source: SOURCE.to_string(),
        status,
        malicious: status == RepStatus::Malicious,
        score: Some(score),
        tags,
        link: Some(link),
        fetched_at: now,
    }
}

pub fn verdict_ip(http: &dyn HttpGet, key: &str, ip: IpAddr, now: i64) -> ReputationVerdict {
    let url = format!("https://www.virustotal.com/api/v3/ip_addresses/{ip}");
    match http.get(&url, &[("x-apikey", key)]) {
        Ok(r) => parse(&r.body, r.status, format!("https://www.virustotal.com/gui/ip-address/{ip}"), now),
        Err(RepError::Network(_)) => simple(RepStatus::Unavailable, None, now),
    }
}

pub fn verdict_domain(http: &dyn HttpGet, key: &str, domain: &str, now: i64) -> ReputationVerdict {
    let url = format!("https://www.virustotal.com/api/v3/domains/{domain}");
    match http.get(&url, &[("x-apikey", key)]) {
        Ok(r) => parse(&r.body, r.status, format!("https://www.virustotal.com/gui/domain/{domain}"), now),
        Err(RepError::Network(_)) => simple(RepStatus::Unavailable, None, now),
    }
}
```

- [ ] **Step 4: Run** — `cd engine && cargo test -p ppcap-core --features online virustotal` → Expected: PASS (4).

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(reputation): VirusTotal adapter (IP + domain)"`

### Task B5: keyed on-disk cache with TTL + atomic write

**Files:**
- Create: `engine/crates/ppcap-core/src/enrich/online/cache.rs`
- Test: in-file (uses `tempfile`, already a dev-dep)

**Interfaces:**
- Produces: `ReputationCache::{load, get, put, save}`; key = `"{source}|{indicator}"`.

- [ ] **Step 1: Write the failing tests:**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::{RepStatus, ReputationVerdict};

    fn v(now: i64) -> ReputationVerdict {
        ReputationVerdict { source: "abuseipdb".to_string(), status: RepStatus::Malicious,
            malicious: true, score: Some(90), tags: vec![], link: None, fetched_at: now }
    }

    #[test]
    fn hit_within_ttl_miss_after() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = ReputationCache::load(dir.path());
        c.put("abuseipdb", "203.0.113.7", v(1000)); // fetched_at = 1000
        // now=1100, ttl=600 -> age 100 <= 600 -> fresh (hit).
        assert!(c.get("abuseipdb", "203.0.113.7", 1100, 600).is_some());
        // now=2000, ttl=600 -> age 1000 > 600 -> stale (miss).
        assert!(c.get("abuseipdb", "203.0.113.7", 2000, 600).is_none());
    }

    #[test]
    fn persists_across_load() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut c = ReputationCache::load(dir.path());
            c.put("greynoise", "203.0.113.7", v(1000));
            c.save().unwrap();
        }
        let c2 = ReputationCache::load(dir.path());
        assert!(c2.get("greynoise", "203.0.113.7", 1100, 600).is_some());
    }
}
```

- [ ] **Step 2: Run** — `cd engine && cargo test -p ppcap-core --features online cache` → Expected: FAIL.

- [ ] **Step 3: Implement:**

```rust
//! Keyed on-disk reputation cache. A single JSON map under `<cache_dir>/reputation.json`, written
//! atomically (tmp + rename). Private/local-only per provider ToS; the caller chooses the TTL.

use crate::enrich::ReputationVerdict;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub struct ReputationCache {
    path: PathBuf,
    entries: BTreeMap<String, ReputationVerdict>,
}

fn key(source: &str, indicator: &str) -> String {
    format!("{source}|{indicator}")
}

impl ReputationCache {
    /// Load (or start empty) from `<cache_dir>/reputation.json`. Never fails — a missing/corrupt
    /// file yields an empty cache (best-effort, like the UI's IndexedDB cache).
    pub fn load(cache_dir: &Path) -> Self {
        let path = cache_dir.join("reputation.json");
        let entries = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        ReputationCache { path, entries }
    }

    /// Fresh verdict for `(source, indicator)` if `now - fetched_at <= ttl_secs`, else `None`.
    pub fn get(&self, source: &str, indicator: &str, now: i64, ttl_secs: i64) -> Option<&ReputationVerdict> {
        self.entries
            .get(&key(source, indicator))
            .filter(|v| now.saturating_sub(v.fetched_at) <= ttl_secs)
    }

    pub fn put(&mut self, source: &str, indicator: &str, verdict: ReputationVerdict) {
        self.entries.insert(key(source, indicator), verdict);
    }

    /// Atomically persist (tmp file + rename). Best-effort; returns the io error if the rename fails.
    pub fn save(&self) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string(&self.entries).unwrap_or_default())?;
        std::fs::rename(&tmp, &self.path)
    }
}
```

- [ ] **Step 4: Run** — `cd engine && cargo test -p ppcap-core --features online cache` → Expected: PASS (2).

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(reputation): on-disk cache with TTL + atomic write"`

### Task B6: per-provider daily budget

**Files:**
- Create: `engine/crates/ppcap-core/src/enrich/online/budget.rs`
- Test: in-file

**Interfaces:**
- Produces: `Budget::{with_defaults, try_spend, exhausted}` keyed by source string.

- [ ] **Step 1: Write the failing tests:**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_reflect_free_tiers() {
        let mut b = Budget::with_defaults();
        // GreyNoise is the tightest; should run out long before AbuseIPDB.
        assert!(b.try_spend("greynoise"));
        for _ in 0..50 { b.try_spend("greynoise"); }
        assert!(b.exhausted("greynoise"));
        assert!(b.try_spend("abuseipdb")); // still has plenty
    }
}
```

- [ ] **Step 2: Run** — `cd engine && cargo test -p ppcap-core --features online budget` → Expected: FAIL.

- [ ] **Step 3: Implement:**

```rust
//! Per-provider daily lookup budget (the binding constraint on free tiers: GreyNoise ~10/day,
//! VirusTotal 500/day, AbuseIPDB 1000/day — each with a safety margin). Cache hits cost nothing;
//! only live fetches call `try_spend`. Over-budget indicators are surfaced, never silently dropped.

use std::collections::HashMap;

pub struct Budget {
    remaining: HashMap<&'static str, u32>,
}

impl Budget {
    /// Conservative defaults (free quota minus margin). Tunable later via config.
    pub fn with_defaults() -> Self {
        let mut remaining = HashMap::new();
        remaining.insert("greynoise", 9); // ~10/day
        remaining.insert("virustotal", 480); // 500/day
        remaining.insert("abuseipdb", 950); // 1000/day
        Budget { remaining }
    }

    /// Try to consume one unit for `source`; `false` if exhausted (or unknown source).
    pub fn try_spend(&mut self, source: &str) -> bool {
        match self.remaining.get_mut(source) {
            Some(n) if *n > 0 => {
                *n -= 1;
                true
            }
            _ => false,
        }
    }

    pub fn exhausted(&self, source: &str) -> bool {
        self.remaining.get(source).copied().unwrap_or(0) == 0
    }
}
```

- [ ] **Step 4: Run** — `cd engine && cargo test -p ppcap-core --features online budget` → Expected: PASS.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(reputation): per-provider daily budget"`

### Task B7: `lookup_reputation` orchestrator + `UreqClient`

**Files:**
- Modify: `engine/crates/ppcap-core/src/enrich/online/mod.rs` (orchestrator + UreqClient)
- Modify: `engine/crates/ppcap-core/src/lib.rs` (gated re-export)
- Test: in-file (FakeHttp)

**Interfaces:**
- Consumes: adapters (B2–B4), `ReputationCache` (B5), `Budget` (B6), `HttpGet`, `ReputationKeys`.
- Produces: `pub fn lookup_reputation(http, ips, keys, cache, budget, ttls, now) -> BTreeMap<String, Vec<ReputationVerdict>>`; `pub struct UreqClient` + `pub fn lookup_reputation_native(ips, keys, cache_dir, now) -> BTreeMap<...>`.

- [ ] **Step 1: Write the failing tests** (append to `online/mod.rs`):

```rust
#[cfg(test)]
mod orchestrator_tests {
    use super::*;
    use crate::enrich::RepStatus;

    #[test]
    fn only_active_providers_run_and_results_key_by_ip() {
        let body = r#"{"data":{"abuseConfidenceScore":96,"totalReports":5}}"#;
        let http = FakeHttp::new(200, body);
        let keys = ReputationKeys { abuseipdb: Some("k".into()), greynoise: None, virustotal: None };
        let mut cache = ReputationCache::load(std::env::temp_dir().as_path());
        let mut budget = Budget::with_defaults();
        let ips = vec!["203.0.113.7".parse().unwrap()];
        let out = lookup_reputation(&http, &ips, &keys, &mut cache, &mut budget, &Ttls::default(), 1000);
        let vs = out.get("203.0.113.7").unwrap();
        assert_eq!(vs.len(), 1); // only abuseipdb active
        assert_eq!(vs[0].source, "abuseipdb");
        assert_eq!(vs[0].status, RepStatus::Malicious);
    }

    #[test]
    fn private_ips_are_skipped() {
        let http = FakeHttp::new(200, "{}");
        let keys = ReputationKeys { abuseipdb: Some("k".into()), ..Default::default() };
        let mut cache = ReputationCache::load(std::env::temp_dir().as_path());
        let mut budget = Budget::with_defaults();
        let ips = vec!["10.0.0.5".parse().unwrap()];
        let out = lookup_reputation(&http, &ips, &keys, &mut cache, &mut budget, &Ttls::default(), 0);
        assert!(out.is_empty());
    }

    #[test]
    fn exhausted_budget_yields_unavailable_not_skip() {
        let http = FakeHttp::new(200, r#"{"data":{"abuseConfidenceScore":10,"totalReports":0}}"#);
        let keys = ReputationKeys { abuseipdb: Some("k".into()), ..Default::default() };
        let mut cache = ReputationCache::load(std::env::temp_dir().as_path());
        let mut budget = Budget::with_defaults();
        // Drain abuseipdb.
        while budget.try_spend("abuseipdb") {}
        let ips = vec!["203.0.113.7".parse().unwrap()];
        let out = lookup_reputation(&http, &ips, &keys, &mut cache, &mut budget, &Ttls::default(), 0);
        assert_eq!(out.get("203.0.113.7").unwrap()[0].status, RepStatus::Unavailable);
    }
}
```

- [ ] **Step 2: Run** — `cd engine && cargo test -p ppcap-core --features online orchestrator` → Expected: FAIL.

- [ ] **Step 3: Implement** (append to `online/mod.rs`):

```rust
use crate::enrich::{RepStatus, ReputationVerdict};
use std::collections::BTreeMap;
use std::path::Path;

/// Per-provider cache TTLs in seconds (spec §8). Tunable later via config.
pub struct Ttls {
    pub abuseipdb: i64,
    pub greynoise: i64,
    pub virustotal: i64,
}
impl Default for Ttls {
    fn default() -> Self {
        Ttls { abuseipdb: 18 * 3600, greynoise: 24 * 3600, virustotal: 12 * 3600 }
    }
}

fn quota_unavailable(source: &str, now: i64) -> ReputationVerdict {
    ReputationVerdict {
        source: source.to_string(), status: RepStatus::Unavailable, malicious: false,
        score: None, tags: vec!["quota".to_string()], link: None, fetched_at: now,
    }
}

/// Look up every public IP against every active provider, cache-first, budget-bounded. `ips`
/// should already be priority-ordered (most-suspicious first) by the caller. Cache is mutated +
/// the caller is responsible for `cache.save()`.
#[allow(clippy::too_many_arguments)]
pub fn lookup_reputation(
    http: &dyn HttpGet,
    ips: &[IpAddr],
    keys: &ReputationKeys,
    cache: &mut ReputationCache,
    budget: &mut Budget,
    ttls: &Ttls,
    now: i64,
) -> BTreeMap<String, Vec<ReputationVerdict>> {
    let mut out: BTreeMap<String, Vec<ReputationVerdict>> = BTreeMap::new();
    for &ip in ips {
        if !is_lookupable(ip) {
            continue;
        }
        let ind = ip.to_string();
        let mut verdicts = Vec::new();

        // One closure per active provider keeps the cache/budget/fetch flow uniform.
        let mut run = |source: &str, ttl: i64, verdicts: &mut Vec<ReputationVerdict>,
                       cache: &mut ReputationCache, budget: &mut Budget,
                       fetch: &dyn Fn() -> ReputationVerdict| {
            if let Some(hit) = cache.get(source, &ind, now, ttl) {
                verdicts.push(hit.clone());
            } else if budget.try_spend(source) {
                let v = fetch();
                cache.put(source, &ind, v.clone());
                verdicts.push(v);
            } else {
                verdicts.push(quota_unavailable(source, now));
            }
        };

        if let Some(k) = &keys.abuseipdb {
            run("abuseipdb", ttls.abuseipdb, &mut verdicts, cache, budget,
                &|| abuseipdb::verdict(http, k, ip, now));
        }
        if let Some(k) = &keys.greynoise {
            run("greynoise", ttls.greynoise, &mut verdicts, cache, budget,
                &|| greynoise::verdict(http, k, ip, now));
        }
        if let Some(k) = &keys.virustotal {
            run("virustotal", ttls.virustotal, &mut verdicts, cache, budget,
                &|| virustotal::verdict_ip(http, k, ip, now));
        }

        if !verdicts.is_empty() {
            out.insert(ind, verdicts);
        }
    }
    out
}

/// The real `ureq`-backed HTTP client (only this struct needs the `online` feature's dep).
pub struct UreqClient {
    agent: ureq::Agent,
}
impl Default for UreqClient {
    fn default() -> Self {
        UreqClient { agent: ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(8))
            .user_agent("PacketPilot/reputation")
            .build() }
    }
}
impl HttpGet for UreqClient {
    fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse, RepError> {
        let mut req = self.agent.get(url);
        for (k, v) in headers {
            req = req.set(k, v);
        }
        match req.call() {
            Ok(resp) => {
                let status = resp.status();
                let body = resp.into_string().map_err(|e| RepError::Network(e.to_string()))?;
                Ok(HttpResponse { status, body })
            }
            // ureq 2.x surfaces 4xx/5xx as Err(Status) — we still want the body (GreyNoise 404).
            Err(ureq::Error::Status(code, resp)) => {
                Ok(HttpResponse { status: code, body: resp.into_string().unwrap_or_default() })
            }
            Err(e) => Err(RepError::Network(e.to_string())),
        }
    }
}

/// Convenience for native callers (CLI/Tauri): build a `UreqClient`, load the cache, look up, save.
pub fn lookup_reputation_native(
    ips: &[IpAddr],
    keys: &ReputationKeys,
    cache_dir: &Path,
    now: i64,
) -> BTreeMap<String, Vec<ReputationVerdict>> {
    let http = UreqClient::default();
    let mut cache = ReputationCache::load(cache_dir);
    let mut budget = Budget::with_defaults();
    let out = lookup_reputation(&http, ips, keys, &mut cache, &mut budget, &Ttls::default(), now);
    let _ = cache.save();
    out
}
```

- [ ] **Step 4: Re-export** — in `lib.rs`: `#[cfg(feature = "online")] pub use crate::enrich::online::{lookup_reputation_native, ReputationKeys};`

- [ ] **Step 5: Run** — `cd engine && cargo test -p ppcap-core --features online` → Expected: PASS (all online tests). Also `cargo build -p ppcap-core` (no features) and `cd engine/crates/ppcap-wasm && cargo build --release` still green.

- [ ] **Step 6: Commit** — `git add -A && git commit -m "feat(reputation): lookup_reputation orchestrator + UreqClient"`

---

## Phase C — CLI wiring (`ppcap analyze --reputation`)

*`ppcap-cli` already enables `ppcap-core/online` (Task B1), so the lookup symbols are always available here — the block below is unconditional (no `#[cfg]`, which in this crate would refer to a non-existent ppcap-cli feature).*

### Task C1: `--reputation` flag + env keys + run the pass

**Files:**
- Modify: `engine/crates/ppcap-cli/Cargo.toml` (add `dirs`)
- Modify: `engine/Cargo.toml` (`[workspace.dependencies]` add `dirs`)
- Modify: `engine/crates/ppcap-cli/src/cli.rs` (flag + dispatch block + test)

**Interfaces:**
- Consumes: `ppcap_core::{run, apply_reputation, ReputationKeys, lookup_reputation_native, enrich::classify_ip}`.

- [ ] **Step 1: Add the dep** — `engine/Cargo.toml` `[workspace.dependencies]`: `dirs = "5"`. Then `engine/crates/ppcap-cli/Cargo.toml` `[dependencies]`: `dirs = { workspace = true }`.

- [ ] **Step 2: Write the failing test** — append to `cli.rs`:

```rust
#[cfg(test)]
mod reputation_cli_tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn reputation_flag_parses() {
        let cli = Cli::try_parse_from(["ppcap", "analyze", "x.pcap", "--reputation"]).unwrap();
        match cli.command {
            Command::Analyze { reputation, .. } => assert!(reputation),
            _ => panic!("expected Analyze"),
        }
    }

    #[test]
    fn reputation_defaults_off() {
        let cli = Cli::try_parse_from(["ppcap", "analyze", "x.pcap"]).unwrap();
        match cli.command {
            Command::Analyze { reputation, .. } => assert!(!reputation),
            _ => panic!("expected Analyze"),
        }
    }
}
```

- [ ] **Step 3: Run to verify it fails** — `cd engine && cargo test -p ppcap-cli reputation_cli_tests` → Expected: FAIL (no `reputation` field).

- [ ] **Step 4: Add the flag** — in the `Command::Analyze { ... }` variant, after `quiet`:

```rust
        /// Enrich public IPs with online reputation (AbuseIPDB / GreyNoise / VirusTotal).
        /// Requires at least one of ABUSEIPDB_API_KEY / GREYNOISE_API_KEY / VIRUSTOTAL_API_KEY.
        #[arg(long)]
        reputation: bool,
```

Add `reputation` to the match-arm destructuring where `Analyze { input, json, .., quiet, .. }` is bound.

- [ ] **Step 5: Run the pass** — change `let out = ppcap_core::run(&input, &cfg, progress)?;` to `let mut out = ...;` and insert immediately after the progress-line termination:

```rust
            if reputation {
                let keys = ppcap_core::ReputationKeys {
                    abuseipdb: std::env::var("ABUSEIPDB_API_KEY").ok().filter(|s| !s.is_empty()),
                    greynoise: std::env::var("GREYNOISE_API_KEY").ok().filter(|s| !s.is_empty()),
                    virustotal: std::env::var("VIRUSTOTAL_API_KEY").ok().filter(|s| !s.is_empty()),
                };
                if keys.is_empty() {
                    if !quiet {
                        let _ = writeln!(std::io::stderr(),
                            "reputation: no provider key set (ABUSEIPDB_API_KEY / GREYNOISE_API_KEY / VIRUSTOTAL_API_KEY); skipping");
                    }
                } else {
                    let ips: Vec<std::net::IpAddr> = out.summary.ip_threats.iter()
                        .filter_map(|t| t.ip.parse().ok())
                        .filter(|ip| ppcap_core::enrich::classify_ip(*ip).is_external())
                        .collect();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    let cache_dir = dirs::cache_dir().unwrap_or_else(std::env::temp_dir).join("packetpilot");
                    let verdicts = ppcap_core::lookup_reputation_native(&ips, &keys, &cache_dir, now);
                    ppcap_core::apply_reputation(&mut out.summary, &verdicts);
                }
            }
```

- [ ] **Step 6: Run** — `cd engine && cargo test -p ppcap-cli && cargo build -p ppcap-cli` → Expected: parse tests PASS, builds clean.

- [ ] **Step 7: Manual smoke (optional, needs a key)** — `ABUSEIPDB_API_KEY=… cargo run -p ppcap-cli -- analyze sample.pcap --reputation --json -` and confirm `ip_threats[].reputation` is populated for public IPs. Without keys, confirm the "no provider key set" notice + unchanged output.

- [ ] **Step 8: Commit** — `git add -A && git commit -m "feat(cli): ppcap analyze --reputation"`

---

## Phase D — WASM export + Tauri command

### Task D1: WASM `apply_reputation` export

**Files:**
- Modify: `engine/crates/ppcap-wasm/src/lib.rs`
- Build: `ui/scripts/build-wasm.mjs` (run, no edit)

**Interfaces:**
- Consumes: `ppcap_core::{AnalysisOutput, apply_reputation, ReputationVerdict}`.
- Produces: JS-callable `apply_reputation(output_json: string, verdicts_json: string) -> string`.

- [ ] **Step 1: Add the export** — append to `ppcap-wasm/src/lib.rs`:

```rust
/// Apply reputation verdicts to a completed analysis. `output_json` is the `AnalysisOutput` from
/// `analyze`; `verdicts_json` is `{ "<ip>": [ReputationVerdict, ...], ... }` (snake_case). Returns
/// the updated `AnalysisOutput` as JSON. Pure + network-free — identical scoring to native callers.
#[wasm_bindgen]
pub fn apply_reputation(output_json: &str, verdicts_json: &str) -> Result<String, JsValue> {
    use std::collections::BTreeMap;
    let mut out: ppcap_core::AnalysisOutput =
        serde_json::from_str(output_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let verdicts: BTreeMap<String, Vec<ppcap_core::ReputationVerdict>> =
        serde_json::from_str(verdicts_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    ppcap_core::apply_reputation(&mut out.summary, &verdicts);
    serde_json::to_string(&out).map_err(|e| JsValue::from_str(&e.to_string()))
}
```

- [ ] **Step 2: Rebuild the wasm bundle** — `cd ui && npm run build:wasm` → Expected: regenerates `ui/src/wasm/*` with the new export. (Prereqs per [build-toolchain memory]: `wasm32-unknown-unknown` target + `wasm-bindgen-cli` `=0.2.125`.)

- [ ] **Step 3: Verify the export exists** — `grep -n "apply_reputation" ui/src/wasm/*.js` → Expected: a generated binding. Behavioral correctness is proven by the cross-surface parity test in Task G1 (which runs this build in jsdom against a golden the native engine also asserts).

- [ ] **Step 4: Commit** — `git add -A && git commit -m "feat(wasm): apply_reputation export + rebuilt bundle"`

### Task D2: Tauri `reputation_lookup` + key-storage commands

**Files:**
- Modify: `ui/src-tauri/Cargo.toml` (enable `online`, add `keyring`)
- Modify: `ui/src-tauri/src/lib.rs` (commands + registration)

**Interfaces:**
- Produces Tauri commands: `reputation_lookup(ips: Vec<String>) -> Result<String, String>` (verdicts JSON); `set_reputation_key(provider: String, key: String) -> Result<(), String>`; `reputation_key_status() -> Result<Vec<String>, String>` (which providers have a key).

- [ ] **Step 1: Deps** — `ui/src-tauri/Cargo.toml`: set `ppcap-core = { path = "../../engine/crates/ppcap-core", features = ["online"] }` and add `keyring = "2"` (pure-Rust OS keychain).

- [ ] **Step 2: Add the commands** — in `ui/src-tauri/src/lib.rs`:

```rust
const KEYRING_SERVICE: &str = "packetpilot-reputation";

fn key_for(provider: &str) -> Result<Option<String>, String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, provider).map_err(|e| e.to_string())?;
    match entry.get_password() {
        Ok(k) if !k.is_empty() => Ok(Some(k)),
        _ => Ok(None),
    }
}

#[tauri::command]
fn set_reputation_key(provider: String, key: String) -> Result<(), String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, &provider).map_err(|e| e.to_string())?;
    entry.set_password(&key).map_err(|e| e.to_string())
}

#[tauri::command]
fn reputation_key_status() -> Result<Vec<String>, String> {
    let mut active = Vec::new();
    for p in ["abuseipdb", "greynoise", "virustotal"] {
        if key_for(p)?.is_some() {
            active.push(p.to_string());
        }
    }
    Ok(active)
}

#[tauri::command]
fn reputation_lookup(ips: Vec<String>) -> Result<String, String> {
    let keys = ppcap_core::ReputationKeys {
        abuseipdb: key_for("abuseipdb")?,
        greynoise: key_for("greynoise")?,
        virustotal: key_for("virustotal")?,
    };
    if keys.is_empty() {
        return Ok("{}".to_string());
    }
    let parsed: Vec<std::net::IpAddr> = ips
        .iter()
        .filter_map(|s| s.parse().ok())
        .filter(|ip| ppcap_core::enrich::classify_ip(*ip).is_external())
        .collect();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let cache_dir = dirs::cache_dir().unwrap_or_else(std::env::temp_dir).join("packetpilot");
    let verdicts = ppcap_core::lookup_reputation_native(&parsed, &keys, &cache_dir, now);
    serde_json::to_string(&verdicts).map_err(|e| e.to_string())
}
```

(Add `dirs = "5"` to `ui/src-tauri/Cargo.toml` if not already present, mirroring the CLI.)

- [ ] **Step 3: Register** — add the three commands to the `tauri::generate_handler![ ... ]` list alongside `analyze_capture, save_report, extract_flow_packets`.

- [ ] **Step 4: Build** — `cd ui/src-tauri && cargo build` → Expected: builds (online + keyring link). Behavioral verification is manual (desktop run) since Tauri commands need the runtime; the underlying `lookup_reputation_native` + `apply_reputation` are unit-tested in Phase A/B.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(tauri): reputation_lookup + keychain key commands"`

---

## Phase E — Browser TS path (proxy fetch, adapters, cache, budget, orchestrator, WASM apply)

*The browser computes verdicts in TS (through the user's proxy) and applies them via the WASM `apply_reputation` — identical scoring to native. Adapters depend on an injected `HttpGet` so they unit-test with zero network (mirrors the Rust design).*

### Task E1: TS types

**Files:**
- Modify: `ui/src/types.ts`
- Test: `ui/src/types.reputation.test.ts` *(new)*

**Interfaces:**
- Produces: `RepStatus`, `ReputationVerdict`, `IpThreat.reputation?`.

- [ ] **Step 1: Write the failing test:**

```ts
import { describe, it, expect } from "vitest";
import type { ReputationVerdict } from "./types";

describe("ReputationVerdict type", () => {
  it("accepts the wire shape emitted by the engine", () => {
    const v: ReputationVerdict = {
      source: "abuseipdb", status: "malicious", malicious: true, score: 96,
      tags: ["ssh"], link: "https://www.abuseipdb.com/check/203.0.113.7", fetched_at: 1750500000,
    };
    expect(v.status).toBe("malicious");
  });
});
```

- [ ] **Step 2: Add the types** — in `ui/src/types.ts`:

```ts
export type RepStatus =
  | "malicious" | "benign" | "clean" | "unknown" | "notfound" | "unavailable";

export interface ReputationVerdict {
  source: string;            // "abuseipdb" | "greynoise" | "virustotal"
  status: RepStatus;
  malicious: boolean;
  score: number | null;      // 0..=100; 0 when clean; null when unknown/notfound/unavailable
  tags: string[];
  link: string | null;
  fetched_at: number;        // unix seconds
}
```

And add to the existing `IpThreat` interface: `reputation?: ReputationVerdict[];`

- [ ] **Step 3: Run** — `cd ui && npx vitest run src/types.reputation.test.ts` → Expected: PASS.

- [ ] **Step 4: Commit** — `git add -A && git commit -m "feat(ui): reputation TS types"`

### Task E2: proxy `HttpGet` + AbuseIPDB / GreyNoise / VirusTotal adapters

**Files:**
- Create: `ui/src/lib/reputation/http.ts`, `abuseipdb.ts`, `greynoise.ts`, `virustotal.ts`
- Test: `ui/src/lib/reputation/adapters.test.ts` *(new)*

**Interfaces:**
- Produces: `type HttpGet = (url, headers) => Promise<{status, body}>`; `proxyHttp(proxyUrl)`; `abuseipdbVerdict`, `greynoiseVerdict`, `virustotalVerdictIp` `(http, key, indicator, now) => Promise<ReputationVerdict>`.

- [ ] **Step 1: Write the failing tests:**

```ts
import { describe, it, expect } from "vitest";
import type { HttpGet } from "./http";
import { abuseipdbVerdict } from "./abuseipdb";
import { greynoiseVerdict } from "./greynoise";
import { virustotalVerdictIp } from "./virustotal";

const fake = (status: number, body: string): HttpGet => async () => ({ status, body });

describe("reputation adapters", () => {
  it("abuseipdb high confidence -> malicious", async () => {
    const v = await abuseipdbVerdict(fake(200, JSON.stringify({ data: { abuseConfidenceScore: 96, totalReports: 5 } })), "k", "203.0.113.7", 1);
    expect(v.status).toBe("malicious");
    expect(v.score).toBe(96);
  });
  it("abuseipdb zero reports -> clean", async () => {
    const v = await abuseipdbVerdict(fake(200, JSON.stringify({ data: { abuseConfidenceScore: 0, totalReports: 0 } })), "k", "1.2.3.4", 1);
    expect(v.status).toBe("clean");
  });
  it("greynoise benign -> benign + actor tag", async () => {
    const v = await greynoiseVerdict(fake(200, JSON.stringify({ classification: "benign", riot: false, noise: true, name: "Shodan.io" })), "k", "203.0.113.7", 1);
    expect(v.status).toBe("benign");
    expect(v.tags).toContain("Shodan.io");
  });
  it("greynoise 404 -> notfound", async () => {
    const v = await greynoiseVerdict(fake(404, JSON.stringify({ message: "not observed" })), "k", "203.0.113.7", 1);
    expect(v.status).toBe("notfound");
  });
  it("virustotal malicious ratio", async () => {
    const body = JSON.stringify({ data: { attributes: { last_analysis_stats: { malicious: 8, suspicious: 2, harmless: 70, undetected: 10, timeout: 0 } } } });
    const v = await virustotalVerdictIp(fake(200, body), "k", "203.0.113.7", 1);
    expect(v.status).toBe("malicious");
    expect(v.score).toBe(9);
  });
});
```

- [ ] **Step 2: Run** — `cd ui && npx vitest run src/lib/reputation/adapters.test.ts` → Expected: FAIL (modules missing).

- [ ] **Step 3: Implement `http.ts`:**

```ts
import type { ReputationVerdict } from "../../types";

export interface HttpResult { status: number; body: string }
/** A GET that returns status + raw body. Real impl relays through the user's proxy. */
export type HttpGet = (url: string, headers: Record<string, string>) => Promise<HttpResult>;

/**
 * Relay through a user-supplied proxy. Contract: `POST {proxyUrl}` with JSON body
 * `{ url, headers }`; the proxy forwards server-side and responds `{ status, body }` (body a string).
 * This is the only way the browser can reach providers that block CORS (spec §7.4).
 */
export function proxyHttp(proxyUrl: string): HttpGet {
  return async (url, headers) => {
    try {
      const resp = await fetch(proxyUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url, headers }),
      });
      if (!resp.ok) return { status: resp.status, body: "" };
      const data = await resp.json();
      return { status: Number(data.status) || 0, body: typeof data.body === "string" ? data.body : JSON.stringify(data.body ?? "") };
    } catch {
      return { status: 0, body: "" };
    }
  };
}

export function unavailable(source: string, now: number): ReputationVerdict {
  return { source, status: "unavailable", malicious: false, score: null, tags: [], link: null, fetched_at: now };
}
```

- [ ] **Step 4: Implement `abuseipdb.ts`:**

```ts
import type { ReputationVerdict, RepStatus } from "../../types";
import { type HttpGet, unavailable } from "./http";

export async function abuseipdbVerdict(http: HttpGet, key: string, ip: string, now: number): Promise<ReputationVerdict> {
  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`;
  const res = await http(url, { Key: key, Accept: "application/json" });
  if (res.status !== 200) return unavailable("abuseipdb", now);
  let d: any;
  try { d = JSON.parse(res.body).data; } catch { return unavailable("abuseipdb", now); }
  const score: number = d?.abuseConfidenceScore ?? 0;
  const total: number = d?.totalReports ?? 0;
  const status: RepStatus = score >= 75 ? "malicious" : score >= 25 ? "unknown" : total === 0 ? "clean" : "unknown";
  const tags: string[] = [];
  if (d?.usageType) tags.push(d.usageType);
  if (d?.isTor) tags.push("tor");
  if (d?.countryCode) tags.push(d.countryCode);
  return { source: "abuseipdb", status, malicious: status === "malicious", score, tags,
    link: `https://www.abuseipdb.com/check/${ip}`, fetched_at: now };
}
```

- [ ] **Step 5: Implement `greynoise.ts`:**

```ts
import type { ReputationVerdict, RepStatus } from "../../types";
import { type HttpGet, unavailable } from "./http";

export async function greynoiseVerdict(http: HttpGet, key: string, ip: string, now: number): Promise<ReputationVerdict> {
  const url = `https://api.greynoise.io/v3/community/${ip}`;
  const res = await http(url, { key });
  if (res.status === 404) {
    return { source: "greynoise", status: "notfound", malicious: false, score: 0, tags: [], link: `https://viz.greynoise.io/ip/${ip}`, fetched_at: now };
  }
  if (res.status !== 200) return unavailable("greynoise", now);
  let r: any;
  try { r = JSON.parse(res.body); } catch { return unavailable("greynoise", now); }
  let status: RepStatus; let score: number;
  if (r.classification === "malicious") { status = "malicious"; score = 95; }
  else if (r.classification === "benign" || r.riot === true) { status = "benign"; score = 5; }
  else { status = "unknown"; score = r.noise ? 50 : 0; }
  const tags: string[] = [];
  if (r.name && r.name !== "unknown") tags.push(r.name);
  if (r.riot) tags.push("business-service");
  if (r.noise) tags.push("internet-scanner");
  return { source: "greynoise", status, malicious: status === "malicious", score, tags,
    link: r.link ?? `https://viz.greynoise.io/ip/${ip}`, fetched_at: now };
}
```

- [ ] **Step 6: Implement `virustotal.ts`:**

```ts
import type { ReputationVerdict, RepStatus } from "../../types";
import { type HttpGet, unavailable } from "./http";

function parse(body: string, status: number, link: string, now: number): ReputationVerdict {
  if (status === 404) return { source: "virustotal", status: "notfound", malicious: false, score: null, tags: [], link, fetched_at: now };
  if (status !== 200) return unavailable("virustotal", now);
  let a: any;
  try { a = JSON.parse(body).data.attributes; } catch { return unavailable("virustotal", now); }
  const st = a?.last_analysis_stats;
  if (!st) return { source: "virustotal", status: "unknown", malicious: false, score: null, tags: [], link, fetched_at: now };
  const total = Math.max(1, (st.malicious ?? 0) + (st.suspicious ?? 0) + (st.harmless ?? 0) + (st.undetected ?? 0));
  const score = Math.round((100 * (st.malicious ?? 0)) / total);
  let s: RepStatus;
  if ((st.malicious ?? 0) > 0) s = "malicious";
  else if ((st.suspicious ?? 0) === 0 && (st.harmless ?? 0) > 0) s = "clean";
  else s = "unknown";
  const tags: string[] = Array.isArray(a.tags) ? [...a.tags] : [];
  if (a.as_owner) tags.push(a.as_owner);
  if (a.country) tags.push(a.country);
  return { source: "virustotal", status: s, malicious: s === "malicious", score, tags, link, fetched_at: now };
}

export async function virustotalVerdictIp(http: HttpGet, key: string, ip: string, now: number): Promise<ReputationVerdict> {
  const res = await http(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, { "x-apikey": key });
  return parse(res.body, res.status, `https://www.virustotal.com/gui/ip-address/${ip}`, now);
}
```

- [ ] **Step 7: Run** — `cd ui && npx vitest run src/lib/reputation/adapters.test.ts` → Expected: PASS (5).

- [ ] **Step 8: Commit** — `git add -A && git commit -m "feat(ui): reputation provider adapters (proxy fetch)"`

### Task E3: reputation IndexedDB cache (reuse `recent.ts` infra)

**Files:**
- Modify: `ui/src/lib/recent.ts` (bump `DB_VERSION`, add store + API)
- Test: `ui/src/lib/reputation/cache.test.ts` *(new; jsdom — fake-indexeddb)*

**Interfaces:**
- Produces: `getReputation(source, indicator, now, ttlSecs)`, `putReputation(source, indicator, verdict)`.

- [ ] **Step 1: Write the failing test:**

```ts
import { describe, it, expect, beforeEach } from "vitest";
import "fake-indexeddb/auto";
import { getReputation, putReputation } from "../recent";

describe("reputation cache", () => {
  it("hit within ttl, miss after", async () => {
    const v = { source: "abuseipdb", status: "malicious" as const, malicious: true, score: 90, tags: [], link: null, fetched_at: 1000 };
    await putReputation("abuseipdb", "203.0.113.7", v);
    expect(await getReputation("abuseipdb", "203.0.113.7", 1100, 600)).not.toBeNull();
    expect(await getReputation("abuseipdb", "203.0.113.7", 2000, 600)).toBeNull();
  });
});
```

- [ ] **Step 2: Run** — `cd ui && npx vitest run src/lib/reputation/cache.test.ts` → Expected: FAIL. *(If `fake-indexeddb` is absent, `npm i -D fake-indexeddb` first — confirm whether existing IndexedDB tests already depend on it.)*

- [ ] **Step 3: Implement** — in `recent.ts`: bump `DB_VERSION` by 1; add `const REPUTATION_STORE = "reputation";`; in `onupgradeneeded` also `if (!db.objectStoreNames.contains(REPUTATION_STORE)) db.createObjectStore(REPUTATION_STORE);`; then:

```ts
import type { ReputationVerdict } from "../types";

function repKey(source: string, indicator: string): string {
  return `${source}|${indicator}`;
}

export async function putReputation(source: string, indicator: string, verdict: ReputationVerdict): Promise<boolean> {
  const db = await openDb();
  if (!db) return false;
  return new Promise((resolve) => {
    try {
      const store = db.transaction(REPUTATION_STORE, "readwrite").objectStore(REPUTATION_STORE);
      const req = store.put(verdict, repKey(source, indicator));
      req.onsuccess = () => resolve(true);
      req.onerror = () => resolve(false);
    } catch { resolve(false); }
  });
}

export async function getReputation(source: string, indicator: string, now: number, ttlSecs: number): Promise<ReputationVerdict | null> {
  const db = await openDb();
  if (!db) return null;
  return new Promise((resolve) => {
    try {
      const store = db.transaction(REPUTATION_STORE, "readonly").objectStore(REPUTATION_STORE);
      const req = store.get(repKey(source, indicator));
      req.onsuccess = () => {
        const v = req.result as ReputationVerdict | undefined;
        if (v && now - v.fetched_at <= ttlSecs) resolve(v);
        else resolve(null);
      };
      req.onerror = () => resolve(null);
    } catch { resolve(null); }
  });
}
```

- [ ] **Step 4: Run** — `cd ui && npx vitest run src/lib/reputation/cache.test.ts` → Expected: PASS.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(ui): reputation IndexedDB cache"`

### Task E4: TS budget + E5: orchestrator

**Files:**
- Create: `ui/src/lib/reputation/budget.ts`, `orchestrator.ts`
- Test: `ui/src/lib/reputation/orchestrator.test.ts` *(new)*

**Interfaces:**
- Produces: `makeBudget()`, `lookupReputation(http, ips, keys, now, opts?) => Promise<Record<string, ReputationVerdict[]>>`.

- [ ] **Step 1: Write the failing test:**

```ts
import { describe, it, expect } from "vitest";
import "fake-indexeddb/auto";
import type { HttpGet } from "./http";
import { lookupReputation } from "./orchestrator";

const fakeAbuse: HttpGet = async () => ({ status: 200, body: JSON.stringify({ data: { abuseConfidenceScore: 96, totalReports: 3 } }) });

describe("lookupReputation", () => {
  it("only active providers run; keyed by ip; private IPs skipped", async () => {
    const out = await lookupReputation(fakeAbuse, ["203.0.113.7", "10.0.0.5"], { abuseipdb: "k" }, 1000);
    expect(Object.keys(out)).toEqual(["203.0.113.7"]);
    expect(out["203.0.113.7"][0].source).toBe("abuseipdb");
    expect(out["203.0.113.7"][0].status).toBe("malicious");
  });
});
```

- [ ] **Step 2: Run** — `cd ui && npx vitest run src/lib/reputation/orchestrator.test.ts` → Expected: FAIL.

- [ ] **Step 3: Implement `budget.ts`:**

```ts
/** Per-provider daily budget; mirrors the Rust default quotas (spec §6.3, §8). */
export function makeBudget(): Record<string, number> {
  return { greynoise: 9, virustotal: 480, abuseipdb: 950 };
}
export function trySpend(budget: Record<string, number>, source: string): boolean {
  if ((budget[source] ?? 0) > 0) { budget[source] -= 1; return true; }
  return false;
}
```

- [ ] **Step 4: Implement `orchestrator.ts`:**

```ts
import type { ReputationVerdict } from "../../types";
import { isPublicIp } from "../data"; // see note below
import type { HttpGet } from "./http";
import { abuseipdbVerdict } from "./abuseipdb";
import { greynoiseVerdict } from "./greynoise";
import { virustotalVerdictIp } from "./virustotal";
import { getReputation, putReputation } from "../recent";
import { makeBudget, trySpend } from "./budget";

export interface RepKeys { abuseipdb?: string; greynoise?: string; virustotal?: string; }
const TTL = { abuseipdb: 18 * 3600, greynoise: 24 * 3600, virustotal: 12 * 3600 };

function quotaUnavailable(source: string, now: number): ReputationVerdict {
  return { source, status: "unavailable", malicious: false, score: null, tags: ["quota"], link: null, fetched_at: now };
}

/** `ips` should be priority-ordered (most-suspicious first). Cache-first, budget-bounded. */
export async function lookupReputation(http: HttpGet, ips: string[], keys: RepKeys, now: number): Promise<Record<string, ReputationVerdict[]>> {
  const out: Record<string, ReputationVerdict[]> = {};
  const budget = makeBudget();
  const providers: Array<[string, number, (h: HttpGet, k: string, ip: string, n: number) => Promise<ReputationVerdict>]> = [];
  if (keys.abuseipdb) providers.push(["abuseipdb", TTL.abuseipdb, abuseipdbVerdict]);
  if (keys.greynoise) providers.push(["greynoise", TTL.greynoise, greynoiseVerdict]);
  if (keys.virustotal) providers.push(["virustotal", TTL.virustotal, virustotalVerdictIp]);

  for (const ip of ips) {
    if (!isPublicIp(ip)) continue;
    const verdicts: ReputationVerdict[] = [];
    for (const [source, ttl, fetchFn] of providers) {
      const cached = await getReputation(source, ip, now, ttl);
      if (cached) { verdicts.push(cached); continue; }
      if (trySpend(budget, source)) {
        const v = await fetchFn(http, (keys as any)[source], ip, now);
        await putReputation(source, ip, v);
        verdicts.push(v);
      } else {
        verdicts.push(quotaUnavailable(source, now));
      }
    }
    if (verdicts.length) out[ip] = verdicts;
  }
  return out;
}
```

- [ ] **Step 5: Add `isPublicIp`** — in `ui/src/lib/data.ts`, add a small helper (the engine already filters, but the browser pre-filters too). A pragmatic check that matches `IpClass::is_external` for the common cases:

```ts
/** True if `ip` is a routable/public address worth a reputation lookup (mirrors engine is_external). */
export function isPublicIp(ip: string): boolean {
  const m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return ip.includes(":") ? !/^(fe80|::1|fc|fd)/i.test(ip) : false; // coarse IPv6
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10 || a === 127 || a === 0) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 169 && b === 254) return false;
  if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT
  if (a >= 224) return false;                          // multicast/reserved
  return true;
}
```

- [ ] **Step 6: Run** — `cd ui && npx vitest run src/lib/reputation/orchestrator.test.ts` → Expected: PASS.

- [ ] **Step 7: Commit** — `git add -A && git commit -m "feat(ui): reputation budget + orchestrator"`

### Task E6: apply verdicts via WASM

**Files:**
- Modify: `ui/src/lib/wasmEngine.ts` (add `applyReputationWasm`, reusing the existing wasm-init guard)
- Test: covered by the parity test in Task G1.

**Interfaces:**
- Consumes: WASM export `apply_reputation` (Task D1); existing wasm init in `wasmEngine.ts`.
- Produces: `applyReputationWasm(outputJson: string, verdicts: Record<string, ReputationVerdict[]>) => Promise<AnalysisOutput>`.

- [ ] **Step 1: Implement** — in `wasmEngine.ts`, importing `apply_reputation` from the same generated module as the existing `analyze` import and reusing its init guard (mirror exactly how `analyzeViaWasm` ensures init):

```ts
import { apply_reputation as wasmApplyReputation } from "../wasm/ppcap_wasm"; // match existing import path
import type { AnalysisOutput, ReputationVerdict } from "../types";

export async function applyReputationWasm(
  outputJson: string,
  verdicts: Record<string, ReputationVerdict[]>,
): Promise<AnalysisOutput> {
  await ensureWasmReady(); // the same init the existing analyzeViaWasm awaits
  const updated = wasmApplyReputation(outputJson, JSON.stringify(verdicts));
  return JSON.parse(updated) as AnalysisOutput;
}
```

- [ ] **Step 2: Typecheck** — `cd ui && npx tsc --noEmit` → Expected: clean (after the wasm rebuild in D1 generated the `apply_reputation` binding + its `.d.ts`).

- [ ] **Step 3: Commit** — `git add -A && git commit -m "feat(ui): applyReputationWasm wrapper"`

---

## Phase F — UI surfacing (threat-card chip, settings, consent, App wiring)

### Task F1: `ReputationChip` on the threat-card row

**Files:**
- Create: `ui/src/cockpit/ReputationChip.tsx`
- Modify: `ui/src/cockpit/ThreatRail.tsx` (`RailRow`)
- Test: `ui/src/cockpit/ReputationChip.test.tsx` *(new)*

**Interfaces:**
- Consumes: `IpThreat.reputation` (E1).
- Produces: `ReputationChip({ reputation })`.

- [ ] **Step 1: Write the failing test:**

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ReputationChip } from "./ReputationChip";
import type { ReputationVerdict } from "../types";

const v = (source: string, status: ReputationVerdict["status"], score: number | null): ReputationVerdict =>
  ({ source, status, malicious: status === "malicious", score, tags: [], link: null, fetched_at: 0 });

describe("ReputationChip", () => {
  it("shows the worst verdict with provider count", () => {
    render(<ReputationChip reputation={[v("abuseipdb", "malicious", 96), v("greynoise", "benign", 5)]} />);
    expect(screen.getByText(/malicious/i)).toBeInTheDocument();
    expect(screen.getByText(/abuseipdb/i)).toBeInTheDocument();
  });

  it("renders nothing when no verdicts", () => {
    const { container } = render(<ReputationChip reputation={[]} />);
    expect(container).toBeEmptyDOMElement();
  });
});
```

- [ ] **Step 2: Run** — `cd ui && npx vitest run src/cockpit/ReputationChip.test.tsx` → Expected: FAIL.

- [ ] **Step 3: Implement `ReputationChip.tsx`:**

```tsx
import type { ReputationVerdict, RepStatus } from "../types";

const RANK: Record<RepStatus, number> = { malicious: 5, benign: 4, unknown: 3, clean: 2, notfound: 1, unavailable: 0 };
const COLOR: Record<RepStatus, string> = {
  malicious: "var(--color-critical, #ef4444)", benign: "var(--color-low, #22c55e)",
  unknown: "var(--color-text-faint)", clean: "var(--color-text-faint)",
  notfound: "var(--color-text-faint)", unavailable: "var(--color-text-faint)",
};

/** Compact summary of a card's reputation verdicts: the worst status + the provider that set it. */
export function ReputationChip({ reputation }: { reputation: ReputationVerdict[] }) {
  if (!reputation || reputation.length === 0) return null;
  const worst = [...reputation].sort((a, b) => RANK[b.status] - RANK[a.status])[0];
  const label = worst.score != null ? `${worst.status} ${worst.score}` : worst.status;
  return (
    <span className="t-tag inline-flex items-center gap-1" title={reputation.map((v) => `${v.source}: ${v.status}`).join(" · ")}>
      <span aria-hidden style={{ width: 6, height: 6, borderRadius: 9999, background: COLOR[worst.status] }} />
      <span style={{ color: COLOR[worst.status] }}>{worst.source} {label}</span>
    </span>
  );
}
```

- [ ] **Step 4: Render it in `RailRow`** — in `ThreatRail.tsx`, import `ReputationChip` and add, inside the metrics row (after the bytes span):

```tsx
        {threat.reputation && threat.reputation.length > 0 && <ReputationChip reputation={threat.reputation} />}
```

- [ ] **Step 5: Run** — `cd ui && npx vitest run src/cockpit/ReputationChip.test.tsx src/cockpit/ThreatRail.test.tsx` → Expected: PASS (chip tests + existing ThreatRail tests still green).

- [ ] **Step 6: Commit** — `git add -A && git commit -m "feat(ui): ReputationChip on threat cards"`

### Task F2: Settings dialog + first-use consent

**Files:**
- Create: `ui/src/cockpit/SettingsDialog.tsx`, `ui/src/cockpit/ReputationConsent.tsx`, `ui/src/lib/reputation/settings.ts`
- Test: `ui/src/lib/reputation/settings.test.ts` *(new)*

**Interfaces:**
- Produces: `settings.ts` — `repEnabled()`, `setRepEnabled(b)`, `getProxyUrl()`, `setProxyUrl(s)`, `getKey(provider)`, `setKey(provider, key)`, `consentGiven()`, `giveConsent()`, `isTauri()`. (Browser → localStorage; desktop keys → Tauri `set_reputation_key`.)

- [ ] **Step 1: Write the failing test:**

```ts
import { describe, it, expect, beforeEach } from "vitest";
import { repEnabled, setRepEnabled, getProxyUrl, setProxyUrl, consentGiven, giveConsent } from "./settings";

describe("reputation settings (browser/localStorage)", () => {
  beforeEach(() => localStorage.clear());
  it("enabled defaults off and toggles", () => {
    expect(repEnabled()).toBe(false);
    setRepEnabled(true);
    expect(repEnabled()).toBe(true);
  });
  it("proxy url round-trips", () => {
    setProxyUrl("https://proxy.example/relay");
    expect(getProxyUrl()).toBe("https://proxy.example/relay");
  });
  it("consent is sticky", () => {
    expect(consentGiven()).toBe(false);
    giveConsent();
    expect(consentGiven()).toBe(true);
  });
});
```

- [ ] **Step 2: Run** — `cd ui && npx vitest run src/lib/reputation/settings.test.ts` → Expected: FAIL.

- [ ] **Step 3: Implement `settings.ts`:**

```ts
// Browser stores keys/proxy/flags in localStorage (the user's own machine). On desktop, KEYS go to
// the OS keychain via Tauri commands; enabled/consent stay in localStorage. Off by default.
const PROVIDERS = ["abuseipdb", "greynoise", "virustotal"] as const;
export type Provider = (typeof PROVIDERS)[number];

export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export function repEnabled(): boolean { return localStorage.getItem("pp.rep.enabled") === "1"; }
export function setRepEnabled(b: boolean): void { localStorage.setItem("pp.rep.enabled", b ? "1" : "0"); }
export function getProxyUrl(): string { return localStorage.getItem("pp.rep.proxyUrl") ?? ""; }
export function setProxyUrl(s: string): void { localStorage.setItem("pp.rep.proxyUrl", s); }
export function consentGiven(): boolean { return localStorage.getItem("pp.rep.consent") === "1"; }
export function giveConsent(): void { localStorage.setItem("pp.rep.consent", "1"); }

/** Browser-only key access. On desktop, keys live in the keychain — use the Tauri commands instead. */
export function getKey(provider: Provider): string { return localStorage.getItem(`pp.rep.key.${provider}`) ?? ""; }
export function setKey(provider: Provider, key: string): void { localStorage.setItem(`pp.rep.key.${provider}`, key); }
export function browserKeys(): Record<string, string> {
  const out: Record<string, string> = {};
  for (const p of PROVIDERS) { const k = getKey(p); if (k) out[p] = k; }
  return out;
}
```

- [ ] **Step 4: Run** — `cd ui && npx vitest run src/lib/reputation/settings.test.ts` → Expected: PASS.

- [ ] **Step 5: Implement the dialogs** — `ReputationConsent.tsx` (a modal that names the providers + IP count and calls `giveConsent`/`onProceed` or `onCancel`):

```tsx
export function ReputationConsent({ ipCount, providers, onProceed, onCancel }:
  { ipCount: number; providers: string[]; onProceed: () => void; onCancel: () => void }) {
  return (
    <div role="dialog" aria-label="Reputation consent" className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="max-w-md rounded-lg bg-[var(--color-surface)] p-5 text-[var(--color-text)]">
        <h2 className="text-sm font-semibold">Send {ipCount} external IPs for reputation lookup?</h2>
        <p className="mt-2 text-xs text-[var(--color-text-faint)]">
          {ipCount} public IP{ipCount === 1 ? "" : "s"} will be sent to {providers.join(", ")} to check reputation.
          Internal IPs, payloads, and the capture itself never leave this device.
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

`SettingsDialog.tsx` — a panel with the enable toggle, the proxy URL field (browser only), and per-provider key fields. On save: browser → `setKey`; desktop → `invoke("set_reputation_key", { provider, key })`. (Mirror the existing dialog/primitive styles in `cockpit/`. Trigger it from a gear action in `CommandBar`/`CommandPalette`.)

```tsx
import { useState } from "react";
import { isTauri, repEnabled, setRepEnabled, getProxyUrl, setProxyUrl, getKey, setKey, type Provider } from "../lib/reputation/settings";

const PROVIDERS: Provider[] = ["abuseipdb", "greynoise", "virustotal"];

export function SettingsDialog({ onClose }: { onClose: () => void }) {
  const [enabled, setEnabled] = useState(repEnabled());
  const [proxy, setProxy] = useState(getProxyUrl());
  const [keys, setKeys] = useState<Record<string, string>>(() =>
    Object.fromEntries(PROVIDERS.map((p) => [p, isTauri() ? "" : getKey(p)])));

  async function save() {
    setRepEnabled(enabled);
    if (!isTauri()) setProxyUrl(proxy);
    for (const p of PROVIDERS) {
      if (!keys[p]) continue;
      if (isTauri()) {
        const { invoke } = await import("@tauri-apps/api/core");
        await invoke("set_reputation_key", { provider: p, key: keys[p] });
      } else {
        setKey(p, keys[p]);
      }
    }
    onClose();
  }

  return (
    <div role="dialog" aria-label="Reputation settings" className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="w-[28rem] rounded-lg bg-[var(--color-surface)] p-5 text-[var(--color-text)]">
        <h2 className="text-sm font-semibold">Online reputation</h2>
        <label className="mt-3 flex items-center gap-2 text-xs">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enable reputation lookups
        </label>
        {!isTauri() && (
          <label className="mt-3 block text-xs">Proxy URL (required in the browser)
            <input className="mt-1 w-full rounded bg-[var(--color-bg)] p-1 font-mono text-xs" value={proxy} onChange={(e) => setProxy(e.target.value)} placeholder="https://your-relay.example/relay" />
          </label>
        )}
        {PROVIDERS.map((p) => (
          <label key={p} className="mt-3 block text-xs uppercase">{p}
            <input type="password" className="mt-1 w-full rounded bg-[var(--color-bg)] p-1 font-mono text-xs"
              value={keys[p]} onChange={(e) => setKeys({ ...keys, [p]: e.target.value })}
              placeholder={isTauri() ? "stored in OS keychain" : "stored locally"} />
          </label>
        ))}
        <div className="mt-4 flex justify-end gap-2">
          <button className="t-tag" onClick={onClose}>Cancel</button>
          <button className="t-tag font-semibold" onClick={save}>Save</button>
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 6: Run** — `cd ui && npx vitest run src/lib/reputation/settings.test.ts && npx tsc --noEmit` → Expected: PASS + clean typecheck.

- [ ] **Step 7: Commit** — `git add -A && git commit -m "feat(ui): reputation settings + consent dialog"`

### Task F3: App wiring (run the pass after a capture loads)

**Files:**
- Modify: `ui/src/App.tsx`
- Test: manual + the parity test (G1) covers the apply path; the lookup/settings are unit-tested in E/F.

**Interfaces:**
- Consumes: `applyReputationWasm` (E6), `lookupReputation`+`proxyHttp` (E2/E5), settings (F2), `isPublicIp` (E5).

- [ ] **Step 1: Add the runner** — in `App.tsx`, define (and call after the capture is applied):

```tsx
import { proxyHttp } from "./lib/reputation/http";
import { lookupReputation } from "./lib/reputation/orchestrator";
import { applyReputationWasm } from "./lib/wasmEngine";
import { repEnabled, getProxyUrl, browserKeys, isTauri, consentGiven, giveConsent } from "./lib/reputation/settings";
import type { AnalysisOutput, ReputationVerdict } from "./types";

async function fetchVerdicts(output: AnalysisOutput): Promise<Record<string, ReputationVerdict[]>> {
  const ips = output.summary.ip_threats.filter((t) => t.ip_class === "public").map((t) => t.ip);
  if (ips.length === 0) return {};
  const now = Math.floor(Date.now() / 1000);
  if (isTauri()) {
    const { invoke } = await import("@tauri-apps/api/core");
    return JSON.parse(await invoke<string>("reputation_lookup", { ips }));
  }
  const proxy = getProxyUrl();
  const keys = browserKeys();
  if (!proxy || Object.keys(keys).length === 0) return {};
  return lookupReputation(proxyHttp(proxy), ips, keys, now);
}

// Call this AFTER applyCapture(output) has set the summary. `reapply` re-funnels the enriched output.
async function runReputation(output: AnalysisOutput, reapply: (o: AnalysisOutput) => void) {
  if (!repEnabled()) return;
  const verdicts = await fetchVerdicts(output);
  if (Object.keys(verdicts).length === 0) return;
  const enriched = await applyReputationWasm(JSON.stringify(output), verdicts);
  reapply(enriched);
}
```

- [ ] **Step 2: Wire the consent gate + call** — where `applyCapture(output)` runs after a successful load, follow it with a consent check then `runReputation`. Pseudo-flow to implement inline (matching App's existing state setters):

```tsx
applyCapture(output);
if (repEnabled()) {
  const publicCount = output.summary.ip_threats.filter((t) => t.ip_class === "public").length;
  if (publicCount > 0) {
    if (consentGiven()) {
      void runReputation(output, applyCapture);
    } else {
      // open <ReputationConsent ipCount={publicCount} providers={activeProviders()} ... /> ;
      // onProceed: giveConsent(); void runReputation(output, applyCapture);
      setConsentPrompt({ output, ipCount: publicCount });
    }
  }
}
```

Add `consentPrompt` state + render `<ReputationConsent .../>` when set; add a gear button that opens `<SettingsDialog/>`. `activeProviders()` = `isTauri()` ? (await `reputation_key_status`) : `Object.keys(browserKeys())`.

- [ ] **Step 3: Verify** — `cd ui && npx tsc --noEmit && npm test` → Expected: typecheck clean, suite green.

- [ ] **Step 4: Commit** — `git add -A && git commit -m "feat(ui): run reputation pass after capture load (consent-gated)"`

---

## Phase G — Cross-surface parity, CI, docs

### Task G1: cross-surface parity test (native Rust == WASM `apply_reputation`)

*The anti-drift guard that justifies Approach B: the same `(output, verdicts)` vector must produce identical output natively and through WASM.*

**Files:**
- Create: `ui/src/test/reputation-parity.fixture.json` (an `{ output, verdicts, expected }` vector)
- Create: `engine/crates/ppcap-core/tests/reputation_parity.rs` (Rust side asserts `expected`)
- Create: `ui/src/lib/reputation/parity.test.ts` (WASM side asserts the same `expected`)

- [ ] **Step 1: Author the fixture** — `ui/src/test/reputation-parity.fixture.json`: a minimal but representative `AnalysisOutput` (2–3 `ip_threats`: one public Low that gets consensus-malicious → Critical, one public Medium that gets GreyNoise-benign → Low, one internal untouched), a `verdicts` map, and the `expected` post-apply `ip_threats` (severity/score/reputation length). Keep it small and hand-verified against the Phase A rules.

- [ ] **Step 2: Rust side** — `engine/crates/ppcap-core/tests/reputation_parity.rs`:

```rust
//! Asserts native apply_reputation matches the shared parity fixture (the WASM side asserts the
//! same `expected` in ui/src/lib/reputation/parity.test.ts → byte-identical scoring across surfaces).
use std::collections::BTreeMap;

#[test]
fn native_apply_matches_fixture() {
    let raw = include_str!("../../../../ui/src/test/reputation-parity.fixture.json");
    let fx: serde_json::Value = serde_json::from_str(raw).unwrap();
    let mut out: ppcap_core::AnalysisOutput = serde_json::from_value(fx["output"].clone()).unwrap();
    let verdicts: BTreeMap<String, Vec<ppcap_core::ReputationVerdict>> =
        serde_json::from_value(fx["verdicts"].clone()).unwrap();
    ppcap_core::apply_reputation(&mut out.summary, &verdicts);

    let expected = &fx["expected"]["ip_threats"];
    for (i, row) in out.summary.ip_threats.iter().enumerate() {
        assert_eq!(row.severity.as_str(), expected[i]["severity"].as_str().unwrap(), "row {i} severity");
        assert_eq!(row.score as u64, expected[i]["score"].as_u64().unwrap(), "row {i} score");
        assert_eq!(row.ip, expected[i]["ip"].as_str().unwrap(), "row {i} ip/order");
    }
}
```

- [ ] **Step 3: WASM side** — `ui/src/lib/reputation/parity.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import fixture from "../../test/reputation-parity.fixture.json";
import { applyReputationWasm } from "../wasmEngine";

describe("cross-surface parity", () => {
  it("WASM apply matches the shared expected (== native)", async () => {
    const enriched = await applyReputationWasm(JSON.stringify((fixture as any).output), (fixture as any).verdicts);
    const got = enriched.summary.ip_threats.map((t) => ({ ip: t.ip, severity: t.severity, score: t.score }));
    const want = (fixture as any).expected.ip_threats.map((t: any) => ({ ip: t.ip, severity: t.severity, score: t.score }));
    expect(got).toEqual(want);
  });
});
```

- [ ] **Step 4: Run both** —
  - `cd engine && cargo test -p ppcap-core --test reputation_parity` → Expected: PASS.
  - `cd ui && npm run build:wasm && npx vitest run src/lib/reputation/parity.test.ts` → Expected: PASS (identical `expected`). If they disagree, the scoring drifted — fix before merge.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "test(reputation): cross-surface native==WASM parity"`

### Task G2: CI coverage for the online feature

**Files:**
- Modify: the CI workflow (`.github/workflows/ci.yml` or equivalent)

- [ ] **Step 1: Add the gated test step** — in the engine job, after the default `cargo test`, add: `cargo test -p ppcap-core --features online` (so the adapters/cache/budget/orchestrator tests run in CI). Confirm the existing wasm-build step (per [ci-wasm-build-gap memory]) still runs `npm run build:wasm` before `tsc`/`vitest` so the new `apply_reputation` binding exists for the parity test.

- [ ] **Step 2: Run locally to mimic CI** — `cd engine && cargo test -p ppcap-core --features online && cargo build -p ppcap-cli && cd ../ui && npm run build:wasm && npm test` → Expected: all green.

- [ ] **Step 3: Commit** — `git add -A && git commit -m "ci: test ppcap-core online feature"`

### Task G3: docs

**Files:**
- Modify: `README.md` (roadmap), `engine/README.md` (feature note)
- Create: `docs/reputation.md` (operator guide: keys, env vars, proxy contract, consent, ToS)

- [ ] **Step 1: README roadmap** — move "Online reputation connectors (AbuseIPDB / GreyNoise / VirusTotal — keyed + cached)" from *Roadmap* into the shipped feature list, noting opt-in + BYO-key + browser-proxy.

- [ ] **Step 2: Operator guide** — `docs/reputation.md`: the three env vars (CLI), the desktop keychain + browser localStorage key storage, the **proxy relay contract** (`POST {url, headers} -> {status, body}`) with a tiny example relay, the per-provider quotas + cache TTLs, and the ToS notes (private cache, BYO keys, no GreyNoise→model-training).

- [ ] **Step 3: Engine README** — document the `online` cargo feature (native-only, pulls `ureq`) and that `apply_reputation` is always-compiled/wasm-safe.

- [ ] **Step 4: Commit** — `git add -A && git commit -m "docs(reputation): operator guide + roadmap + feature notes"`

---

## Deferred to a fast-follow (out of scope for this plan)

- **SNI-domain reputation (VirusTotal, opt-in `--reputation-domains`).** The VT adapter already handles domains (Task B4 `verdict_domain` / E2 mirror), but there's no per-domain *card* to attach verdicts to, and selecting distinct SNIs needs a new bounded `summary.sni_hosts` plus a small UI surface. This plan ships **IP reputation end-to-end**; domains are a clean follow-up that reuses the existing adapter.
- **Configurable TTL/budget tuning UI** (constants are sensible defaults now).
- **Rate-limit pacing/backoff beyond the daily budget** (429 already degrades to `Unavailable`; a token-bucket inter-request delay can be added if a provider tightens per-minute limits).

---

## Self-Review

*Run after the plan is written (done inline below).*

- **Spec coverage:** §3 decisions D1–D6 → Phases A–F; §4 data contract → A1/A2/E1; §5 architecture/module layout → A6/B/D/E; §6 indicator selection + privacy + budgeting → B6/B7/C1/E5 (`is_external` filter, priority order, quota guard); §7 provider adapters → B2–B4 + E2 (exact endpoints/auth/score/envelopes); §8 cache/rate-limit → B5/B6/E3/E4; §9 scoring uplift → A3–A5 (+ parity G1); §10 config/keys → C1/D2/F2; §11 UI → F1–F3; §12 error handling → adapters' `Unavailable` paths; §13 testing → every task + G1; §14 ToS → B5/B6 defaults + G3 docs. **Domains (§2/§7.3)** are explicitly deferred (see above) — the only intentional scope reduction.
- **Placeholders:** none — every code step carries real code; the one earlier thinko (cache test) was corrected.
- **Type consistency:** `ReputationVerdict`/`RepStatus` identical across Rust (A1) ↔ TS (E1); `apply_reputation(summary, verdicts: BTreeMap<String, Vec<ReputationVerdict>>)` consistent in A3/A6/D1; adapter signature `verdict(http, key, ip, now)` consistent B2–B4 ↔ E2; cache key `"{source}|{indicator}"` consistent B5 ↔ E3; budget defaults (9/480/950) consistent B6 ↔ E4.
