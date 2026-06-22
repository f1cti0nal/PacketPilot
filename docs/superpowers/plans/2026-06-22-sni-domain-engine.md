# SNI-domain reputation — Sub-project A (Engine) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The engine spine for SNI-domain reputation — a `DomainThreat` model + a network-free `summary.domain_threats` SNI rollup + a pure `apply_domain_reputation` fold + an `online`-gated VirusTotal domain lookup + WASM export + parity + CLI pass.

**Architecture:** Mirror the reputation engine (`IpThreat`/`apply_reputation`/`lookup_reputation`) keyed by domain. Aggregation is always-on + network-free; lookups are behind the `online` cargo feature. `apply_domain_reputation` is the single pure cross-surface fold.

**Tech Stack:** Rust (`ppcap-core`, `ppcap-wasm`, `ppcap-cli`); Vitest for the TS parity side.

## Global Constraints

- **`apply_domain_reputation` is pure / network-free / wasm-safe** — the single source of the domain-enrichment rule (in `enrich/reputation.rs`, NOT behind any feature). Native, WASM, CLI all call it; a parity test asserts native ≡ WASM.
- **Network lookups stay behind the native-only `online` feature** (`enrich/online/`), reusing the existing `HttpGet` + cache + budget. **VT-only** for domains.
- **SNI aggregation is always-on, network-free** (stats stage, no feature gate).
- **`summary.domain_threats` is `#[serde(default)]`** — no schema bump; old captures still load.
- **No severity/incident coupling** — domains are a display rollup; verdicts attach but never change a host's severity or raise an incident.
- **Bounded:** top **50** hosts by bytes; SNI normalized lowercase, deduped; empty / IP-literal SNI skipped.
- **C-free CI gate stays scoped to `cargo tree -p ppcap-core`** (the `online` `ring`/`cc` dep is the accepted exception). Engine gates: `cargo fmt`, `cargo clippy --workspace --all-targets -D warnings`, `cargo test --workspace`, `cargo test --features online`.
- **WASM rebuild:** after adding the WASM export, `cd ui && npm run build:wasm` so the parity test sees `apply_domain_reputation`.
- **TOOLCHAIN:** cargo at `/c/Users/ravid/.cargo/bin`; the `online` build needs MinGW (`/c/Users/ravid/opt/mingw64/bin`) for `ring`. node/npx at `/c/Program Files/nodejs`. Run cargo from `engine/`. Stage specific files (never `git add -A`).

## Reference: existing patterns (verbatim, to mirror)

```rust
// model/summary.rs:105 — IpThreat (the model to mirror)
// enrich/reputation.rs:34 — ReputationVerdict { source, status, malicious, score:Option<u8>, tags, link, fetched_at }
// enrich/reputation.rs:62 — apply_reputation(summary, &BTreeMap<String, Vec<ReputationVerdict>>) (host-keyed fold)
// stats/mod.rs — StatsAccumulator { …, per_ip_threat: HashMap<IpAddr, IpThreatStat> }; observe_scored_flow(f,sc); finish() builds ip_threats
// enrich/online/virustotal.rs:106 — verdict_domain(http, key, domain, now) -> ReputationVerdict (already written)
// enrich/online/mod.rs:121 — lookup_reputation(http, ips, keys, cache, budget, ttls, now) -> BTreeMap; :241 lookup_reputation_native
// enrich/online/cache.rs — cache.get(source,&ind,now,ttl) / cache.put(source,&ind,v); key = "source|indicator"
// enrich/online/budget.rs — budget.try_spend(source) -> bool
// ppcap-wasm/src/lib.rs:164 — #[wasm_bindgen] apply_reputation(output_json, verdicts_json) -> Result<String, JsValue>
// ppcap-cli/src/cli.rs:191 — the `if reputation { … }` pass (collect IPs → lookup_reputation_native → apply_reputation)
```

---

### Task 1: `DomainThreat` model + `summary.domain_threats`

**Files:**
- Modify: `engine/crates/ppcap-core/src/model/summary.rs`

**Interfaces:**
- Produces: `pub struct DomainThreat { host: String, flows: u64, bytes: u64, reputation: Vec<ReputationVerdict> }`; `Summary.domain_threats: Vec<DomainThreat>` (`#[serde(default)]`).

- [ ] **Step 1: Write the failing test** — add to `summary.rs` `#[cfg(test)] mod tests` (or the existing test module):

```rust
#[test]
fn domain_threats_serde_roundtrip_and_default() {
    let dt = DomainThreat { host: "a.example".into(), flows: 3, bytes: 99, reputation: vec![] };
    let j = serde_json::to_string(&dt).unwrap();
    assert_eq!(serde_json::from_str::<DomainThreat>(&j).unwrap(), dt);

    // Old summaries (no domain_threats key) still deserialize → empty.
    let out = crate::model::output::AnalysisOutput::default();
    let mut v = serde_json::to_value(&out).unwrap();
    v["summary"].as_object_mut().unwrap().remove("domain_threats");
    let back: crate::model::output::AnalysisOutput = serde_json::from_value(v).unwrap();
    assert!(back.summary.domain_threats.is_empty());
}
```

- [ ] **Step 2: Run it to verify it fails** — `cd engine && cargo test -p ppcap-core domain_threats_serde` → FAIL (DomainThreat / field undefined).

- [ ] **Step 3: Implement** — add the struct after `IpThreat` in `summary.rs`:

```rust
/// One per-domain (TLS SNI host) rollup row, ranked by traffic. A display surface — not
/// severity-scored. `reputation` is empty unless the (opt-in) domain reputation pass ran.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DomainThreat {
    pub host: String,
    pub flows: u64,
    pub bytes: u64,
    /// Per-provider domain reputation verdicts (VirusTotal). Empty unless the pass ran.
    #[serde(default)]
    pub reputation: Vec<crate::enrich::ReputationVerdict>,
}
```

In `struct Summary`, after the `ip_threats: Vec<IpThreat>,` field, add:

```rust
    /// Top TLS SNI hosts by traffic. `#[serde(default)]` keeps older summaries readable.
    #[serde(default)]
    pub domain_threats: Vec<DomainThreat>,
```

Then fix every place that constructs a `Summary` literal (the compiler will list them — `stats/mod.rs finish()` and any test builders): add `domain_threats: Vec::new(),`. (Task 2 fills it for real in `finish()`.)

- [ ] **Step 4: Run it to verify it passes** — `cd engine && cargo test -p ppcap-core domain_threats_serde` → PASS; `cargo build -p ppcap-core` → compiles.

- [ ] **Step 5: Commit**

```bash
git add engine/crates/ppcap-core/src/model/summary.rs
git commit -m "feat(model): DomainThreat + summary.domain_threats (serde default)"
```

---

### Task 2: SNI aggregation in stats

**Files:**
- Modify: `engine/crates/ppcap-core/src/stats/mod.rs`

**Interfaces:**
- Consumes: `DomainThreat` (Task 1), `FlowRecord.sni: Option<String>`.
- Produces: `finish()` populates `summary.domain_threats` (top-50 by bytes).

- [ ] **Step 1: Write the failing test** — add to `stats/mod.rs` `#[cfg(test)] mod tests`, mirroring the existing `observe_scored_flow`/`finish` test in this file (build `FlowRecord`s + `ScoredFlow`s the same way the existing ip_threats test does, but set `f.sni`). The behavioral assertions:

```rust
#[test]
fn sni_domains_aggregate_ranked_and_filtered() {
    let mut acc = StatsAccumulator::new(StatsConfig::default());
    // Build flows with SNI (reuse this file's existing flow/scored-flow test helpers):
    //  - "B.Example" 100 bytes, "b.example" 50 bytes (same host, case-insensitive) → merged 150
    //  - "a.example" 200 bytes
    //  - "1.2.3.4" (IP literal) and "" (empty) → skipped
    // observe each via acc.observe_scored_flow(&flow, &scored);
    let summary = acc.finish();
    let hosts: Vec<&str> = summary.domain_threats.iter().map(|d| d.host.as_str()).collect();
    assert_eq!(hosts, vec!["a.example", "b.example"]); // desc by bytes (200 > 150)
    let b = summary.domain_threats.iter().find(|d| d.host == "b.example").unwrap();
    assert_eq!(b.bytes, 150);
    assert_eq!(b.flows, 2);
    assert!(summary.domain_threats.iter().all(|d| d.reputation.is_empty()));
}
```

> NOTE to implementer: read the existing ip_threats stats test in this file to see exactly how a `FlowRecord` + `ScoredFlow` are constructed (`f.key`, `f.severity`, `f.total_bytes()`, `sc.evidence`), then build the SNI flows the same way with `f.sni = Some(...)`. Adjust byte amounts to match the assertions.

- [ ] **Step 2: Run it to verify it fails** — `cd engine && cargo test -p ppcap-core sni_domains_aggregate` → FAIL.

- [ ] **Step 3: Implement** — in `stats/mod.rs`:

(a) A module-level helper + a per-domain stat struct:

```rust
/// A TLS SNI host worth aggregating: non-empty, has a dot, and is not an IP literal.
fn valid_domain(host: &str) -> bool {
    !host.is_empty() && host.contains('.') && host.parse::<std::net::IpAddr>().is_err()
}

#[derive(Debug, Clone, Default)]
struct DomainStat {
    flows: u64,
    bytes: u64,
}
```

(b) Add the field to `StatsAccumulator` (next to `per_ip_threat`): `per_domain: HashMap<String, DomainStat>,` and initialize it in `StatsAccumulator::new()` (next to `per_ip_threat: HashMap::new()`): `per_domain: HashMap::new(),`.

(c) Fold SNI at the end of `observe_scored_flow`:

```rust
    // SNI domain rollup (traffic-ranked; bounded by max_tracked_keys, like per_ip_threat).
    if let Some(raw) = f.sni.as_deref() {
        let host = raw.trim().to_ascii_lowercase();
        if valid_domain(&host)
            && (self.per_domain.contains_key(&host)
                || self.per_domain.len() < self.cfg.max_tracked_keys)
        {
            let e = self.per_domain.entry(host).or_default();
            e.flows += 1;
            e.bytes += f.total_bytes();
        }
    }
```

(d) In `finish()`, after the `ip_threats` build block and before the `Summary { … }` construction, build the domains:

```rust
    // Domain (SNI) rollups: desc by bytes, tie-break desc flows, then asc host. Top-N.
    const TOP_K_DOMAINS: usize = 50;
    let mut domain_threats: Vec<crate::model::summary::DomainThreat> = self
        .per_domain
        .iter()
        .map(|(host, s)| crate::model::summary::DomainThreat {
            host: host.clone(),
            flows: s.flows,
            bytes: s.bytes,
            reputation: Vec::new(),
        })
        .collect();
    domain_threats.sort_by(|a, b| {
        b.bytes
            .cmp(&a.bytes)
            .then(b.flows.cmp(&a.flows))
            .then(a.host.cmp(&b.host))
    });
    domain_threats.truncate(TOP_K_DOMAINS);
```

Then set `domain_threats,` in the `Summary { … }` literal (replacing the `domain_threats: Vec::new()` placeholder from Task 1).

- [ ] **Step 4: Run it to verify it passes** — `cd engine && cargo test -p ppcap-core sni_domains_aggregate` → PASS; `cargo test -p ppcap-core` → all green.

- [ ] **Step 5: Commit**

```bash
git add engine/crates/ppcap-core/src/stats/mod.rs
git commit -m "feat(stats): aggregate TLS SNI hosts into summary.domain_threats (top-50 by bytes)"
```

---

### Task 3: `apply_domain_reputation` pure fold

**Files:**
- Modify: `engine/crates/ppcap-core/src/enrich/reputation.rs`

**Interfaces:**
- Produces: `pub fn apply_domain_reputation(summary: &mut Summary, verdicts: &BTreeMap<String, Vec<ReputationVerdict>>)`. Re-export it from the crate root the same way `apply_reputation` is exported (check `lib.rs` — add `apply_domain_reputation` to the `pub use enrich::{… apply_reputation …}` line).

- [ ] **Step 1: Write the failing test** — add to `reputation.rs` `#[cfg(test)] mod tests`:

```rust
#[test]
fn apply_domain_reputation_attaches_by_host() {
    use crate::model::summary::DomainThreat;
    let mut summary = crate::model::output::AnalysisOutput::default().summary;
    summary.domain_threats = vec![
        DomainThreat { host: "evil.example".into(), flows: 1, bytes: 1, reputation: vec![] },
        DomainThreat { host: "good.example".into(), flows: 1, bytes: 1, reputation: vec![] },
    ];
    let mut verdicts: BTreeMap<String, Vec<ReputationVerdict>> = BTreeMap::new();
    verdicts.insert("evil.example".into(), vec![ReputationVerdict {
        source: "virustotal".into(), status: RepStatus::Malicious, malicious: true,
        score: Some(90), tags: vec![], link: None, fetched_at: 0,
    }]);
    apply_domain_reputation(&mut summary, &verdicts);
    let evil = summary.domain_threats.iter().find(|d| d.host == "evil.example").unwrap();
    assert_eq!(evil.reputation.len(), 1);
    assert_eq!(evil.reputation[0].status, RepStatus::Malicious);
    let good = summary.domain_threats.iter().find(|d| d.host == "good.example").unwrap();
    assert!(good.reputation.is_empty()); // host not in verdicts → unchanged
}
```

- [ ] **Step 2: Run it to verify it fails** — `cd engine && cargo test -p ppcap-core apply_domain_reputation` → FAIL.

- [ ] **Step 3: Implement** — add to `reputation.rs` (after `apply_reputation`):

```rust
/// Attach VirusTotal domain reputation verdicts to `summary.domain_threats`, keyed by host.
/// Pure, network-free, deterministic — the single source of the domain-enrichment rule (mirrors
/// [`apply_reputation`]). Display-only: it does NOT change severity or raise incidents.
pub fn apply_domain_reputation(
    summary: &mut Summary,
    verdicts: &BTreeMap<String, Vec<ReputationVerdict>>,
) {
    for d in summary.domain_threats.iter_mut() {
        if let Some(vs) = verdicts.get(&d.host) {
            if !vs.is_empty() {
                d.reputation = vs.clone();
            }
        }
    }
}
```

Then re-export it: in `engine/crates/ppcap-core/src/lib.rs`, find the `pub use enrich::{…}` line that exports `apply_reputation` and add `apply_domain_reputation` to it.

- [ ] **Step 4: Run it to verify it passes** — `cd engine && cargo test -p ppcap-core apply_domain_reputation` → PASS.

- [ ] **Step 5: Commit**

```bash
git add engine/crates/ppcap-core/src/enrich/reputation.rs engine/crates/ppcap-core/src/lib.rs
git commit -m "feat(enrich): apply_domain_reputation pure fold (host-keyed, display-only)"
```

---

### Task 4: Online VT domain lookup (behind `online`)

**Files:**
- Modify: `engine/crates/ppcap-core/src/enrich/online/mod.rs`

**Interfaces:**
- Consumes: `virustotal::verdict_domain` (exists), the existing `ReputationCache`/`Budget`/`Ttls`/`ReputationKeys`/`UreqClient`, `cache.get`/`put`, `budget.try_spend`.
- Produces: `pub fn lookup_domain_reputation(http, hosts: &[String], keys, cache, budget, ttls, now) -> BTreeMap<String, Vec<ReputationVerdict>>` and `pub fn lookup_domain_reputation_native(hosts: &[String], keys, cache_dir, now) -> BTreeMap<…>`.

- [ ] **Step 1: Write the failing test** — add to `online/mod.rs` `#[cfg(test)] mod tests` (this file already has online tests with a fake `HttpGet` — reuse that fake; if the test module lives elsewhere, mirror the existing `lookup_reputation` test):

```rust
#[test]
fn domain_lookup_uses_vt_caches_and_budgets() {
    // FakeHttp returns a VT domains 200 body with a malicious stat (reuse the existing fake
    // used by the IP lookup tests in this module).
    let http = FakeHttp::vt_domain_malicious(); // adapt to the existing fake's constructor
    let keys = ReputationKeys { abuseipdb: None, greynoise: None, virustotal: Some("k".into()) };
    let mut cache = ReputationCache::default();
    let mut budget = Budget::with_defaults();
    let hosts = vec!["evil.example".to_string()];
    let out = lookup_domain_reputation(&http, &hosts, &keys, &mut cache, &mut budget, &Ttls::default(), 0);
    assert_eq!(out.get("evil.example").unwrap()[0].status, RepStatus::Malicious);
    // Second call hits the cache (no new budget spend / no new http call):
    let before = http.calls();
    let _ = lookup_domain_reputation(&http, &hosts, &keys, &mut cache, &mut budget, &Ttls::default(), 0);
    assert_eq!(http.calls(), before, "second lookup should be served from cache");
}
```

> NOTE: adapt to the existing fake `HttpGet` in this module (the IP lookup tests already define one — find it and either add a VT-domain-malicious response or reuse a generic canned-200 fake). Keep the cache-hit assertion.

- [ ] **Step 2: Run it to verify it fails** — `cd engine && cargo test -p ppcap-core --features online domain_lookup` → FAIL.

- [ ] **Step 3: Implement** — add to `online/mod.rs` (VT-only — abuseipdb/greynoise are IP-only):

```rust
/// Look up VirusTotal domain reputation for `hosts`, reusing the existing cache + budget
/// (keyed `virustotal|<host>`). VT-only — the other providers don't do domains.
pub fn lookup_domain_reputation(
    http: &dyn HttpGet,
    hosts: &[String],
    keys: &ReputationKeys,
    cache: &mut ReputationCache,
    budget: &mut Budget,
    ttls: &Ttls,
    now: i64,
) -> BTreeMap<String, Vec<ReputationVerdict>> {
    let mut out: BTreeMap<String, Vec<ReputationVerdict>> = BTreeMap::new();
    let Some(k) = &keys.virustotal else { return out };
    for host in hosts {
        let source = "virustotal";
        let v = if let Some(hit) = cache.get(source, host, now, ttls.virustotal) {
            hit.clone()
        } else if budget.try_spend(source) {
            let v = virustotal::verdict_domain(http, k, host, now);
            cache.put(source, host, v.clone());
            v
        } else {
            quota_unavailable(source, now)
        };
        out.insert(host.clone(), vec![v]);
    }
    out
}

/// Native convenience wrapper (CLI/Tauri): loads/saves the on-disk cache.
pub fn lookup_domain_reputation_native(
    hosts: &[String],
    keys: &ReputationKeys,
    cache_dir: &Path,
    now: i64,
) -> BTreeMap<String, Vec<ReputationVerdict>> {
    let http = UreqClient::default();
    let mut cache = ReputationCache::load(cache_dir);
    let mut budget = Budget::with_defaults();
    let out = lookup_domain_reputation(&http, hosts, keys, &mut cache, &mut budget, &Ttls::default(), now);
    let _ = cache.save();
    out
}
```

> NOTE: `quota_unavailable` is the same helper `lookup_reputation` uses (already in this module). If `ReputationCache::default()` isn't available for the test, use `ReputationCache::load(tempdir)` or the constructor the existing tests use.

- [ ] **Step 4: Run it to verify it passes** — `cd engine && cargo test -p ppcap-core --features online domain_lookup` → PASS. (Prepend MinGW to PATH if `ring` errors.)

- [ ] **Step 5: Commit**

```bash
git add engine/crates/ppcap-core/src/enrich/online/mod.rs
git commit -m "feat(online): lookup_domain_reputation (VT, cache+budget reuse)"
```

---

### Task 5: WASM export + CLI domain pass

**Files:**
- Modify: `engine/crates/ppcap-wasm/src/lib.rs` (export), `engine/crates/ppcap-cli/src/cli.rs` (domain pass)

**Interfaces:**
- Consumes: `ppcap_core::apply_domain_reputation` (Task 3), `ppcap_core::lookup_domain_reputation_native` (Task 4).
- Produces (WASM): `apply_domain_reputation(output_json, verdicts_json) -> Result<String, JsValue>`.

- [ ] **Step 1: WASM export** — add to `engine/crates/ppcap-wasm/src/lib.rs` (after `apply_reputation`):

```rust
/// Apply VirusTotal domain reputation verdicts to a completed analysis. `output_json` is the
/// `AnalysisOutput`; `verdicts_json` is `{ "<host>": [ReputationVerdict, ...], ... }`. Pure +
/// network-free — identical to native callers.
#[wasm_bindgen]
pub fn apply_domain_reputation(output_json: &str, verdicts_json: &str) -> Result<String, JsValue> {
    use std::collections::BTreeMap;
    let mut out: ppcap_core::AnalysisOutput =
        serde_json::from_str(output_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let verdicts: BTreeMap<String, Vec<ppcap_core::ReputationVerdict>> =
        serde_json::from_str(verdicts_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    ppcap_core::apply_domain_reputation(&mut out.summary, &verdicts);
    serde_json::to_string(&out).map_err(|e| JsValue::from_str(&e.to_string()))
}
```

- [ ] **Step 2: CLI domain pass** — in `engine/crates/ppcap-cli/src/cli.rs`, inside the existing `if reputation { … }` block, AFTER the IP `apply_reputation(&mut out.summary, &verdicts);` line (still inside the `else` where keys exist), add:

```rust
        // Domain (SNI) reputation — VT-only; same keys/cache/timestamp.
        let hosts: Vec<String> = out
            .summary
            .domain_threats
            .iter()
            .map(|d| d.host.clone())
            .collect();
        if !hosts.is_empty() {
            let domain_verdicts =
                ppcap_core::lookup_domain_reputation_native(&hosts, &keys, &cache_dir, now);
            ppcap_core::apply_domain_reputation(&mut out.summary, &domain_verdicts);
        }
```

(`keys`, `cache_dir`, `now` are already in scope from the IP pass above.)

- [ ] **Step 3: Build + verify** — `cd engine && export PATH="/c/Users/ravid/opt/mingw64/bin:/c/Users/ravid/.cargo/bin:$PATH" && cargo build --workspace && cargo test -p ppcap-core` → compiles + green. Then rebuild wasm: `cd ../ui && npm run build:wasm` → clean; `grep apply_domain_reputation src/wasm/ppcap_wasm.js` → present.

- [ ] **Step 4: Commit** (stage Rust source only; `ui/src/wasm/` is gitignored):

```bash
git add engine/crates/ppcap-wasm/src/lib.rs engine/crates/ppcap-cli/src/cli.rs
git commit -m "feat(wasm+cli): apply_domain_reputation export + CLI domain reputation pass"
```

---

### Task 6: Cross-surface parity (native ≡ WASM)

**Files:**
- Modify: `ui/src/test/reputation-parity.fixture.json` (add a domain block), `engine/crates/ppcap-core/tests/reputation_parity.rs`, `ui/src/lib/reputation/parity.test.ts`

**Interfaces:**
- Consumes: native `apply_domain_reputation` + the WASM export (built in Task 5).

- [ ] **Step 1: Extend the fixture** — in `ui/src/test/reputation-parity.fixture.json`, (a) add a `domain_threats` array to `output.summary` (2 hosts, e.g. `evil.example` + `good.example`, `reputation: []`); (b) add a top-level `"domain_verdicts": { "evil.example": [ { "source":"virustotal","status":"malicious","malicious":true,"score":90,"tags":[],"link":null,"fetched_at":0 } ] }`; (c) add `"expected_domains": [ { "host":"evil.example","reputation_len":1 }, { "host":"good.example","reputation_len":0 } ]`.

- [ ] **Step 2: Native assertion** — append to `engine/crates/ppcap-core/tests/reputation_parity.rs`:

```rust
#[test]
fn native_apply_domain_matches_fixture() {
    let raw = include_str!("../../../../ui/src/test/reputation-parity.fixture.json");
    let fx: serde_json::Value = serde_json::from_str(raw).unwrap();
    let mut out: ppcap_core::AnalysisOutput = serde_json::from_value(fx["output"].clone()).unwrap();
    let verdicts: std::collections::BTreeMap<String, Vec<ppcap_core::ReputationVerdict>> =
        serde_json::from_value(fx["domain_verdicts"].clone()).unwrap();
    ppcap_core::apply_domain_reputation(&mut out.summary, &verdicts);

    let expected = fx["expected_domains"].as_array().unwrap();
    for exp in expected {
        let host = exp["host"].as_str().unwrap();
        let row = out.summary.domain_threats.iter().find(|d| d.host == host).unwrap();
        assert_eq!(row.reputation.len() as u64, exp["reputation_len"].as_u64().unwrap(), "{host}");
    }
}
```

- [ ] **Step 3: WASM assertion** — append a test to `ui/src/lib/reputation/parity.test.ts` (the file already `initSync`s the wasm). Add `apply_domain_reputation` to the import from `../../wasm/ppcap_wasm.js`, then:

```ts
it("WASM apply_domain matches the shared expected (== native)", () => {
  const outputJson = JSON.stringify((fixture as any).output);
  const verdictsJson = JSON.stringify((fixture as any).domain_verdicts);
  const enriched = JSON.parse(apply_domain_reputation(outputJson, verdictsJson)) as AnalysisOutput;
  const got = (enriched.summary as any).domain_threats.map((d: any) => ({ host: d.host, n: d.reputation.length }));
  const want = (fixture as any).expected_domains.map((e: any) => ({ host: e.host, n: e.reputation_len }));
  // compare by host
  for (const w of want) {
    expect(got.find((g: any) => g.host === w.host)?.n).toBe(w.n);
  }
});
```

- [ ] **Step 4: Run both** — `cd engine && cargo test -p ppcap-core --test reputation_parity` → both pass. `cd ../ui && npm run build:wasm && npx vitest run src/lib/reputation/parity.test.ts` → passes (the rebuilt wasm carries the export).

- [ ] **Step 5: Commit**

```bash
git add ui/src/test/reputation-parity.fixture.json engine/crates/ppcap-core/tests/reputation_parity.rs ui/src/lib/reputation/parity.test.ts
git commit -m "test(parity): native==WASM apply_domain_reputation"
```

---

### Task 7: Engine gates + coverage verification

**Files:**
- Add focused tests if a gate flags a gap.

- [ ] **Step 1: Engine gates** — `cd engine && export PATH="/c/Users/ravid/opt/mingw64/bin:/c/Users/ravid/.cargo/bin:$PATH"`:
  - `cargo fmt --all --check` → clean.
  - `cargo clippy --workspace --all-targets -- -D warnings` → no warnings.
  - `cargo test --workspace` → green.
  - `cargo test -p ppcap-core --features online` → green (the domain lookup test).

- [ ] **Step 2: C-free gate (unchanged)** — confirm the offline default graph is still C-compiler-free: `cargo tree -p ppcap-core | grep -i ring` → no output (ring only appears under `--features online`). Do NOT broaden the gate.

- [ ] **Step 3: UI parity gate under the locked toolchain** — `cd ui && export PATH="/c/Program Files/nodejs:$PATH" && npm ci && node -p "require('./node_modules/vitest/package.json').version"` (→ 1.6.1) && `npm run build:wasm && npm run build` (EXIT 0, 0 TS errors) && `npm run test:coverage` (EXIT 0; `All files` ≥ 80/70 — paste it). The new code is mostly Rust; the only UI change is the parity test, so coverage should be unaffected.

- [ ] **Step 4: Commit** (only if gap-filling tests were added)

```bash
git add engine/crates/ppcap-core
git commit -m "test(domain): engine gate fill"
```

---

## Self-Review

**1. Spec coverage:** DomainThreat + summary field (T1) → spec §2; SNI aggregation top-50 (T2) → §3; apply_domain_reputation pure fold (T3) → §4; online VT lookup + native wrapper (T4) → §5; WASM export + CLI pass (T5) → §6; parity (T6) → §5 cross-surface; gates incl. C-free + build:wasm (T7) → constraints. No severity coupling (T3/T4 attach only). VT-only (T4). serde default (T1). All spec sections map. ✓

**2. Placeholder scan:** every code step has complete code. The NOTEs (mirror the existing stats/online test harness for fixture construction; confirm the `quota_unavailable`/`ReputationCache` constructors; the crate-root re-export line) are concrete in-repo verifications, not placeholders. ✓

**3. Type consistency:** `DomainThreat { host, flows, bytes, reputation }` (T1) used identically in T2 (build), T3 (`apply_domain_reputation` fold), T5 (CLI collects `.host`), T6 (parity). `apply_domain_reputation(summary, &BTreeMap<String, Vec<ReputationVerdict>>)` consistent T3/T5/T6. `lookup_domain_reputation(_native)` signatures consistent T4/T5. ✓
