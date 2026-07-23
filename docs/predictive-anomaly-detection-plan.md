# PacketPilot — Predictive Anomaly Detection

**Implementation Plan**

| | |
|---|---|
| **Status** | **Implemented** on this branch — engine + CLI + browser/desktop UI parity, adversarially designed, fully test-verified |
| **Feature branch** | `claude/predictive-anomaly-detection-planning-uwgayg` |
| **Date** | 2026-07-21 |
| **Scope** | Engine (Rust: new `forecast` module + one bounded `stats` accumulator + `analyze`/`model`/`score`/`detect`/`report`/`gen` seams) · CLI (`analyze --no-forecast` + stderr summary) · UI (React/TS `FindingKind` + `KIND_META` + kill-chain maps) · WASM/desktop (rides the existing `AnalysisOutput` — no new export) |

> **Implementation status (what actually shipped).** This plan was executed on the branch above.
> Predictive Anomaly Detection (PAD) forecasts each internal host's within-capture **outbound**
> time-series and raises `traffic_anomaly` findings for **egress spikes**, **transient drops**, and
> **sustained level shifts (CUSUM changepoints)** — behaviour-relative-to-its-own-recent-trajectory,
> learned inside a **single capture** with no cross-capture history. It is **on by default** (no
> sidecar, no flag), so anomalies ride through `--json`/`--html`/CSV/STIX and the browser/desktop UI
> for free.
>
> - **Engine core** — new `forecast` module (Holt double-exponential smoother + residual-EWMA
>   prediction band + two-sided CUSUM; `ForecastParams`/`ForecastInput`/`HostSeries`/`ForecastReport`/
>   `detect_traffic_anomalies`), one net-new bounded `StatsAccumulator::per_host_epoch` accumulator +
>   its `forecast_input` projector, `FindingKind::TrafficAnomaly` + every exhaustive match arm,
>   `score_traffic_anomaly` + `PTS_FC_*`/`FC_UPLIFT_CAP`, the analyze seam, and a
>   `Scenario::TrafficSpike` generator fixture.
> - **CLI** — `analyze --no-forecast` opt-out + a `forecast: N …` stderr summary line.
> - **Browser/desktop** — findings live on `summary.findings`, which the wasm `analyze` already
>   serialises whole, so PAD surfaces in the dashboard/findings/exports with **no wasm `.rs` change**;
>   the UI adds the `traffic_anomaly` `FindingKind`, its `KIND_META` (label + `TrendingUp` icon), and
>   the two kill-chain stage maps.
> - **Verified here:** engine `cargo fmt --all --check` / `clippy --workspace --all-targets -D warnings`
>   / `test --workspace` (671 tests incl. 12 forecaster-unit + 2 stats-substrate + 3 e2e), the
>   `--features online` suite, and the **cc-free gate**; UI `tsc -b`, Vitest (**983**), and
>   `vite build`; plus a real CLI smoke (`gen --scenario traffic-spike | analyze` → one
>   `traffic_anomaly` finding). **Not verifiable in this sandbox** (left to CI, per the BBL
>   precedent): the wasm32 bundle rebuild (`build:wasm`), Playwright e2e, and the Tauri desktop build.

> **How this plan was produced.** Eight parallel readers each mapped one subsystem PAD touches —
> the time-series/stats substrate, the detection engine, the data model, the analyze+scoring
> pipeline, the baseline (BBL) module, the CLI, the WASM/UI parity surfaces, and the repo's
> gen/CI/testing conventions — reading the checked-out source. The design was synthesised from those
> maps and run through an adversarial review across three lenses (engine correctness & reuse, hard
> invariants, product/UX vs. BBL). Every cited path/line/signature was verified against the tree, and
> the review corrections are folded in (Appendix A).

---

## 1. Summary & Goals

### What ships

**Predictive Anomaly Detection (PAD)** teaches PacketPilot to *forecast* each internal host's traffic
and flag what the forecast did not predict. During the streaming pass it accumulates a per-host,
per-second **egress** series; at EOF it runs an online **one-step-ahead forecaster** — Holt's double
exponential smoothing (a `level` + a `trend`) — over each host's series, and raises an explainable
`traffic_anomaly` finding when a bin lands outside the forecast's **prediction band** (`forecast ± z·σ`,
σ an EWMA of the forecast residuals) or when a **sustained** departure trips a two-sided **CUSUM**
changepoint. It is *predictive* in the true forecasting sense, needs **no sidecar and no prior
captures**, and is built almost entirely from machinery the engine already has: the live per-second
histogram substrate (`StatsAccumulator`), the adaptive time-bucket chooser (`choose_bucket_width`),
the `Finding` → `apply_findings` → per-IP threat-card path, the transparent `add_term` score ledger,
and the `Scenario`/gen fixture harness. The genuinely new code is small and bounded: the forecaster
(pure `f64`, O(1) state per host) and one insert-only-capped per-`(host, second)` accumulator.

### What it changes vs. today's engine

| Dimension | Today | New with PAD |
|---|---|---|
| Detection basis | Absolute thresholds (`Beacon`/`PortScan`/`Exfil`/`SynFlood`) or set membership (IOC, first-seen peer) | The **first forecasting** detector: a value is anomalous relative to what the host's own trajectory *predicted* |
| Temporal awareness | Single per-flow/per-host aggregates; `time_histogram` is display-only | Reads the **shape over time** — a burst at 03:14, a ramp, a transient drop — that an aggregate collapses away |
| History needed | — | **None**: learns the host's normal *within this one capture* (no warm-up over N captures) |
| Explainability | Every score point → one `ScoreTerm` + evidence line | Each anomaly dimension is one `add_term` point + one forecast-vs-actual evidence line |

### How PAD complements Behavioral Baseline Learning (BBL)

PAD and BBL (`docs/behavioral-baseline-learning-plan.md`) are deliberately **orthogonal**:

| | Behavioral Baseline Learning | Predictive Anomaly Detection |
|---|---|---|
| Question | "Is this capture unusual for this host's **history**?" | "Did this host's traffic do something its **own forecast** did not predict, right here?" |
| Reference | A per-host aggregate learned across **many prior captures** (sidecar) | The host's **within-capture trajectory** (no sidecar) |
| Reads | One number per host per capture (mean ± k·σ, first-seen sets) | The **per-bin time-series** (level, trend, residual σ, CUSUM) |
| Warm-up | ≥ `min_captures` captures | ≥ `min_bins` bins **inside the capture** |
| Blind spot each fills | Blind to *when within a capture* volume arrived | Blind to *cross-capture* novelty (a first-ever peer) |

A host on a legitimately rising week-over-week trend eventually false-positives BBL's lagging mean;
PAD forecasts the trend and stays quiet — but flags the moment the host jumps *off* its own trend
mid-capture. They fire on genuinely different signals and both uplift the same per-IP threat card.

### Non-goals (this plan's core)

Local-first, on-device, single-capture, offline only. **No** cross-capture forecast history, **no**
seasonality/Holt-Winters, **no** ML/clustering, **no** per-peer or per-port sub-series. Those are
follow-ups (§13), scoped out exactly as BBL scopes out its team-store and ML upgrades.

---

## 2. Concept & Chosen Approach

### 2.1 Why forecasting, not another threshold

Every current detector answers "is this value past a fixed line?" PAD answers "is this value far from
what we *predicted*?" — which adapts to each host's own scale and trend, so it neither drowns a busy
server in alerts nor misses a quiet host's small-but-off-trend burst. PAD forecasts **outbound egress
keyed by the internal sender** and, symmetrically, **inbound ingress keyed by the internal receiver**
(§13) — detecting both a host *emitting* volume and a victim *receiving* it, each attributed to the
internal host it concerns. The three shapes it catches (described for egress; ingress mirrors them on
the receive series):

- **Egress spike** — one bin far above the upper band: a host *launching* outbound volume (an exfil
  burst, a C2 dump, or participation in an outbound flood). The symmetric **ingress spike** flags a host
  *under* an inbound byte-flood (`T1498`), complementing `SynFlood`'s half-open-connection view (§13).
- **Transient drop** — one bin far below the lower band where the forecast expected real traffic: a
  collapse toward silence that then **recovers** (a stalled transfer, a paused process). A host that
  goes silent and never resumes has no trailing bins, so end-of-capture silence is out of scope (§12).
- **Level shift** — a *sustained* departure (a ramp/plateau, not a blip), caught by CUSUM: a sustained
  exfil ramp, an outbound scan/flood ramp, or a device becoming newly chatty.

### 2.2 The substrate already exists

`StatsAccumulator` already maintains a live per-second series — `per_second: HashMap<i64, SecStat>`
(`stats/mod.rs`), folded during streaming and re-bucketed at `finish()` into a bounded
`time_histogram` via `build_time_histogram`/`choose_bucket_width` (adaptive "nice" width, ≤
`max_time_buckets`). PAD reuses that exact **adaptive bin width** so its forecast bins line up with the
UI timeline, and adds **one** net-new per-host dimension so anomalies can be attributed to a host.

### 2.3 Per-entity scoping and attribution: internal senders

An anomaly must attach to a real `Finding.src_ip` so it uplifts a per-IP card and flows into
incidents/chains. PAD therefore forecasts **egress per internal host**: the streaming fold records
`wire_len` into a `(src_ip, epoch_second)` cell **only when the sender is internal** —
`!classify_ip(src).is_external()`, the same monitored-network gate BBL uses (`enrich`). External
senders and pure destinations are excluded. This makes every `traffic_anomaly` attributable and keeps
the accumulator focused on the network we actually model.

### 2.4 One post-EOF pass, before the summary is sealed

The forecast runs at the same seam as the BBL compare — after the `detect_*` extends and **before**
`stats.apply_findings` / `stats.finish()` (`analyze/mod.rs`) — reading the still-live accumulator via
a read-only projector. So `traffic_anomaly` findings uplift the per-IP cards and feed
`correlate_incidents`/`reconstruct_attack_chains` exactly like every other detector.

---

## 3. The Forecast Math (all pure `f64`, O(1) state per host)

For a host's contiguous, zero-gap-filled bin series `y[0..n]`, with parameters
(`α` level, `β` trend, `γ` residual-variance, `z` band, `min_bins` warm-up, CUSUM `k`/`h`):

```
level  = y[0]
trend  = y[1] - y[0]
var    = 0                       # EWMA of squared forecast residuals
σ_floor = max(sigma_floor_frac · mean(y), 1)

for t in 1..n:
    forecast = level + trend                    # one-step-ahead
    resid    = y[t] - forecast
    σ        = max(√var, σ_floor)               # residual σ from history BEFORE this bin
    z_t      = resid / σ

    if t >= min_bins:                           # warm-up gate
        if z_t >= z:                    SPIKE
        elif z_t <= -z and forecast > σ_floor:  DROP
        cusum_hi = max(0, cusum_hi + z_t - k)   # two-sided CUSUM on standardized residual
        cusum_lo = max(0, cusum_lo - z_t - k)
        if cusum_hi > h or cusum_lo > h:  LEVEL_SHIFT; reset both

    prev  = level                               # advance Holt + variance EWMA
    level = α·y[t] + (1-α)·(level + trend)
    trend = β·(level - prev) + (1-β)·trend
    var   = γ·resid² + (1-γ)·var
```

The **σ floor tied to the host's mean** is the key false-positive guard: a host that means 1 MB/bin
does not flag a few-KB wobble as "many σ". The warm-up gate is the single-capture analogue of BBL's
`min_captures`. Everything is fixed-order arithmetic over a sorted series — deterministic, no clock,
no RNG. Shipped defaults (`ForecastParams::default`): `α=0.4, β=0.2, γ=0.3, z=4.0, min_bins=8,
cusum_k=0.5, cusum_h=6.0, min_bin_bytes=8192, max_hosts=256, max_findings=256, sigma_floor_frac=0.15`.

---

## 4. Engine module shape — `forecast/mod.rs`

New module `engine/crates/ppcap-core/src/forecast/mod.rs` (single-word dir + `mod.rs`, matching
`baseline/`, `timemachine/`, `sanitize/`). Public surface (re-exported from `lib.rs`):

```rust
pub struct ForecastParams { /* enabled + the tunables in §3 */ }
pub struct HostSeries   { pub host: String, pub start_epoch_sec: i64, pub bin_secs: i64, pub bins: Vec<u64> }
pub struct ForecastInput { pub bin_secs: i64, pub series: Vec<HostSeries> }
pub struct Anomaly       { host, severity, score, title, evidence, first_seen_ns, last_seen_ns, attack }
pub struct ForecastReport { pub anomalies: Vec<Anomaly>, pub hosts_analyzed: usize }
impl ForecastReport { pub fn into_findings(self) -> Vec<Finding> }   // kind = TrafficAnomaly
pub fn detect_traffic_anomalies(input: &ForecastInput, p: &ForecastParams) -> ForecastReport;
```

`detect_traffic_anomalies` skips trivial hosts (peak bin `< min_bin_bytes`), forecasts each series,
folds a host's hits into **one** `Anomaly` (one host → one finding, aggregating the hit kinds — the
BBL `Deviation` shape), then sorts worst-first (`score` desc, `severity` desc, `host` asc) and caps at
`max_findings`. `into_findings` maps each `Anomaly` to a `Finding { kind: TrafficAnomaly, src_ip:
host, dst_ip: None, attack: ["T1048"] for volume-up shapes, first/last_seen_ns: the anomalous
window }`.

### 4.1 Compiler-forced exhaustive `match FindingKind` arms

`FindingKind::TrafficAnomaly` is appended last (preserves existing ordinals → `Ord`/`Hash`
stability). The variant forces a new arm at every no-`_` match — all added:

| Site | Arm |
|---|---|
| `model/finding.rs` `as_str` | `=> "traffic_anomaly"` |
| `detect/mod.rs` `stage_ordinal` | `=> 5` (exfiltration/impact) |
| `detect/mod.rs` `stage_label` | `=> "Exfiltration"` |
| `detect/mod.rs` `kind_phrase` | `=> "showed a traffic pattern its own forecast did not predict"` |
| `report/mod.rs` `kind_label` | `=> "Traffic Forecast Anomaly"` |

`victims_of`, `handoff_weight`, `campaign_infra_key` (all `_`-fallback) and `technique_name`
(string-keyed, `_ => id`) need **no** change; `T1048` is already in `technique_name`.

---

## 5. The substrate — `stats/mod.rs`

- **New config bound** `StatsConfig::max_forecast_cells` (default `131_072`, ≈ 6–8 MiB worst-case),
  sized *independently* of `max_tracked_keys` (2M) so the accumulator can never blow the ≤64 MiB heap
  budget.
- **New accumulator** `per_host_epoch: HashMap<(IpAddr, i64), u64>` — per-`(internal host, second)`
  egress `wire_len`, folded per packet right after `bump_ip` (where `src_ip`, `ts_ns`, `ts_known`,
  `wire_len` are all in scope), gated on `ts_known && !classify_ip(src).is_external()`, via an
  **insert-only** bound (existing cell accumulates; a new cell past the cap is dropped) — O(1) per
  packet, and non-distorting under saturation because interior cells are never evicted (§7). This
  deliberately differs from the heavy-hitter `bump_bounded` used elsewhere, because this key grows with
  capture duration rather than over a finite entity space.
- **New projector** `StatsAccumulator::forecast_input(&self, &ForecastParams) -> ForecastInput`
  (read-only, called before `finish()`): groups cells by host via `BTreeMap`, re-buckets to the
  network histogram's adaptive width (`choose_bucket_width`), ranks hosts by total egress and keeps
  the top `max_hosts`, then materialises each kept host as a **contiguous, zero-gap-filled** `Vec<u64>`
  across *its own* active window (leading-zero-prefix avoided so a late-appearing host isn't a false
  spike; interior silence stays visible so a drop is detectable). Bounded: ≤ `max_time_buckets` bins
  per host, ≤ `max_hosts` hosts.

---

## 6. Analyze pipeline & scoring

- **`PipelineConfig::forecast: ForecastParams`** (default = `ForecastParams::default()`, i.e.
  **enabled**). Native + wasm both use the default, so PAD is on everywhere unless disabled.
- **Seam** (`analyze/mod.rs`), inserted after the BBL compare and before `stats.apply_findings`:
  ```rust
  if cfg.forecast.enabled {
      let fc_input = stats.forecast_input(&cfg.forecast);
      findings.extend(detect_traffic_anomalies(&fc_input, &cfg.forecast).into_findings());
  }
  ```
- **Scoring** (`score/mod.rs`) — `score_traffic_anomaly(dims: &[(String, i32)]) -> ScoredDeviation`,
  identical in shape to `score_baseline_deviation`: each dimension is one `add_term` point, the sum is
  clamped to `[0, FC_UPLIFT_CAP]` (clamp delta recorded), severity via `Severity::from_score`.
  Weights: `PTS_FC_SPIKE=15`, `PTS_FC_LEVEL_SHIFT=15`, `PTS_FC_DROP=10`, `FC_UPLIFT_CAP=45`. So an
  anomaly **alone tops out at Medium**; High/Critical must come from corroboration (a co-located IOC
  floor or a beacon/exfil finding on the same host lifting the card), never from stacking points —
  exactly the module's stated philosophy and `REP_UPLIFT_CAP`/`DEV_UPLIFT_CAP` precedent.

---

## 7. Performance, Determinism & Invariants (explicit)

- **Bounded memory, independent of capture size.** The one net-new map is capped by
  `max_forecast_cells`; per-host series are ≤ `max_time_buckets` bins; forecaster state is O(1) per
  host. Verified: `golden_e2e`/`end_to_end` still assert `peak_heap_bytes() <
  PHASE0_BUDGET.max_peak_heap_bytes` and pass.
- **O(1) per-packet fold — the keying nuance, called out honestly.** Unlike every other stats map
  (which keys on a *finite* entity space — IP, port, proto-path), `per_host_epoch`'s `(host, second)`
  key grows with capture **duration × active hosts**, so it saturates far sooner. It therefore uses an
  **insert-only** bound (existing cell accumulates; a new cell past the cap is dropped) rather than the
  heavy-hitter `bump_bounded` evictor — so the fold stays **O(1)** with no per-cell eviction scan that
  would scale with capture length, and eviction never removes an *interior* cell, so a saturated
  capture stops extending a host's series rather than silently corrupting it into a false drop. (This
  is the one place PAD deviates from the "reuse `bump_bounded` uncritically" pattern, deliberately.)
- **Single-pass streaming.** One extra O(1) map op per internal-sender packet; the forecast is a
  pure post-EOF projection + transform (no second packet pass, no pcap re-read, like the BBL compare).
- **C-compiler-free.** Pure-Rust `f64` + `HashMap`/`BTreeMap`; no new deps → the CI cc-free gate stays
  clean (verified).
- **Deterministic.** Sorted `BTreeMap` grouping, host ranking with an `IpAddr` tie-break, fixed-order
  arithmetic, worst-first emit with a total-order tie-break; no `Date::now`/`rand`. The gen fixture is
  byte-reproducible for the same seed+count (test).
- **Offline & local-first.** No network; nothing leaves the device.
- **Schema untouched.** PAD is summary-level (findings only); the Parquet/flow schema and the
  `schema_drift.rs` guard are not touched.

---

## 8. CLI Surface

PAD is on by default, so `ppcap analyze <cap>` already emits `traffic_anomaly` findings into
`--json`/`--html`/`--csv`/`--stix`. Added:

- **`analyze --no-forecast`** — opt-out flag; sets `cfg.forecast.enabled = false`.
- **Stderr summary** — `forecast: N predictive traffic anomal{y,ies}` (unless `--quiet`/disabled),
  mirroring the `baseline:`/`wrote Time Machine index` lines.
- **`gen --scenario traffic-spike`** — the fixture below, for a one-command demo:
  `ppcap gen spike.pcap --scenario traffic-spike --packets 400 && ppcap analyze spike.pcap`.

---

## 9. WASM + UI Surface

**Rides for free:** `traffic_anomaly` findings live on `summary.findings`, which the wasm `analyze`
serialises whole — so they appear in the browser/desktop dashboard, `FindingsView`,
graph/heatmap/matrix, and CSV/STIX/Sigma exports with **no wasm `.rs` change** (the `AnalysisOutput`
ride-through, like BBL). The wasm bundle is regenerated by CI's `build:wasm` from the updated engine.

**Net-new TS (compiler-forced, minimal):**
- `types.ts` — add `"traffic_anomaly"` to the `FindingKind` union.
- `lib/findingKinds.ts` — `KIND_META.traffic_anomaly = { label: "Traffic Forecast Anomaly", Icon:
  TrendingUp }` (the union addition forces this exhaustive-`Record` entry, and the two other exhaustive
  `Record<FindingKind, string>` kill-chain maps — `lib/killChain.ts` and `cockpit/IncidentHero.tsx`
  `KIND_STAGE` → `"Exfiltration"`).

No dedicated tab/panel — matching what BBL actually shipped (the finding surfaces through the shared
findings UI). A forecast-band overlay on the existing timeline chart is a documented follow-up (§13).

---

## 10. Testing

- **Forecaster unit** (`forecast/mod.rs`, 12 tests): steady/linear-ramp stay silent; spike, drop, and
  sustained level-shift each flagged; warm-up and trivial-host gates; disabled no-op; deterministic
  worst-first output; anomaly-alone caps at Medium; `into_findings` field mapping; `hhmmss` UTC.
- **Substrate integration** (`stats/mod.rs`, 2 tests): real `observe_packet → forecast_input →
  detect_traffic_anomalies` on a hand-built spike; external senders excluded.
- **Full-pipeline e2e** (`tests/forecast_e2e.rs`, 3 tests): `gen TrafficSpike → analyze::run` raises a
  `traffic_anomaly` attributed to the spiking host and uplifts its threat card; `--no-forecast`
  suppresses it; generation is deterministic.
- **Generator** — `Scenario::TrafficSpike` (`gen/mod.rs`): one internal host, a flat ~1 frame/second
  TLS baseline with a concentrated burst all in one mid-capture second; `all().len()` assertion bumped
  7→8; `from_str_opt` tokens (`spike`/`traffic-spike`); `weights_for` arm.
- **CLI** — `analyze --no-forecast` parse test.
- **UI** — `tsc -b`, the full Vitest suite (983), and `vite build` all green.

---

## 11. Phased Milestones (all shipped on this branch)

- **M1 — Forecaster + substrate + wiring.** `forecast/mod.rs`, `per_host_epoch` + `forecast_input`,
  `FindingKind::TrafficAnomaly` + arms, the analyze seam, `score_traffic_anomaly`. *Value: any capture
  gets spike/drop/level-shift findings, fully offline.*
- **M2 — Generator fixture + full e2e.** `Scenario::TrafficSpike` + `forecast_e2e.rs`. *Value: a
  one-command demo and a file→analyze regression gate.*
- **M3 — CLI + UI parity.** `--no-forecast` + stderr summary; TS `FindingKind`/`KIND_META`/kill-chain
  maps. *Value: control on the CLI and a proper label/icon everywhere findings render.*

---

## 12. Risks, Edge Cases & Open Questions

| Risk / case | Mitigation |
|---|---|
| **Short-capture / cold-start FPs** (few bins) | `min_bins` (8) warm-up gate: a host with too few bins raises nothing — the single-capture analogue of BBL's `min_captures`. |
| **Very smooth series → tiny σ → phantom spikes** | σ **floor tied to the host's mean** (`sigma_floor_frac·mean`), so small wobbles never read as many σ; `z=4` band on top. |
| **Bursty-but-benign hosts** | `min_bin_bytes` ignores trivial talkers; the residual-EWMA σ adapts to a naturally variable host so its normal bursts widen the band rather than alerting. |
| **Attribution** | Egress-per-internal-sender keying makes every finding a real `src_ip`; `apply_findings` uplifts that host's card and incidents/chains stay clean (no synthetic "network" actor). |
| **Internal egress proxy / gateway** | An internal proxy that funnels all egress is a permanent heavy-hitter whose *aggregate* shape is a meaningless blend. **Resolved** by the per-peer decomposition (§13): each `(host, external peer)` egress sub-series is forecast independently, so a spike to one destination that the blended aggregate masks is caught and named (`dst_ip = peer`). Peers of a host whose aggregate already fired are suppressed (the host-level finding subsumes them), so the pass only adds signal, not noise. |
| **Long/wide captures → cell saturation** | `max_forecast_cells` bounds heap independently of `max_tracked_keys`; the **insert-only** bound keeps the fold O(1) and, by never evicting interior cells, avoids manufacturing false drops — a saturated capture simply stops extending each host's series (§7). |
| **Spike inflates σ and masks a following drop** | Accepted and intended (one event → one finding); the σ floor and one-host-one-finding aggregation keep it from cascading. |
| **Adaptive bin width dilutes a spike on huge captures** | Bins follow `choose_bucket_width` so the series stays ≤ `max_time_buckets`; the spike is measured against the same width the UI shows. Per-bin resolution on multi-day captures is a follow-up. |

**Open questions for review:** (1) default `z` — 4, or expose a UI sensitivity control? (2) should a
*disappeared* baseline beacon (a drop of a previously-regular channel) escalate above a generic drop?
(3) forecast **ingress** as well as egress for inbound-flood victims, or leave that to `SynFlood`?
— **resolved:** ingress *is* forecast (a second per-host receive series, `T1498`), complementing rather
than replacing `SynFlood` (§13, "Intra-capture ingress forecasting").

---

## 13. Follow-ups

**Shipped since the core:**

- **Forecast-band overlay** on the UI timeline (`ui/src/lib/forecast.ts` + `ActivityHeatmap`) — draws
  `forecast ± z·σ` and the actual line over `time_histogram`, marking `traffic_anomaly` bins (PR #140).
- **Cross-capture predictive mode** — extends the **BBL** sidecar with bounded, time-ordered per-host
  history rings for **outbound bytes, inbound bytes, and connection count**
  (`HostBaseline.{bytes_out,bytes_in,flows}_recent: Vec<RecentPoint>`, `#[serde(default)]`), and in
  `compare_to_baseline` **supersedes** the static `mean + volume_k·σ` gate on each metric with a **Holt
  trend forecast** of the next capture (a shared `volume_forecast_dim` helper over `forecast_next`;
  band `forecast ± forecast_z·σ`) whenever the host has ≥ `min_forecast_points` samples — so a host on
  a legitimate rising trend no longer false-positives (the mean lags a trend), while an *off-trend*
  jump (or a collapse below the trend) still fires as a `baseline_deviation` (`PTS_DEV_VOLUME_FORECAST`).
  Older sidecars (no series) fall back to the static gate per metric. A side benefit: the scale-relative
  σ floor closes the old `sd == 0` blind spot (a huge spike over a perfectly constant baseline was
  previously unflagged). Engine-only; rides the existing `--baseline` path and the `baseline_deviation`
  UI surface (no CLI/UI/wasm change). `BaselineParams`: `forecast_enabled`, `forecast_z` (3.0),
  `min_forecast_points` (4), `max_recent_points` (24).

- **Seasonality (Holt-Winters additive)** — makes the cross-capture volume forecast **rhythm-aware**.
  Each host/metric keeps a bounded per-**phase** seasonal profile (`{metric}_seasonal: Vec<RunningStat>`,
  one slot per phase — day-of-week by default, hour-of-day configurable), folded from each capture's
  *own* wall-clock phase (via a new `CaptureProfile.capture_unix` threaded through
  `compare_to_baseline_at`). When the profile is populated across ≥ `min_seasonal_phases` slots, the
  forecast becomes **level + trend + seasonal factor** (`seasonal_forecast` deseasonalises the recency
  ring, runs Holt via `forecast_next`, then re-adds the phase's factor), superseding the plain trend —
  so a value that is normal *for its rhythm* is not flagged even if it is high overall, and an
  *off-rhythm* value fires even if it is unremarkable against the flat mean. Falls back to the plain
  trend/static gate when a phase profile is too sparse. Engine-only; rides `--baseline` +
  `baseline_deviation` (no CLI/UI/wasm change). `BaselineParams`: `seasonal_enabled`, `seasonal_period`
  (7), `seasonal_slot_secs` (86 400), `min_seasonal_samples` (2), `min_seasonal_phases` (3).

- **Intra-capture ingress forecasting** — the single-pcap PAD detector now forecasts each internal
  host's **received** (inbound) byte series alongside its egress one, so an inbound-flood/spike victim
  is flagged *within one capture* rather than only across captures. `stats` folds a second bounded
  per-host/second grid keyed on the **internal destination** (`per_host_epoch_in`, a `fold_forecast_cell`
  helper shared with the egress grid), and `forecast_input_ingress` projects it into the same
  `ForecastInput` carrying a new `direction: FlowDir` (`Out`/`In`). The forecaster is direction-blind;
  only `aggregate` reads the tag — labelling evidence/title **inbound** vs **outbound** and mapping the
  MITRE technique to `T1498` (Network DoS) for ingress vs `T1048` (Exfiltration) for egress. `analyze`
  runs both passes through the *same* `detect_traffic_anomalies`, so an inbound anomaly is attributed to
  the internal **receiver** (the victim) and rides the identical finding → threat-card path. Complements
  `SynFlood` (half-open connection floods) by catching high-**byte** inbound spikes it does not model.
  Engine-only; no CLI/UI/wasm change, no new config (reuses `ForecastParams` and `max_forecast_cells`).

- **Per-peer egress sub-series** — closes the **egress-proxy blind spot** (§12). Alongside its
  whole-host egress series, each internal host's egress is now decomposed **by external peer**: `stats`
  folds a third bounded grid keyed `(internal host, external peer, second)` (`per_host_peer_epoch`,
  external counterparty only — internal↔internal is already covered by both hosts' aggregates; the
  generalised `fold_forecast_cell` and a shared `materialize_forecast_series` back all three grids),
  and `forecast_input_peers` projects the top `max_peers_per_host` peers of the top `max_hosts` hosts
  into per-`(host, peer)` sub-series. `HostSeries`/`Anomaly` gain an optional `peer`; the forecaster
  stays peer-blind (only `aggregate` reads it, adding a "to `<peer>`" infix to the evidence/title), and
  `into_findings` carries the peer into the finding's `dst_ip`. `analyze` runs the peer pass after the
  aggregate egress pass and **suppresses peers of any host whose aggregate already fired** — so the
  pass only surfaces the *masked* case (a spike to one destination diluted in a blended aggregate, e.g.
  through a proxy) rather than restating host-level alarms. Engine-only; no CLI/UI/wasm change.
  `ForecastParams`: `max_peers_per_host` (8, `0` disables); `StatsConfig`: `max_forecast_subcells`
  (131 072, insert-only like `max_forecast_cells`).

- **Per-port egress sub-series** — the complement of the per-peer split: each internal host's egress is
  also decomposed **by service port** (the well-known side, `min(src,dst)`), so a spike concentrated on
  one service — *including one spread across many peers*, which the per-peer split divides away — is
  caught and attributed to the port. `stats` folds a fourth bounded grid keyed `(internal host, service
  port, second)` (`per_host_port_epoch`, port-bearing egress of any destination locality since a
  port-concentrated spike matters whether the peer is internal or external; low-cardinality key, shares
  the `max_forecast_subcells` cap), and `forecast_input_ports` projects the top `max_ports_per_host`
  ports of the top `max_hosts` hosts. `HostSeries`/`Anomaly` gain an optional `port` (mutually exclusive
  with `peer`); `aggregate`'s infix becomes "on port `<p>`" and `into_findings` carries it into the
  finding's `dst_port`. `analyze` runs the port pass last with a strict **whole-host > peer > port**
  suppression (each pass adds its fired hosts to the skip set), so a single spike is never double-
  reported as both a peer and a port anomaly. Engine-only; no CLI/UI/wasm change. `ForecastParams`:
  `max_ports_per_host` (8, `0` disables).

**Still deferred:** **per-peer *ingress*** (which external source flooded a given internal victim) —
additive, mirroring the per-peer egress pass, and it does not disturb the shipped core.

---

## 14. File-by-File Change Checklist

| File | Add / Modify | Reason |
|---|---|---|
| `engine/crates/ppcap-core/src/forecast/mod.rs` | **Add** | Forecaster + types + `detect_traffic_anomalies` + `into_findings` + 12 unit tests |
| `engine/crates/ppcap-core/src/lib.rs` | Modify | `pub mod forecast;` + re-export block |
| `engine/crates/ppcap-core/src/model/finding.rs` | Modify | `FindingKind::TrafficAnomaly` + `as_str` arm |
| `engine/crates/ppcap-core/src/detect/mod.rs` | Modify | new arms in `stage_ordinal`/`stage_label`/`kind_phrase` |
| `engine/crates/ppcap-core/src/report/mod.rs` | Modify | new arm in exhaustive `kind_label` |
| `engine/crates/ppcap-core/src/score/mod.rs` | Modify | `score_traffic_anomaly` + `PTS_FC_*`/`FC_UPLIFT_CAP` |
| `engine/crates/ppcap-core/src/stats/mod.rs` | Modify | `max_forecast_cells`, `per_host_epoch` field + per-packet fold + `forecast_input` projector + 2 tests |
| `engine/crates/ppcap-core/src/analyze/mod.rs` | Modify | `PipelineConfig::forecast` + the detection seam |
| `engine/crates/ppcap-core/src/gen/mod.rs` | Modify | `Scenario::TrafficSpike` + `next_traffic_spike` + `all()`/`from_str_opt`/assertion |
| `engine/crates/ppcap-core/src/gen/mix.rs` | Modify | `weights_for` arm |
| `engine/crates/ppcap-core/tests/forecast_e2e.rs` | **Add** | gen→analyze e2e (3 tests) |
| `engine/crates/ppcap-cli/src/cli.rs` | Modify | `--no-forecast` flag + wiring + stderr summary + parse test |
| `ui/src/types.ts` | Modify | `"traffic_anomaly"` `FindingKind` |
| `ui/src/lib/findingKinds.ts` | Modify | `KIND_META.traffic_anomaly` (+ `TrendingUp` import) |
| `ui/src/lib/killChain.ts` · `ui/src/cockpit/IncidentHero.tsx` | Modify | `KIND_STAGE` entry (exhaustive `Record`) |
| **NOT touched** | — | `columnar/*`, `FLOW_PARQUET_VERSION`, `sql/schema.sql`, wasm `FlowDto`, `schema_drift.rs`; `ppcap-wasm/src/lib.rs` (rides `AnalysisOutput`); `supabase/*`, `relay/*` |

---

## Guarantees, verified by tests

- **Detection** — a host whose egress spikes / drops / shifts raises a `traffic_anomaly` at the
  expected severity; a conforming, warm-up, or trivial host stays silent.
- **Attribution & ride-through** — the finding attaches to the internal sender, uplifts its per-IP
  card, and appears in `summary.findings`/exports/UI.
- **Bounded & offline** — pure post-EOF transform over an already-bounded accumulator; no packet
  re-read, no network; peak heap within the Phase-0 budget.
- **Deterministic** — same input ⇒ byte-identical findings and byte-identical generated capture.
- **Explainable** — every anomaly point reconciles to one `add_term` point + one forecast-vs-actual
  evidence line (the `score_traffic_anomaly` ledger), and that evidence rides onto the per-IP card via
  `apply_findings`. Honest scoping: as with BBL, the *typed* `ScoreTerm`s are **not** surfaced on
  `IpThreat.score_terms` (the `Finding` struct carries no `terms` field) — evidence-line parity with
  BBL, not term-level parity with per-flow scoring.

---

## Appendix A — Design-review corrections (folded in)

Adversarial review across engine / invariants / product lenses (all three verdicts: *buildable and
sound*, verified against the checked-out tree with `cargo check`/tests run). Load-bearing fixes, most
important first:

1. **Insert-only substrate, not heavy-hitter (invariants — major).** Memory was already bounded
   (`max_forecast_cells` = 131 072, verified), but the `(host, second)` key grows with capture
   *duration × hosts*, so it saturates far sooner than any finite-entity stats map, and the original
   `bump_bounded` evictor would then run an O(cap) scan per new cell (a duration-scaling CPU cliff) and
   could evict light interior cells → **manufacture false drops**. Corrected in code to an **insert-only**
   bound: O(1) per packet, no interior eviction, non-distorting under saturation (§7). This is the one
   place PAD deliberately declines to reuse `bump_bounded`.
2. **Attribution to a real host (engine/product).** A network-wide anomaly has no `src_ip` and
   `apply_findings` skips non-IP `src_ip`. Corrected: forecast **egress per internal sender**, so every
   finding is attributable. Acknowledged residual blind spot: an internal egress *proxy* aggregates
   many users' traffic onto one host (§12).
3. **Seam ordering (engine).** The forecast reads the **live** accumulator *before* `finish()` consumes
   it and *before* `apply_findings`, so anomalies uplift cards and feed incidents/chains — the
   BBL-compare seam, not a post-`finish()` transform over `time_histogram`.
4. **Outbound-only framing, no "DDoS onset" (product — major).** PAD keys on the internal *sender*, so
   a spike is a host *launching* volume (exfil burst / outbound-flood participation), never a victim
   *under* an inbound DDoS. Every "DDoS onset" claim was reframed to outbound egress (§1, §2.1).
5. **Drops are transient, not "host went dark" (product — major).** Gap-fill spans only a host's own
   active window, so end-of-capture silence raises nothing; only a transient collapse that *recovers*
   is caught. The value claim was restated accordingly (§1, §2.1, §12), and the `PTS_FC_DROP` code
   comment fixed.
6. **σ floor tied to scale (product).** A raw residual-EWMA σ collapses on smooth series → phantom
   spikes; the mean-relative σ floor is the primary FP guard.
7. **Explainability is BBL-parity, not term-level (product — minor).** `score_traffic_anomaly` builds
   `ScoreTerm`s but `Finding` has no `terms` field, so (exactly like BBL) the typed terms don't reach
   `IpThreat.score_terms` — evidence-line parity, stated honestly (Guarantees).
8. **One-kind + all exhaustive sites (engine).** One `FindingKind::TrafficAnomaly` (spike/drop/shift in
   evidence, mirroring `BaselineDeviation`); arms at `finding.rs:as_str`,
   `detect/mod.rs:{stage_ordinal,stage_label,kind_phrase}`, `report/mod.rs:kind_label`, and the three TS
   exhaustive maps (`KIND_META`, two `KIND_STAGE`) — not `technique_name`/`victims_of` (fallbacks).

## Appendix B — Citation verification

Every load-bearing path/symbol/signature above was read from and re-verified against the checked-out
tree at branch `claude/predictive-anomaly-detection-planning-uwgayg`, and the implementation compiles
and passes `cargo test --workspace`, `--features online`, the cc-free gate, `tsc -b`, Vitest, and
`vite build`. Treat line-specific references as anchors — `grep` before editing, as the repo evolves.
