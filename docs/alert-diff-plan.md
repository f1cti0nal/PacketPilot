# PacketPilot — Alert Diff (what changed since the last capture)

**Implementation Plan**

| | |
|---|---|
| **Status** | **Implemented** on this branch — engine `diff_alerts` + CLI `--diff` + Compare-tab Alerts section |
| **Feature branch** | `claude/smart-alerting-context-t78kzq` (stacked; PR #149) |
| **Date** | 2026-07-23 |
| **Scope** | Engine (Rust: pure `diff_alerts` + `AlertDiff` model) · CLI (`ppcap alerts <new> --diff <old>`) · UI (Compare tab gains an Alerts section via `lib/diff.ts`) · Docs |

> **How this plan was produced.** Single-pass design continuing this session's pipeline: the
> SAC plan (§16) names alert diffing as a follow-up ("the Time Machine `newly_flagged` spirit
> at the alert layer"), and the ids it relies on were designed for exactly this (stable across
> captures: `host:<ip>` / `chain:<host-set-hash>` / `rollup:<kind>`). Grounded in firsthand
> reads of `ui/src/lib/diff.ts` (`diffByKey` generic, `SummaryDiff`, per-entity delta fns) and
> the `Alerts` CLI subcommand.

> **Implementation status (what actually shipped).** Everything in §2–§5 landed: the
> `AlertDiff` model + pure `diff_alerts` (4 unit tests: partition, ordering, identity, serde),
> `ppcap alerts <new> --diff <old>` with the human table + `--json` AlertDiff report (parse +
> dispatch tests incl. a two-summary new/changed roundtrip), and the Compare tab's Alerts
> section via `lib/diff.ts` (`alertDeltas` + `SummaryDiff.alerts`, 4 new UI tests). Verified
> here: 844 engine tests, 1028 UI tests, clippy, `tsc`, fmt.

---

## 1. Summary & Goals

**What ships.** **Alert Diff (AD)** — the third leg of the alerting trilogy: within-capture
queue (SAC) → case-wide queue (CAQ) → **across-time diff**. Given two analyses of the same
network (yesterday's capture vs today's), the diff answers the recurring-monitoring question
directly: which stories are **new** (the actionable delta — Time Machine's `newly_flagged`
generalized from indicators to whole stories), which **resolved** (present before, gone now),
which **changed** (priority/band moved — a Review story climbing into Investigate is the
early-warning signal), and how many are unchanged. Matching is by the stable alert id, so a
host's story lines up across captures with zero configuration.

Surfaces: `ppcap alerts <new.json> --diff <old.json>` (human table + optional `--json`
machine report) and the existing **Compare** tab, which already diffs threats/incidents/
findings — alerts become its fourth (and headline) section.

**Non-goals.** No persistence/ack state (still the sidecar follow-up); no N-way timelines
(pairwise, like the rest of Compare); no case-level diffing (case queues can be diffed with
the same fn later); IP-churn tolerance (DHCP renumbering breaks `host:` id equality — honest
limitation, documented; the entity-identity follow-up in the BBL plan is the real fix).

## 2. Engine (`detect/alerts.rs` + `model/alert.rs`)

```rust
/// Compact projection of one alert for diff rows (no context bundle — the full alert lives
/// in its own summary).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AlertDiffEntry {
    pub id: String,
    pub source: AlertSource,
    pub band: PriorityBand,
    pub priority: u16,
    pub severity: Severity,
    pub title: String,
    pub actor: String,
}

/// One story present in both queues whose rank moved.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AlertDiffChange {
    pub id: String,
    pub title: String,              // the AFTER side's headline
    pub actor: String,
    pub before_priority: u16,
    pub after_priority: u16,
    pub delta: i32,                 // after - before (signed)
    pub before_band: PriorityBand,
    pub after_band: PriorityBand,
}

/// The pairwise queue diff. All vectors worst-first; `changed` by |delta| desc.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AlertDiff {
    pub new_alerts: Vec<AlertDiffEntry>,   // ids only in `after` — the actionable delta
    pub resolved: Vec<AlertDiffEntry>,     // ids only in `before`
    pub changed: Vec<AlertDiffChange>,     // in both, priority or band moved
    pub unchanged: u64,                    // in both, rank identical
}

pub fn diff_alerts(before: &[Alert], after: &[Alert]) -> AlertDiff
```

Pure, deterministic (BTreeMap by id — ids are unique within a queue by construction), sorted
with strict total orders ending in `id asc`. Lives beside `derive_alerts`; re-exported from
lib.rs. Serde snake_case throughout; all-new types (no back-compat surface).

## 3. CLI

`ppcap alerts <new.json> --diff <old.json> [--json <path|->]` — loads both analyses,
re-derives both queues (idempotent, so pre-SAC summaries work too), prints:

```
alert diff: 2 new, 1 resolved, 1 changed, 4 unchanged (old: 6 alerts, new: 7)
  NEW      [investigate  63/100] SYN flood: 45.77.13.37:443 …
  NEW      [review       41/100] Weak TLS posture: 3 hosts …
  RESOLVED [review       56/100] Cleartext credentials: 10.0.0.51 …
  CHANGED  [review→act_now +34 ] Multi-stage incident on 10.13.37.7
```

With `--diff`, `--json` writes the `AlertDiff` report (not the updated analysis — documented
in the flag help). Exit 0 always (a diff is information, not a failure).

## 4. UI (Compare tab)

`lib/diff.ts`: `SummaryDiff` gains `alerts: DiffResult<Alert>` via the existing `diffByKey`
(key = `a.id`; deltas on priority, band, severity, finding_count, action). `CompareView`
renders an "Alerts" section first — new/resolved/changed with band chips and priority deltas,
reusing the view's existing section pattern. Unit tests beside the existing diff tests.
(Client-side TS diff mirrors the Rust semantics — the house lib-port convention, cited in the
file header like `lib/forecast.ts`.)

## 5. Testing (named)

Engine unit: `diff_partitions_new_resolved_changed_unchanged`,
`diff_orders_worst_first_and_by_magnitude`, `diff_of_identical_queues_is_all_unchanged`,
`diff_serde_roundtrips`. CLI: `alerts_diff_flag_parses`,
`alerts_diff_reports_new_and_changed` (two hand-built summaries through `dispatch`).
UI: `diff.test.ts` alert cases + a CompareView section test.

## 6. Invariants & Checklist

Pure/deterministic/bounded (queues are already ≤32+protected rows) · no schema changes to
`Summary`/`CaseSummary` (the diff is a transform, not a stored field) · wasm untouched
(the browser diffs in TS, per the existing CompareView architecture).

| File | Change |
|---|---|
| `engine/crates/ppcap-core/src/model/alert.rs` | `AlertDiffEntry`/`AlertDiffChange`/`AlertDiff` |
| `engine/crates/ppcap-core/src/detect/alerts.rs` | `diff_alerts` + unit tests |
| `engine/crates/ppcap-core/src/lib.rs` | re-exports |
| `engine/crates/ppcap-cli/src/cli.rs` | `--diff` on the `Alerts` subcommand + tests |
| `ui/src/lib/diff.ts` (+ test) | `alerts` section in `SummaryDiff` |
| `ui/src/views/CompareView.tsx` (+ test) | Alerts section |
| `docs/batch-triage.md` / README | — (no change; SAC plan §16 references satisfied) |

**Follow-ups:** ack/dismiss sidecar ("new since last review"), case-level diff, entity
identity for DHCP churn.
