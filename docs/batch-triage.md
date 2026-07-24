# Batch / Case Triage

Point PacketPilot at a **folder** of captures — an IR case, a day of hourly rotations, a folder of
malware samples — and get one **ranked index** (worst-severity captures first) plus **cross-capture
correlation** (an IP / SNI domain / JA3 that shows up across ≥2 captures). Captures are kept
*separate but correlated* — PacketPilot never force-merges unrelated pcaps.

Batch mode reuses the single-capture pipeline verbatim per file: each capture is analyzed exactly as
`analyze <file>` would, into a per-capture slot of a **case directory** that the DuckDB schema
already unions (`{CASE_DIR}/parquet/flow/*.parquet`).

## Usage

```sh
# Triage every capture under ./incoming into ./mycase
ppcap analyze --batch ./incoming --case-out ./mycase

# Recurse into subdirectories; abort on the first unparseable capture
ppcap analyze --batch ./incoming --recursive --strict --case-out ./mycase
```

| Flag | Meaning |
|---|---|
| `--batch <DIR>` | Analyze every `*.pcap` / `*.pcapng` / `*.pcap.gz` / `*.pcapng.gz` under `<DIR>` (mutually exclusive with a single `input`). |
| `--recursive` | Descend into subdirectories (default: top level only). |
| `--case-out <DIR>` | Case output root (default `./case`). |
| `--strict` | A capture that fails to parse aborts the whole batch (default: record it as `error` and continue). |
| `--threat-feed <F>` · `--hash` | Applied per capture, exactly as in single-capture mode. |

## Output — the case directory

```
<case-out>/
├── case.json                     # ranked index + shared indicators (the machine-readable roll-up)
├── case.html                     # self-contained case report (ranked table + shared indicators)
├── captures/
│   ├── <id>.json                 # per-capture summary JSON (identical to `analyze --json`)
│   └── <id>.html                 # per-capture triage report (deep-linked from case.html)
└── parquet/flow/
    └── <id>.parquet              # per-capture flows, unioned by the DuckDB `{CASE_DIR}` view
```

`<id>` is a stable 16-hex FNV-1a hash of the capture's path relative to the input directory, so the
same folder yields the same ids across runs and machines.

### `case.json`

- `captures[]` — one row per discovered capture, **ranked worst-severity first** (ties broken by
  finding count, then path; errored captures last). Each row carries `worst_severity`,
  `severity_counts`, `total_packets`/`total_flows`, `finding_count`, `status` (`ok`/`error`), and
  the case-relative `parquet_path` / `summary_path` / `report_path`.
- `shared_indicators[]` — indicators seen in **≥2** captures, ranked worst-severity first. Each has
  `kind` (`ip` / `domain` / `ja3`), `value`, the `captures` list (capture ids), and the
  `worst_severity` associated with it across those captures.

## Querying the whole case in DuckDB

The shipped schema already unions every capture's flows:

```sh
ppcap init-db --case-dir ./mycase > case.sql
duckdb -init case.sql   # the `flow` view now spans all captures in the case
```

## Case alert queue

Each capture in the batch already gets its own Smart Alerting queue (`summary.alerts` in
`captures/<id>.json` — see `docs/smart-alerting-context-plan.md`). The case fuses them into
**one ranked, case-wide queue** — `case.json`'s `case_alerts` and the "Case alert queue" card
at the top of `case.html`. The merge key is the alert id itself, which is stable across
captures by construction (`host:<ip>`, `chain:<host-set>`, `rollup:<kind>`): the same story
recurring in several captures collapses into one row carrying its capture list, a summed
finding count, and a **bounded recurrence uplift** (`+5` per extra capture, capped `+15`) —
cross-capture persistence is corroboration, the same doctrine as `shared_indicators`'
≥2-captures gate, and the uplift appears as a visible ledger term
(`"recurring: seen in 4 captures (+15)"`; the terms always sum to the fused priority).

```
case alerts: 7 across 30 captures — 1 act-now, 2 investigate; top: "Multi-stage incident on 10.13.37.7"
```

The queue is capped at 64 rows; `total_case_alerts` records the pre-truncation count, so
truncation is never silent, and the untouched per-capture queues remain the full receipts.
`shared_indicators` stays as-is — indicators correlate *values* across captures, the queue
correlates *stories*.

## Guarantees

- **Bounded memory** — captures are processed *sequentially* in sorted order, so peak heap stays
  one-capture-sized regardless of how many files the folder holds.
- **Deterministic** — sorted discovery + stable ids; identical input folders produce identical
  `case.json`.
- **Robust** — one malformed capture is recorded as `status:"error"` and skipped (no partial Parquet
  is left behind to pollute the DuckDB union); it never aborts the batch unless `--strict`.

## Not in v1 (follow-ups)

Bounded parallelism (`--jobs N`) for wall-clock on large folders; a desktop "open a folder → case
dashboard" UX; identical-capture hash-dedup and cross-capture flow stitching; team-server shared
cases.
