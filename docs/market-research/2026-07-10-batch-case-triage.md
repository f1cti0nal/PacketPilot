# Market research & feature plan — Batch / Case Triage (many pcaps → one ranked index)

*Date: 2026-07-10 · Author: automated market-research routine · Status: **proposal, awaiting approval***

---

## 1. Market research — the competitive landscape

PacketPilot's wedge is *one-click triage of a saved pcap*, local-first, on a fast streaming
Rust engine. The engine is now remarkably complete for a **single** capture: L2–L7 decode, flow
reconstruction, payload-aware classification, behavioral detection (beaconing, host sweeps, exfil,
DGA, DNS/ICMP tunneling), JA3/JA4, TLS/QUIC decrypt, cleartext-cred & PII findings, IOC + MITRE
enrichment, online reputation, artifact carve-to-disk (shipped #116), explainable severity, and
HTML/JSON/CSV/STIX/MISP/CEF/Sigma output. The recurring analyst asks that PacketPilot *still*
doesn't serve are no longer about depth on one file — they are about **working across many files**.

| Theme (from analyst commentary & tool comparisons, 2025–2026) | Who serves it today | PacketPilot today |
|---|---|---|
| **Triage a *set* of captures** (an IR case, a day of hourly rotations, a folder of samples) and get one ranked view | Scripts around tshark/Zeek; Arkime/Malcolm (heavy infra) | ✗ **one capture at a time** — the gap |
| **Keep captures separate but correlated** — *don't* blindly merge unrelated pcaps | NetworkMiner **force-merges** loaded pcaps (documented pain point) | ✗ no multi-capture concept |
| Automated **cross-capture correlation** ("same C2 IP / JA3 seen across N captures") | NDR appliances; custom SIEM pipelines | ✗ per-capture only, though the detectors that would feed it already exist |
| Collaboration / shared browsing of results | CloudShark (browser, per-URL sharing) | Partial — self-contained HTML report (local-first by design) |
| Extract the files/artifacts transferred | NetworkMiner | ✅ **shipped** (#116, opt-in carve-to-disk) |
| Cleartext credential / PII exposure | NetworkMiner | ✅ **built** — `CleartextCreds` + PII findings |

**The clearest remaining gap is batch / case-level triage.** This is not a new hypothesis — the
prior routine (2026-07-08, §7) logged it as the "secondary opportunity, recommend as a separate
proposal after v1." v1 (carve) shipped; this is that proposal.

### What users are asking for / struggling with (documented)
- **NetworkMiner force-merges multiple pcaps:** *"If you have loaded multiple pcap files, they
  will be merged by NetworkMiner. If they are not related to each other, make sure to remove the
  previously loaded pcap file(s) and reload."* Analysts triaging *unrelated* captures must load,
  clear, reload — one at a time — losing per-capture identity when they don't.
- **Automated correlation across a capture set** ("piece together suspicious IPs, odd protocol
  behavior, unusual transfers across vast captures … connect the dots") is cited as a top-wanted
  2026 capability — and it is inherently a *multi-capture* operation.
- **Scale / high-throughput triage** is a repeated Wireshark limitation ("excels at interactive
  analysis but is not a high-throughput engine"). IR teams and MSSPs receive captures in bulk
  (hourly rotations, per-host collections, malware sample folders) and need a first-pass ranking,
  not to open each file by hand.

Sources: netresec.com (NetworkMiner, multi-pcap merge behavior); calmops.com NetworkMiner guide
2026; thectoclub.com & saaspodium.com Wireshark-alternatives roundups 2026; goworkwize.com
(CloudShark collaboration / automated correlation); worldmetrics.org (packet-analysis market size,
$0.99B in 2026 → $2.53B by 2035). Full URLs in §9.

## 2. Why this is a strong fit for PacketPilot

The batch model is **already half-designed in the data layer** — it just can't be populated yet:

- The shipped DuckDB schema (`engine/crates/ppcap-core/sql/schema.sql`) reads
  `read_parquet('{CASE_DIR}/parquet/flow/*.parquet', union_by_name = true)` — the flow view is
  **already a union over many captures' Parquet in one case directory**. The `{CASE_DIR}` token and
  the `init-db --case-dir` flag exist today. The schema anticipates a case = a folder of captures;
  nothing writes that folder.
- The engine is **already headless and fast** (~1.17M pkt/s, bounded ~38 MiB heap) and runs one
  capture at a time via `ppcap_core::run(&input, &cfg, progress)`. Batch is a **loop over existing
  code**, not new analysis machinery — each capture is analyzed exactly as today, into a
  per-capture slot of the case directory.
- The cross-capture rollup leans on outputs the detectors **already produce**: per-IP report
  cards, findings, JA3/JA4, IOC hits. "This C2 IP appears in 4 of 12 captures" is an aggregation
  over existing per-capture summaries — no new detection logic.

So the feature is mostly **orchestration + aggregation over tested code**, plus a case-level
summary/report — a natural extension of the single-capture pipeline into the case layout the
schema already expects.

## 3. Feasibility & value assessment

| | Assessment |
|---|---|
| **Value** | High — closes the last big *workflow* gap (many-capture triage) for the IR/MSSP audience; turns "open each file by hand" into "point at a folder, get a ranked index." Cross-capture correlation is an analytic edge NetworkMiner (which merges) structurally cannot offer. |
| **Feasibility** | High — reuses the single-capture pipeline verbatim per file; the CASE_DIR / `union_by_name` Parquet layout is already shipped. Medium/low risk. |
| **Fit with product ethos** | Excellent — 100% local-first (no infra, unlike Arkime/Malcolm), one-command, bounded-memory (captures processed sequentially → peak heap stays one-capture-sized). Extends "one click" to "one click over a case." |
| **Key tensions** | (a) Wall-clock is sum-of-captures when sequential — acceptable for a first cut; expose optional bounded parallelism as a follow-up. (b) Mixed/hostile inputs in a folder must not abort the whole run — one bad capture is skipped-and-logged, never fatal. (c) Scope discipline: v1 is CLI + JSON/HTML case index; the desktop "open a folder" UX is a fast follow, not v1. |

## 4. Proposed feature — v1 scope

**Batch / Case Triage: analyze a folder of captures into one case directory + a ranked index.**

**In scope (v1):**
- **CLI `analyze --batch <DIR>`** (mutually exclusive with a single `input`): discover
  `*.pcap` / `*.pcapng` / `*.pcap.gz` under `<DIR>` (non-recursive v1; `--recursive` opt-in), and
  run the existing pipeline over each, writing per-capture output into the **case layout the schema
  already expects** — `<case>/parquet/flow/<capture-id>.parquet`, plus a per-capture summary JSON.
- **Case index output** — a combined ranked artifact:
  - `case.json`: per-capture roll-up (capture id, filename, packet/flow counts, top severity,
    finding counts) **ranked by worst severity**, plus a **cross-capture correlation** block:
    indicators (IP / domain / JA3) that appear in ≥2 captures, with the capture list per indicator.
  - `case.html`: a self-contained case report — the ranked capture table (each row linking to that
    capture's existing single-capture report) + the shared-indicator section. Reuses the existing
    HTML report renderer.
- **Robustness:** a capture that fails to parse is recorded as `status: "error"` in `case.json`
  and skipped — never aborts the batch (unless `--strict`). Progress is per-capture on stderr.
- **Determinism & memory:** captures processed sequentially in sorted filename order → identical
  output across runs and one-capture-sized peak heap regardless of folder size.

**Out of scope (v1) — documented as follow-ups:**
- Bounded parallel capture processing (`--jobs N`) for wall-clock on large folders.
- Desktop "open a folder → case dashboard" UX and case persistence (leans on the same `case.json`).
- Recursive dedup of *identical* captures (hash-collapse) and cross-capture flow stitching.
- Team-server shared cases (the Phase 4 "hybrid" half — distinct effort).

## 5. Implementation approach (grounded in the code)

1. **`ppcap-cli/src/cli.rs`** — add `--batch <DIR>`, `--recursive`, and a `--case-out <DIR>` (case
   output root) to `analyze`; make `input` optional and enforce "exactly one of `input` / `--batch`".
   Discover + sort capture paths; assign each a stable `capture_id` (hash of relative path).
2. **`ppcap-core` — new `batch` (or `case`) module** — `run_case(dir, cfg) -> CaseSummary`: loop,
   call the existing `run()` per capture into `<case>/parquet/flow/<id>.parquet` + collect each
   `AnalysisOutput`; catch per-capture errors into a status list. No new decode/detect code.
3. **Case aggregation** — `CaseSummary { captures: Vec<CaptureEntry>, shared_indicators: Vec<...> }`,
   ranked by severity; `shared_indicators` computed by intersecting per-capture IP/domain/JA3 sets
   (bounded, streaming-friendly). Pure over the existing per-capture summaries.
4. **`report/mod.rs`** — a `case_html(&CaseSummary)` renderer reusing the existing report styling;
   per-capture rows deep-link to each capture's single-capture HTML.
5. **Schema** — none required: `{CASE_DIR}/parquet/flow/*.parquet` + `init-db --case-dir` already
   exist; the batch writer simply populates that layout so the DuckDB view works over the whole case.
6. **Docs** — `docs/batch-triage.md` operator guide; README roadmap tick.
7. **(Follow-up, not v1)** Desktop folder-picker + case view.

## 6. Success criteria

- **Correctness:** `analyze --batch <dir>` over a folder of N synthetic captures produces N
  per-capture Parquet files under the case layout and a `case.json` whose per-capture counts match
  running `analyze` on each file individually (equivalence test on generated fixtures).
- **Ranking:** `case.json` orders captures by worst severity; a capture containing a seeded
  beacon/exfil scenario ranks above a benign web-only capture.
- **Correlation:** an IOC IP seeded into ≥2 generated captures appears once in `shared_indicators`
  with the correct capture list; an IP in only one capture does not.
- **Robustness:** a deliberately truncated/garbage file in the folder yields `status:"error"` for
  that entry and does **not** abort the batch; `--strict` makes it fatal.
- **Memory:** peak heap over a 20-capture batch stays within one-capture budget (bounded, plateaus)
  — sequential processing verified.
- **DuckDB:** the shipped view (`init-db --case-dir <case>`) queries the populated case directory
  and unions all captures' flows (`union_by_name`).
- **Tests green:** `cargo test -p ppcap-core` (new batch/aggregation/robustness tests) + clippy +
  fmt; UI `test:coverage` + `build` + `build:wasm` unaffected (no UI change in v1).

## 7. Secondary opportunity (noted, not proposed for build now)

**Non-HTTP artifact carve breadth** (SMTP/IMAP/POP3 attachments, FTP, SMB/SMB2, TFTP) — the
remaining NetworkMiner extraction breadth beyond HTTP (#116). Higher effort per protocol; distinct
from the batch workflow. Recommend after batch v1.

## 8. Recommendation

Proceed with **v1 Batch / Case Triage (CLI `analyze --batch`, ranked `case.json` + `case.html`,
cross-capture correlation)**. It is the highest-value remaining *workflow* gap, it is largely
orchestration + aggregation over already-tested single-capture code, and it completes a case
layout the DuckDB schema already ships. It preserves the local-first, one-command, bounded-memory
ethos and gives PacketPilot an analytic edge (correlate, don't merge) over NetworkMiner. The
desktop folder UX and parallelism are logged as fast follows; non-HTTP carve breadth is the next
extraction proposal.

**This is a proposal awaiting maintainer approval — no implementation has been started.** Steps
6–8 of the routine (implement → PR → merge to main → deploy to production → announce) are held for
explicit human sign-off, per the same gate the carve proposal used.

## 9. Sources

- NetworkMiner — netresec.com/?page=NetworkMiner ; calmops.com/network/networkminer-forensics-guide/
  (multi-pcap merge behavior; artifact/credential extraction).
- Wireshark alternatives / wants — thectoclub.com/tools/best-wireshark-alternative/ ;
  saaspodium.com/blogs/network-analyzer-software/best-wireshark-alternatives-packet-analyzers ;
  goworkwize.com/blog/wireshark-alternatives (CloudShark collaboration, automated correlation).
- Market size — worldmetrics.org/best/packet-analysis-software/ ($0.99B 2026 → $2.53B 2035).
- Internal — `engine/crates/ppcap-core/sql/schema.sql` (CASE_DIR / `union_by_name`);
  `docs/market-research/2026-07-08-artifact-extraction.md` §7 (batch logged as secondary opportunity).
