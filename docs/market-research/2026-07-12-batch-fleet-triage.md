# Market research & feature plan — Batch / Fleet Triage

*Date: 2026-07-12 · Author: automated market-research routine · Status: **proposal, awaiting approval***

---

## 0. Context — where PacketPilot stands today

PacketPilot's wedge is *one-click triage of a **single** saved pcap*, local-first, on a fast
streaming Rust engine. The core is mature: streaming decode, flow reconstruction, payload-aware
classification, explainable severity, IOC + MITRE ATT&CK enrichment, TLS/QUIC/SSH fingerprinting
(JA3/JA3S/JA4/JA4-Q/HASSH), a broad detection suite (port scan, SYN flood, ARP spoof, ICMP tunnel,
DGA, cryptomining, beacons, suspicious UA, disguised download), SIEM/detection-rule exports
(CSV/STIX/MISP/CEF/Sigma), passive DNS, a threat graph, and — as of #116 — opt-in **artifact
extraction** (carve HTTP downloads to disk).

The last routine (2026-07-08) shipped artifact extraction and explicitly logged **batch / fleet
triage** as the recommended *next* proposal (see `2026-07-08-artifact-extraction.md` §7). This
round's independent market scan confirms it as the clearest remaining gap.

## 1. Market research — the competitive landscape

Everything PacketPilot does today is **per-capture**: point it at one pcap, get one dashboard. The
recurring 2025–2026 analyst complaint that PacketPilot does *not* answer is **volume**:

| Theme (from analyst commentary & tool comparisons) | Who serves it today | PacketPilot today |
|---|---|---|
| **Triage *many* captures at once** — a directory / day's worth / a fleet of sensors | Custom scripts, A-Packets (subscription), Hatching Triage, PacketSafari Triage | ✗ **one capture at a time** — the gap |
| Extract the actual files/artifacts transferred | NetworkMiner (all protocols), PacketPilot (HTTP, #116) | ✅ HTTP; non-HTTP breadth still open |
| SIEM / detection-rule interop | Zeek, Suricata, PacketPilot | ✅ Built |
| Explainable severity / summary-first triage | Sniffnet, Brim, PacketPilot | ✅ Built |
| Web-based sharing / collaboration | CloudShark / Malcolm | Partial (local-first HTML report by design) |

**The clearest, best-validated gap is batch / fleet triage.** Across 2025–2026 DFIR and MSSP
writing, the dominant pain is not "help me read one capture" — it is **"I have hundreds or
thousands of captures / alerts and must decide, fast, which few deserve a human."**

### What users are asking for / struggling with (documented)

- *"Scripts like these can triage hundreds of PCAPs and flag patterns worth your attention …
  automate triage pipelines that flag similar patterns in future captures."* — the 2026 DFIR norm
  is **repeatable, version-controlled batch pipelines**, not one-file-at-a-time GUIs.
- *"Compress triage and timeline generation into one or two script calls rather than a dozen
  manual steps."* — the explicit 2026 workflow direction.
- For SOC analysts *"the biggest challenge with PCAP is … wading through hundreds, even thousands,
  of alerts every day"* and making a **quick keep/discard determination** — the job is ranking and
  triaging *out* the noise, at volume.
- Commercial tools already monetize exactly this: **A-Packets** sells *"subscriptions for recurring
  SOC or DFIR work"* whose value is *"removing the boring triage work … at volume,"* and
  **PacketSafari Triage** *"maps the capture"* so an analyst starts from evidence. Both keep raw
  traffic **inside the customer boundary** — precisely PacketPilot's local-first ethos.

Sources: paulserban.eu ("Dissecting PCAP Files for Malware Analysis," 2026 — batch scripting of
hundreds of pcaps); msppentesting.com ("What Is PCAP … 2026" — automate triage pipelines);
apackets.com (A-Packets — subscription batch triage, on-prem boundary); packetsafari.com
(PacketSafari Triage — map-then-investigate, keep traffic in-boundary); opentext.com ("Smart PCAP …
time machine for the SOC"); netresec.com & securityboulevard.com (NetworkMiner file-extraction
comparisons, 2025-05); thectoclub.com / goworkwize.com (Wireshark-alternatives roundups, 2026).

## 2. Why this is a strong fit for PacketPilot

PacketPilot is **uniquely positioned** to serve batch triage because the hard part — a fast,
bounded-memory, *headless* per-capture analyzer — is **already built and benchmarked** (~1.17M
pkt/s, peak heap bounded regardless of capture size). Batch triage is not new analysis machinery;
it is a thin **orchestration + aggregation layer** over the existing, tested single-capture path:

- The single entry point `analyze::run(path, &PipelineConfig, progress) -> AnalysisOutput` already
  returns a self-contained `AnalysisOutput { source_path, source_sha256, source_bytes,
  summary: Summary { severity_counts, ip_threats, category_breakdown, … }, elapsed_ms }`.
- Every field a ranked cross-capture index needs — top severity, per-band flow counts, the
  highest-scoring IP threat cards, capture size/duration — is **already in `Summary`**. Batch
  triage reads these off each per-file result; it decodes nothing new.
- Bounded memory is preserved trivially: process one capture at a time, keep only each capture's
  **small headline** (not its flows) in memory, stream the combined index to disk.

## 3. Feasibility & value assessment

| | Assessment |
|---|---|
| **Value** | High — opens a distinct, currently-unserved audience (MSSP / SOC / DFIR high-volume pipelines) with the single most-cited 2025–2026 pain point, and it monetizes cleanly (mirrors A-Packets' recurring-work tier, but local-first). |
| **Feasibility** | High — pure orchestration over the existing `analyze::run` seam. No new packet parsing, no new detections. Low risk. |
| **Fit with product ethos** | Excellent — runs **locally** over a local directory of pcaps; captures never leave the device. Reinforces the local-first wedge exactly where the commercial competition charges a subscription. |
| **Key tension** | Failure isolation: one malformed/oversized capture in a directory of 500 must **not** abort the batch. The engine already "never panics on malformed input," so per-file `Result` handling + a skipped/errored column is sufficient — surfaced here for sign-off. |

## 4. Proposed feature — v1 scope

**Batch / Fleet Triage: `analyze --batch <DIR>` → one combined, ranked incident index.**

**In scope (v1):**
- CLI: `ppcap analyze --batch <DIR>` (mutually exclusive with the single positional `<FILE>`).
  Discovers `*.pcap` / `*.pcapng` / `*.pcap.gz` under `<DIR>` (non-recursive by default;
  `--recursive` opt-in), analyzes each with the existing pipeline, and emits a **combined index**.
- Output: `--batch-out <FILE>` writing a ranked **CSV** and/or **JSON** — one row per capture:
  `path, source_sha256, size_bytes, duration_s, total_flows, worst_severity, crit/high/med/low
  counts, top_ip_threat (ip+score), top_category, elapsed_ms, status`. Rows sorted **worst-first**
  (Critical desc, then High, then threat score) so the analyst reads the top of the file and stops.
- Robustness: each capture analyzed independently; a file that errors becomes a `status=error` row
  with the message — the batch always completes. `--fail-fast` opt-in flips this for CI use.
- Determinism & bounded memory: sequential by default (`--jobs N` opt-in for parallelism); only
  per-capture headlines are retained; the index streams to disk. Peak heap stays bounded.
- Progress: a one-line-per-capture progress log to stderr (`[ 34/500 ] capture.pcap → HIGH`),
  never interleaved into the machine-readable index.

**Out of scope (v1) — documented as follow-ups:**
- A batch **UI / desktop** view (v1 is headless-CLI first, matching how the audience actually runs
  it — in a pipeline). A "fleet overview" dashboard is the natural v2.
- Cross-capture **correlation** (same IOC/JA4 seen across N captures → one meta-incident). High
  value, distinct effort; log as a separate proposal.
- Per-capture full artifact/report emission in batch mode (keep v1 to the ranked index; a
  `--emit-per-capture <DIR>` that also drops each capture's JSON/HTML is an easy follow-up).

## 5. Implementation approach (grounded in the code)

1. **`ppcap-cli/src/cli.rs`** — add `--batch <DIR>`, `--batch-out <FILE>`, `--recursive`,
   `--jobs <N>`, `--fail-fast` to the `analyze` subcommand; make `--batch` and the positional
   `<FILE>` mutually exclusive (clap `conflicts_with`). CLI signatures are otherwise stable.
2. **`ppcap-core` — new `batch` module** (`src/batch/mod.rs`): `run_batch(dir, cfg, opts) ->
   BatchIndex`. Walk the directory (glob the three extensions; honor `recursive`), and for each
   file call the existing `analyze::run(path, &PipelineConfig, |_|{})`, catching its `Result` into
   a per-file `BatchRow`. This is the only orchestration point; it adds no decode logic.
3. **`model` — `BatchRow` / `BatchIndex`** (`src/model/batch.rs`): a small serde struct projecting
   the fields listed in §4 out of each `AnalysisOutput.summary`. `BatchIndex` sorts worst-first and
   serializes to JSON; a `to_csv()` writer emits the CSV. Reuse `SeverityCounts` and the existing
   `IpThreat` ranking already computed per capture — no re-derivation.
4. **`--jobs N`** — optional bounded parallelism with a fixed worker pool over the file list
   (each worker owns its own pipeline state; results collected and *then* sorted, so output stays
   deterministic regardless of completion order). Default `N=1`.
5. **Docs** — README "Quickstart" gains a batch example; `PROJECT-SPEC.md` notes the batch seam.

No engine internals change: `run_batch` is a consumer of the same public `analyze::run` the
single-file path already uses.

## 6. Success criteria

- **Correctness:** a batch over a directory of K synthetic captures produces exactly K non-error
  rows whose per-capture fields (worst severity, severity counts, top IP threat) equal what a
  single `analyze` of each file reports. Rows are ordered worst-first.
- **Robustness:** a directory containing a truncated / non-pcap / oversized file yields a
  `status=error` row for that file and **valid rows for all others** — the batch completes
  (verified with a deliberately corrupt fixture). `--fail-fast` instead exits non-zero on first error.
- **Bounded memory:** peak heap for a 500-capture batch is within noise of a single large-capture
  run — only headlines are retained, flows are not (assert via the metrics harness).
- **Determinism:** identical index bytes across runs and across `--jobs 1` vs `--jobs 8` (sort is
  total; ties broken by `source_sha256`).
- **Analyst outcome:** from a directory of a day's captures, an analyst runs one command and reads
  a ranked CSV whose top rows are the captures that need a human — the workflow that today forces
  a hand-rolled script or a per-file GUI loop.
- **Tests green:** `cargo test -p ppcap-core` (new batch orchestration + corrupt-fixture +
  determinism tests) + clippy + rustfmt; CLI smoke test; UI gates unaffected (no UI in v1).

## 7. Secondary opportunities (noted, not proposed for build now)

- **Cross-capture correlation** — the same IOC / JA4 / C2 domain across many captures collapsed
  into one fleet-level meta-incident. The highest-value *v2* once the batch index exists; distinct
  effort (needs a cross-capture aggregation key), so recommend as a separate proposal.
- **Non-HTTP artifact extraction** (SMTP/POP3/IMAP/FTP/SMB2) — still the biggest single forensics
  differentiator vs. NetworkMiner (see 2026-07-08 doc). Larger effort (new protocol reassembly);
  keep logged. Batch triage is lower-risk and opens a new audience, so it ranks ahead of it here.
- **Batch/fleet UI** — a "fleet overview" dashboard over the batch index (v1 is headless-first).

## 8. Recommendation

Proceed with **v1 Batch / Fleet Triage (`analyze --batch <dir>` → ranked incident index)** — it is
the highest-value, lowest-risk remaining gap: the most-cited 2025–2026 volume pain, a distinct
unserved audience (MSSP/SOC/DFIR), a clean monetization mirror of the commercial subscription tiers
but **local-first**, and — critically — it reuses the already-benchmarked headless engine at a
single public seam, adding **no** new packet-parsing surface. **Requires maintainer sign-off on the
failure-isolation default (§3): one bad capture must not sink the batch (skip-and-continue by
default, `--fail-fast` opt-in).** Cross-capture correlation, non-HTTP extraction, and a fleet UI are
logged as follow-ups.
