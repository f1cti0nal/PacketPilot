# Market research & feature plan — Artifact Extraction (carve-to-disk)

*Date: 2026-07-08 · Author: automated market-research routine · Status: **proposal, awaiting approval***

---

## 1. Market research — the competitive landscape

PacketPilot's wedge is *one-click triage of a saved pcap*, local-first, on a fast streaming
Rust engine. Research into what analysts ask for — and what makes them reach for a *different*
tool than PacketPilot / Wireshark — surfaced a small number of recurring themes:

| Theme (from analyst commentary & tool comparisons) | Who serves it today | PacketPilot today |
|---|---|---|
| **Extract the actual files/artifacts** transferred in a capture (not just detect them) | **NetworkMiner** (flagship feature), Wireshark "Export Objects" (manual) | Detects & hashes HTTP downloads, but **discards the bytes** — cannot hand the analyst the file |
| SIEM / detection-rule interop (Sigma, STIX, MISP, CEF) | Zeek, Suricata, various | ✅ **Built** — `export/mod.rs` emits CSV, STIX 2.1, MISP, CEF, Sigma |
| Web-based sharing / collaboration | CloudShark / Malcolm | Partial — self-contained HTML report export (local-first by design) |
| Batch / high-volume triage of *many* pcaps | Hatching Triage, custom scripts | ✗ one capture at a time (secondary opportunity — see §7) |
| Steep learning curve / manual filtering | Sniffnet, Brim | ✅ Addressed — summary-first triage dashboard + explainable severity |

**The clearest, best-validated gap is artifact extraction.** Across 2025–2026 tool comparisons,
the single most-cited reason forensic analysts choose a dedicated tool over Wireshark is that it
**automatically reconstructs and saves the files** carried in the traffic — NetworkMiner does this
for HTTP, FTP, TFTP, SMB/SMB2, SMTP, POP3 and IMAP the moment a pcap is opened, "sparing tedious
manual work." It is described repeatedly as the go-to capability for after-the-fact forensics.

### What users are asking for / struggling with (documented)
- *"NetworkMiner will save you time and spare you tedious manual work"* — file reconstruction is
  the differentiator vs. Wireshark's manual per-packet inspection.
- Malware PCAP analysis is *"meticulous, technical, and time-consuming"*; the payoff step is
  getting the **carried payload** out to submit to a sandbox / hash-lookup / static analysis.
- Analysts *pivot on indicators of interest* — the carried file (and its hash) is the pivot that
  ties a network capture to a malware verdict.

Sources: netresec.com (NetworkMiner "Comparison of tools that extract files from PCAP", 2025-05);
securityboulevard.com (same, 2025-05); calmops.com NetworkMiner guide 2026; thectoclub.com &
comparitech.com Wireshark-alternatives roundups 2026; corelight.com PCAP glossary; hatching.github.io
(Triage, batch context).

## 2. Why this is a strong fit for PacketPilot

PacketPilot is **already ~90% of the way there and doesn't know it.** The engine's
`carve/mod.rs` module already:

- watches HTTP **responses** and reassembles the body **in TCP-sequence order** (gap-aborts, so a
  wrong file is never produced),
- **de-frames** `Content-Length` / `Transfer-Encoding: chunked` and **content-decodes**
  `gzip`/`deflate` on the fly, so it holds the file's *real* bytes,
- streams those exact decoded bytes through a SHA-256 hasher and a content-signature scanner
  (`CarveSink::feed()`), then **throws the bytes away** (deliberate `O(1)`-memory, no-retention
  design), keeping only `CarvedFile { client, server, sha256, size, known_bad, signatures }`.

So the plaintext, de-chunked, de-compressed file bytes **already flow past a single function**
today. Turning "hash and discard" into "hash and *optionally* also write to a local file" is a
small, contained extension of tested code — not new reassembly machinery.

## 3. Feasibility & value assessment

| | Assessment |
|---|---|
| **Value** | High — closes the single most-cited competitive gap vs. Wireshark/NetworkMiner; unlocks the downstream workflow (submit carved file → sandbox / VirusTotal / static analysis). |
| **Feasibility** | High for HTTP downloads (extends the existing carver at one seam). Medium/low risk. Non-HTTP protocols (SMTP/FTP/SMB) are a larger, separate effort — explicitly out of scope for v1. |
| **Fit with product ethos** | Good, *if opt-in*. "Captures never leave the device" is preserved — files are written **locally**, to an analyst-chosen directory, only when explicitly requested. |
| **Key tension** | The carver's design brags "no file bytes are retained." Extraction necessarily retains/writes bytes, and those bytes may be malware. Mitigated exactly as NetworkMiner does: **off by default**, opt-in flag, size-capped, written to a caller-chosen dir, with a clear on-disk warning. Surfaced here for the maintainer to sign off. |

## 4. Proposed feature — v1 scope

**Artifact Extraction: carve cleartext HTTP downloads to disk (opt-in).**

**In scope (v1):**
- CLI: a new `--carve-dir <DIR>` flag on `analyze`. When set, each carved HTTP download's decoded
  body is written to `<DIR>/<sha256><ext>` (extension inferred from the content-signature file-type
  magic, else `.bin`). Off by default → current behavior and memory profile unchanged.
- Bounded & safe: reuse the carver's existing `MAX_BODY` (64 MiB) cap; skip (never truncate) files
  over cap; sanitize the only filename input (the hash — already hex, so path-traversal-proof);
  known-bad / suspicious files written with a `.quarantine` suffix so a double-click won't run them.
- Summary: add `extracted_path: Option<String>` to `CarvedFile` so the JSON/HTML report can link
  the analyst to the file on disk.
- Desktop (Tauri): a per-capture "Extract files" action that carves into an OS-native chosen folder
  and reveals it; wired through the same engine path.

**Out of scope (v1) — documented as follow-ups:**
- Non-HTTP protocols (SMTP/IMAP/POP3 attachments, FTP, SMB/SMB2, TFTP) — the NetworkMiner breadth.
- HTTP **request** bodies (uploads / exfil capture).
- Browser-build extraction (would stream a blob download; desktop/CLI first).

## 5. Implementation approach (grounded in the code)

1. **`carve/mod.rs`** — give `CarveSink` an optional bounded body sink (`Option<FileSink>`). At the
   single existing `CarveSink::feed()` point where decoded bytes are hashed+scanned, also
   `write_all` them to the file when extraction is enabled. Finalize in `CarveState::feed_body`
   (rename/commit the temp file to `<sha256><ext>` once the hash & signatures are known; delete on
   abort so a gap-aborted carve never leaves a partial file). O(1) extra memory — bytes are teed,
   not buffered.
2. **`analyze/mod.rs`** — thread a `carve_dir: Option<PathBuf>` config into the `HttpBodyCarver`;
   populate `CarvedFile.extracted_path`.
3. **`model/summary.rs`** — add `#[serde(default)] extracted_path: Option<String>` to `CarvedFile`
   (serde-default keeps old JSON readable).
4. **`ppcap-cli/src/cli.rs`** — add `--carve-dir` to `analyze`; pass through.
5. **`report/mod.rs`** — link `extracted_path` in the carved-files section when present.
6. **UI (`ui/src/`)** — `types.ts` `extracted_path?`; the carved-files card shows a filename/badge;
   desktop adds the "Extract files" action + Tauri command.

## 6. Success criteria

- **Correctness:** the extracted file's on-disk SHA-256 equals the `CarvedFile.sha256` the engine
  reports, for plain, chunked, and gzip/deflate downloads (round-trip test on synthetic captures +
  the EICAR fixture). A gap-aborted carve leaves **no** file on disk.
- **Safety:** default run writes nothing; over-cap downloads are skipped, not truncated; filenames
  are hash-derived (no traversal); known-bad bodies get the `.quarantine` suffix.
- **Perf unchanged when off:** with no `--carve-dir`, ingest throughput and peak-heap match the
  current benchmark (≥250k pkt/s, bounded heap) within noise.
- **Analyst outcome:** from a triage run, an analyst can obtain the carried file and its hash and
  hand it to a sandbox/VT in one step — the workflow that currently forces them to NetworkMiner.
- **Tests green:** `cargo test -p ppcap-core` (incl. new round-trip/abort tests) + clippy; UI
  `test:coverage` + `build` + `build:wasm`.

## 7. Secondary opportunity (noted, not proposed for build now)

**Batch / fleet triage** — analysts triage *hundreds* of pcaps; PacketPilot is one-at-a-time. A CLI
`analyze --batch <dir>` producing a combined ranked index (top incidents per capture → one CSV/JSON)
would serve MSSP/high-volume pipelines and leans on the engine's existing headless speed
(~1.17M pkt/s). Higher effort, distinct audience; recommend as a separate proposal after v1.

## 8. Recommendation

Proceed with **v1 Artifact Extraction (HTTP downloads, opt-in carve-to-disk)** — it is the
highest-value, lowest-risk gap: strongest market validation, and it reuses the existing, tested
carver at a single seam. **Requires maintainer sign-off on the retain-bytes / write-malware-locally
tension (§3)** before implementation, since it softens the carver's current "no bytes retained"
guarantee (opt-in, off by default). Non-HTTP breadth and batch triage are logged as follow-ups.
