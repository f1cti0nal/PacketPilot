# PacketPilot — Evidence Integrity & Chain of Custody

**Implementation Plan**

| | |
|---|---|
| **Status** | **Implemented** on this branch — engine custody module + CLI (`--evidence`, `ppcap verify`) + docs; UI/WASM untouched by design |
| **Feature branch** | `claude/smart-alerting-context-t78kzq` (stacked after Smart Alerting) |
| **Date** | 2026-07-23 |
| **Scope** | Engine (Rust: new `custody/` module — sealed manifest + verification) · CLI (`analyze --evidence` + `ppcap verify` subcommand) · Docs (user doc + README) · **No UI / no WASM changes in v1** (file-centric, local-first; Tauri hook is a follow-up) |

> **How this plan was produced.** Single-pass design over the subsystem map built for the
> Smart Alerting feature (same session), grounded in the repo's own market research
> (docs/market-research/2026-07-11 §3: evidence admissibility named the next validated gap
> after Batch Triage and Safe Share, both since shipped) and the two in-tree precedents this
> layer generalizes: `SanitizeManifest` (sanitize/mod.rs:140 — tool/version/options/hashes
> sidecar) and the Time Machine sidecar discipline (schema_version, reject-newer, provenance).
> Every cited path/line verified against the checked-out tree.

> **Implementation status (what actually shipped).** Everything in §2–§7 landed: `custody/mod.rs`
> (manifest + seal + verify, 6 unit tests incl. tamper/missing/size-mismatch outcomes and the
> FIPS 180-4 vector), `analyze --evidence` assembling the manifest LAST after every artifact
> write, `ppcap verify` with per-file outcomes and exit-code gating (2 CLI tests incl. a full
> gen→analyze→verify→tamper roundtrip over relative paths), docs/evidence-custody.md, README.
> Verified here: 836 engine tests, clippy, fmt; ppcap-wasm compiles untouched. Open question
> §9(1) resolved as planned (v1: no summary-JSON change).

---

## 1. Summary & Goals

**What ships.** **Evidence Integrity & Chain of Custody (ECC)**: `ppcap analyze --evidence
<path>` writes a **sealed evidence manifest** alongside the run's artifacts — the input
capture's SHA-256, every produced artifact's SHA-256 + size (summary JSON, flows Parquet, HTML
report, CSV/STIX exports, Time Machine index, baseline sidecar), the exact tool version and
effective settings (the reproducibility recipe), and the capture's own time window — the whole
record made tamper-evident by a **seal**: a SHA-256 over the manifest's canonical serialization.
`ppcap verify <manifest>` then re-hashes everything and reports, per artifact, *intact /
missing / modified*, with exit codes an evidence pipeline can gate on. This turns the analysis
output from "some files" into a **court-presentable evidence bundle**: integrity (hashes),
provenance (tool + settings + timestamps), and reproducibility (the engine is already
deterministic — same input + same settings ⇒ byte-identical outputs — the manifest records the
recipe that makes that claim checkable).

**What it changes vs. today's engine:**

| Today | With ECC |
|---|---|
| Input hash available (`--hash`), artifact hashes nowhere | Every artifact hashed and recorded in one manifest |
| Safe Share has a custody manifest for the *sanitized copy* only (sanitize/mod.rs:140) | The *analysis run itself* gets the custody treatment — Safe Share's precedent generalized |
| "Was this report modified since the analyst produced it?" is unanswerable | `ppcap verify` answers it per artifact, offline, in seconds |
| Settings that produced an output are lost after the shell history scrolls | The manifest records the effective flags in stable order — the reproducibility recipe |
| No tamper evidence on the record itself | The seal makes the manifest self-verifying: any edit flips `seal_sha256` |

**Non-goals (v1, honestly scoped).** No cryptographic *signing* (authenticity): the seal
proves *integrity* (the record hasn't changed), not *who* made it — signing requires key
management and a signature dependency, and the house has a hard no-new-deps invariant
(SHA-256 is vendored). The manifest is designed to be signed *externally* (detached signature
over the manifest file by `gpg`/`ssh-keygen -Y`/etc.), documented in the user doc. No deep
reproducibility check (`verify --reproduce` re-running the analysis and byte-comparing) — the
recipe is recorded; the re-run harness is a follow-up (§10). No UI/WASM surface — the browser
has no filesystem; the Tauri desktop hook is a follow-up.

---

## 2. Data Model (`engine/crates/ppcap-core/src/custody/mod.rs`, new)

```rust
pub const EVIDENCE_SCHEMA_VERSION: u32 = 1;

/// One produced artifact, hashed. `role` is an open string token so future artifact kinds
/// need no schema change: "summary_json" | "flows_parquet" | "html_report" | "findings_csv" |
/// "stix_bundle" | "capture_index" | "baseline_profile".
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArtifactRecord {
    pub role: String,
    /// Path exactly as the run wrote it. Verification resolves relative paths against the
    /// manifest file's own directory, so a bundle stays verifiable after being moved whole.
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

/// The sealed chain-of-custody record for one analysis run. Serde field order IS the
/// canonical form (schema_version pins it); every post-v1 field takes `#[serde(default)]`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EvidenceManifest {
    pub schema_version: u32,           // = 1; from_json_str rejects newer
    pub tool: String,                  // "ppcap"
    pub engine_version: String,
    /// Unix seconds the run finished; 0 in clockless contexts (house convention).
    pub created_unix_secs: i64,
    /// The effective analyze settings, one `--flag[=value]` token per entry, in the CLI's
    /// declaration order — the reproducibility recipe (deterministic).
    pub settings: Vec<String>,
    pub source_path: String,
    pub source_sha256: String,
    pub source_bytes: u64,
    /// Capture window (ns) from the summary — ties the record to the evidence timeline.
    pub first_ts_ns: Option<i64>,
    pub last_ts_ns: Option<i64>,
    /// Sorted by (role, path); every artifact this run wrote to disk. Stdout artifacts
    /// (`--json -`) are unverifiable streams and are deliberately not recorded.
    pub artifacts: Vec<ArtifactRecord>,
    /// SHA-256 (lowercase hex) over the manifest's canonical JSON serialized with THIS field
    /// set to "" — the tamper-evident seal. `seal()` computes it; `verify_seal()` recomputes
    /// and compares. Any edit to any field flips it.
    pub seal_sha256: String,
}
```

Plus `VerifyOutcome { Ok, Missing, HashMismatch, SizeMismatch }` (serde snake_case),
`ArtifactCheck { record, outcome, actual_sha256: Option<String>, actual_bytes: Option<u64> }`,
and `VerifyReport { seal_ok: bool, source: ArtifactCheck, artifacts: Vec<ArtifactCheck>,
all_ok() }` — serializable so `ppcap verify --json` emits a machine-readable report.

**API** (re-exported from lib.rs): `EvidenceManifest::{seal, verify_seal, to_json_pretty,
from_json_str}` compile everywhere (pure); `#[cfg(not(target_arch = "wasm32"))]
pub fn hash_file(path) -> Result<(String, u64)>` (streams through the vendored
`analyze::Sha256`, fixed 64 KiB buffer — bounded memory) and
`pub fn verify_manifest(&EvidenceManifest, manifest_dir: &Path) -> VerifyReport` are
native-only, mirroring `sanitize_file`'s cfg gate (lib.rs:108-109). The engine's `run()`
stays filesystem-free; all manifest assembly happens CLI-side (the Time Machine pattern).

## 3. Semantics

- **Seal canonicalization** = `serde_json::to_string` (compact) of the struct with
  `seal_sha256 = ""` — deterministic because serde emits fields in declaration order and the
  schema version pins that order. No custom canonical-JSON machinery needed.
- **Verification**: seal first (any manifest edit fails fast with every artifact reported
  `SizeMismatch`-free — the seal failure is the headline), then source, then each artifact:
  re-hash, compare hash then size. Relative paths resolve against the manifest's directory;
  absolute paths as-is. Pure fs-reads; never panics on missing/unreadable files (→ `Missing`).
- **Settings capture**: built from the *destructured clap fields* (not raw argv, so
  `dispatch()`-level tests exercise it identically), one token per set flag in declaration
  order, values rendered exactly as given (`--threat-feed feeds/iocs.json`). Input path and
  artifact paths appear in their dedicated fields, not in `settings`.
- **Input hash**: computed unconditionally when `--evidence` is set (an unhashed input is not
  evidence), reusing the run's `--hash` result when already present
  (`AnalysisOutput.source_sha256`) to avoid a second read pass.

## 4. CLI Surface

- `ppcap analyze <in> --evidence <path> …` — after **all** artifact writes (JSON :471-480,
  HTML :482-493, CSV :495-501, STIX :503-513, index :515-529, `--update-baseline` sidecar),
  hash each written file, assemble, `seal()`, write. stderr one-liner:
  `evidence: sealed manifest (5 artifacts, input a1b2c3…) -> case.evidence.json`.
- `ppcap verify <manifest> [--json <path|->]` — pure transform mirroring `rescan`: seal check
  + per-artifact table to stderr (`OK / MISSING / MODIFIED (hash mismatch)`), optional JSON
  report. Exit 0 all-intact · 1 any failure (incl. bad seal) · 2 usage. Example stderr:

  ```
  seal: OK (schema v1, ppcap 0.1.0, created 2026-07-23T09:14:02Z)
  source: OK   sample.pcap (14.1 MB, sha256 a1b2c3…)
  summary_json: OK       out.json
  html_report:  MODIFIED report.html (hash mismatch)
  verify: 1 of 5 artifacts failed
  ```

## 5. Testing (named)

Unit (`custody/mod.rs` `#[cfg(test)]`): `seal_roundtrips_and_any_field_edit_breaks_it`,
`serde_rejects_newer_schema`, `canonical_form_is_deterministic`,
`verify_reports_ok_missing_and_modified` (tempdir artifacts),
`relative_paths_resolve_against_manifest_dir`, `hash_file_matches_known_vector`.
CLI (`cli.rs` tests): `evidence_flag_parses`, `verify_subcommand_parses`,
`analyze_evidence_then_verify_roundtrip` (gen a small capture → analyze with
`--json`+`--html`+`--evidence` → dispatch verify → Ok), `verify_detects_tampered_artifact`
(flip one byte in the HTML → exit err + MODIFIED row). Serde/order determinism throughout.

## 6. Performance & Invariants

Bounded memory (64 KiB streaming hash — the ingest discipline); zero cost when `--evidence`
is absent; deterministic (no clock in the seal input beyond the recorded `created_unix_secs`
field itself; BTree-free — vectors sorted explicitly); pure-Rust, no new dependencies (the
vendored SHA-256 is the only hash primitive); offline/local-first; `Summary`/Parquet/WASM
schemas untouched — the manifest is a sidecar, exactly like the baseline and Time Machine
files.

## 7. File-by-File Checklist

| File | Add/Modify | Reason |
|---|---|---|
| `engine/crates/ppcap-core/src/custody/mod.rs` | **Add** | manifest + seal + verify + tests |
| `engine/crates/ppcap-core/src/analyze/mod.rs` | Modify | `pub(crate)` on the vendored `Sha256` + `hash_file_sha256` reuse |
| `engine/crates/ppcap-core/src/lib.rs` | Modify | `pub mod custody;` + re-exports |
| `engine/crates/ppcap-cli/src/cli.rs` | Modify | `--evidence` flag + manifest assembly + `Verify` subcommand + tests |
| `docs/evidence-custody.md` | **Add** | user-facing doc (batch-triage.md genre) |
| `README.md` | Modify | feature bullet + quickstart line |
| **NOT touched** | — | `model/*`, `report/*`, `stats/*`, wasm, UI, Parquet/SQL schemas |

## 8. Milestones

**M1** custody module + unit tests · **M2** `--evidence` wiring + one-liner · **M3** `verify`
subcommand + roundtrip/tamper tests · **M4** docs (user doc + README). Each independently
shippable.

## 9. Risks & Open Questions

| Risk | Mitigation |
|---|---|
| Seal misread as a signature (false authenticity claim) | Docs state plainly: integrity not authenticity; external detached-signature workflow documented |
| Canonical form drifts if struct fields are reordered | schema_version pins the order; a determinism test locks the serialized form |
| Artifacts written after the manifest (future flags) escape it | Manifest assembly is the LAST step of the analyze arm; a comment marks the ordering invariant |
| Relative-path bundles moved partially | Per-artifact `Missing` outcome names exactly what broke |

Open questions: (1) should `--evidence` imply `--hash`-style provenance in the summary JSON
too? (v1: no — the manifest is the evidence surface). (2) `verify --reproduce` (re-run +
byte-compare) — follow-up. (3) Case-level manifest for `analyze --batch` — follow-up.

## 10. Follow-ups

Detached-signature helper (`ppcap verify --require-signature`), `verify --reproduce`,
batch/case-level evidence bundles, Tauri "Export evidence bundle" button, RFC 3161
timestamping via an opt-in TSA (network — off by default forever).
