//! Evidence Integrity & Chain of Custody — the sealed manifest for one analysis run.
//!
//! An [`EvidenceManifest`] records everything an evidence pipeline needs to trust the run's
//! outputs: the input capture's SHA-256, every produced artifact's SHA-256 + size, the exact
//! tool version and effective settings (the reproducibility recipe — the engine is
//! deterministic, so same input + same settings ⇒ byte-identical outputs), and the capture's
//! own time window. The record is made tamper-evident by a **seal**: a SHA-256 over the
//! manifest's canonical JSON with the seal field empty — editing any field flips it.
//!
//! The seal proves **integrity** (the record hasn't changed), not **authenticity** (who made
//! it): authenticity is an external detached signature over the manifest file
//! (`gpg --detach-sign` / `ssh-keygen -Y sign`), deliberately out of the engine (no key
//! management, no new crypto dependencies — the vendored SHA-256 stays the only primitive).
//!
//! This generalizes the two in-tree precedents: `SanitizeManifest` (Safe Share's custody
//! sidecar for the *sanitized copy*) and the Time Machine sidecar discipline
//! (`schema_version`, reject-newer, provenance fields, CLI-side filesystem writes).
//!
//! ## Invariants
//!
//! - Pure and deterministic: sealing has no clock (the recorded `created_unix_secs` is an
//!   ordinary field supplied by the caller); canonical form = this crate's serde output,
//!   whose field order is pinned by `schema_version`.
//! - Bounded memory: file hashing streams through a fixed 64 KiB buffer.
//! - Verification never panics: unreadable/missing artifacts become typed outcomes.
//! - The engine's streaming pipeline is untouched — manifests are assembled CLI-side.

use crate::model::summary::Summary;

/// Sidecar schema version. `from_json_str` rejects manifests written by a NEWER engine.
pub const EVIDENCE_SCHEMA_VERSION: u32 = 1;

/// One produced artifact, hashed. `role` is an open string token ("summary_json",
/// "flows_parquet", "html_report", "findings_csv", "stix_bundle", "capture_index",
/// "baseline_profile") so future artifact kinds need no schema change.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArtifactRecord {
    pub role: String,
    /// Path exactly as the run wrote it. Verification resolves relative paths against the
    /// manifest file's own directory, so a bundle stays verifiable after being moved whole.
    pub path: String,
    /// Lowercase-hex SHA-256 of the artifact's bytes.
    pub sha256: String,
    pub bytes: u64,
}

/// The sealed chain-of-custody record for one analysis run. The serde field order IS the
/// canonical form (pinned by [`EVIDENCE_SCHEMA_VERSION`]); every post-v1 field must take
/// `#[serde(default)]`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EvidenceManifest {
    pub schema_version: u32,
    /// Always `"ppcap"` (mirrors `SanitizeManifest.tool`).
    pub tool: String,
    pub engine_version: String,
    /// Unix seconds the run finished; 0 when the caller has no clock (house convention).
    pub created_unix_secs: i64,
    /// The effective analyze settings, one `--flag[=value]` token per entry in the CLI's
    /// declaration order — the reproducibility recipe. Input/artifact paths live in their
    /// dedicated fields, not here.
    pub settings: Vec<String>,
    pub source_path: String,
    /// Lowercase-hex SHA-256 of the input capture (mandatory — an unhashed input is not
    /// evidence).
    pub source_sha256: String,
    pub source_bytes: u64,
    /// Capture window (ns since epoch) from the summary — ties the record to the evidence
    /// timeline. `None` for empty captures.
    pub first_ts_ns: Option<i64>,
    pub last_ts_ns: Option<i64>,
    /// Every artifact this run wrote to disk, sorted by (role, path). Stdout artifacts
    /// (`--json -`) are unverifiable streams and are deliberately not recorded.
    pub artifacts: Vec<ArtifactRecord>,
    /// SHA-256 (lowercase hex) over the canonical JSON of this manifest serialized with THIS
    /// field set to `""` — the tamper-evident seal.
    pub seal_sha256: String,
}

impl EvidenceManifest {
    /// Start an unsealed manifest for a run. `settings` is the reproducibility recipe;
    /// `now_unix_secs` comes from the caller (0 in clockless contexts).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        engine_version: &str,
        now_unix_secs: i64,
        settings: Vec<String>,
        source_path: &str,
        source_sha256: &str,
        source_bytes: u64,
        summary: &Summary,
        mut artifacts: Vec<ArtifactRecord>,
    ) -> EvidenceManifest {
        artifacts.sort_by(|a, b| a.role.cmp(&b.role).then_with(|| a.path.cmp(&b.path)));
        EvidenceManifest {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            tool: "ppcap".to_string(),
            engine_version: engine_version.to_string(),
            created_unix_secs: now_unix_secs,
            settings,
            source_path: source_path.to_string(),
            source_sha256: source_sha256.to_string(),
            source_bytes,
            first_ts_ns: summary.first_ts_ns,
            last_ts_ns: summary.last_ts_ns,
            artifacts,
            seal_sha256: String::new(),
        }
    }

    /// The canonical byte form the seal covers: compact JSON with `seal_sha256` empty.
    fn canonical_bytes(&self) -> crate::Result<Vec<u8>> {
        let mut unsealed = self.clone();
        unsealed.seal_sha256 = String::new();
        Ok(serde_json::to_vec(&unsealed)?)
    }

    /// Compute and set the seal. Idempotent (the seal field itself is excluded).
    pub fn seal(&mut self) -> crate::Result<()> {
        let bytes = self.canonical_bytes()?;
        self.seal_sha256 = crate::analyze::hex_of(&crate::analyze::sha256(&bytes));
        Ok(())
    }

    /// Recompute the seal and compare — `false` means the record was edited after sealing.
    pub fn verify_seal(&self) -> bool {
        match self.canonical_bytes() {
            Ok(bytes) => {
                crate::analyze::hex_of(&crate::analyze::sha256(&bytes)) == self.seal_sha256
            }
            Err(_) => false,
        }
    }

    pub fn to_json_pretty(&self) -> crate::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse a manifest, rejecting one written by a newer engine (the sidecar convention).
    pub fn from_json_str(s: &str) -> crate::Result<EvidenceManifest> {
        let m: EvidenceManifest = serde_json::from_str(s)?;
        if m.schema_version > EVIDENCE_SCHEMA_VERSION {
            return Err(crate::PpError::Config(format!(
                "evidence schema_version {} is newer than this engine supports ({})",
                m.schema_version, EVIDENCE_SCHEMA_VERSION
            )));
        }
        Ok(m)
    }
}

/// Per-file verification outcome.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyOutcome {
    /// Present, same size, same hash.
    Ok,
    /// The file could not be opened/read at the resolved path.
    Missing,
    /// The bytes hash differently — the file was modified (or replaced).
    HashMismatch,
    /// Same hash cannot happen with a different size; this is reported when the size differs
    /// (fast pre-check) so the operator sees truncation/growth called out explicitly.
    SizeMismatch,
}

/// One checked file: the manifest's record plus what verification actually found.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArtifactCheck {
    pub record: ArtifactRecord,
    pub outcome: VerifyOutcome,
    /// The re-computed hash, when the file was readable. `#[serde(default)]` for forward compat.
    #[serde(default)]
    pub actual_sha256: Option<String>,
    /// The observed size, when the file was readable. `#[serde(default)]` for forward compat.
    #[serde(default)]
    pub actual_bytes: Option<u64>,
}

/// The full verification report for one manifest.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerifyReport {
    /// The seal recomputed cleanly — `false` means the RECORD itself was edited, and every
    /// per-file result below must be read with that suspicion.
    pub seal_ok: bool,
    /// The input capture, checked like any artifact (role "source").
    pub source: ArtifactCheck,
    /// Every recorded artifact, in manifest order.
    pub artifacts: Vec<ArtifactCheck>,
}

impl VerifyReport {
    /// Everything intact: the seal, the source, and every artifact.
    pub fn all_ok(&self) -> bool {
        self.seal_ok
            && self.source.outcome == VerifyOutcome::Ok
            && self
                .artifacts
                .iter()
                .all(|a| a.outcome == VerifyOutcome::Ok)
    }

    /// Count of files (source + artifacts) that failed.
    pub fn failed_count(&self) -> usize {
        let src = usize::from(self.source.outcome != VerifyOutcome::Ok);
        src + self
            .artifacts
            .iter()
            .filter(|a| a.outcome != VerifyOutcome::Ok)
            .count()
    }
}

/// Stream a file through the vendored SHA-256 with a fixed 64 KiB buffer.
/// Returns `(lowercase_hex, byte_count)`.
#[cfg(not(target_arch = "wasm32"))]
pub fn hash_file(path: &std::path::Path) -> crate::Result<(String, u64)> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)
        .map_err(|e| crate::PpError::io(format!("open {}", path.display()), e))?;
    let mut hasher = crate::analyze::Sha256::new();
    let mut buf = [0u8; 65_536];
    let mut total: u64 = 0;
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| crate::PpError::io(format!("read {}", path.display()), e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((crate::analyze::hex_of(&hasher.finalize_bytes()), total))
}

/// Resolve a manifest-recorded path: relative paths are anchored at the manifest file's own
/// directory so a bundle moved whole stays verifiable; absolute paths are used as-is.
#[cfg(not(target_arch = "wasm32"))]
fn resolve(manifest_dir: &std::path::Path, recorded: &str) -> std::path::PathBuf {
    let p = std::path::Path::new(recorded);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        manifest_dir.join(p)
    }
}

/// Check one recorded file on disk. Never panics: unreadable ⇒ `Missing`.
#[cfg(not(target_arch = "wasm32"))]
fn check_file(manifest_dir: &std::path::Path, record: ArtifactRecord) -> ArtifactCheck {
    let path = resolve(manifest_dir, &record.path);
    match hash_file(&path) {
        Err(_) => ArtifactCheck {
            record,
            outcome: VerifyOutcome::Missing,
            actual_sha256: None,
            actual_bytes: None,
        },
        Ok((sha, bytes)) => {
            let outcome = if bytes != record.bytes {
                VerifyOutcome::SizeMismatch
            } else if sha != record.sha256 {
                VerifyOutcome::HashMismatch
            } else {
                VerifyOutcome::Ok
            };
            ArtifactCheck {
                record,
                outcome,
                actual_sha256: Some(sha),
                actual_bytes: Some(bytes),
            }
        }
    }
}

/// Verify a manifest against the filesystem: the seal first, then the source, then every
/// artifact. `manifest_dir` is the directory the manifest file was loaded from (relative
/// recorded paths resolve against it). Pure reads; deterministic; never panics.
#[cfg(not(target_arch = "wasm32"))]
pub fn verify_manifest(
    manifest: &EvidenceManifest,
    manifest_dir: &std::path::Path,
) -> VerifyReport {
    let source_record = ArtifactRecord {
        role: "source".to_string(),
        path: manifest.source_path.clone(),
        sha256: manifest.source_sha256.clone(),
        bytes: manifest.source_bytes,
    };
    VerifyReport {
        seal_ok: manifest.verify_seal(),
        source: check_file(manifest_dir, source_record),
        artifacts: manifest
            .artifacts
            .iter()
            .cloned()
            .map(|r| check_file(manifest_dir, r))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_with(artifacts: Vec<ArtifactRecord>) -> EvidenceManifest {
        let mut m = EvidenceManifest::new(
            "0.1.0",
            1_700_000_000,
            vec![
                "--hash".to_string(),
                "--threat-feed feeds/iocs.json".to_string(),
            ],
            "sample.pcap",
            "aa".repeat(32).as_str(),
            1234,
            &Summary::empty(),
            artifacts,
        );
        m.seal().unwrap();
        m
    }

    fn artifact(role: &str, path: &str) -> ArtifactRecord {
        ArtifactRecord {
            role: role.to_string(),
            path: path.to_string(),
            sha256: "bb".repeat(32),
            bytes: 10,
        }
    }

    #[test]
    fn seal_roundtrips_and_any_field_edit_breaks_it() {
        let m = manifest_with(vec![artifact("summary_json", "out.json")]);
        assert!(m.verify_seal(), "a freshly sealed manifest verifies");
        assert_eq!(m.seal_sha256.len(), 64, "lowercase-hex SHA-256");

        // Editing ANY field after sealing flips the seal.
        let mut tampered = m.clone();
        tampered.source_sha256 = "cc".repeat(32);
        assert!(!tampered.verify_seal());
        let mut tampered = m.clone();
        tampered.artifacts[0].bytes = 11;
        assert!(!tampered.verify_seal());
        let mut tampered = m.clone();
        tampered.settings.push("--no-forecast".to_string());
        assert!(!tampered.verify_seal());
        let mut tampered = m.clone();
        tampered.created_unix_secs += 1;
        assert!(!tampered.verify_seal());

        // Re-sealing is idempotent: the seal field itself is excluded from the input.
        let mut resealed = m.clone();
        resealed.seal().unwrap();
        assert_eq!(resealed.seal_sha256, m.seal_sha256);
    }

    #[test]
    fn canonical_form_is_deterministic() {
        let a = manifest_with(vec![artifact("summary_json", "out.json")]);
        let b = manifest_with(vec![artifact("summary_json", "out.json")]);
        assert_eq!(a.seal_sha256, b.seal_sha256, "same content, same seal");
        // Artifacts sort by (role, path) at construction — insertion order is irrelevant.
        let c = manifest_with(vec![
            artifact("summary_json", "out.json"),
            artifact("html_report", "report.html"),
        ]);
        let d = manifest_with(vec![
            artifact("html_report", "report.html"),
            artifact("summary_json", "out.json"),
        ]);
        assert_eq!(c.seal_sha256, d.seal_sha256);
        assert_eq!(c.artifacts[0].role, "html_report");
    }

    #[test]
    fn serde_rejects_newer_schema_and_roundtrips_current() {
        let m = manifest_with(vec![artifact("summary_json", "out.json")]);
        let json = m.to_json_pretty().unwrap();
        let back = EvidenceManifest::from_json_str(&json).unwrap();
        assert_eq!(back, m);
        assert!(back.verify_seal(), "the seal survives a JSON round-trip");

        let newer = json.replace("\"schema_version\": 1", "\"schema_version\": 99");
        let err = EvidenceManifest::from_json_str(&newer).unwrap_err();
        assert!(err.to_string().contains("newer than this engine supports"));
    }

    #[test]
    fn hash_file_matches_known_vector() {
        // SHA-256("abc") — FIPS 180-4 test vector, matching the vendored hasher's own tests.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("abc.bin");
        std::fs::write(&p, b"abc").unwrap();
        let (hex, bytes) = hash_file(&p).unwrap();
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(bytes, 3);
    }

    #[test]
    fn verify_reports_ok_missing_and_modified() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("in.pcap");
        std::fs::write(&src, b"capture-bytes").unwrap();
        let ok_art = dir.path().join("out.json");
        std::fs::write(&ok_art, b"{}").unwrap();
        let bad_art = dir.path().join("report.html");
        std::fs::write(&bad_art, b"<html>original</html>").unwrap();

        let (src_sha, src_bytes) = hash_file(&src).unwrap();
        let (ok_sha, ok_bytes) = hash_file(&ok_art).unwrap();
        let (bad_sha, bad_bytes) = hash_file(&bad_art).unwrap();
        let mut m = EvidenceManifest::new(
            "0.1.0",
            0,
            Vec::new(),
            "in.pcap", // relative: resolves against the manifest dir
            &src_sha,
            src_bytes,
            &Summary::empty(),
            vec![
                ArtifactRecord {
                    role: "summary_json".into(),
                    path: "out.json".into(),
                    sha256: ok_sha,
                    bytes: ok_bytes,
                },
                ArtifactRecord {
                    role: "html_report".into(),
                    path: "report.html".into(),
                    sha256: bad_sha,
                    bytes: bad_bytes,
                },
                ArtifactRecord {
                    role: "findings_csv".into(),
                    path: "gone.csv".into(),
                    sha256: "dd".repeat(32),
                    bytes: 5,
                },
            ],
        );
        m.seal().unwrap();

        // Same-size modification => HashMismatch (not SizeMismatch).
        std::fs::write(&bad_art, b"<html>TAMPERED</html>").unwrap();

        let report = verify_manifest(&m, dir.path());
        assert!(report.seal_ok);
        assert_eq!(report.source.outcome, VerifyOutcome::Ok);
        let by_role = |role: &str| {
            report
                .artifacts
                .iter()
                .find(|a| a.record.role == role)
                .unwrap()
        };
        assert_eq!(by_role("summary_json").outcome, VerifyOutcome::Ok);
        assert_eq!(by_role("html_report").outcome, VerifyOutcome::HashMismatch);
        assert_eq!(by_role("findings_csv").outcome, VerifyOutcome::Missing);
        assert!(!report.all_ok());
        assert_eq!(report.failed_count(), 2);

        // Truncation is called out as a size mismatch, checked before the hash.
        std::fs::write(&bad_art, b"<h>").unwrap();
        let report = verify_manifest(&m, dir.path());
        assert_eq!(by_role("html_report").record.role, "html_report"); // silence unused
        assert_eq!(
            report
                .artifacts
                .iter()
                .find(|a| a.record.role == "html_report")
                .unwrap()
                .outcome,
            VerifyOutcome::SizeMismatch
        );
    }

    #[test]
    fn relative_paths_resolve_against_manifest_dir_absolute_kept() {
        let dir = tempfile::tempdir().unwrap();
        let abs = dir.path().join("abs.bin");
        std::fs::write(&abs, b"x").unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve(elsewhere.path(), abs.to_str().unwrap()),
            abs,
            "absolute recorded paths are used as-is"
        );
        assert_eq!(
            resolve(dir.path(), "rel/o.json"),
            dir.path().join("rel/o.json")
        );
    }
}
