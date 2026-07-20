//! The top-level analysis result. Fully implemented contract type.
//!
//! [`AnalysisOutput`] wraps the [`Summary`] with provenance (source path/hash/bytes,
//! link type, engine version) and the optional flows-Parquet path. It is what the CLI
//! serializes to stdout.

use crate::model::summary::Summary;

/// The complete result of analyzing one capture.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AnalysisOutput {
    /// On-disk/JSON schema version; `1` in Phase 0.
    pub schema_version: u32,
    /// `env!("CARGO_PKG_VERSION")` of the engine that produced this.
    pub engine_version: String,
    pub source_path: String,
    /// Lowercase hex SHA-256 of the source; `None` unless `--hash` was requested.
    pub source_sha256: Option<String>,
    pub source_bytes: u64,
    /// Link-layer type display token, e.g. `"EN10MB"`.
    pub link_type: String,
    pub summary: Summary,
    pub flows_parquet_path: Option<String>,
    pub elapsed_ms: u64,
    /// Behavioral Baseline Learning: this capture's per-internal-host behavioral snapshot
    /// (egress peers/ports/volumes), the learn payload folded into a persisted baseline sidecar.
    /// `None` unless the baseline snapshot was requested. `#[serde(default)]` keeps older
    /// summaries readable and leaves the default output shape unchanged when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<crate::baseline::CaptureProfile>,
}

impl AnalysisOutput {
    /// Serialize as pretty (multi-line) JSON.
    pub fn to_json_pretty(&self) -> crate::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Serialize as compact (single-line) JSON.
    pub fn to_json(&self) -> crate::Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

impl Default for AnalysisOutput {
    fn default() -> Self {
        Self {
            schema_version: 1,
            engine_version: String::new(),
            source_path: String::new(),
            source_sha256: None,
            source_bytes: 0,
            link_type: String::new(),
            summary: Summary::empty(),
            flows_parquet_path: None,
            elapsed_ms: 0,
            baseline: None,
        }
    }
}
