//! Always-compiled reputation types + the pure, network-free severity folding.
//!
//! Provider adapters + HTTP live behind the `online` feature in [`crate::enrich::online`];
//! THIS module compiles everywhere (incl. `wasm32`) so the browser applies verdicts via the
//! WASM `apply_reputation` export and gets the SAME scoring as native callers.

use crate::model::severity::Severity;
use crate::model::summary::Summary;
use std::collections::BTreeMap;
#[allow(unused_imports)]
use std::collections::HashSet;

/// Per-provider reputation status. Distinguishes "no data" from "clean" so absence is never
/// read as innocence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RepStatus {
    /// Provider asserts malicious → raises severity.
    Malicious,
    /// Provider asserts KNOWN-benign attribution → suppression-worthy (GreyNoise benign / RIOT).
    Benign,
    /// Analyzed, no adverse signal, but no positive benign attribution → 0 pts, never suppresses.
    Clean,
    /// Analyzed but inconclusive.
    Unknown,
    /// Provider has no record (HTTP 404 / NotFoundError) — NOT "clean".
    NotFound,
    /// Lookup failed/skipped: error, bad key, quota exhausted, offline.
    Unavailable,
}

impl Default for RepStatus {
    fn default() -> Self {
        RepStatus::Unknown
    }
}

/// One provider's verdict for one indicator. `source` is a `String` (not `&'static str`) so it
/// round-trips through JSON on the WASM boundary.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReputationVerdict {
    /// `"abuseipdb" | "greynoise" | "virustotal"`.
    pub source: String,
    pub status: RepStatus,
    /// `== matches!(status, RepStatus::Malicious)`. Retained for wire back-compat / convenience.
    pub malicious: bool,
    /// 0..=100; `Some(0)` when `Clean`; `None` when `Unknown`/`NotFound`/`Unavailable`.
    pub score: Option<u8>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Provider report page for the indicator (evidence drill-down).
    #[serde(default)]
    pub link: Option<String>,
    /// Unix seconds the verdict was fetched (cache freshness / "as of" display).
    #[serde(default)]
    pub fetched_at: i64,
}

/// Temporary stub — real implementation lives in Task A3.
pub fn apply_reputation(
    _summary: &mut Summary,
    _verdicts: &BTreeMap<String, Vec<ReputationVerdict>>,
) {
}

// Suppress unused-import warning for Severity until A3 wires it in.
const _: fn() = || {
    let _: Severity;
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_serde_roundtrip_snake_case() {
        let v = ReputationVerdict {
            source: "abuseipdb".to_string(),
            status: RepStatus::Malicious,
            malicious: true,
            score: Some(96),
            tags: vec!["ssh".to_string(), "brute-force".to_string()],
            link: Some("https://www.abuseipdb.com/check/203.0.113.7".to_string()),
            fetched_at: 1_750_500_000,
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("\"status\":\"malicious\""));
        let back: ReputationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn status_default_is_unknown() {
        assert_eq!(RepStatus::default(), RepStatus::Unknown);
    }
}
