//! "Teach it once" analyst suppressions. Fully implemented contract type.
//!
//! A [`SuppressionRule`] is an analyst's *benign* verdict turned into a reusable match: "a
//! `missing_sni` finding from 10.0.0.0/8 to 52.1.2.3 is expected here". Rules live in plain,
//! versioned JSON files ([`SuppressionFile`]) so one analyst can keep them offline and a team
//! can share them through git — there is no server. The active rules ride along in
//! `Summary.suppression_rules`, which is what lets the alert queue re-derive at every seam
//! (analyze / rule fold / reputation) without a config channel; the per-finding outcome lands
//! in `Summary.suppressions`. Matching lives in [`crate::detect::suppress`].
//!
//! ## Invariants
//!
//! - **Nothing is silently dropped:** a suppressed finding leaves the alert queue but is listed
//!   in `Summary.suppressions` with the rule that hid it, so `Σ alert.finding_count +
//!   suppressed == findings.len()`.
//! - **Guardrails beat rules:** confirmed malware, ARP spoofing, OT control writes, and any
//!   finding touching an IOC- or reputation-flagged host are never hidden; the rule hit is
//!   recorded as [`SuppressionOutcome::Blocked`] instead.
//! - Findings, incidents and attack chains are never mutated — suppression only shapes the
//!   alert queue.

/// The on-disk file format version written by this build.
pub const SUPPRESSION_FILE_VERSION: u32 = 1;

/// One analyst verdict as a match rule. Every `Option` field is a wildcard when `None`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SuppressionRule {
    /// `"sup:{:016x}"` — FNV-1a of the normalized match key, so the same verdict taught twice
    /// (or by two analysts) dedupes to one rule. Filled in on load when absent.
    #[serde(default)]
    pub id: String,
    /// The finding kind's snake_case token (`FindingKind::as_str`). Required — there is no
    /// kind wildcard. Kept as a string so a file written by a newer build with a kind this
    /// build does not know still loads (the rule simply never matches).
    pub kind: String,
    /// Source host: an IP or a CIDR; `None` matches any source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<String>,
    /// Destination host: an IP or a CIDR; `None` matches any destination (including fan-out
    /// findings with no single destination).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst: Option<String>,
    /// Destination port; `None` matches any port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<u16>,
    /// Why this is benign — the analyst's note, shown wherever the rule hides something.
    #[serde(default)]
    pub reason: String,
    /// Who taught it (free text: a name, handle or email).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// When it was taught, `YYYY-MM-DD`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// Last day the rule applies, `YYYY-MM-DD`; `None` never expires. Expiry is evaluated when
    /// a file is loaded (the analysis itself has no clock).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
}

/// A suppression rule file — the unit a team commits to git.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SuppressionFile {
    /// Format version ([`SUPPRESSION_FILE_VERSION`]).
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub rules: Vec<SuppressionRule>,
}

fn default_version() -> u32 {
    SUPPRESSION_FILE_VERSION
}

impl Default for SuppressionFile {
    fn default() -> Self {
        SuppressionFile {
            version: SUPPRESSION_FILE_VERSION,
            rules: Vec::new(),
        }
    }
}

/// Why a matching rule was not allowed to hide a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    /// The finding kind is never suppressible (confirmed malware, ARP spoofing, OT writes).
    ProtectedKind,
    /// The source or destination host matched the offline IOC feed.
    ThreatIntel,
    /// The source or destination host has a `Malicious` online-reputation verdict.
    Reputation,
}

impl BlockReason {
    /// Stable snake_case token (matches the serde wire form).
    pub fn as_str(self) -> &'static str {
        match self {
            BlockReason::ProtectedKind => "protected_kind",
            BlockReason::ThreatIntel => "threat_intel",
            BlockReason::Reputation => "reputation",
        }
    }
}

/// What a matching rule did to one finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "reason")]
pub enum SuppressionOutcome {
    /// The finding left the alert queue.
    Suppressed,
    /// A rule matched but a guardrail kept the finding in the queue.
    Blocked(BlockReason),
}

/// One finding a rule matched, with the outcome. Ascending by `finding_index`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SuppressionHit {
    /// Index into `Summary.findings`.
    pub finding_index: u32,
    /// The first matching rule's id (rules are checked in file order).
    pub rule_id: String,
    #[serde(flatten)]
    pub outcome: SuppressionOutcome,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_file_parses_with_defaults() {
        let f: SuppressionFile =
            serde_json::from_str(r#"{"rules":[{"kind":"missing_sni","src":"10.0.0.5"}]}"#).unwrap();
        assert_eq!(f.version, SUPPRESSION_FILE_VERSION);
        assert_eq!(f.rules[0].kind, "missing_sni");
        assert_eq!(f.rules[0].dst, None);
        assert!(f.rules[0].id.is_empty());
    }

    #[test]
    fn hit_wire_form_is_flat() {
        let hit = SuppressionHit {
            finding_index: 3,
            rule_id: "sup:1".into(),
            outcome: SuppressionOutcome::Blocked(BlockReason::ThreatIntel),
        };
        let v = serde_json::to_value(&hit).unwrap();
        assert_eq!(v["status"], "blocked");
        assert_eq!(v["reason"], "threat_intel");
        let back: SuppressionHit = serde_json::from_value(v).unwrap();
        assert_eq!(back, hit);
        let ok = SuppressionHit {
            outcome: SuppressionOutcome::Suppressed,
            ..hit
        };
        let v = serde_json::to_value(&ok).unwrap();
        assert_eq!(v["status"], "suppressed");
        assert_eq!(serde_json::from_value::<SuppressionHit>(v).unwrap(), ok);
    }
}
