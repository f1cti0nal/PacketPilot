//! Verdict severity band. Fully implemented contract type.
//!
//! The Rust enum is canonical. `serde` emits **lowercase** in JSON (`"critical"`) and
//! [`Severity::as_str`] emits the same lowercase token used by the DuckDB `severity_t` enum
//! (`'info','low','medium','high','critical'`). Variant order is ascending so the derived
//! `Ord`/`.max()` yields the *worst* severity directly.
//!
//! `Severity` lives in `model` (not `score`) so that `model::flow::FlowRecord` can carry a
//! `Severity` field while `score::score_flow` consumes a `FlowRecord` without forming a
//! `model::flow -> score -> model::flow` dependency cycle (mirrors how `Category` lives here).

/// Verdict band. Variant order is ascending (`Info < Low < Medium < High < Critical`) so the
/// derived `Ord` and `.max()` give the worst severity directly, matching the DuckDB
/// `severity_t` enum order.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "lowercase")] // "info","low","medium","high","critical"
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Stable lowercase token used in the Parquet `severity` column and the DuckDB
    /// `severity_t` enum. Equals the serde wire token.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Ascending numeric rank (`Info`=0 .. `Critical`=4) for cross-comparisons.
    pub fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    /// Parse a lowercase wire token back into a [`Severity`]; `None` for anything else.
    pub fn from_str_opt(s: &str) -> Option<Severity> {
        Some(match s {
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => return None,
        })
    }

    /// Map a 0..=100 threat score into its severity band.
    ///
    /// Bands: `Info` 0–14, `Low` 15–34, `Medium` 35–59, `High` 60–84, `Critical` 85–100.
    pub fn from_score(s: u16) -> Severity {
        match s {
            0..=14 => Severity::Info,
            15..=34 => Severity::Low,
            35..=59 => Severity::Medium,
            60..=84 => Severity::High,
            _ => Severity::Critical,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_is_ascending_and_max_is_worst() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::High < Severity::Critical);
        assert_eq!(Severity::Low.max(Severity::Critical), Severity::Critical);
    }

    #[test]
    fn token_roundtrip_matches_severity_t() {
        for s in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(Severity::from_str_opt(s.as_str()), Some(s));
        }
    }

    #[test]
    fn from_score_band_boundaries() {
        assert_eq!(Severity::from_score(0), Severity::Info);
        assert_eq!(Severity::from_score(14), Severity::Info);
        assert_eq!(Severity::from_score(15), Severity::Low);
        assert_eq!(Severity::from_score(34), Severity::Low);
        assert_eq!(Severity::from_score(35), Severity::Medium);
        assert_eq!(Severity::from_score(59), Severity::Medium);
        assert_eq!(Severity::from_score(60), Severity::High);
        assert_eq!(Severity::from_score(84), Severity::High);
        assert_eq!(Severity::from_score(85), Severity::Critical);
        assert_eq!(Severity::from_score(100), Severity::Critical);
    }
}
