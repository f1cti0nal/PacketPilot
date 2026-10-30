//! Noise budget: how far a capture was boiled down — packets to flows to findings to the
//! stories an analyst actually reads — and a transparent estimate of the review time that saved.
//!
//! The estimate is deliberately simple and always shown with its inputs. Without PacketPilot an
//! analyst skims the flow table and triages every raw finding on its own; with it they read the
//! alert queue, where each alert is one story (a chain, an incident, or a rollup):
//!
//! ```text
//! manual = flows / 1000 × minutes_per_1k_flows + findings × minutes_per_finding
//! with   = stories × minutes_per_story
//! saved  = max(0, manual − with)
//! ```
//!
//! The per-item minutes default to [`ReviewRates::default`] and a team can override them with a
//! small versioned JSON file (`review-rates.json`, see [`parse_review_rates`]), kept in git next
//! to its suppressions and playbooks. Pure and deterministic: re-derived with the alert queue.

#[cfg(test)]
mod tests;

use crate::model::alert::PriorityBand;
use crate::model::summary::Summary;
use crate::model::suppression::SuppressionOutcome;

/// The only review-rates file version this build reads.
pub const REVIEW_RATES_VERSION: u32 = 1;

/// The largest per-item figure accepted (a working day), so a typo cannot claim years saved.
const MAX_MINUTES: f64 = 480.0;

/// Minutes an analyst spends per unit of review. Every field is optional in the file.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ReviewRates {
    pub version: u32,
    /// Skimming a thousand rows of the flow table.
    pub minutes_per_1k_flows: f64,
    /// Triaging one raw finding on its own (look it up, pivot, decide).
    pub minutes_per_finding: f64,
    /// Reading one alert story end to end, with its context bundle and playbook.
    pub minutes_per_story: f64,
}

impl Default for ReviewRates {
    fn default() -> Self {
        ReviewRates {
            version: REVIEW_RATES_VERSION,
            minutes_per_1k_flows: 5.0,
            minutes_per_finding: 10.0,
            minutes_per_story: 15.0,
        }
    }
}

/// The capture's noise budget. Counts are exact; the minutes are an estimate from `rates`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct NoiseBudget {
    pub packets: u64,
    pub flows: u64,
    /// Every behavioral finding, before analyst suppressions.
    pub findings: u64,
    /// Findings an analyst suppression rule took out of the queue.
    pub suppressed: u64,
    /// Alerts in the queue: each one story an analyst reads.
    pub stories: u64,
    /// Stories in the Investigate or Act now band.
    pub urgent: u64,
    /// Estimated review time without the queue.
    pub manual_minutes: f64,
    /// Estimated review time reading the queue.
    pub queue_minutes: f64,
    /// `max(0, manual_minutes − queue_minutes)`.
    pub saved_minutes: f64,
    /// The rates the estimate used.
    pub rates: ReviewRates,
}

/// The noise budget of `summary` under `rates`.
pub fn noise_budget(summary: &Summary, rates: ReviewRates) -> NoiseBudget {
    let findings = summary.findings.len() as u64;
    let suppressed = summary
        .suppressions
        .iter()
        .filter(|h| h.outcome == SuppressionOutcome::Suppressed)
        .count() as u64;
    let stories = summary.alerts.len() as u64;
    let urgent = summary
        .alerts
        .iter()
        .filter(|a| matches!(a.band, PriorityBand::Investigate | PriorityBand::ActNow))
        .count() as u64;
    let manual_minutes = summary.total_flows as f64 / 1000.0 * rates.minutes_per_1k_flows
        + findings as f64 * rates.minutes_per_finding;
    let queue_minutes = stories as f64 * rates.minutes_per_story;
    NoiseBudget {
        packets: summary.total_packets,
        flows: summary.total_flows,
        findings,
        suppressed,
        stories,
        urgent,
        manual_minutes: round1(manual_minutes),
        queue_minutes: round1(queue_minutes),
        saved_minutes: round1((manual_minutes - queue_minutes).max(0.0)),
        rates,
    }
}

/// Recompute `summary.noise_budget`, keeping the rates it already carries (a team file applied
/// at analyze time survives every later re-derivation).
pub fn refresh_noise_budget(summary: &mut Summary) {
    let rates = summary
        .noise_budget
        .as_ref()
        .map_or_else(ReviewRates::default, |b| b.rates);
    summary.noise_budget = Some(noise_budget(summary, rates));
}

/// Apply team review rates to an analysis and recompute its budget.
pub fn apply_review_rates(summary: &mut Summary, rates: ReviewRates) {
    summary.noise_budget = Some(noise_budget(summary, rates));
}

/// Parse and check a `review-rates.json`. Fields left out keep their defaults; every problem is
/// reported at once.
pub fn parse_review_rates(text: &str) -> Result<ReviewRates, Vec<String>> {
    let rates: ReviewRates =
        serde_json::from_str(text).map_err(|e| vec![format!("not a review-rates file: {e}")])?;
    let mut problems = Vec::new();
    if rates.version != REVIEW_RATES_VERSION {
        problems.push(format!(
            "version {} is not supported (expected {REVIEW_RATES_VERSION})",
            rates.version
        ));
    }
    for (name, v) in [
        ("minutes_per_1k_flows", rates.minutes_per_1k_flows),
        ("minutes_per_finding", rates.minutes_per_finding),
        ("minutes_per_story", rates.minutes_per_story),
    ] {
        if !v.is_finite() || !(0.0..=MAX_MINUTES).contains(&v) {
            problems.push(format!(
                "{name} must be between 0 and {MAX_MINUTES} (got {v})"
            ));
        }
    }
    if problems.is_empty() {
        Ok(rates)
    } else {
        Err(problems)
    }
}

impl NoiseBudget {
    /// `4.2M packets → 61k flows → 9 stories, about 6 h saved (estimate)`.
    pub fn headline(&self) -> String {
        format!(
            "{} packets → {} flows → {} {}, {}",
            compact(self.packets),
            compact(self.flows),
            compact(self.stories),
            if self.stories == 1 {
                "story"
            } else {
                "stories"
            },
            saved_phrase(self.saved_minutes),
        )
    }

    /// The counts and formula behind [`headline`](Self::headline), one line.
    pub fn explain(&self) -> String {
        let r = &self.rates;
        format!(
            "{} findings ({} suppressed), {} urgent; estimate: {} min to skim flows and triage \
             findings one by one ({} min per 1k flows, {} min per finding) vs {} min to read the \
             queue ({} min per story)",
            self.findings,
            self.suppressed,
            self.urgent,
            fmt_min(self.manual_minutes),
            fmt_min(r.minutes_per_1k_flows),
            fmt_min(r.minutes_per_finding),
            fmt_min(self.queue_minutes),
            fmt_min(r.minutes_per_story),
        )
    }
}

/// `about 6 h saved (estimate)`, `about 25 min saved (estimate)`, `no review time saved`.
pub fn saved_phrase(minutes: f64) -> String {
    if minutes < 1.0 {
        "no review time saved".to_string()
    } else if minutes < 60.0 {
        format!("about {} min saved (estimate)", minutes.round() as u64)
    } else {
        let h = minutes / 60.0;
        if h < 10.0 {
            format!(
                "about {} h saved (estimate)",
                fmt_min((h * 2.0).round() / 2.0)
            )
        } else {
            format!("about {} h saved (estimate)", h.round() as u64)
        }
    }
}

/// `950`, `61k`, `4.2M`, `1.3B`.
pub fn compact(n: u64) -> String {
    let f = |v: f64, unit: &str| {
        if v < 10.0 {
            format!("{}{unit}", fmt_min((v * 10.0).floor() / 10.0))
        } else {
            format!("{}{unit}", v.floor() as u64)
        }
    };
    match n {
        0..=999 => n.to_string(),
        1_000..=999_999 => f(n as f64 / 1e3, "k"),
        1_000_000..=999_999_999 => f(n as f64 / 1e6, "M"),
        _ => f(n as f64 / 1e9, "B"),
    }
}

/// A minute figure without a trailing `.0`.
fn fmt_min(v: f64) -> String {
    if v.fract() == 0.0 {
        format!("{}", v as i64)
    } else {
        format!("{v:.1}")
    }
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}
