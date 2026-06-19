//! Transparent, deterministic per-flow threat scoring.
//!
//! [`score_flow`] turns a classified [`FlowRecord`] plus a [`FeedMatch`] into a
//! [`ScoredFlow`] (0..=100 score + a [`Severity`] band + an exact, human-readable evidence
//! trail + ATT&CK ids). It is pure: every nonzero contribution pushes its own evidence
//! string, and when the raw sum is clamped to the 0..=100 bounds the clamp delta is recorded
//! too, so the evidence trail always reconciles to the reported score.
//!
//! ## Scoring rationale
//!
//! - **Bands** ([`Severity::from_score`]): Info/Low/Medium occupy even ~20-point ranges;
//!   High/Critical sit higher so a single benign signal cannot reach High on points alone —
//!   the IOC *floor* (below) is the only fast path to High, keeping "an IOC forces High"
//!   honest.
//! - **Category** (the dominant term): only `C2`(+45)/`Anomalous`(+40) reach Medium alone;
//!   `Scan`/`TunnelVpn`(+25) reach Low alone; benign categories(+3) accrue almost nothing
//!   without an IOC or behavioral signal.
//! - **IOC**(+35 each): large, but it is the *floor*, not the points, that guarantees
//!   >=High — so the rule survives even when every other term is zero (the synthetic
//!   > Web+SNI case).
//! - **Externality**(+15 / -10): asymmetric. On the synthetic corpus (all RFC1918 `10.x`)
//!   this is almost always -10, which is the honest reason demo verdicts come from the IOC
//!   floor, not from a fabricated public peer.
//! - **Behavior**(+10): refines an already-categorized flow; never manufactures a verdict
//!   alone.

use crate::enrich::{attack_for, classify_ip, FeedMatch};
use crate::model::category::Category;
use crate::model::flow::FlowRecord;

pub use crate::model::severity::Severity;

// ---- Weighted term constants (single source; documented above) ------------------------

const PTS_C2: i32 = 45;
const PTS_ANOMALOUS: i32 = 40;
const PTS_SCAN: i32 = 25;
const PTS_TUNNEL: i32 = 25;
const PTS_MEDIUM_RISK_CAT: i32 = 10; // email / file_transfer / remote_access
const PTS_BENIGN_CAT: i32 = 3; // web / dns / voip / iot_ot

const PTS_IOC: i32 = 35; // per IOC dimension (ip, domain)
const PTS_EXTERNAL: i32 = 15;
const PTS_ALL_INTERNAL: i32 = -10;
const PTS_BEHAVIOR: i32 = 10;

/// Beacon byte ceiling. MUST match `classify::BEACON_MAX_BYTES` (kept local to avoid coupling
/// to that module's private constants).
const BEACON_MAX_BYTES: u64 = 4_096;

// ---- Output ---------------------------------------------------------------------------

/// The scored verdict for one flow.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ScoredFlow {
    /// Severity band (`Info` by default).
    pub severity: Severity,
    /// Threat score, clamped to 0..=100.
    pub score: u16,
    /// Exact evidence string for every nonzero term plus any floor reason.
    pub evidence: Vec<String>,
    /// MITRE ATT&CK technique ids (0 or 1 in Phase 2).
    pub attack: Vec<String>,
}

/// Score one classified flow against the feed-match summary. Pure and deterministic.
pub fn score_flow(rec: &FlowRecord, fm: &FeedMatch) -> ScoredFlow {
    let mut acc: i32 = 0;
    let mut evidence: Vec<String> = Vec::new();

    // --- Category term -----------------------------------------------------------------
    match rec.category {
        Category::C2 => {
            acc += PTS_C2;
            evidence.push("category c2 (+45)".to_string());
        }
        Category::Anomalous => {
            acc += PTS_ANOMALOUS;
            evidence.push("category anomalous (+40)".to_string());
        }
        Category::Scan => {
            acc += PTS_SCAN;
            evidence.push("category scan (+25)".to_string());
        }
        Category::TunnelVpn => {
            acc += PTS_TUNNEL;
            evidence.push("category tunnel_vpn (+25)".to_string());
        }
        Category::Email | Category::FileTransfer | Category::RemoteAccess => {
            acc += PTS_MEDIUM_RISK_CAT;
            evidence.push(format!("category {} (+10)", rec.category.as_str()));
        }
        Category::Web | Category::Dns | Category::Voip | Category::IotOt => {
            acc += PTS_BENIGN_CAT;
            evidence.push(format!("category {} (+3)", rec.category.as_str()));
        }
        Category::Unknown => {
            // +0; still recorded for transparency.
            evidence.push("category unknown (+0)".to_string());
        }
    }

    // --- IOC terms ---------------------------------------------------------------------
    if fm.ip {
        acc += PTS_IOC;
        evidence.push("ioc: endpoint ip on threat feed (+35)".to_string());
    }
    if fm.domain {
        acc += PTS_IOC;
        evidence.push("ioc: sni on threat feed (+35)".to_string());
    }

    // --- Externality term --------------------------------------------------------------
    let lo_ext = classify_ip(rec.key.lo_ip).is_external();
    let hi_ext = classify_ip(rec.key.hi_ip).is_external();
    if lo_ext || hi_ext {
        acc += PTS_EXTERNAL;
        evidence.push("external public peer (+15)".to_string());
    } else {
        acc += PTS_ALL_INTERNAL;
        evidence.push("all-internal peers (-10)".to_string());
    }

    // --- Behavioral terms --------------------------------------------------------------
    if rec.category == Category::Scan && rec.pkts_rev == 0 {
        acc += PTS_BEHAVIOR;
        evidence.push("behavior: scan-shaped probe (+10)".to_string());
    }
    if rec.category == Category::C2
        && rec.total_bytes() <= BEACON_MAX_BYTES
        && rec.pkts_fwd >= 2
        && rec.pkts_rev >= 2
    {
        acc += PTS_BEHAVIOR;
        evidence.push("behavior: beacon-shaped (+10)".to_string());
    }

    // --- Summation + clamp + reconcile -------------------------------------------------
    let mut score = acc.clamp(0, 100) as u16;
    // When the raw accumulation falls outside the 0..=100 contract bounds the clamp is the
    // one adjustment the term evidence does not account for; record it so the evidence trail
    // always reconciles to the reported score. No-op in the common in-range case.
    if i32::from(score) != acc {
        evidence.push(format!("clamp: raw {acc} -> {score}"));
    }
    let mut sev = Severity::from_score(score);

    if fm.any() {
        // FLOOR 1: any IOC match forces at least High.
        if sev.rank() < Severity::High.rank() {
            sev = Severity::High;
            score = score.max(60);
            evidence.push("floor: ioc match forces High (>= 60)".to_string());
        }
        // FLOOR 2: IOC on a C2/Anomalous flow forces Critical.
        if matches!(rec.category, Category::C2 | Category::Anomalous) {
            sev = Severity::Critical;
            score = score.max(90);
            evidence.push("floor: ioc + c2/anomalous forces Critical (>= 90)".to_string());
        }
    }

    let mut attack = Vec::new();
    if let Some(t) = attack_for(rec.category) {
        attack.push(t.id.to_string());
    }

    ScoredFlow {
        severity: sev,
        score,
        evidence,
        attack,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::flow::{FlowKey, FlowRecord};
    use crate::model::packet::Transport;
    use std::net::{IpAddr, Ipv4Addr};

    fn rec(cat: Category) -> FlowRecord {
        let key = FlowKey {
            lo_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            hi_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            lo_port: 1234,
            hi_port: 443,
            transport: Transport::Tcp,
        };
        let mut r = FlowRecord::new(key, 0);
        r.category = cat;
        r
    }

    #[test]
    fn benign_web_is_info() {
        let r = rec(Category::Web);
        let s = score_flow(&r, &FeedMatch::default());
        // +3 -10 -> clamp 0 -> Info.
        assert_eq!(s.severity, Severity::Info);
        assert_eq!(s.score, 0);
        assert!(s.evidence.iter().any(|e| e == "all-internal peers (-10)"));
        // The clamp from the negative raw sum is recorded so the evidence reconciles to 0.
        assert!(s.evidence.iter().any(|e| e == "clamp: raw -7 -> 0"));
    }

    #[test]
    fn ioc_forces_high() {
        let r = rec(Category::Web);
        let s = score_flow(
            &r,
            &FeedMatch {
                domain: true,
                ..Default::default()
            },
        );
        assert_eq!(s.severity, Severity::High);
        assert!(s.score >= 60);
        assert!(s
            .evidence
            .iter()
            .any(|e| e == "ioc: sni on threat feed (+35)"));
        assert!(s
            .evidence
            .iter()
            .any(|e| e == "floor: ioc match forces High (>= 60)"));
    }

    #[test]
    fn ioc_plus_c2_forces_critical() {
        let mut r = rec(Category::C2);
        r.pkts_fwd = 3;
        r.pkts_rev = 3;
        r.bytes_fwd = 100;
        r.bytes_rev = 100;
        let s = score_flow(
            &r,
            &FeedMatch {
                ip: true,
                ..Default::default()
            },
        );
        assert_eq!(s.severity, Severity::Critical);
        assert!(s.score >= 90);
        assert_eq!(s.attack, vec!["T1071".to_string()]);
        assert!(s.evidence.iter().any(|e| e == "category c2 (+45)"));
        assert!(s
            .evidence
            .iter()
            .any(|e| e == "ioc: endpoint ip on threat feed (+35)"));
        assert!(s
            .evidence
            .iter()
            .any(|e| e == "floor: ioc + c2/anomalous forces Critical (>= 90)"));
    }

    #[test]
    fn scan_shaped_evidence() {
        let mut r = rec(Category::Scan);
        r.pkts_fwd = 1;
        r.pkts_rev = 0;
        let s = score_flow(&r, &FeedMatch::default());
        assert!(s.evidence.iter().any(|e| e == "category scan (+25)"));
        assert!(s
            .evidence
            .iter()
            .any(|e| e == "behavior: scan-shaped probe (+10)"));
        // +25 +10 -10 = 25 -> Low.
        assert_eq!(s.severity, Severity::Low);
    }

    #[test]
    fn score_never_exceeds_100() {
        let mut r = rec(Category::C2);
        r.pkts_fwd = 3;
        r.pkts_rev = 3;
        r.bytes_fwd = 100;
        r.bytes_rev = 100;
        let s = score_flow(
            &r,
            &FeedMatch {
                ip: true,
                domain: true,
            },
        );
        assert!(s.score <= 100);
    }

    #[test]
    fn evidence_strings_are_exact() {
        let r = rec(Category::Unknown);
        let s = score_flow(&r, &FeedMatch::default());
        assert!(s.evidence.iter().any(|e| e == "category unknown (+0)"));
    }
}
