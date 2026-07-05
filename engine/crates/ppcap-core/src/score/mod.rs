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
//! - **Heuristic-C2 confidence cap**: a shape-only `C2` (labeled by `classify::looks_like_beacon`,
//!   carrying no `app_proto_src`) is a *candidate*, not a verdict. Without corroboration it is
//!   held at Medium so `C2`(+45)+`external`(+15)=60 cannot flag a benign public peer as High on
//!   a single weak flow. The two corroboration paths still reach High: an IOC (the floors), or a
//!   cross-flow periodic-beacon finding that uplifts the host card afterward.

use crate::enrich::{attack_for, classify_ip, FeedMatch};
use crate::model::category::Category;
use crate::model::flow::FlowRecord;
use crate::model::summary::ScoreTerm;

pub use crate::model::severity::Severity;

// ---- Weighted term constants (single source; documented above) ------------------------

const PTS_C2: i32 = 45;
const PTS_ANOMALOUS: i32 = 40;
const PTS_SCAN: i32 = 25;
const PTS_TUNNEL: i32 = 25;
const PTS_MEDIUM_RISK_CAT: i32 = 10; // email / file_transfer / remote_access
const PTS_BENIGN_CAT: i32 = 3; // web / dns / voip / iot_ot

const PTS_IOC: i32 = 35; // per IOC dimension (ip, domain, tls fingerprint)
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
    /// Typed additive score contributions (one per `add_term` call). Mirrors the `(±N)`
    /// evidence strings but machine-readable. Clamp/floor entries are NOT terms.
    #[serde(default)]
    pub terms: Vec<ScoreTerm>,
}

/// Push one additive scoring contribution: bumps the accumulator, records a typed
/// [`ScoreTerm`], and appends a byte-identical `"{label} ({points:+})"` evidence string.
fn add_term(
    acc: &mut i32,
    evidence: &mut Vec<String>,
    terms: &mut Vec<ScoreTerm>,
    label: impl Into<String>,
    points: i32,
) {
    let label = label.into();
    *acc += points;
    terms.push(ScoreTerm {
        label: label.clone(),
        points,
    });
    evidence.push(format!("{label} ({points:+})"));
}

/// Score one classified flow against the feed-match summary. Pure and deterministic.
pub fn score_flow(rec: &FlowRecord, fm: &FeedMatch) -> ScoredFlow {
    let mut acc: i32 = 0;
    let mut evidence: Vec<String> = Vec::new();
    let mut terms: Vec<ScoreTerm> = Vec::new();

    // --- Category term -----------------------------------------------------------------
    match rec.category {
        Category::C2 => {
            add_term(&mut acc, &mut evidence, &mut terms, "category c2", PTS_C2);
        }
        Category::Anomalous => {
            add_term(
                &mut acc,
                &mut evidence,
                &mut terms,
                "category anomalous",
                PTS_ANOMALOUS,
            );
        }
        Category::Scan => {
            add_term(
                &mut acc,
                &mut evidence,
                &mut terms,
                "category scan",
                PTS_SCAN,
            );
        }
        Category::TunnelVpn => {
            add_term(
                &mut acc,
                &mut evidence,
                &mut terms,
                "category tunnel_vpn",
                PTS_TUNNEL,
            );
        }
        Category::Email | Category::FileTransfer | Category::RemoteAccess => {
            add_term(
                &mut acc,
                &mut evidence,
                &mut terms,
                format!("category {}", rec.category.as_str()),
                PTS_MEDIUM_RISK_CAT,
            );
        }
        Category::Web | Category::Dns | Category::Voip | Category::IotOt => {
            add_term(
                &mut acc,
                &mut evidence,
                &mut terms,
                format!("category {}", rec.category.as_str()),
                PTS_BENIGN_CAT,
            );
        }
        Category::Unknown => {
            // +0; still recorded for transparency.
            add_term(&mut acc, &mut evidence, &mut terms, "category unknown", 0);
        }
    }

    // --- IOC terms ---------------------------------------------------------------------
    if fm.ip {
        add_term(
            &mut acc,
            &mut evidence,
            &mut terms,
            "ioc: endpoint ip on threat feed",
            PTS_IOC,
        );
    }
    if fm.domain {
        add_term(
            &mut acc,
            &mut evidence,
            &mut terms,
            "ioc: sni on threat feed",
            PTS_IOC,
        );
    }
    if fm.fingerprint {
        add_term(
            &mut acc,
            &mut evidence,
            &mut terms,
            "ioc: tls fingerprint on threat feed",
            PTS_IOC,
        );
    }

    // --- Externality term --------------------------------------------------------------
    let lo_ext = classify_ip(rec.key.lo_ip).is_external();
    let hi_ext = classify_ip(rec.key.hi_ip).is_external();
    if lo_ext || hi_ext {
        add_term(
            &mut acc,
            &mut evidence,
            &mut terms,
            "external public peer",
            PTS_EXTERNAL,
        );
    } else {
        add_term(
            &mut acc,
            &mut evidence,
            &mut terms,
            "all-internal peers",
            PTS_ALL_INTERNAL,
        );
    }

    // --- Behavioral terms --------------------------------------------------------------
    if rec.category == Category::Scan && rec.pkts_rev == 0 {
        add_term(
            &mut acc,
            &mut evidence,
            &mut terms,
            "behavior: scan-shaped probe",
            PTS_BEHAVIOR,
        );
    }
    if rec.category == Category::C2
        && rec.total_bytes() <= BEACON_MAX_BYTES
        && rec.pkts_fwd >= 2
        && rec.pkts_rev >= 2
    {
        add_term(
            &mut acc,
            &mut evidence,
            &mut terms,
            "behavior: beacon-shaped",
            PTS_BEHAVIOR,
        );
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

    // CONFIDENCE CAP: a heuristic (non-DPI) C2 is a *candidate*, not a verdict. In Phase 0 a
    // flow is labeled `C2` purely by shape (`classify::looks_like_beacon` — a small, two-way
    // exchange on a port we could not name), recorded with no app-proto provenance
    // (`app_proto_src == None`). That signal alone must not reach High: `category c2 (+45)`
    // plus an `external public peer (+15)` already sums to 60, so a single benign public flow
    // on an odd port (NTP, STUN, an app heartbeat, or TLS whose handshake was snaplen-clipped)
    // would otherwise be flagged High. Hold such an uncorroborated candidate at Medium. Both
    // corroboration paths still reach High untouched: an IOC match (the floors below, which
    // only fire on `fm.any()`), or a cross-flow periodic-beacon finding (`detect::beacon`,
    // High/70 to an external peer) that uplifts the host card raise-only after scoring.
    let heuristic_c2 = rec.category == Category::C2 && rec.app_proto_src.is_none();
    if heuristic_c2 && !fm.any() && sev.rank() > Severity::Medium.rank() {
        sev = Severity::Medium;
        score = score.min(59);
        evidence.push("cap: heuristic c2 candidate held at Medium without corroboration".to_string());
    }

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
        terms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::{Enricher, ThreatFeed};
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

    /// Sentinel JA3 that is in the embedded builtin set (label "test-sig").
    const SENTINEL_JA3: &str = "00000000000000000000000000000000";

    #[test]
    fn fingerprint_ioc_adds_35_once_and_floors_high() {
        // Use Web category so the flow scores well below 60 pre-IOC (benign path):
        // +3 (web) -10 (all-internal) = -7 → clamped to 0 → Info.
        let mut rec = rec(Category::Web);
        rec.ja3 = Some(SENTINEL_JA3.into());
        // Set ja4 to the same sentinel — matches_ja4 won't find it (it's ja3-only in
        // the builtin set) but both fields being set exercises the "ja3_ioc || ja4_ioc"
        // gate in feed_match without producing a second fingerprint evidence line.
        rec.ja4 = Some(SENTINEL_JA3.into());
        let enr = Enricher::new(ThreatFeed::empty());
        let e = enr.enrich(&rec);
        assert!(
            e.ja3_ioc || e.ja4_ioc,
            "expected fingerprint IOC from sentinel JA3"
        );
        let fm = enr.feed_match(&e);
        assert!(fm.fingerprint, "FeedMatch.fingerprint must be true");
        let scored = score_flow(&rec, &fm);
        assert!(
            scored.severity.rank() >= Severity::High.rank(),
            "fingerprint IOC must floor severity to High, got {:?}",
            scored.severity
        );
        // +35 applied exactly once even though both ja3 and ja4 fields are set:
        let fp_count = scored
            .evidence
            .iter()
            .filter(|s| s.contains("tls fingerprint"))
            .count();
        assert_eq!(
            fp_count, 1,
            "expected exactly one tls fingerprint evidence line, got {fp_count}: {:?}",
            scored.evidence
        );
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
                ..Default::default()
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

    #[test]
    fn score_flow_emits_typed_terms_matching_evidence() {
        // Mirror the ioc_plus_c2_forces_critical fixture: C2 category + ip IOC.
        // This hits: category c2 (+45), ioc: endpoint ip on threat feed (+35),
        //            all-internal peers (-10), behavior: beacon-shaped (+10).
        let mut r = rec(Category::C2);
        r.pkts_fwd = 3;
        r.pkts_rev = 3;
        r.bytes_fwd = 100;
        r.bytes_rev = 100;
        let sc = score_flow(
            &r,
            &FeedMatch {
                ip: true,
                ..Default::default()
            },
        );

        // Additive terms are typed:
        assert!(
            sc.terms
                .iter()
                .any(|t| t.label == "category c2" && t.points == 45),
            "expected category c2 term: {:?}",
            sc.terms
        );
        assert!(
            sc.terms
                .iter()
                .any(|t| t.label == "ioc: endpoint ip on threat feed" && t.points == 35),
            "expected ioc ip term: {:?}",
            sc.terms
        );
        assert!(
            sc.terms
                .iter()
                .any(|t| t.label == "all-internal peers" && t.points == -10),
            "expected all-internal term: {:?}",
            sc.terms
        );
        assert!(
            sc.terms
                .iter()
                .any(|t| t.label == "behavior: beacon-shaped" && t.points == 10),
            "expected beacon-shaped term: {:?}",
            sc.terms
        );

        // Every term has a byte-identical evidence string:
        for t in &sc.terms {
            let expected = format!("{} ({:+})", t.label, t.points);
            assert!(
                sc.evidence.contains(&expected),
                "missing evidence for term {t:?}; evidence = {:?}",
                sc.evidence
            );
        }

        // Clamp/floor are NOT terms:
        assert!(
            !sc.terms
                .iter()
                .any(|t| t.label.starts_with("clamp") || t.label.starts_with("floor")),
            "clamp/floor must not appear in terms: {:?}",
            sc.terms
        );
    }
}
