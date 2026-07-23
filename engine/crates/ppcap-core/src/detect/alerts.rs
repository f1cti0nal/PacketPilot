//! Smart Alerting with Context — the ranked, deduplicated, context-bundled triage queue.
//!
//! [`derive_alerts`] is a **pure, idempotent** post-pass over the finished
//! [`Summary`]: it reads `findings` / `incidents` / `attack_chains` / `ip_threats` and the
//! identity/context rollups, and produces `Summary.alerts` — one row per *adversary story*,
//! ranked by a transparent priority ledger. It runs at three seams (end of analyze, after
//! `fold_rule_findings`, after `apply_reputation`) and always **re-derives** rather than
//! patches, which is what keeps native and wasm output byte-identical.
//!
//! ## Invariants
//!
//! - **Coverage:** every index into `Summary.findings` lands in exactly one alert's
//!   `finding_indices` (`Σ finding_count == findings.len()`), and the invariant survives
//!   truncation via a single overflow rollup. Grouping is the noise mechanism; nothing is
//!   ever silently dropped, and `findings`/`incidents`/`attack_chains` are never mutated.
//! - **Ledger:** `Σ priority_terms.points == priority` exactly — caps, floors and clamps are
//!   materialized as signed terms (unlike `score_flow`, where clamps are evidence-only: an
//!   alert has no separate evidence vector, so the ledger *is* the explanation).
//! - **Corroboration doctrine as queue order:** the base is always the existing story score
//!   (chain / incident / finding — their escalations are never re-derived, so structure
//!   bonuses cannot stack twice); positive uplift is capped (`ALERT_UPLIFT_CAP`, mirroring
//!   `REP_UPLIFT_CAP`); and an uncorroborated sub-High story can never cross into the High
//!   band (`CAP_UNCORROBORATED`) — High/Critical urgency comes only from floors or
//!   corroboration, never from point-stacking.
//! - **Bounded / deterministic / offline:** BTree containers, strict total-order sort ending
//!   in a unique id, FNV-1a ids, compile-time constants (no config surface — the attack-chain
//!   precedent, forced by the re-derive seams having no config channel), no clock, no
//!   network, no `f64`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::enrich::{classify_ip, cloud_provider, RepStatus};
use crate::model::alert::{
    Alert, AlertContext, AlertSource, ContextEntry, ContextKind, HostContext, PeerContext,
    PriorityBand,
};
use crate::model::finding::{Finding, FindingKind};
use crate::model::severity::Severity;
use crate::model::summary::{IpThreat, ScoreTerm, Summary};

use super::{fnv1a64, kind_phrase, stage_label, stage_ordinal};

// ---- Bounds (compile-time; no config surface — determinism + schema stability) ---------

/// Soft emission bound: rows with `priority >= 60` or matching [`never_dampen`] are never
/// dropped; the dropped tail collapses into one overflow rollup (coverage survives).
const MAX_ALERTS: usize = 32;
/// Listed actor hosts per alert (`host_count` keeps the exact total). Mirrors
/// `MAX_CHAIN_VICTIMS`.
const MAX_ALERT_HOSTS: usize = 16;
/// External peers of interest per alert, worst-first.
const MAX_ALERT_PEERS: usize = 4;
/// Typed context entries per alert, `(kind ordinal, text)` order.
const MAX_CONTEXT_ENTRIES: usize = 12;

// ---- Priority weights (the corroboration doctrine as constants) ------------------------

/// Any implicated threat card matched the offline IOC feed, or a known-malicious /
/// signature-matched file member. Corroboration, not points-stacking: see the floors.
pub const PTS_ALERT_IOC: i32 = 10;
/// At least one `Malicious` online-reputation verdict on an implicated card.
pub const PTS_ALERT_REP: i32 = 10;
/// A `BaselineDeviation` member: the actor did something first-seen vs its learned self
/// (warmup gating upstream keeps this trustworthy).
pub const PTS_ALERT_NOVEL: i32 = 5;
/// A `TrafficAnomaly` member: the actor departed from its own within-capture forecast.
pub const PTS_ALERT_ANOM: i32 = 5;
/// Every external peer is attributed cloud/CDN address space and none is IOC/reputation-bad —
/// churn toward managed clouds is the classic benign explanation. Skipped entirely under
/// [`never_dampen`] (never applied-then-floored, so the ledger cannot show a malicious-peer
/// alert being cloud-dampened).
pub const PTS_ALERT_CLOUD_PEER: i32 = -10;
/// Every member finding is untimestamped — temporal ordering degraded to taxonomy.
pub const PTS_ALERT_UNTIMED: i32 = -5;
/// Total POSITIVE adjustment ceiling (mirrors the reputation module's `REP_UPLIFT_CAP`):
/// stacked weak uplifts cannot exceed ~one band.
pub const ALERT_UPLIFT_CAP: i32 = 25;
/// The generalized weak-alone cap: a story whose base is below High with zero IOC/reputation
/// corroboration can never cross into the High band.
pub const CAP_UNCORROBORATED: u16 = 59;
/// An IOC-backed alert is at least Investigate (mirrors the per-flow IOC High floor).
pub const FLOOR_ALERT_IOC: u16 = 60;
/// Reputation consensus (>= 2 malicious providers on one card) forces Act-Now territory
/// (mirrors the reputation Critical floor).
pub const FLOOR_ALERT_REP_CONSENSUS: u16 = 90;

/// Kinds that must never blend into a rollup and, on a chain host, tell their own story even
/// when the chain does not step through them: intel/content-confirmed malware, explicit
/// user-loaded rule matches, safety-critical OT writes, and active MITM.
fn never_rollup(kind: FindingKind) -> bool {
    matches!(
        kind,
        FindingKind::MalwareDownload
            | FindingKind::MalwareSignature
            | FindingKind::RuleMatch
            | FindingKind::IcsControlCommand
            | FindingKind::ArpSpoof
    )
}

/// Weak / hygiene-class kinds: posture-and-self-relative signals that may roll up cross-host
/// when the host shows no stronger story. A `Beacon` is deliberately *not* weak — a lone
/// Medium beacon host gets a real host alert, never a "rollup of 1".
fn is_weak_kind(kind: FindingKind) -> bool {
    matches!(
        kind,
        FindingKind::WeakTls
            | FindingKind::TlsCertHealth
            | FindingKind::CleartextCreds
            | FindingKind::PiiExposure
            | FindingKind::SuspiciousUa
            | FindingKind::PortScan
            | FindingKind::BaselineDeviation
            | FindingKind::TrafficAnomaly
    )
}

/// A finding that must tell its own story when a chain would otherwise swallow it: a
/// [`never_rollup`] kind or anything already High+.
fn standalone_eligible(f: &Finding) -> bool {
    never_rollup(f.kind) || f.severity >= Severity::High
}

/// Canonical kill-chain stage labels by ordinal (matches `stage_label`'s vocabulary; used for
/// the "next expected" hint).
const STAGE_LABELS: [&str; 7] = [
    "Discovery",
    "Credential Access",
    "Lateral Movement",
    "Collection",
    "Command & Control",
    "Exfiltration",
    "Impact",
];

// ---- Derivation -----------------------------------------------------------------------

/// Derive the ranked alert queue from a finished [`Summary`]. Pure and idempotent: reads
/// everything, writes nothing, ignores `summary.alerts`.
pub fn derive_alerts(summary: &Summary) -> Vec<Alert> {
    let findings = &summary.findings;
    if findings.is_empty() {
        return Vec::new();
    }
    let n = findings.len();

    // Actor host -> ascending finding indices. Total: every finding appears exactly once.
    let mut host_findings: BTreeMap<&str, Vec<u32>> = BTreeMap::new();
    for (i, f) in findings.iter().enumerate() {
        host_findings
            .entry(f.src_ip.as_str())
            .or_default()
            .push(i as u32);
    }

    let mut claimed = vec![false; n];
    let mut alerts: Vec<Alert> = Vec::new();

    // Tier 1 — chain alerts. `attack_chains` is already sorted worst-first and its chains
    // have disjoint host sets (single-parent forest), so claiming by host is total and
    // cap-proof (MAX_STEPS_PER_HOST can evict step refs; `chain.hosts` cannot lie).
    // Only CROSS-HOST chains qualify: reconstruction emits a chain for every actor host, so a
    // single-host chain — even multi-tactic — is its incident re-wrapped (the incident already
    // carries the multi-stage escalation and narrative); letting `tactic_count >= 2` qualify
    // would also dress two weak posture kinds on one host up as a "chain" and dodge the
    // hygiene rollup.
    let mut chain_hosts_all: BTreeSet<&str> = BTreeSet::new();
    for chain in &summary.attack_chains {
        if chain.host_count < 2 {
            continue;
        }
        let step_set: BTreeSet<u32> = chain.steps.iter().map(|s| s.finding_index).collect();
        let mut members: Vec<u32> = Vec::new();
        for h in &chain.hosts {
            chain_hosts_all.insert(h.as_str());
            let Some(idxs) = host_findings.get(h.as_str()) else {
                continue;
            };
            for &i in idxs {
                if claimed[i as usize] {
                    continue;
                }
                let f = &findings[i as usize];
                // An unrelated strong story on a pivot host is NOT this chain's to tell —
                // tier 2 extracts it. Steps evicted by the per-host cap are the host's
                // LOWEST-ranked findings; weak evictees stay covered here, while strong
                // evictees (possible when >64 High findings share a host) become tier-2
                // standalone alerts and, at flood scale, fold into the bounded overflow
                // rollup rather than voiding the queue cap.
                if standalone_eligible(f) && !step_set.contains(&i) {
                    continue;
                }
                claimed[i as usize] = true;
                members.push(i);
            }
        }
        if members.is_empty() {
            continue;
        }
        members.sort_unstable();
        alerts.push(assemble(
            Seed {
                source: AlertSource::Chain,
                id_key: format!("chain:{}", chain.id),
                base: chain.score as i32,
                base_label: "base: attack-chain score",
                severity: chain.severity,
                title: chain.title.clone(),
                narrative: chain.narrative.clone(),
                actor: chain.hosts.first().cloned().unwrap_or_default(),
                hosts: chain.hosts.clone(),
                host_count: chain.host_count,
                chain_id: Some(chain.id.clone()),
                incident_hosts: chain.hosts.clone(),
                chain_confidence: Some(chain.confidence),
                members,
            },
            summary,
        ));
    }

    // Tier 2 — standalone strong findings extracted from qualifying-chain hosts. The per-key
    // ordinal keeps ids collision-free even for repeated same-key findings (e.g. several
    // RuleMatch rules firing on one flow).
    let mut key_ordinals: BTreeMap<String, u32> = BTreeMap::new();
    for i in 0..n {
        if claimed[i] {
            continue;
        }
        let f = &findings[i];
        if !standalone_eligible(f) || !chain_hosts_all.contains(f.src_ip.as_str()) {
            continue;
        }
        claimed[i] = true;
        let key = format!(
            "finding:{}:{}:{}:{}",
            f.kind.as_str(),
            f.src_ip,
            f.dst_ip.as_deref().unwrap_or("-"),
            f.dst_port
                .map_or_else(|| "-".to_string(), |p| p.to_string()),
        );
        let ordinal = key_ordinals.entry(key.clone()).or_insert(0);
        let id_key = format!("{key}:{ordinal}");
        *ordinal += 1;
        alerts.push(assemble(
            Seed {
                source: AlertSource::Finding,
                id_key,
                base: f.score as i32,
                base_label: "base: finding score",
                severity: f.severity,
                title: f.title.clone(),
                narrative: f.title.clone(),
                actor: f.src_ip.clone(),
                hosts: vec![f.src_ip.clone()],
                host_count: 1,
                chain_id: None,
                incident_hosts: Vec::new(),
                chain_confidence: None,
                members: vec![i as u32],
            },
            summary,
        ));
    }

    // Tier 3 — host alerts: every non-chain host whose remaining findings are not weak-only
    // claims ALL of them (a weak finding on an implicated host corroborates the host's story
    // — it can never be buried in a fleet-wide rollup).
    for (host, idxs) in &host_findings {
        let rem: Vec<u32> = idxs
            .iter()
            .copied()
            .filter(|&i| !claimed[i as usize])
            .collect();
        if rem.is_empty() {
            continue;
        }
        let weak_only = rem.iter().all(|&i| {
            let f = &findings[i as usize];
            is_weak_kind(f.kind) && f.severity <= Severity::Medium
        });
        if weak_only {
            continue; // tier 4's
        }
        for &i in &rem {
            claimed[i as usize] = true;
        }
        // One Incident exists per actor host; fall back to the worst member defensively.
        let incident = summary.incidents.iter().find(|inc| inc.host == **host);
        let (base, base_label, severity, title, narrative) = match incident {
            Some(inc) => (
                inc.score as i32,
                "base: incident score",
                inc.severity,
                inc.title.clone(),
                inc.narrative.clone(),
            ),
            None => {
                let worst = rem
                    .iter()
                    .map(|&i| &findings[i as usize])
                    .max_by_key(|f| (f.score, f.severity))
                    .expect("rem is non-empty");
                (
                    worst.score as i32,
                    "base: worst member finding score",
                    worst.severity,
                    worst.title.clone(),
                    worst.title.clone(),
                )
            }
        };
        alerts.push(assemble(
            Seed {
                source: AlertSource::Host,
                id_key: format!("host:{host}"),
                base,
                base_label,
                severity,
                title,
                narrative,
                actor: (*host).to_string(),
                hosts: vec![(*host).to_string()],
                host_count: 1,
                chain_id: None,
                incident_hosts: vec![(*host).to_string()],
                chain_confidence: None,
                members: rem,
            },
            summary,
        ));
    }

    // Tier 4 — per-kind hygiene rollups over what remains (all on weak-only hosts).
    let mut by_kind: BTreeMap<FindingKind, Vec<u32>> = BTreeMap::new();
    for i in 0..n {
        if !claimed[i] {
            by_kind.entry(findings[i].kind).or_default().push(i as u32);
        }
    }
    for (kind, idxs) in by_kind {
        let hosts: Vec<String> = idxs
            .iter()
            .map(|&i| findings[i as usize].src_ip.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let host_count = hosts.len() as u32;
        let worst = idxs
            .iter()
            .map(|&i| &findings[i as usize])
            .max_by_key(|f| (f.score, f.severity))
            .expect("group is non-empty");
        let label = crate::report::kind_label(kind);
        let title = format!(
            "{label}: {host_count} host{} ({} finding{})",
            if host_count == 1 { "" } else { "s" },
            idxs.len(),
            if idxs.len() == 1 { "" } else { "s" },
        );
        let narrative = format!(
            "{host_count} host{} {}.",
            if host_count == 1 { "" } else { "s" },
            kind_phrase(kind),
        );
        alerts.push(assemble(
            Seed {
                source: AlertSource::Rollup,
                id_key: format!("rollup:{}", kind.as_str()),
                base: worst.score as i32,
                base_label: "base: worst member finding score",
                severity: worst.severity,
                title,
                narrative,
                actor: hosts.first().cloned().unwrap_or_default(),
                hosts,
                host_count,
                chain_id: None,
                incident_hosts: Vec::new(),
                chain_confidence: None,
                members: idxs,
            },
            summary,
        ));
    }

    // Rank: strict total order (ids are unique by construction, so the sort is strict).
    sort_queue(&mut alerts);
    truncate_with_overflow(alerts, summary)
}

/// The queue's total order: priority desc, severity desc, tier asc, first-seen asc
/// (None last), id asc.
fn sort_queue(alerts: &mut [Alert]) {
    alerts.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then(b.severity.rank().cmp(&a.severity.rank()))
            .then(a.source.tier().cmp(&b.source.tier()))
            .then(match (a.first_seen_ns, b.first_seen_ns) {
                (Some(x), Some(y)) => x.cmp(&y),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            })
            .then_with(|| a.id.cmp(&b.id))
    });
}

/// A row that must survive both the dampen terms and the emission cap: confirmed-bad or
/// safety-relevant evidence, and multi-host chains (the headline the feature exists for).
fn never_dampen(
    severity: Severity,
    source: AlertSource,
    host_count: u32,
    member_kinds: &BTreeSet<FindingKind>,
    ioc_backed: bool,
    rep_malicious: bool,
) -> bool {
    severity == Severity::Critical
        || member_kinds.iter().any(|k| {
            matches!(
                k,
                FindingKind::MalwareDownload
                    | FindingKind::MalwareSignature
                    | FindingKind::IcsControlCommand
            )
        })
        || ioc_backed
        || rep_malicious
        || (matches!(source, AlertSource::Chain) && host_count >= 2)
}

// ---- Assembly -------------------------------------------------------------------------

/// Per-tier inputs to [`assemble`].
struct Seed {
    source: AlertSource,
    /// Pre-hash id key (tier-prefixed, unique within its namespace).
    id_key: String,
    /// The existing story score — never re-derived (double-count guard).
    base: i32,
    base_label: &'static str,
    severity: Severity,
    title: String,
    narrative: String,
    actor: String,
    hosts: Vec<String>,
    host_count: u32,
    chain_id: Option<String>,
    incident_hosts: Vec<String>,
    /// `Some` for chain alerts (copied verbatim into `confidence`).
    chain_confidence: Option<u8>,
    /// Ascending member indices into `summary.findings`.
    members: Vec<u32>,
}

/// Build one [`Alert`] from a [`Seed`]: member rollups, corroboration lookup, the priority
/// ledger, confidence, context bundle, and the action line.
fn assemble(seed: Seed, summary: &Summary) -> Alert {
    let findings = &summary.findings;
    let members: Vec<&Finding> = seed
        .members
        .iter()
        .map(|&i| &findings[i as usize])
        .collect();

    // Member rollups.
    let member_kinds: BTreeSet<FindingKind> = members.iter().map(|f| f.kind).collect();
    let has_dev = member_kinds.contains(&FindingKind::BaselineDeviation);
    let has_anom = member_kinds.contains(&FindingKind::TrafficAnomaly);
    let all_untimed = members.iter().all(|f| f.first_seen_ns.is_none());
    let first_seen_ns = members.iter().filter_map(|f| f.first_seen_ns).min();
    let last_seen_ns = members.iter().filter_map(|f| f.last_seen_ns).max();

    // Distinct member destinations, ascending (BTreeSet), with the lowest port seen per peer.
    let mut dst_ports: BTreeMap<&str, Option<u16>> = BTreeMap::new();
    for f in &members {
        if let Some(dst) = f.dst_ip.as_deref() {
            let slot = dst_ports.entry(dst).or_insert(f.dst_port);
            *slot = match (*slot, f.dst_port) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
    }

    // Implicated IPs (actor hosts ∪ member destinations) looked up in the threat cards.
    let mut implicated: BTreeSet<&str> = seed.hosts.iter().map(String::as_str).collect();
    implicated.extend(dst_ports.keys().copied());

    let malware_member = member_kinds.iter().any(|k| {
        matches!(
            k,
            FindingKind::MalwareDownload | FindingKind::MalwareSignature
        )
    });
    let ioc_ip = implicated
        .iter()
        .find(|ip| card_of(summary, ip).is_some_and(|c| c.ioc))
        .copied();
    let ioc_backed = ioc_ip.is_some() || malware_member;
    let rep_ip = implicated
        .iter()
        .find(|ip| rep_count_of(summary, ip) >= 1)
        .copied();
    let rep_consensus = implicated.iter().any(|ip| rep_count_of(summary, ip) >= 2);

    // External-peer attribution (for the cloud dampen + the peer list).
    let ext_peers: Vec<&str> = dst_ports
        .keys()
        .copied()
        .filter(|ip| {
            ip.parse::<IpAddr>()
                .map(|p| classify_ip(p).is_external())
                .unwrap_or(false)
        })
        .collect();
    let all_ext_cloud = !ext_peers.is_empty()
        && ext_peers.iter().all(|ip| {
            cloud_of(summary, ip).is_some()
                && !card_of(summary, ip).is_some_and(|c| c.ioc)
                && rep_count_of(summary, ip) == 0
        });

    let nd = never_dampen(
        seed.severity,
        seed.source,
        seed.host_count,
        &member_kinds,
        ioc_backed,
        rep_ip.is_some(),
    );

    // Confidence (chain alerts copy the chain's own figure).
    let confidence: u8 = match seed.chain_confidence {
        Some(c) => c,
        None => {
            let class_base: i32 = if malware_member {
                90
            } else if member_kinds.contains(&FindingKind::RuleMatch) {
                75
            } else if member_kinds.iter().all(|&k| is_weak_kind(k)) {
                50
            } else {
                70
            };
            let mut c = class_base + 5 * (member_kinds.len() as i32 - 1).min(2);
            if ioc_backed || rep_ip.is_some() {
                c += 10;
            }
            if all_untimed {
                c -= 10;
            }
            c.clamp(0, 100) as u8
        }
    };

    // ---- The priority ledger (Σ terms == priority, by construction) ----
    let mut terms: Vec<ScoreTerm> = Vec::new();
    let push = |terms: &mut Vec<ScoreTerm>, label: String, points: i32| {
        terms.push(ScoreTerm { label, points });
    };
    push(&mut terms, seed.base_label.to_string(), seed.base);
    let mut p: i32 = seed.base;

    let mut pos: i32 = 0;
    if let Some(ip) = ioc_ip {
        pos += PTS_ALERT_IOC;
        push(
            &mut terms,
            format!("corroborated: IOC feed hit on {ip}"),
            PTS_ALERT_IOC,
        );
    } else if malware_member {
        pos += PTS_ALERT_IOC;
        push(
            &mut terms,
            format!("corroborated: known-malicious file on {}", seed.actor),
            PTS_ALERT_IOC,
        );
    }
    if let Some(ip) = rep_ip {
        pos += PTS_ALERT_REP;
        push(
            &mut terms,
            format!("corroborated: reputation malicious on {ip}"),
            PTS_ALERT_REP,
        );
    }
    if has_dev {
        pos += PTS_ALERT_NOVEL;
        push(
            &mut terms,
            "novel: deviates from learned baseline".to_string(),
            PTS_ALERT_NOVEL,
        );
    }
    if has_anom {
        pos += PTS_ALERT_ANOM;
        push(
            &mut terms,
            "novel: own-forecast traffic anomaly".to_string(),
            PTS_ALERT_ANOM,
        );
    }
    let conf_adj = ((confidence as i32 - 60) / 4).clamp(-15, 10);
    if conf_adj > 0 {
        pos += conf_adj;
        push(&mut terms, format!("confidence: {confidence}%"), conf_adj);
    } else if conf_adj < 0 {
        p += conf_adj;
        push(&mut terms, format!("confidence: {confidence}%"), conf_adj);
    }
    if pos > ALERT_UPLIFT_CAP {
        push(
            &mut terms,
            format!("cap: uplift bounded at +{ALERT_UPLIFT_CAP}"),
            ALERT_UPLIFT_CAP - pos,
        );
        pos = ALERT_UPLIFT_CAP;
    }
    p += pos;

    if !nd {
        if all_ext_cloud {
            p += PTS_ALERT_CLOUD_PEER;
            push(
                &mut terms,
                "context: all external peers are known cloud infrastructure".to_string(),
                PTS_ALERT_CLOUD_PEER,
            );
        }
        if all_untimed {
            p += PTS_ALERT_UNTIMED;
            push(
                &mut terms,
                "context: no timestamps on any member".to_string(),
                PTS_ALERT_UNTIMED,
            );
        }
    }

    if ioc_backed && p < FLOOR_ALERT_IOC as i32 {
        push(
            &mut terms,
            format!("floor: IOC-backed forces the High band (>= {FLOOR_ALERT_IOC})"),
            FLOOR_ALERT_IOC as i32 - p,
        );
        p = FLOOR_ALERT_IOC as i32;
    }
    if rep_consensus && p < FLOOR_ALERT_REP_CONSENSUS as i32 {
        push(
            &mut terms,
            format!("floor: reputation consensus forces act-now (>= {FLOOR_ALERT_REP_CONSENSUS})"),
            FLOOR_ALERT_REP_CONSENSUS as i32 - p,
        );
        p = FLOOR_ALERT_REP_CONSENSUS as i32;
    }
    if seed.base < FLOOR_ALERT_IOC as i32
        && !ioc_backed
        && rep_ip.is_none()
        && p > CAP_UNCORROBORATED as i32
    {
        push(
            &mut terms,
            format!("cap: uncorroborated story stays below High (<= {CAP_UNCORROBORATED})"),
            CAP_UNCORROBORATED as i32 - p,
        );
        p = CAP_UNCORROBORATED as i32;
    }
    if p > 100 {
        push(&mut terms, format!("clamp: raw {p} -> 100"), 100 - p);
        p = 100;
    } else if p < 0 {
        push(&mut terms, format!("clamp: raw {p} -> 0"), -p);
        p = 0;
    }
    let priority = p as u16;

    // Kill-chain position (member-derived, uniform across tiers).
    let rep_stage = members
        .iter()
        .enumerate()
        .max_by_key(|(i, f)| (stage_ordinal(f.kind), f.score, std::cmp::Reverse(*i)))
        .map(|(_, f)| *f)
        .expect("members is non-empty");
    let stage_ord = stage_ordinal(rep_stage.kind);
    let stage = stage_label(rep_stage.kind).to_string();
    // "Next expected" only makes sense when the stage token sits on the canonical ladder:
    // RuleMatch's label is "Signature Match" (ordinal 4 but not a ladder rung), and predicting
    // "Exfiltration" after a mere imported-signature hit would overstate the evidence.
    let next_stage = if stage == STAGE_LABELS[stage_ord as usize]
        && (stage_ord as usize) < STAGE_LABELS.len() - 1
    {
        Some(STAGE_LABELS[stage_ord as usize + 1].to_string())
    } else {
        None
    };

    // ATT&CK ids in story order, deduped preserving first occurrence.
    let mut attack: Vec<String> = Vec::new();
    for f in &members {
        for id in &f.attack {
            if !attack.contains(id) {
                attack.push(id.clone());
            }
        }
    }

    // Primary peer: the story names exactly one distinct destination AND it is external —
    // the field's contract is "C2 / drop", so an internal victim never publishes here
    // (action_for falls back to the representative finding's dst for internal stories).
    let peer = if dst_ports.len() == 1 && ext_peers.len() == 1 {
        ext_peers.first().map(|s| s.to_string())
    } else {
        None
    };
    let peer_port = peer
        .as_deref()
        .and_then(|ip| dst_ports.get(ip).copied().flatten());

    // Action: keyed on the furthest-stage strongest member, and attributed to the host that
    // PERFORMED that step — on a multi-host chain the machine to isolate is the pivot host
    // doing the beacon/exfil, not the chain root the alert is filed under.
    let action = action_for(rep_stage, peer.as_deref(), peer_port, &rep_stage.src_ip);

    let context = build_context(
        &seed,
        summary,
        &members,
        &dst_ports,
        &ext_peers,
        next_stage.as_deref(),
    );

    let mut hosts = seed.hosts;
    hosts.truncate(MAX_ALERT_HOSTS);
    let mut incident_hosts = seed.incident_hosts;
    incident_hosts.truncate(MAX_ALERT_HOSTS);

    Alert {
        id: format!("alert:{:016x}", fnv1a64(seed.id_key.as_bytes())),
        source: seed.source,
        band: PriorityBand::from_priority(priority),
        priority,
        confidence,
        severity: seed.severity,
        title: seed.title,
        narrative: seed.narrative,
        action,
        actor: seed.actor,
        hosts,
        host_count: seed.host_count,
        peer,
        attack,
        stage,
        stage_ordinal: stage_ord,
        next_stage,
        priority_terms: terms,
        context,
        finding_count: seed.members.len() as u32,
        finding_indices: seed.members,
        chain_id: seed.chain_id,
        incident_hosts,
        first_seen_ns,
        last_seen_ns,
    }
}

/// Deterministic recommended next step, keyed on the representative member finding.
fn action_for(f: &Finding, peer: Option<&str>, port: Option<u16>, actor: &str) -> String {
    let peer_disp = peer
        .map(|p| match port {
            Some(pt) => format!("{p}:{pt}"),
            None => p.to_string(),
        })
        .or_else(|| f.dst_ip.clone())
        .unwrap_or_else(|| "the destination".to_string());
    match f.kind {
        FindingKind::Beacon => {
            format!("Isolate {actor}; block {peer_disp} at the egress firewall")
        }
        FindingKind::DataExfil => {
            format!("Isolate {actor}; determine what data left toward {peer_disp}")
        }
        FindingKind::DnsTunnel | FindingKind::Dga => {
            format!("Block the resolver path and capture DNS logs from {actor}")
        }
        FindingKind::IcmpTunnel => {
            format!("Isolate {actor}; inspect the ICMP channel toward {peer_disp}")
        }
        FindingKind::HostSweep | FindingKind::PortScan => {
            format!("Identify the scan source {actor}; verify it is an authorized scanner")
        }
        FindingKind::BruteForce => {
            format!("Lock the targeted accounts on {peer_disp}; review authentication logs")
        }
        FindingKind::CleartextCreds => {
            "Rotate the exposed credentials; move the service to TLS".to_string()
        }
        FindingKind::PiiExposure => {
            "Identify the PII flow and move it to an encrypted channel".to_string()
        }
        FindingKind::LateralMovement => {
            format!("Contain {actor}; audit the admin sessions it opened")
        }
        FindingKind::RuleMatch => {
            "Review the matched signature rule and the flow it fired on".to_string()
        }
        FindingKind::TlsCertHealth | FindingKind::WeakTls => {
            "Schedule TLS configuration remediation on the listed hosts".to_string()
        }
        FindingKind::ArpSpoof => {
            format!("Locate the spoofing host near {actor}; check switch port security")
        }
        FindingKind::SynFlood => {
            format!("Rate-limit or filter the flood source toward {peer_disp}")
        }
        FindingKind::SuspiciousUa => {
            format!("Verify the attack-tool traffic from {actor} is authorized testing")
        }
        FindingKind::DisguisedDownload
        | FindingKind::MalwareDownload
        | FindingKind::MalwareSignature => {
            format!("Quarantine {actor}; hunt the file hash across the fleet")
        }
        FindingKind::Cryptomining => {
            format!("Terminate the miner on {actor}; block the pool at {peer_disp}")
        }
        FindingKind::ExposedRemoteAccess => {
            "Close the exposed remote-access path or gate it behind a VPN".to_string()
        }
        FindingKind::IcsControlCommand => {
            format!("Verify {actor} is an authorized HMI/engineering workstation now")
        }
        FindingKind::BaselineDeviation => {
            format!("Review {actor}'s first-seen behavior against expected change activity")
        }
        FindingKind::TrafficAnomaly => {
            format!("Compare {actor}'s traffic window against scheduled jobs and backups")
        }
    }
}

/// Threat-card lookup for an implicated IP (ip_threats is bounded to the top-k rows).
fn card_of<'a>(summary: &'a Summary, ip: &str) -> Option<&'a IpThreat> {
    summary.ip_threats.iter().find(|c| c.ip == ip)
}

/// Count of `Malicious` reputation verdicts on an IP's card (0 when the pass never ran).
fn rep_count_of(summary: &Summary, ip: &str) -> u8 {
    card_of(summary, ip).map_or(0, |c| {
        c.reputation
            .iter()
            .filter(|v| v.status == RepStatus::Malicious)
            .count()
            .min(u8::MAX as usize) as u8
    })
}

/// Cloud-provider attribution: the card's `cloud:` tag if present, else the static table.
fn cloud_of(summary: &Summary, ip: &str) -> Option<String> {
    if let Some(c) = card_of(summary, ip) {
        if let Some(tag) = c.tags.iter().find(|t| t.starts_with("cloud:")) {
            return Some(tag.trim_start_matches("cloud:").to_string());
        }
    }
    ip.parse::<IpAddr>()
        .ok()
        .and_then(cloud_provider)
        .map(str::to_string)
}

/// Build the context bundle: actor identity, peers of interest, and the typed fact list —
/// all joined from rollups the Summary already carries.
fn build_context(
    seed: &Seed,
    summary: &Summary,
    members: &[&Finding],
    dst_ports: &BTreeMap<&str, Option<u16>>,
    ext_peers: &[&str],
    next_stage: Option<&str>,
) -> AlertContext {
    let findings = &summary.findings;
    // The actor's flag is actor-scoped: on a multi-host chain a pivot host's deviation must
    // not stamp the chain root (the alert-wide novelty term stays alert-level in the ledger;
    // the BaselineNovelty entry carries the deviating host's own IP).
    let actor_new_to_baseline = members
        .iter()
        .any(|f| f.kind == FindingKind::BaselineDeviation && f.src_ip == seed.actor);

    // Actor identity: arp_hosts (ip -> mac) ⋈ dhcp_hosts (mac -> hostname/vendor).
    let mac = summary
        .arp_hosts
        .iter()
        .find(|a| a.ip == seed.actor)
        .map(|a| a.mac.clone());
    let dhcp = mac
        .as_deref()
        .and_then(|m| summary.dhcp_hosts.iter().find(|d| d.mac == m));
    let actor_internal = seed
        .actor
        .parse::<IpAddr>()
        .map(|ip| !classify_ip(ip).is_external())
        .unwrap_or(false);
    let actor = HostContext {
        ip: seed.actor.clone(),
        hostname: dhcp.and_then(|d| d.hostname.clone()),
        mac,
        vendor: dhcp.and_then(|d| d.vendor_class.clone()),
        internal: actor_internal,
        cloud: cloud_of(summary, &seed.actor),
        new_to_baseline: actor_new_to_baseline,
    };

    // Peers of interest: external member destinations, worst-first, capped.
    let mut peers: Vec<PeerContext> = ext_peers
        .iter()
        .map(|&ip| PeerContext {
            ip: ip.to_string(),
            domain: summary
                .resolved_ips
                .iter()
                .find(|r| r.ip == ip)
                .map(|r| r.domain.clone()),
            cloud: cloud_of(summary, ip),
            ioc: card_of(summary, ip).is_some_and(|c| c.ioc),
            reputation_malicious: rep_count_of(summary, ip),
            dst_port: dst_ports.get(ip).copied().flatten(),
        })
        .collect();
    peers.sort_by(|a, b| {
        b.ioc
            .cmp(&a.ioc)
            .then(b.reputation_malicious.cmp(&a.reputation_malicious))
            .then_with(|| {
                let score = |p: &PeerContext| card_of(summary, &p.ip).map_or(0, |c| c.score);
                score(b).cmp(&score(a))
            })
            .then_with(|| a.ip.cmp(&b.ip))
    });
    peers.truncate(MAX_ALERT_PEERS);

    // Typed fact entries.
    let mut entries: Vec<ContextEntry> = Vec::new();
    let mut entry = |kind: ContextKind, text: String, fi: Option<u32>, ip: Option<String>| {
        entries.push(ContextEntry {
            kind,
            text,
            finding_index: fi,
            ip,
        });
    };

    if actor.hostname.is_some() || actor.mac.is_some() {
        let name = actor.hostname.as_deref().unwrap_or("unknown-host");
        let vendor = actor
            .vendor
            .as_deref()
            .map(|v| format!(" ({v})"))
            .unwrap_or_default();
        let mac_disp = actor
            .mac
            .as_deref()
            .map(|m| format!(" [{m}]"))
            .unwrap_or_default();
        entry(
            ContextKind::Identity,
            format!("identity: {} = {name}{vendor}{mac_disp}", seed.actor),
            None,
            Some(seed.actor.clone()),
        );
    }
    for p in &peers {
        if p.ioc {
            entry(
                ContextKind::ThreatIntel,
                format!("threat intel: {} matches the offline IOC feed", p.ip),
                None,
                Some(p.ip.clone()),
            );
        }
        if p.reputation_malicious > 0 {
            entry(
                ContextKind::Reputation,
                format!(
                    "reputation: {} flagged malicious by {} provider{}",
                    p.ip,
                    p.reputation_malicious,
                    if p.reputation_malicious == 1 { "" } else { "s" },
                ),
                None,
                Some(p.ip.clone()),
            );
        }
        if let Some(domain) = &p.domain {
            entry(
                ContextKind::PassiveDns,
                format!("passive dns: {} resolved from {domain}", p.ip),
                None,
                Some(p.ip.clone()),
            );
        }
        if let Some(cloud) = &p.cloud {
            entry(
                ContextKind::CloudProvider,
                format!(
                    "peer {} is {cloud} address space — common for benign SaaS",
                    p.ip
                ),
                None,
                Some(p.ip.clone()),
            );
        }
    }
    if let Some((idx, f)) = seed.members.iter().find_map(|&i| {
        let f = &findings[i as usize];
        (f.kind == FindingKind::BaselineDeviation).then_some((i, f))
    }) {
        let detail = f
            .evidence
            .first()
            .cloned()
            .unwrap_or_else(|| f.title.clone());
        entry(
            ContextKind::BaselineNovelty,
            format!("baseline: {detail}"),
            Some(idx),
            Some(f.src_ip.clone()),
        );
    }
    if let Some((idx, f)) = seed.members.iter().find_map(|&i| {
        let f = &findings[i as usize];
        (f.kind == FindingKind::TrafficAnomaly).then_some((i, f))
    }) {
        let detail = f
            .evidence
            .first()
            .cloned()
            .unwrap_or_else(|| f.title.clone());
        entry(
            ContextKind::ForecastAnomaly,
            format!("forecast: {detail}"),
            Some(idx),
            Some(f.src_ip.clone()),
        );
    }
    {
        // Distinct stage labels over members, in kill-chain order.
        let mut stages: Vec<(u8, &str)> = members
            .iter()
            .map(|f| (stage_ordinal(f.kind), stage_label(f.kind)))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        stages.dedup_by_key(|(_, l)| *l);
        let path: Vec<&str> = stages.iter().map(|(_, l)| *l).collect();
        let next = next_stage
            .map(|s| format!("; next expected: {s}"))
            .unwrap_or_default();
        entry(
            ContextKind::KillChain,
            format!("kill chain: {}{next}", path.join(" → ")),
            None,
            None,
        );
    }
    for c in summary
        .carved_files
        .iter()
        .filter(|c| {
            c.client == seed.actor
                || seed.hosts.contains(&c.client)
                || dst_ports.contains_key(c.server.as_str())
        })
        .take(2)
    {
        // Char-boundary-safe truncation: `sha256` is an arbitrary String after `ppcap alerts`
        // deserializes a hand-crafted summary — a byte-index slice could panic mid-character.
        let short: String = c.sha256.chars().take(12).collect();
        let verdict = if c.known_bad {
            "known-bad".to_string()
        } else if !c.signatures.is_empty() {
            c.signatures.join(", ")
        } else {
            "no signature match".to_string()
        };
        entry(
            ContextKind::CarvedFile,
            format!(
                "carved: {} byte file sha256 {short}… ({verdict}) from {}",
                c.size, c.server
            ),
            None,
            Some(c.server.clone()),
        );
    }
    if let Some(ed) = summary.encrypted_dns.iter().find(|e| e.host == seed.actor) {
        entry(
            ContextKind::EncryptedDns,
            format!(
                "visibility: {} resolves via {} — passive DNS is blind here",
                seed.actor, ed.resolver
            ),
            None,
            Some(seed.actor.clone()),
        );
    }

    entries.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.text.cmp(&b.text)));
    entries.dedup_by(|a, b| a.kind == b.kind && a.text == b.text);
    entries.truncate(MAX_CONTEXT_ENTRIES);

    AlertContext {
        actor,
        peers,
        entries,
    }
}

/// Enforce the emission bound without ever breaking coverage. Only [`never_dampen`]-class
/// rows (confirmed-bad / safety-relevant / multi-host-chain evidence — a set an adversary
/// cannot inflate with plain high-scoring decoys) are exempt from the positional cap; every
/// other dropped row folds into ONE overflow rollup that carries every dropped finding index
/// AND inherits the worst dropped row's priority/severity, so folded actionable rows keep
/// their rank visibility instead of sinking to the bottom. A bare `priority >= 60` is
/// deliberately NOT an exemption: a broad High Suricata rule matching ordinary traffic can
/// mint thousands of base-70 host alerts (`MAX_RULE_FINDINGS = 5000`), and an unbounded
/// exemption would let that flood void the queue bound the feature exists to provide.
fn truncate_with_overflow(alerts: Vec<Alert>, summary: &Summary) -> Vec<Alert> {
    if alerts.len() <= MAX_ALERTS {
        return alerts;
    }
    let protected = |a: &Alert| -> bool {
        let member_kinds: BTreeSet<FindingKind> = a
            .finding_indices
            .iter()
            .map(|&i| summary.findings[i as usize].kind)
            .collect();
        never_dampen(
            a.severity,
            a.source,
            a.host_count,
            &member_kinds,
            a.context.peers.iter().any(|p| p.ioc),
            a.context.peers.iter().any(|p| p.reputation_malicious > 0),
        )
    };
    let mut kept: Vec<Alert> = Vec::new();
    let mut dropped: Vec<Alert> = Vec::new();
    for (pos, a) in alerts.into_iter().enumerate() {
        if pos < MAX_ALERTS - 1 || protected(&a) {
            kept.push(a);
        } else {
            dropped.push(a);
        }
    }
    if dropped.is_empty() {
        return kept;
    }

    // The overflow rollup: every dropped index retained, worst dropped row representative.
    let mut indices: Vec<u32> = dropped
        .iter()
        .flat_map(|a| a.finding_indices.iter().copied())
        .collect();
    indices.sort_unstable();
    let hosts_all: BTreeSet<&str> = dropped
        .iter()
        .flat_map(|a| a.hosts.iter().map(String::as_str))
        .collect();
    let host_count = hosts_all.len() as u32;
    let mut hosts: Vec<String> = hosts_all.into_iter().map(str::to_string).collect();
    hosts.truncate(MAX_ALERT_HOSTS);
    let worst = &dropped[0]; // dropped preserves queue order — the first is the worst
    let priority = worst.priority;
    let mut attack: Vec<String> = Vec::new();
    for a in &dropped {
        for id in &a.attack {
            if !attack.contains(id) {
                attack.push(id.clone());
            }
        }
    }
    let title = format!(
        "Overflow: {} alert{} covering {} finding{} (queue capped at {MAX_ALERTS})",
        dropped.len(),
        if dropped.len() == 1 { "" } else { "s" },
        indices.len(),
        if indices.len() == 1 { "" } else { "s" },
    );
    let overflow = Alert {
        id: format!("alert:{:016x}", fnv1a64(b"rollup:overflow")),
        source: AlertSource::Rollup,
        // Inherits the WORST dropped row's rank so folded actionable rows stay visible at
        // their level instead of sinking below the hygiene tail.
        band: PriorityBand::from_priority(priority),
        priority,
        confidence: worst.confidence,
        severity: worst.severity,
        title,
        narrative: format!(
            "{} ranked-below-the-cap alerts were folded into this overflow group to keep the \
             queue bounded; every member finding index is retained, and this row ranks at the \
             worst folded alert's priority.",
            dropped.len()
        ),
        action: "Review after the alerts above".to_string(),
        actor: worst.actor.clone(),
        hosts,
        host_count,
        peer: None,
        attack,
        stage: worst.stage.clone(),
        stage_ordinal: worst.stage_ordinal,
        next_stage: worst.next_stage.clone(),
        priority_terms: vec![ScoreTerm {
            label: "base: worst folded alert priority".to_string(),
            points: priority as i32,
        }],
        context: AlertContext {
            actor: worst.context.actor.clone(),
            peers: Vec::new(),
            entries: Vec::new(),
        },
        finding_count: indices.len() as u32,
        finding_indices: indices,
        chain_id: None,
        incident_hosts: Vec::new(),
        first_seen_ns: dropped.iter().filter_map(|a| a.first_seen_ns).min(),
        last_seen_ns: dropped.iter().filter_map(|a| a.last_seen_ns).max(),
    };
    kept.push(overflow);
    sort_queue(&mut kept);
    kept
}

#[cfg(test)]
mod tests {
    use super::super::{correlate_incidents, fold_rule_findings, reconstruct_attack_chains};
    use super::*;
    use crate::enrich::{IpClass, ReputationVerdict};

    /// Finding literal helper: severity derived from the score, timestamps optional.
    fn f(
        kind: FindingKind,
        score: u16,
        src: &str,
        dst: Option<&str>,
        port: Option<u16>,
        ts: Option<(i64, i64)>,
    ) -> Finding {
        Finding {
            kind,
            severity: Severity::from_score(score),
            score,
            title: format!("{}: {src}", kind.as_str()),
            src_ip: src.to_string(),
            dst_ip: dst.map(str::to_string),
            dst_port: port,
            attack: vec!["T1071".to_string()],
            evidence: vec![format!("{} evidence", kind.as_str())],
            interval_ns: None,
            jitter_cv: None,
            contacts: None,
            first_seen_ns: ts.map(|(a, _)| a),
            last_seen_ns: ts.map(|(_, b)| b),
            victims: match kind {
                // Give fan-out kinds their victims so chain pivots can form.
                FindingKind::HostSweep | FindingKind::LateralMovement => {
                    dst.map(|d| vec![d.to_string()]).unwrap_or_default()
                }
                _ => Vec::new(),
            },
        }
    }

    /// A threat card with just the fields the alert pass reads.
    fn card(ip: &str, ioc: bool, tags: Vec<&str>, malicious: usize) -> IpThreat {
        IpThreat {
            ip: ip.to_string(),
            ip_class: IpClass::Public,
            severity: Severity::Medium,
            score: 50,
            flows: 1,
            bytes: 1,
            ioc,
            tags: tags.into_iter().map(str::to_string).collect(),
            attack: Vec::new(),
            evidence: Vec::new(),
            reputation: (0..malicious)
                .map(|i| ReputationVerdict {
                    source: format!("provider{i}"),
                    status: RepStatus::Malicious,
                    malicious: true,
                    score: Some(99),
                    tags: Vec::new(),
                    link: None,
                    fetched_at: 0,
                })
                .collect(),
            fingerprints: Vec::new(),
            score_terms: Vec::new(),
        }
    }

    /// Build a finished Summary the way analyze does: findings + incidents + chains.
    fn mk_summary(findings: Vec<Finding>) -> Summary {
        let mut s = Summary::empty();
        s.incidents = correlate_incidents(&findings);
        s.attack_chains = reconstruct_attack_chains(&findings);
        s.findings = findings;
        s
    }

    /// The ACR worked example: sweep+brute on A pivoting to beacon+exfil on B — one chain.
    fn chain_findings() -> Vec<Finding> {
        const S: i64 = 1_000_000_000;
        vec![
            f(
                FindingKind::HostSweep,
                65,
                "10.0.0.5",
                Some("10.0.0.7"),
                None,
                Some((S, 2 * S)),
            ),
            f(
                FindingKind::BruteForce,
                70,
                "10.0.0.5",
                Some("10.0.0.7"),
                Some(22),
                Some((3 * S, 4 * S)),
            ),
            f(
                FindingKind::Beacon,
                70,
                "10.0.0.7",
                Some("45.77.13.37"),
                Some(443),
                Some((5 * S, 6 * S)),
            ),
            f(
                FindingKind::DataExfil,
                72,
                "10.0.0.7",
                Some("45.77.13.37"),
                Some(443),
                Some((7 * S, 8 * S)),
            ),
        ]
    }

    /// Coverage invariant: every finding index in exactly one alert.
    fn assert_coverage(summary: &Summary, alerts: &[Alert]) {
        let mut seen = vec![0usize; summary.findings.len()];
        for a in alerts {
            assert_eq!(
                a.finding_count as usize,
                a.finding_indices.len(),
                "finding_count mismatch on {}",
                a.id
            );
            for &i in &a.finding_indices {
                seen[i as usize] += 1;
            }
        }
        for (i, &count) in seen.iter().enumerate() {
            assert_eq!(count, 1, "finding {i} covered {count} times");
        }
    }

    #[test]
    fn empty_summary_yields_no_alerts() {
        assert!(derive_alerts(&Summary::empty()).is_empty());
    }

    #[test]
    fn chain_alert_covers_member_hosts_and_incidents() {
        let summary = mk_summary(chain_findings());
        assert_eq!(
            summary.attack_chains.len(),
            1,
            "fixture must form one chain"
        );
        let alerts = derive_alerts(&summary);
        assert_coverage(&summary, &alerts);
        assert_eq!(alerts.len(), 1, "one chain alert tells the whole story");
        let a = &alerts[0];
        assert_eq!(a.source, AlertSource::Chain);
        assert_eq!(
            a.chain_id.as_deref(),
            Some(summary.attack_chains[0].id.as_str())
        );
        assert_eq!(a.hosts, vec!["10.0.0.5", "10.0.0.7"]);
        assert_eq!(a.incident_hosts, vec!["10.0.0.5", "10.0.0.7"]);
        assert_eq!(a.finding_count, 4);
        assert_eq!(a.stage, "Exfiltration");
        assert_eq!(a.next_stage.as_deref(), Some("Impact"));
        // Base is the chain's own score — never re-derived (double-count guard).
        assert_eq!(a.priority_terms[0].label, "base: attack-chain score");
        assert_eq!(
            a.priority_terms[0].points,
            summary.attack_chains[0].score as i32
        );
    }

    #[test]
    fn forty_findings_collapse_to_under_ten_alerts() {
        let mut findings = chain_findings();
        // 30 hygiene findings across 30 distinct quiet hosts (3 kinds x 10 hosts).
        for i in 0..10u8 {
            findings.push(f(
                FindingKind::WeakTls,
                30,
                &format!("10.1.0.{i}"),
                Some(&format!("10.9.0.{i}")),
                Some(443),
                None,
            ));
            findings.push(f(
                FindingKind::TlsCertHealth,
                35,
                &format!("10.2.0.{i}"),
                Some(&format!("10.9.1.{i}")),
                Some(443),
                None,
            ));
            findings.push(f(
                FindingKind::SuspiciousUa,
                30,
                &format!("10.3.0.{i}"),
                Some(&format!("10.9.2.{i}")),
                Some(80),
                None,
            ));
        }
        // One confirmed malware delivery on its own host.
        findings.push(f(
            FindingKind::MalwareDownload,
            85,
            "10.4.0.1",
            Some("45.77.13.38"),
            Some(80),
            None,
        ));
        let summary = mk_summary(findings);
        let alerts = derive_alerts(&summary);
        assert_coverage(&summary, &alerts);
        assert!(
            alerts.len() < 10,
            "expected <10 alerts, got {}: {:?}",
            alerts.len(),
            alerts.iter().map(|a| &a.title).collect::<Vec<_>>()
        );
        // The strongest story leads the queue.
        assert!(matches!(
            alerts[0].source,
            AlertSource::Chain | AlertSource::Host
        ));
        // The hygiene tail became per-kind rollups.
        assert!(alerts.iter().any(|a| a.source == AlertSource::Rollup));
    }

    #[test]
    fn unrelated_strong_finding_evicted_from_chain_steps_gets_own_alert() {
        // Simulate the MAX_STEPS_PER_HOST eviction: a strong RuleMatch on a chain host whose
        // step reference was dropped — the chain must not swallow it.
        let mut findings = chain_findings();
        findings.push(f(
            FindingKind::RuleMatch,
            75,
            "10.0.0.7",
            Some("45.77.13.40"),
            Some(8080),
            None,
        ));
        let mut summary = mk_summary(findings);
        let rule_idx = (summary.findings.len() - 1) as u32;
        for chain in &mut summary.attack_chains {
            chain.steps.retain(|s| s.finding_index != rule_idx);
        }
        let alerts = derive_alerts(&summary);
        assert_coverage(&summary, &alerts);
        let standalone = alerts
            .iter()
            .find(|a| a.source == AlertSource::Finding)
            .expect("the evicted RuleMatch gets its own alert");
        assert_eq!(standalone.finding_indices, vec![rule_idx]);
        assert_eq!(standalone.actor, "10.0.0.7");
    }

    #[test]
    fn lone_medium_beacon_is_a_host_alert_not_a_rollup() {
        let summary = mk_summary(vec![f(
            FindingKind::Beacon,
            45,
            "10.0.0.9",
            Some("45.77.13.37"),
            Some(443),
            None,
        )]);
        let alerts = derive_alerts(&summary);
        assert_eq!(alerts.len(), 1);
        assert_eq!(
            alerts[0].source,
            AlertSource::Host,
            "a beacon is never hygiene"
        );
    }

    #[test]
    fn weak_group_on_implicated_host_rides_host_alert() {
        // The anti-burying rule: weak_tls on a beaconing host corroborates the host's story.
        let findings = vec![
            f(
                FindingKind::Beacon,
                45,
                "10.0.0.9",
                Some("45.77.13.37"),
                Some(443),
                None,
            ),
            f(
                FindingKind::WeakTls,
                30,
                "10.0.0.9",
                Some("45.77.13.37"),
                Some(443),
                None,
            ),
            // Another host's weak_tls stays rollup-able.
            f(
                FindingKind::WeakTls,
                30,
                "10.1.0.1",
                Some("10.9.0.1"),
                Some(443),
                None,
            ),
        ];
        let summary = mk_summary(findings);
        let alerts = derive_alerts(&summary);
        assert_coverage(&summary, &alerts);
        let host_alert = alerts
            .iter()
            .find(|a| a.source == AlertSource::Host && a.actor == "10.0.0.9")
            .expect("beacon host gets a host alert");
        assert_eq!(
            host_alert.finding_indices,
            vec![0, 1],
            "weak_tls rides along"
        );
        let rollup = alerts
            .iter()
            .find(|a| a.source == AlertSource::Rollup)
            .expect("the quiet host's weak_tls still rolls up");
        assert_eq!(rollup.finding_indices, vec![2]);
    }

    #[test]
    fn uncorroborated_story_caps_below_high() {
        // Lone Medium beacon at the top of its band: base 59 + confidence uplift would cross
        // 60 — the uncorroborated cap holds it at 59 with a visible term. (Timestamped so the
        // untimed dampen stays out of the arithmetic.)
        let summary = mk_summary(vec![f(
            FindingKind::Beacon,
            59,
            "10.0.0.9",
            Some("45.77.13.37"),
            Some(443),
            Some((1_000_000_000, 2_000_000_000)),
        )]);
        let alerts = derive_alerts(&summary);
        assert_eq!(alerts[0].priority, CAP_UNCORROBORATED);
        assert_eq!(alerts[0].band, PriorityBand::Review);
        assert!(
            alerts[0]
                .priority_terms
                .iter()
                .any(|t| t.label.starts_with("cap: uncorroborated")),
            "cap term must be visible: {:?}",
            alerts[0].priority_terms
        );
    }

    #[test]
    fn ioc_floors_investigate_with_visible_term() {
        let mut summary = mk_summary(vec![f(
            FindingKind::Beacon,
            45,
            "10.0.0.9",
            Some("45.77.13.37"),
            Some(443),
            None,
        )]);
        summary.ip_threats = vec![card("45.77.13.37", true, vec!["public", "ioc"], 0)];
        let alerts = derive_alerts(&summary);
        assert!(alerts[0].priority >= FLOOR_ALERT_IOC);
        assert!(alerts[0]
            .priority_terms
            .iter()
            .any(|t| t.label.starts_with("corroborated: IOC feed hit")));
        assert!(alerts[0].context.peers.iter().any(|p| p.ioc));
    }

    #[test]
    fn reputation_consensus_floors_act_now() {
        let mut summary = mk_summary(vec![f(
            FindingKind::Beacon,
            45,
            "10.0.0.9",
            Some("45.77.13.37"),
            Some(443),
            None,
        )]);
        summary.ip_threats = vec![card("45.77.13.37", false, vec!["public"], 2)];
        let alerts = derive_alerts(&summary);
        assert!(alerts[0].priority >= FLOOR_ALERT_REP_CONSENSUS);
        assert_eq!(alerts[0].band, PriorityBand::ActNow);
        assert!(alerts[0]
            .priority_terms
            .iter()
            .any(|t| t.label.starts_with("floor: reputation consensus")));
    }

    #[test]
    fn cloud_peers_dampen_but_never_dampen_skips_terms() {
        // Uncorroborated beacon to a cloud-tagged peer: the dampen term appears.
        let mut summary = mk_summary(vec![f(
            FindingKind::Beacon,
            45,
            "10.0.0.9",
            Some("45.77.13.37"),
            Some(443),
            None,
        )]);
        summary.ip_threats = vec![card("45.77.13.37", false, vec!["public", "cloud:aws"], 0)];
        let dampened = derive_alerts(&summary);
        assert!(dampened[0]
            .priority_terms
            .iter()
            .any(|t| t.label.starts_with("context: all external peers")));

        // Same story, but the peer is an IOC: never_dampen — the term must never appear.
        summary.ip_threats = vec![card("45.77.13.37", true, vec!["public", "cloud:aws"], 0)];
        let protected = derive_alerts(&summary);
        assert!(
            !protected[0]
                .priority_terms
                .iter()
                .any(|t| t.label.starts_with("context: all external peers")),
            "dampen terms are skipped entirely under never_dampen, not applied-then-floored"
        );
        assert!(protected[0].priority > dampened[0].priority);
    }

    #[test]
    fn priority_terms_ledger_reproduces_priority() {
        let mut findings = chain_findings();
        findings.push(f(
            FindingKind::WeakTls,
            30,
            "10.1.0.1",
            Some("10.9.0.1"),
            Some(443),
            None,
        ));
        findings.push(f(
            FindingKind::BaselineDeviation,
            40,
            "10.0.0.7",
            Some("45.77.13.37"),
            Some(443),
            None,
        ));
        let mut summary = mk_summary(findings);
        summary.ip_threats = vec![card("45.77.13.37", true, vec!["public", "ioc"], 1)];
        let alerts = derive_alerts(&summary);
        assert_coverage(&summary, &alerts);
        for a in &alerts {
            let sum: i32 = a.priority_terms.iter().map(|t| t.points).sum();
            assert_eq!(
                sum, a.priority as i32,
                "ledger must reconcile for {}: {:?}",
                a.id, a.priority_terms
            );
        }
    }

    #[test]
    fn truncation_emits_overflow_rollup_and_keeps_coverage() {
        // 40 lone-beacon hosts -> 40 host alerts -> truncation folds the tail into one
        // overflow rollup; coverage stays exact and nothing actionable is lost.
        let findings: Vec<Finding> = (0..40u8)
            .map(|i| {
                f(
                    FindingKind::Beacon,
                    45,
                    &format!("10.0.{i}.9"),
                    Some(&format!("10.8.{i}.1")),
                    Some(443),
                    None,
                )
            })
            .collect();
        let summary = mk_summary(findings);
        let alerts = derive_alerts(&summary);
        assert_coverage(&summary, &alerts);
        assert!(alerts.len() <= MAX_ALERTS, "soft bound holds here");
        let overflow = alerts
            .iter()
            .find(|a| a.title.starts_with("Overflow:"))
            .expect("overflow rollup exists");
        assert!(overflow.finding_count >= 9, "the dropped tail is absorbed");
    }

    #[test]
    fn high_priority_decoy_flood_stays_bounded_with_visible_overflow() {
        // A broad High Suricata rule matching ordinary traffic can mint one base-70 host
        // alert per host (up to MAX_RULE_FINDINGS = 5000). None of them is never_dampen
        // (no IOC / malware / ICS / multi-host chain), so the positional cap must hold and
        // the folded actionable rows must keep their rank via the overflow's inherited
        // priority — the decoy-flood resistance the noise layer exists for.
        let findings: Vec<Finding> = (0..100u32)
            .map(|i| {
                f(
                    FindingKind::RuleMatch,
                    70,
                    &format!("10.{}.{}.9", i / 250, i % 250),
                    Some("45.77.13.40"),
                    Some(8080),
                    None,
                )
            })
            .collect();
        let summary = mk_summary(findings);
        let alerts = derive_alerts(&summary);
        assert_coverage(&summary, &alerts);
        assert!(
            alerts.len() <= MAX_ALERTS,
            "the queue bound holds under a High-score flood; got {}",
            alerts.len()
        );
        let overflow = alerts
            .iter()
            .find(|a| a.title.starts_with("Overflow:"))
            .expect("overflow rollup exists");
        assert!(
            overflow.priority >= 60,
            "the overflow inherits the worst folded row's actionable rank"
        );
    }

    #[test]
    fn non_ascii_sha256_in_carved_files_does_not_panic() {
        // `ppcap alerts` feeds arbitrary user JSON into derive_alerts; a carved-file hash
        // whose 12th byte falls mid-character must not panic the char-boundary slice.
        let mut summary = mk_summary(vec![f(
            FindingKind::Beacon,
            45,
            "10.0.0.9",
            Some("45.77.13.37"),
            Some(443),
            None,
        )]);
        summary.carved_files = vec![crate::model::summary::CarvedFile {
            client: "10.0.0.9".to_string(),
            server: "45.77.13.37".to_string(),
            sha256: "aaaaaaaaaaa\u{e9}".to_string(), // byte 12 is inside the 2-byte 'é'
            size: 1,
            known_bad: false,
            signatures: Vec::new(),
            extracted_path: None,
        }];
        let alerts = derive_alerts(&summary);
        assert!(alerts.iter().any(|a| a
            .context
            .entries
            .iter()
            .any(|e| e.kind == ContextKind::CarvedFile)));
    }

    #[test]
    fn chain_action_targets_the_representative_step_host() {
        // On a multi-host chain the machine to isolate is the pivot host performing the
        // furthest-stage step (10.0.0.7 doing the exfil), not the chain root (10.0.0.5).
        let summary = mk_summary(chain_findings());
        let alerts = derive_alerts(&summary);
        assert_eq!(alerts[0].source, AlertSource::Chain);
        assert_eq!(
            alerts[0].actor, "10.0.0.5",
            "the alert is filed under the root"
        );
        assert!(
            alerts[0].action.contains("10.0.0.7"),
            "the action names the acting host: {}",
            alerts[0].action
        );
        assert!(!alerts[0].action.contains("Isolate 10.0.0.5"));
    }

    #[test]
    fn rule_match_alert_publishes_no_next_stage() {
        // "Signature Match" (RuleMatch's stage label) is not on the canonical ladder, so
        // predicting "next expected: Exfiltration" from a mere signature hit is suppressed.
        let summary = mk_summary(vec![f(
            FindingKind::RuleMatch,
            70,
            "10.0.0.9",
            Some("45.77.13.37"),
            Some(8080),
            None,
        )]);
        let alerts = derive_alerts(&summary);
        assert_eq!(alerts[0].stage, "Signature Match");
        assert_eq!(alerts[0].next_stage, None);
        assert!(alerts[0]
            .context
            .entries
            .iter()
            .all(|e| !e.text.contains("next expected")));
    }

    #[test]
    fn internal_only_story_publishes_no_peer() {
        // `peer` is the "C2 / drop" contract — an internal victim must never publish there.
        let summary = mk_summary(vec![f(
            FindingKind::BruteForce,
            64,
            "10.0.0.5",
            Some("10.0.0.7"),
            Some(22),
            None,
        )]);
        let alerts = derive_alerts(&summary);
        assert_eq!(alerts[0].peer, None);
        // The action still names the internal target via the finding's own dst fallback.
        assert!(
            alerts[0].action.contains("10.0.0.7"),
            "{}",
            alerts[0].action
        );
    }

    #[test]
    fn pivot_host_deviation_does_not_stamp_the_chain_root() {
        // new_to_baseline is actor-scoped: a deviation on the pivot host (10.0.0.7) must not
        // flag the chain root (10.0.0.5) as new-to-baseline.
        let mut findings = chain_findings();
        findings.push(f(
            FindingKind::BaselineDeviation,
            40,
            "10.0.0.7",
            Some("45.77.13.37"),
            Some(443),
            None,
        ));
        let summary = mk_summary(findings);
        let alerts = derive_alerts(&summary);
        let chain_alert = alerts
            .iter()
            .find(|a| a.source == AlertSource::Chain)
            .expect("chain alert");
        assert_eq!(chain_alert.actor, "10.0.0.5");
        assert!(
            !chain_alert.context.actor.new_to_baseline,
            "the root did not deviate; the deviation belongs to 10.0.0.7"
        );
        // The alert-level novelty term still fires (it is legitimately alert-wide).
        assert!(chain_alert
            .priority_terms
            .iter()
            .any(|t| t.label.starts_with("novel: deviates")));
    }

    #[test]
    fn derive_alerts_is_deterministic_and_idempotent() {
        let mut summary = mk_summary(chain_findings());
        summary.ip_threats = vec![card("45.77.13.37", true, vec!["public", "ioc"], 0)];
        let a1 = derive_alerts(&summary);
        let a2 = derive_alerts(&summary);
        assert_eq!(a1, a2, "same input, same queue");
        // Idempotent: a summary that already carries alerts derives the same queue.
        summary.alerts = a1.clone();
        let a3 = derive_alerts(&summary);
        assert_eq!(a1, a3);
    }

    #[test]
    fn derive_alerts_is_stable_under_finding_permutation() {
        // Reversing the finding order changes indices but must not change the queue's
        // semantic content: same ids, same priorities, same member counts.
        let findings = {
            let mut v = chain_findings();
            v.push(f(
                FindingKind::WeakTls,
                30,
                "10.1.0.1",
                Some("10.9.0.1"),
                Some(443),
                None,
            ));
            v
        };
        let forward = mk_summary(findings.clone());
        let reversed = mk_summary(findings.into_iter().rev().collect());
        let fa = derive_alerts(&forward);
        let ra = derive_alerts(&reversed);
        let key = |alerts: &[Alert]| -> Vec<(String, u16, u32)> {
            alerts
                .iter()
                .map(|a| (a.id.clone(), a.priority, a.finding_count))
                .collect()
        };
        assert_eq!(key(&fa), key(&ra));
    }

    #[test]
    fn alerts_serde_roundtrip_and_default() {
        // A pre-alerting summary (no `alerts` key) still deserializes.
        let old = serde_json::to_value(Summary::empty()).map(|mut v| {
            v.as_object_mut().unwrap().remove("alerts");
            v
        });
        let s: Summary = serde_json::from_value(old.unwrap()).unwrap();
        assert!(s.alerts.is_empty());

        // A populated alert round-trips byte-stable.
        let mut summary = mk_summary(chain_findings());
        summary.alerts = derive_alerts(&summary);
        let json = serde_json::to_string(&summary).unwrap();
        let back: Summary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    #[test]
    fn fold_rule_findings_rederives_alerts() {
        let mut summary = mk_summary(chain_findings());
        summary.alerts = derive_alerts(&summary);
        let before = summary.alerts.clone();
        let rule = f(
            FindingKind::RuleMatch,
            60,
            "10.5.0.1",
            Some("45.77.13.39"),
            Some(8080),
            None,
        );
        fold_rule_findings(&mut summary, &[rule]);
        assert_ne!(summary.alerts, before, "the fold re-derives the queue");
        assert_coverage(&summary, &summary.alerts.clone());
        assert!(
            summary
                .alerts
                .iter()
                .any(|a| a.finding_indices.contains(&4)),
            "the folded rule finding is covered"
        );
    }

    #[test]
    fn hygiene_rollup_groups_per_kind_with_counts() {
        let findings: Vec<Finding> = (0..9u8)
            .map(|i| {
                f(
                    FindingKind::WeakTls,
                    30,
                    &format!("10.1.0.{i}"),
                    Some(&format!("10.9.0.{i}")),
                    Some(443),
                    None,
                )
            })
            .collect();
        let summary = mk_summary(findings);
        let alerts = derive_alerts(&summary);
        assert_eq!(alerts.len(), 1);
        let a = &alerts[0];
        assert_eq!(a.source, AlertSource::Rollup);
        assert_eq!(a.host_count, 9);
        assert_eq!(a.finding_count, 9);
        assert!(a.title.contains("9 hosts"), "title: {}", a.title);
        assert!(a.band <= PriorityBand::Review, "hygiene stays below High");
    }
}
