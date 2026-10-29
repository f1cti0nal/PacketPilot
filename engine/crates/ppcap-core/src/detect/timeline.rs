//! Incident timelines — one chronological, cross-host story per alert.
//!
//! [`derive_timelines`] is a **pure, idempotent** post-pass over the finished [`Summary`], run
//! right after the alert queue at every re-derive seam (see [`super::alerts::refresh_alerts`]).
//! For each alert it merges four sources into one time-ordered row list:
//!
//! - **detections** — every member finding, at its first activity;
//! - **lateral hops** — the attack chain's pivot edges whose two steps are both members;
//! - **context** — the first flow between the story's endpoints and the DNS answer that resolved
//!   each peer (from `Summary.timeline_context`, recorded by the streaming pass);
//! - **downloads** — carved files fetched by the story's hosts, with their SHA-256.
//!
//! Every row carries a [`PacketScope`] (host, optional peer and port, time window), so the packets
//! behind it are one carve away. Bounded (per-alert row cap, keeping detections and hops ahead of
//! context when it bites) and deterministic (strict total-order sort, BTree containers, no clock).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::model::alert::Alert;
use crate::model::attack_chain::{AttackChain, EdgeKind};
use crate::model::finding::Finding;
use crate::model::severity::Severity;
use crate::model::summary::{CarvedFile, Summary};
use crate::model::timeline::{
    AlertTimeline, DnsAnswer, FirstContact, PacketScope, TimelineEvent, TimelineEventKind,
};

use super::{human_bytes, kind_phrase, stage_label};

/// Rows kept per timeline (`event_count` keeps the total).
pub const MAX_TIMELINE_EVENTS: usize = 200;
/// Endpoint pairs per alert considered for first-contact / DNS rows.
const MAX_CONTEXT_PAIRS: usize = 64;
/// Victims per fan-out finding considered for first-contact rows.
const MAX_VICTIMS: usize = 16;
/// Carved files per alert.
const MAX_DOWNLOADS: usize = 32;
/// Packet window after a first contact / DNS answer (the row has an instant, not a span).
const INSTANT_WINDOW_NS: i64 = 10_000_000_000;
/// Hex digits of a SHA-256 shown in a row title (the detail carries the full hash).
const HASH_PREFIX: usize = 12;

/// Derive one timeline per alert, in queue order.
pub fn derive_timelines(summary: &Summary) -> Vec<AlertTimeline> {
    let ctx = Index::new(summary);
    summary
        .alerts
        .iter()
        .map(|a| timeline_for(a, summary, &ctx))
        .collect()
}

/// Lookups shared by every alert's timeline.
struct Index<'a> {
    /// `(receiving client, ip)` → answer; a clientless answer (hand-edited JSON) keys on `""`.
    dns: BTreeMap<(&'a str, &'a str), &'a DnsAnswer>,
    /// Unordered `(min, max)` endpoint pair → first contact.
    contacts: BTreeMap<(&'a str, &'a str), &'a FirstContact>,
    chains: BTreeMap<&'a str, &'a AttackChain>,
    /// Whole-capture window, for rows with no timestamp of their own.
    capture: (i64, i64),
}

impl<'a> Index<'a> {
    fn new(s: &'a Summary) -> Index<'a> {
        let c = &s.timeline_context;
        Index {
            dns: c
                .dns_answers
                .iter()
                .map(|d| ((d.client.as_deref().unwrap_or(""), d.ip.as_str()), d))
                .collect(),
            contacts: c
                .first_contacts
                .iter()
                .map(|fc| (pair(&fc.initiator, &fc.responder), fc))
                .collect(),
            chains: s.attack_chains.iter().map(|c| (c.id.as_str(), c)).collect(),
            capture: (s.capture_start_ns(), s.capture_end_ns()),
        }
    }
}

fn pair<'a>(a: &'a str, b: &'a str) -> (&'a str, &'a str) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

fn is_ip(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
}

/// A packet scope for `host` (+ `peer`, + `port`) over `[start, end]`, or `None` when `host` is
/// not an IP address. A non-IP peer is dropped rather than failing the whole scope.
fn scope(
    host: &str,
    peer: Option<&str>,
    port: Option<u16>,
    start: i64,
    end: i64,
) -> Option<PacketScope> {
    if !is_ip(host) {
        return None;
    }
    Some(PacketScope {
        host: host.to_string(),
        peer: peer.filter(|p| is_ip(p)).map(str::to_string),
        port,
        start_ns: start.min(end),
        end_ns: start.max(end),
    })
}

/// The first `n` characters of `s` (char-safe: hashes come from user-editable JSON).
fn prefix(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

fn timeline_for(alert: &Alert, s: &Summary, ix: &Index<'_>) -> AlertTimeline {
    let members: Vec<(u32, &Finding)> = alert
        .finding_indices
        .iter()
        .filter_map(|&i| s.findings.get(i as usize).map(|f| (i, f)))
        .collect();
    let member_set: BTreeSet<u32> = members.iter().map(|(i, _)| *i).collect();

    let mut events: Vec<TimelineEvent> = Vec::new();
    // Every endpoint the story touches.
    let mut endpoints: BTreeSet<&str> = BTreeSet::new();
    // (actor, peer) pairs in member order, deduped, capped.
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    let mut seen_pairs: BTreeSet<(&str, &str)> = BTreeSet::new();

    for &(idx, f) in &members {
        endpoints.insert(f.src_ip.as_str());
        events.push(detection_event(idx, f, ix.capture));
        for peer in f.dst_ip.iter().chain(f.victims.iter().take(MAX_VICTIMS)) {
            endpoints.insert(peer.as_str());
            if peer == &f.src_ip || pairs.len() >= MAX_CONTEXT_PAIRS {
                continue;
            }
            if seen_pairs.insert(pair(&f.src_ip, peer)) {
                pairs.push((f.src_ip.as_str(), peer.as_str()));
            }
        }
    }

    // Lateral hops from the chain's pivot edges (both ends must belong to this alert — a chain
    // host's standalone finding may have been extracted into its own alert).
    if let Some(chain) = alert.chain_id.as_deref().and_then(|id| ix.chains.get(id)) {
        for e in chain.edges.iter().filter(|e| e.kind == EdgeKind::Pivot) {
            let (Some(from), Some(to)) = (
                chain.steps.get(e.from as usize),
                chain.steps.get(e.to as usize),
            ) else {
                continue;
            };
            if !member_set.contains(&from.finding_index) || !member_set.contains(&to.finding_index)
            {
                continue;
            }
            let ts = to.first_seen_ns.or(from.last_seen_ns);
            let start = from.first_seen_ns.or(ts).unwrap_or(ix.capture.0);
            let end = ts.unwrap_or(ix.capture.1);
            let after = e
                .via_kind
                .map(|k| format!(" after {} {}", from.actor, kind_phrase(k)))
                .unwrap_or_default();
            events.push(TimelineEvent {
                ts_ns: ts,
                end_ns: None,
                kind: TimelineEventKind::Pivot,
                host: to.actor.clone(),
                peer: Some(from.actor.clone()),
                dst_port: None,
                title: format!("Lateral hop {} → {}{after}", from.actor, to.actor),
                detail: from.evidence.clone(),
                severity: from.severity.max(to.severity),
                tactic: Some("Lateral Movement".to_string()),
                attack: Vec::new(),
                finding_index: Some(to.finding_index),
                packets: scope(&to.actor, Some(&from.actor), None, start, end),
            });
        }
    }

    // First contact between each (actor, peer) pair.
    for &(a, b) in &pairs {
        let Some(fc) = ix.contacts.get(&pair(a, b)) else {
            continue;
        };
        let to = match fc.port {
            Some(p) => format!("{}:{p}", fc.responder),
            None => fc.responder.clone(),
        };
        events.push(TimelineEvent {
            ts_ns: Some(fc.first_seen_ns),
            end_ns: None,
            kind: TimelineEventKind::FirstContact,
            host: fc.initiator.clone(),
            peer: Some(fc.responder.clone()),
            dst_port: fc.port,
            title: format!("First contact {} → {to}", fc.initiator),
            detail: None,
            severity: Severity::Info,
            tactic: None,
            attack: Vec::new(),
            finding_index: None,
            packets: scope(
                &fc.initiator,
                Some(&fc.responder),
                fc.port,
                fc.first_seen_ns,
                fc.first_seen_ns.saturating_add(INSTANT_WINDOW_NS),
            ),
        });
    }

    // The DNS answer each actor itself received for its peer (never another host's lookup).
    for &(actor, peer) in &pairs {
        let Some(d) = ix
            .dns
            .get(&(actor, peer))
            .or_else(|| ix.dns.get(&("", peer)))
        else {
            continue;
        };
        let host = actor;
        events.push(TimelineEvent {
            ts_ns: Some(d.first_seen_ns),
            end_ns: None,
            kind: TimelineEventKind::DnsAnswer,
            host: host.to_string(),
            peer: Some(d.ip.clone()),
            dst_port: None,
            title: format!("{} resolved to {}", d.domain, d.ip),
            detail: None,
            severity: Severity::Info,
            tactic: None,
            attack: Vec::new(),
            finding_index: None,
            packets: scope(
                host,
                None,
                Some(53),
                d.first_seen_ns.saturating_sub(1_000_000_000),
                d.first_seen_ns.saturating_add(1_000_000_000),
            ),
        });
    }

    // Files moved between the story's own endpoints (a host fetching from a peer its findings
    // name) — never every file a host fetched, which would bury the one from the C2.
    let files = s
        .carved_files
        .iter()
        .filter(|c| endpoints.contains(c.client.as_str()) && endpoints.contains(c.server.as_str()))
        .take(MAX_DOWNLOADS);
    for c in files {
        events.push(download_event(c, ix.capture));
    }

    finish(alert, events)
}

fn detection_event(idx: u32, f: &Finding, capture: (i64, i64)) -> TimelineEvent {
    let start = f.first_seen_ns.unwrap_or(capture.0);
    let end = f.last_seen_ns.or(f.first_seen_ns).unwrap_or(capture.1);
    TimelineEvent {
        ts_ns: f.first_seen_ns,
        end_ns: f.last_seen_ns.filter(|&l| Some(l) != f.first_seen_ns),
        kind: TimelineEventKind::Detection,
        host: f.src_ip.clone(),
        peer: f.dst_ip.clone(),
        dst_port: f.dst_port,
        title: f.title.clone(),
        detail: f.evidence.first().cloned(),
        severity: f.severity,
        tactic: Some(stage_label(f.kind).to_string()),
        attack: f.attack.clone(),
        finding_index: Some(idx),
        packets: scope(&f.src_ip, f.dst_ip.as_deref(), f.dst_port, start, end),
    }
}

fn download_event(c: &CarvedFile, capture: (i64, i64)) -> TimelineEvent {
    let severity = if c.known_bad {
        Severity::Critical
    } else if !c.yara.is_empty() {
        Severity::High
    } else if !c.signatures.is_empty() {
        Severity::Medium
    } else {
        Severity::Info
    };
    let flag = if c.known_bad { " (known-bad)" } else { "" };
    let mut detail = format!("SHA-256 {}", c.sha256);
    if !c.signatures.is_empty() {
        detail.push_str(&format!(" · {}", c.signatures.join(", ")));
    }
    if !c.yara.is_empty() {
        detail.push_str(&format!(" · YARA {}", c.yara.join(", ")));
    }
    if c.protocol != "http" {
        detail.push_str(&format!(" · {}", c.protocol.to_ascii_uppercase()));
    }
    if let Some(name) = &c.filename {
        detail.push_str(&format!(" · {name}"));
    }
    let (verb, dir) = if c.upload {
        ("sent", "to")
    } else {
        ("downloaded", "from")
    };
    // The whole transfer (an older summary has no completion time: pad the start instead).
    let start = c.first_seen_ns.unwrap_or(capture.0);
    let end = match (c.first_seen_ns, c.last_seen_ns) {
        (_, Some(last)) => last.saturating_add(1_000_000_000),
        (Some(first), None) => first.saturating_add(INSTANT_WINDOW_NS),
        (None, None) => capture.1,
    };
    TimelineEvent {
        ts_ns: c.first_seen_ns,
        end_ns: None,
        kind: TimelineEventKind::FileDownload,
        host: c.client.clone(),
        peer: Some(c.server.clone()),
        dst_port: None,
        title: format!(
            "{} {verb} {} {dir} {} (sha256 {}…){flag}",
            c.client,
            human_bytes(c.size),
            c.server,
            prefix(&c.sha256, HASH_PREFIX)
        ),
        detail: Some(detail),
        severity,
        tactic: None,
        attack: Vec::new(),
        finding_index: None,
        packets: scope(&c.client, Some(&c.server), None, start, end),
    }
}

/// Chronological order: timed rows first by time, then kind (context before the detection it
/// explains), host, title, finding index — a strict total order, so output is deterministic.
fn chrono(a: &TimelineEvent, b: &TimelineEvent) -> std::cmp::Ordering {
    let t = |e: &TimelineEvent| (e.ts_ns.is_none(), e.ts_ns.unwrap_or(0));
    t(a).cmp(&t(b))
        .then(a.kind.cmp(&b.kind))
        .then_with(|| a.host.cmp(&b.host))
        .then_with(|| a.title.cmp(&b.title))
        .then(a.finding_index.cmp(&b.finding_index))
}

/// Whether a row must survive the cap ahead of plain context.
fn keep_rank(e: &TimelineEvent) -> (u8, u8) {
    let core = matches!(
        e.kind,
        TimelineEventKind::Detection | TimelineEventKind::Pivot
    ) || e.severity >= Severity::High;
    (u8::from(!core), 4 - e.severity.rank().min(4))
}

fn finish(alert: &Alert, mut events: Vec<TimelineEvent>) -> AlertTimeline {
    let event_count = events.len() as u32;
    if events.len() > MAX_TIMELINE_EVENTS {
        events.sort_by(|a, b| keep_rank(a).cmp(&keep_rank(b)).then_with(|| chrono(a, b)));
        events.truncate(MAX_TIMELINE_EVENTS);
    }
    events.sort_by(chrono);

    let mut hosts: Vec<String> = Vec::new();
    for e in &events {
        if !hosts.contains(&e.host) {
            hosts.push(e.host.clone());
        }
    }
    let first_ts_ns = events.iter().filter_map(|e| e.ts_ns).min();
    let last_ts_ns = events.iter().filter_map(|e| e.end_ns.or(e.ts_ns)).max();
    AlertTimeline {
        alert_id: alert.id.clone(),
        title: alert.title.clone(),
        hosts,
        first_ts_ns,
        last_ts_ns,
        events,
        event_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::alerts::refresh_alerts;
    use crate::detect::{correlate_incidents, reconstruct_attack_chains};
    use crate::model::finding::FindingKind;
    use crate::model::timeline::TimelineContext;

    const S: i64 = 1_000_000_000;

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
                FindingKind::HostSweep | FindingKind::LateralMovement => {
                    dst.map(|d| vec![d.to_string()]).unwrap_or_default()
                }
                _ => Vec::new(),
            },
        }
    }

    /// Sweep + brute force on A, then B beacons and exfiltrates to a C2: one cross-host chain,
    /// with the DNS answer, first contact and a known-bad download recorded around it.
    fn summary() -> Summary {
        let findings = vec![
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
                Some((6 * S, 9 * S)),
            ),
            f(
                FindingKind::DataExfil,
                72,
                "10.0.0.7",
                Some("45.77.13.37"),
                Some(443),
                Some((10 * S, 12 * S)),
            ),
        ];
        let mut s = Summary::empty();
        s.first_ts_ns = Some(0);
        s.last_ts_ns = Some(20 * S);
        s.incidents = correlate_incidents(&findings);
        s.attack_chains = reconstruct_attack_chains(&findings);
        s.findings = findings;
        s.timeline_context = TimelineContext {
            dns_answers: vec![DnsAnswer {
                ip: "45.77.13.37".into(),
                domain: "c2.example".into(),
                client: Some("10.0.0.7".into()),
                first_seen_ns: 5 * S,
            }],
            first_contacts: vec![FirstContact {
                initiator: "10.0.0.7".into(),
                responder: "45.77.13.37".into(),
                port: Some(443),
                first_seen_ns: 5 * S + 1,
            }],
        };
        s.carved_files = vec![CarvedFile {
            client: "10.0.0.7".into(),
            server: "45.77.13.37".into(),
            sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".into(),
            size: 68,
            known_bad: true,
            signatures: Vec::new(),
            extracted_path: None,
            first_seen_ns: Some(5 * S + 2),
            last_seen_ns: Some(8 * S),
            ..Default::default()
        }];
        refresh_alerts(&mut s);
        s
    }

    fn chain_timeline(s: &Summary) -> &AlertTimeline {
        let alert = s
            .alerts
            .iter()
            .find(|a| a.chain_id.is_some())
            .expect("chain alert");
        s.timelines
            .iter()
            .find(|t| t.alert_id == alert.id)
            .expect("its timeline")
    }

    #[test]
    fn one_timeline_per_alert_in_queue_order() {
        let s = summary();
        assert_eq!(s.timelines.len(), s.alerts.len());
        for (a, t) in s.alerts.iter().zip(&s.timelines) {
            assert_eq!(a.id, t.alert_id);
            assert_eq!(a.title, t.title);
            assert_eq!(t.event_count as usize, t.events.len());
        }
    }

    #[test]
    fn chain_timeline_tells_the_story_in_order_across_hosts() {
        let s = summary();
        let t = chain_timeline(&s);
        let kinds: Vec<_> = t.events.iter().map(|e| (e.kind, e.host.as_str())).collect();
        use TimelineEventKind::*;
        assert_eq!(
            kinds,
            vec![
                (Detection, "10.0.0.5"), // sweep @1s
                (Detection, "10.0.0.5"), // brute force @3s
                (DnsAnswer, "10.0.0.7"), // c2.example @5s
                (FirstContact, "10.0.0.7"),
                (FileDownload, "10.0.0.7"),
                (Pivot, "10.0.0.7"),     // A -> B, at B's first step
                (Detection, "10.0.0.7"), // beacon @6s
                (Detection, "10.0.0.7"), // exfil @10s
            ],
            "{:#?}",
            t.events
        );
        assert_eq!(t.hosts, vec!["10.0.0.5", "10.0.0.7"]);
        assert_eq!(t.first_ts_ns, Some(S));
        assert_eq!(t.last_ts_ns, Some(12 * S));
        // Timestamps never go backwards.
        assert!(t.events.windows(2).all(|w| w[0].ts_ns <= w[1].ts_ns));
    }

    #[test]
    fn every_row_is_one_carve_from_its_packets() {
        let s = summary();
        let t = chain_timeline(&s);
        for e in &t.events {
            let p = e.packets.as_ref().expect("packet scope");
            assert_eq!(p.host, e.host);
            assert!(p.start_ns <= p.end_ns);
        }
        let beacon = t
            .events
            .iter()
            .find(|e| e.title.starts_with("beacon"))
            .unwrap();
        let p = beacon.packets.as_ref().unwrap();
        assert_eq!(p.peer.as_deref(), Some("45.77.13.37"));
        assert_eq!(p.port, Some(443));
        assert_eq!((p.start_ns, p.end_ns), (6 * S, 9 * S));
        assert_eq!(beacon.end_ns, Some(9 * S));
        assert!(beacon.finding_index.is_some());

        let dns = t
            .events
            .iter()
            .find(|e| e.kind == TimelineEventKind::DnsAnswer)
            .unwrap();
        assert_eq!(dns.title, "c2.example resolved to 45.77.13.37");
        assert_eq!(dns.packets.as_ref().unwrap().port, Some(53));
    }

    #[test]
    fn pivot_names_both_hosts_and_the_handoff() {
        let s = summary();
        let t = chain_timeline(&s);
        let hop = t
            .events
            .iter()
            .find(|e| e.kind == TimelineEventKind::Pivot)
            .unwrap();
        assert!(
            hop.title.starts_with("Lateral hop 10.0.0.5 → 10.0.0.7"),
            "{}",
            hop.title
        );
        assert_eq!(hop.peer.as_deref(), Some("10.0.0.5"));
        assert_eq!(hop.tactic.as_deref(), Some("Lateral Movement"));
        let p = hop.packets.as_ref().unwrap();
        assert_eq!(p.peer.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn known_bad_download_is_critical_with_full_hash() {
        let s = summary();
        let t = chain_timeline(&s);
        let dl = t
            .events
            .iter()
            .find(|e| e.kind == TimelineEventKind::FileDownload)
            .unwrap();
        assert_eq!(dl.severity, Severity::Critical);
        assert!(
            dl.title.contains("(sha256 275a021bbfb6…) (known-bad)"),
            "{}",
            dl.title
        );
        assert!(dl
            .detail
            .as_deref()
            .unwrap()
            .contains(&s.carved_files[0].sha256));
    }

    #[test]
    fn download_window_covers_the_whole_transfer() {
        let mut s = summary();
        let window = |s: &Summary| {
            let p = chain_timeline(s)
                .events
                .iter()
                .find(|e| e.kind == TimelineEventKind::FileDownload)
                .and_then(|e| e.packets.clone())
                .unwrap();
            (p.start_ns, p.end_ns)
        };
        // Ends a second past the packet that completed the body (a 45 s download is not cut at 10 s).
        s.carved_files[0].last_seen_ns = Some(50 * S);
        refresh_alerts(&mut s);
        assert_eq!(window(&s), (5 * S + 2, 51 * S));
        // An older summary without the completion time falls back to a padded start.
        s.carved_files[0].last_seen_ns = None;
        refresh_alerts(&mut s);
        assert_eq!(window(&s), (5 * S + 2, 15 * S + 2));
    }

    #[test]
    fn only_downloads_between_story_endpoints_join() {
        let mut s = summary();
        // Large unrelated CDN files fetched by the beaconing host rank ahead of the C2's file.
        let cdn = s.carved_files[0].clone();
        let mut unrelated: Vec<CarvedFile> = (0..MAX_DOWNLOADS as u64 + 4)
            .map(|i| CarvedFile {
                server: "93.184.216.34".into(),
                sha256: format!("{i:064x}"),
                size: 1_000_000 + i,
                known_bad: false,
                ..cdn.clone()
            })
            .collect();
        unrelated.push(cdn);
        s.carved_files = unrelated;
        refresh_alerts(&mut s);
        let dls: Vec<_> = chain_timeline(&s)
            .events
            .iter()
            .filter(|e| e.kind == TimelineEventKind::FileDownload)
            .collect();
        assert_eq!(dls.len(), 1, "{dls:#?}");
        assert_eq!(dls[0].peer.as_deref(), Some("45.77.13.37"));
    }

    #[test]
    fn another_hosts_dns_lookup_stays_out_of_the_story() {
        let mut s = summary();
        // A different host resolved the same C2 earlier; only 10.0.0.7's own answer is its story.
        s.timeline_context.dns_answers.insert(
            0,
            DnsAnswer {
                ip: "45.77.13.37".into(),
                domain: "shared.example".into(),
                client: Some("10.0.0.99".into()),
                first_seen_ns: S / 2,
            },
        );
        refresh_alerts(&mut s);
        let dns: Vec<_> = chain_timeline(&s)
            .events
            .iter()
            .filter(|e| e.kind == TimelineEventKind::DnsAnswer)
            .collect();
        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0].host, "10.0.0.7");
        assert_eq!(dns[0].title, "c2.example resolved to 45.77.13.37");
        // With no answer of its own, the row is omitted rather than borrowed.
        s.timeline_context.dns_answers.remove(1);
        refresh_alerts(&mut s);
        assert!(!chain_timeline(&s)
            .events
            .iter()
            .any(|e| e.kind == TimelineEventKind::DnsAnswer));
    }

    #[test]
    fn rederive_is_idempotent_and_survives_json() {
        let mut s = summary();
        let before = s.timelines.clone();
        refresh_alerts(&mut s);
        assert_eq!(s.timelines, before);
        let back: Summary = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back.timelines, before);
        assert_eq!(back.timeline_context, s.timeline_context);
    }

    #[test]
    fn untimed_rows_sort_last_and_scope_the_whole_capture() {
        let mut s = Summary::empty();
        s.first_ts_ns = Some(S);
        s.last_ts_ns = Some(9 * S);
        s.findings = vec![
            f(
                FindingKind::Beacon,
                70,
                "10.0.0.7",
                Some("45.77.13.37"),
                Some(443),
                None,
            ),
            f(
                FindingKind::DataExfil,
                72,
                "10.0.0.7",
                Some("45.77.13.37"),
                Some(443),
                Some((2 * S, 3 * S)),
            ),
        ];
        s.incidents = correlate_incidents(&s.findings);
        refresh_alerts(&mut s);
        let t = &s.timelines[0];
        assert_eq!(t.events.last().unwrap().ts_ns, None);
        let p = t.events.last().unwrap().packets.as_ref().unwrap();
        assert_eq!((p.start_ns, p.end_ns), (S, 9 * S));
    }

    #[test]
    fn hostile_strings_do_not_panic() {
        let mut s = summary();
        s.carved_files[0].sha256 = "aaaaaaaaaaa\u{e9}\u{e9}".into(); // multibyte at the cut
        s.findings[0].src_ip = "not an ip".into();
        refresh_alerts(&mut s);
        assert!(!s.timelines.is_empty());
        let rows = s.timelines.iter().flat_map(|t| &t.events);
        assert!(rows
            .clone()
            .any(|e| e.host == "not an ip" && e.packets.is_none()));
    }

    #[test]
    fn cap_keeps_detections_ahead_of_context() {
        let alert = summary().alerts[0].clone();
        let ctx = |i: i64| TimelineEvent {
            ts_ns: Some(i),
            end_ns: None,
            kind: TimelineEventKind::FirstContact,
            host: "10.0.0.1".into(),
            peer: None,
            dst_port: None,
            title: format!("ctx {i}"),
            detail: None,
            severity: Severity::Info,
            tactic: None,
            attack: Vec::new(),
            finding_index: None,
            packets: None,
        };
        let mut events: Vec<_> = (0..MAX_TIMELINE_EVENTS as i64 + 50).map(ctx).collect();
        let mut det = ctx(10_000);
        det.kind = TimelineEventKind::Detection;
        events.push(det);
        let t = finish(&alert, events);
        assert_eq!(t.events.len(), MAX_TIMELINE_EVENTS);
        assert_eq!(t.event_count as usize, MAX_TIMELINE_EVENTS + 51);
        assert_eq!(t.events.last().unwrap().kind, TimelineEventKind::Detection);
        assert!(t.events.windows(2).all(|w| w[0].ts_ns <= w[1].ts_ns));
    }
}
