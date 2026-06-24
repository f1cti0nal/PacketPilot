//! Streaming summary accumulator (heavy-hitter bounded).
//!
//! Folds every packet and every closed flow into a [`Summary`]. All per-key maps
//! (talkers, ports, protocol paths, time buckets) are capped at `max_tracked_keys` with a
//! degradation policy that preserves heavy hitters, so memory stays bounded on adversarial
//! captures. Designed as a commutative monoid (mergeable) for a future Phase-0.5 parallel
//! split.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

use crate::enrich::classify_ip;
use crate::model::category::Category;
use crate::model::flow::FlowRecord;
use crate::model::packet::{PacketMeta, Transport};
use crate::model::severity::Severity;
use crate::model::summary::{
    CategoryCount, FingerprintHit, IpThreat, PortCount, ProtoCount, ScoreTerm, SeverityCounts,
    Summary, TimeBucket, TopTalker,
};
use crate::score::ScoredFlow;

/// Tuning for the stats accumulator.
#[derive(Debug, Clone)]
pub struct StatsConfig {
    pub top_k_talkers: usize,
    pub top_k_ports: usize,
    pub top_k_protos: usize,
    /// Cap on distinct tracked keys per dimension (graceful degradation; heavy hitters kept).
    pub max_tracked_keys: usize,
    /// Max rows in the `ip_threats` summary table (desc by score).
    pub top_k_ip_threats: usize,
    /// Max deduped evidence strings retained per IP-threat row (bounds memory).
    ///
    /// The retained evidence is anchored to the IP's representative (max-severity, then
    /// max-score) flow: when a flow strictly raises that verdict its evidence is seeded
    /// first, then later flows top the list up to this cap. This guarantees the evidence
    /// shown justifies the row's reported severity/score (e.g. the IOC and floor strings of
    /// a Critical flow are never crowded out by earlier benign flows), rather than reflecting
    /// flow-close arrival order.
    pub max_evidence_per_ip: usize,
    /// Upper bound on emitted `time_histogram` buckets. Packets are tallied per-second while
    /// streaming, then re-bucketed at [`finish`](StatsAccumulator::finish) into at most this
    /// many "nice"-width buckets (see [`choose_bucket_width`]). Keeps the timeline series — and
    /// the downstream summary JSON / report SVG — small and readable for any capture duration.
    pub max_time_buckets: usize,
}

impl Default for StatsConfig {
    fn default() -> Self {
        StatsConfig {
            top_k_talkers: 50,
            top_k_ports: 50,
            top_k_protos: 30,
            max_tracked_keys: 2_000_000,
            top_k_ip_threats: 50,
            max_evidence_per_ip: 6,
            max_time_buckets: 1_000,
        }
    }
}

/// Per-IP rollup for top-talker tracking.
#[derive(Debug, Clone, Copy, Default)]
struct IpStat {
    pkts: u64,
    bytes: u64,
    flows: u64,
}

/// Per (port, transport) rollup for the port histogram.
#[derive(Debug, Clone, Copy, Default)]
struct PortStat {
    pkts: u64,
    bytes: u64,
}

/// Per-protocol-path rollup for the protocol hierarchy.
#[derive(Debug, Clone, Copy, Default)]
struct PathStat {
    pkts: u64,
    bytes: u64,
}

/// Per-second rollup for the time histogram.
#[derive(Debug, Clone, Copy, Default)]
struct SecStat {
    pkts: u64,
    bytes: u64,
}

/// Per-category rollup for the category breakdown.
#[derive(Debug, Clone, Copy, Default)]
struct CatStat {
    flows: u64,
    pkts: u64,
    bytes: u64,
}

/// A TLS SNI host worth aggregating: non-empty, has a dot, and is not an IP literal.
fn valid_domain(host: &str) -> bool {
    !host.is_empty() && host.contains('.') && host.parse::<std::net::IpAddr>().is_err()
}

/// Per-SNI-domain rollup for traffic-ranked aggregation.
#[derive(Debug, Clone, Default)]
struct DomainStat {
    flows: u64,
    bytes: u64,
}

/// Per-IP threat rollup state (worst verdict + bounded evidence union).
#[derive(Debug, Clone, Default)]
struct IpThreatStat {
    max_sev: Severity, // Default = Info
    max_score: u16,
    flows: u64,
    bytes: u64,
    ioc: bool,
    attack: BTreeSet<String>,          // deterministic sorted union
    evidence: Vec<String>,             // bounded, deduped
    fingerprints: Vec<FingerprintHit>, // bounded (MAX_FP_PER_IP), deduped by full equality
    terms: Vec<ScoreTerm>, // additive scoring terms from the worst (representative) flow
}

/// The streaming summary accumulator.
pub struct StatsAccumulator {
    cfg: StatsConfig,

    total_packets: u64,
    total_bytes: u64,
    captured_bytes: u64,
    decode_errors: u64,
    non_ip_frames: u64,
    total_flows: u64,

    proto: crate::model::summary::ProtoCounts,

    first_ts: Option<i64>,
    last_ts: Option<i64>,

    per_ip: HashMap<IpAddr, IpStat>,
    /// Keyed by `(service_port, ip_proto_number)` so the key stays `Ord` (the `Transport`
    /// enum is not ordered); the transport token is reconstructed at `finish`.
    per_port: HashMap<(u16, u8), PortStat>,
    per_proto_path: HashMap<String, PathStat>,
    per_second: HashMap<i64, SecStat>,

    /// Fixed 12-slot category breakdown indexed by `Category::all()` position.
    per_category: [CatStat; 12],

    /// Per-source distinct destination ports observed on SYN-only packets (scan signal).
    /// Bounded both in the number of sources and in the spread tracked per source.
    scan_spread: HashMap<IpAddr, std::collections::HashSet<u16>>,

    /// Flow counts per severity band (Phase 2).
    severity_counts: SeverityCounts,
    /// Per-IP threat rollups (Phase 2); bounded by `max_tracked_keys`.
    per_ip_threat: HashMap<IpAddr, IpThreatStat>,
    /// Per-SNI-domain traffic rollups; bounded by `max_tracked_keys`.
    per_domain: HashMap<String, DomainStat>,
}

/// Upper bound on distinct destination ports retained per source for scan detection.
/// Keeps the scan map bounded on pathological captures while remaining far above any
/// realistic `scan_port_threshold`.
const SCAN_PORTS_PER_SRC_CAP: usize = 4096;

impl StatsAccumulator {
    /// Create an empty accumulator.
    pub fn new(cfg: StatsConfig) -> StatsAccumulator {
        StatsAccumulator {
            cfg,
            total_packets: 0,
            total_bytes: 0,
            captured_bytes: 0,
            decode_errors: 0,
            non_ip_frames: 0,
            total_flows: 0,
            proto: crate::model::summary::ProtoCounts::default(),
            first_ts: None,
            last_ts: None,
            per_ip: HashMap::new(),
            per_port: HashMap::new(),
            per_proto_path: HashMap::new(),
            per_second: HashMap::new(),
            per_category: [CatStat::default(); 12],
            scan_spread: HashMap::new(),
            severity_counts: SeverityCounts::default(),
            per_ip_threat: HashMap::new(),
            per_domain: HashMap::new(),
        }
    }

    /// Fold one decoded packet (packet-level tallies only; flow-level tallies come via
    /// [`observe_flow`](Self::observe_flow)).
    pub fn observe_packet(&mut self, p: &PacketMeta) {
        // Totals.
        self.total_packets += 1;
        self.total_bytes += u64::from(p.wire_len);
        self.captured_bytes += u64::from(p.cap_len);

        // Capture window.
        self.first_ts = Some(match self.first_ts {
            Some(t) => t.min(p.ts_ns),
            None => p.ts_ns,
        });
        self.last_ts = Some(match self.last_ts {
            Some(t) => t.max(p.ts_ns),
            None => p.ts_ns,
        });

        // Per-second histogram (floor division toward negative infinity so that
        // pre-epoch timestamps land in a stable, monotone bucket).
        let epoch_sec = p.ts_ns.div_euclid(1_000_000_000);
        bump_bounded(
            &mut self.per_second,
            epoch_sec,
            self.cfg.max_tracked_keys,
            |s| {
                s.pkts += 1;
                s.bytes += u64::from(p.wire_len);
            },
            |s| s.pkts,
            SecStat::default,
        );

        // ARP / non-IP frames: counted, then short-circuit the IP/transport path.
        let Some((src_ip, src_port, dst_ip, dst_port)) = p.endpoints() else {
            self.non_ip_frames += 1;
            self.proto.non_ipv4 += 1;
            return;
        };

        // Per-IP talkers: bump both endpoints' packet/byte tallies.
        let wire = u64::from(p.wire_len);
        self.bump_ip(src_ip, wire);
        self.bump_ip(dst_ip, wire);

        // Transport + app-proto inference. The "service port" is the well-known side,
        // i.e. the smaller of the two ports for port-bearing transports.
        let service_port = if p.transport.has_ports() {
            src_port.min(dst_port)
        } else {
            0
        };

        match p.transport {
            Transport::Tcp => {
                self.proto.tcp += 1;
                let app = app_proto_tcp(service_port);
                match app {
                    AppProto::Http => self.proto.http += 1,
                    AppProto::Tls => self.proto.tls += 1,
                    AppProto::Dns => self.proto.dns += 1,
                    _ => self.proto.other_tcp += 1,
                }
                self.bump_path(proto_path("tcp", app), wire);
            }
            Transport::Udp => {
                self.proto.udp += 1;
                let app = app_proto_udp(service_port);
                match app {
                    AppProto::Dns => self.proto.dns += 1,
                    AppProto::Http => self.proto.http += 1,
                    AppProto::Tls => self.proto.tls += 1,
                    _ => self.proto.other_udp += 1,
                }
                self.bump_path(proto_path("udp", app), wire);
            }
            other => {
                // SCTP / ICMP / ICMPv6 / Other: no app-proto refinement, recorded under
                // their transport token in the protocol hierarchy only.
                let token = transport_path_token(other);
                self.bump_path(format!("ip.{token}"), wire);
            }
        }

        // Port histogram: keyed on the service port for port-bearing transports.
        if p.transport.has_ports() {
            self.bump_port(service_port, p.transport, wire);
        }

        // Scanner tracking: record (src -> dst_port) spread for SYN-only probes.
        if p.is_tcp_syn_only() {
            self.record_scan_probe(src_ip, dst_port);
        }
    }

    /// Record that a frame failed to decode (increments `decode_errors` and
    /// `proto.truncated`).
    pub fn record_decode_error(&mut self) {
        self.decode_errors += 1;
        self.proto.truncated += 1;
    }

    /// Fold one closed flow (flow- and category-level tallies).
    pub fn observe_flow(&mut self, f: &FlowRecord) {
        self.total_flows += 1;

        let idx = category_index(f.category);
        let slot = &mut self.per_category[idx];
        slot.flows += 1;
        slot.pkts += f.total_pkts();
        slot.bytes += f.total_bytes();

        // Per-IP flow counts for both canonical endpoints. Only bump endpoints already
        // tracked, or insert under the same bounded policy used for packet tallies, so a
        // flow with an evicted endpoint does not silently reintroduce it unbounded.
        self.bump_ip_flows(f.key.lo_ip);
        self.bump_ip_flows(f.key.hi_ip);
    }

    /// Fold a scored, closed flow. Called from `analyze::process_flow` AFTER
    /// [`observe_flow`](Self::observe_flow). Bounds the per-IP map like the other maps:
    /// a brand-new key at capacity is dropped (graceful degradation).
    pub fn observe_scored_flow(&mut self, f: &FlowRecord, sc: &ScoredFlow) {
        self.severity_counts.bump(f.severity);
        for ip in [f.key.lo_ip, f.key.hi_ip] {
            if !self.per_ip_threat.contains_key(&ip)
                && self.per_ip_threat.len() >= self.cfg.max_tracked_keys
            {
                continue;
            }
            let e = self.per_ip_threat.entry(ip).or_default();
            e.flows += 1;
            e.bytes += f.total_bytes();
            e.ioc |= f.ioc;
            // A flow that strictly raises the IP's verdict becomes the representative flow:
            // reseed the evidence from it so the retained strings justify the reported
            // severity/score (the IOC/floor strings of the worst flow are never crowded out
            // by earlier benign flows). Later flows top up the remaining slots in order.
            if f.severity > e.max_sev || (f.severity == e.max_sev && f.threat_score > e.max_score) {
                e.max_sev = f.severity;
                e.max_score = f.threat_score;
                e.evidence.clear();
                e.terms = sc.terms.clone();
                for ev in &sc.evidence {
                    if e.evidence.len() >= self.cfg.max_evidence_per_ip {
                        break;
                    }
                    if !e.evidence.contains(ev) {
                        e.evidence.push(ev.clone());
                    }
                }
            }
            for a in &sc.attack {
                e.attack.insert(a.clone());
            }
            for ev in &sc.evidence {
                if e.evidence.len() < self.cfg.max_evidence_per_ip && !e.evidence.contains(ev) {
                    e.evidence.push(ev.clone());
                }
            }
            // Fingerprint rollup: only when the flow carried a matched label.
            if let Some(label) = &f.fingerprint_label {
                let hit = FingerprintHit {
                    ja3: f.ja3.clone(),
                    ja4: f.ja4.clone(),
                    label: label.clone(),
                };
                const MAX_FP_PER_IP: usize = 6;
                if e.fingerprints.len() < MAX_FP_PER_IP && !e.fingerprints.contains(&hit) {
                    e.fingerprints.push(hit);
                }
            }
        }

        // SNI domain rollup (traffic-ranked; bounded by max_tracked_keys, like per_ip_threat).
        if let Some(raw) = f.sni.as_deref() {
            let host = raw.trim().to_ascii_lowercase();
            if valid_domain(&host)
                && (self.per_domain.contains_key(&host)
                    || self.per_domain.len() < self.cfg.max_tracked_keys)
            {
                let e = self.per_domain.entry(host).or_default();
                e.flows += 1;
                e.bytes += f.total_bytes();
            }
        }
    }

    /// Merge cross-flow [`crate::model::finding::Finding`]s into the per-IP threat rollups so a
    /// behavioral verdict (e.g. a beacon) elevates the implicated hosts' threat cards. Called
    /// once after the streaming pass and before [`finish`](Self::finish). Both endpoints of a
    /// finding are uplifted; an already-higher card is never lowered (mirrors
    /// [`observe_scored_flow`](Self::observe_scored_flow)).
    pub fn apply_findings(&mut self, findings: &[crate::model::finding::Finding]) {
        for f in findings {
            // Both endpoints are implicated: the beaconing host and the peer it calls.
            for ip_str in [Some(f.src_ip.as_str()), f.dst_ip.as_deref()]
                .into_iter()
                .flatten()
            {
                let Ok(ip) = ip_str.parse::<IpAddr>() else {
                    continue;
                };
                // Bound the map like every other per-key dimension: a brand-new key at capacity
                // is dropped (graceful degradation).
                if !self.per_ip_threat.contains_key(&ip)
                    && self.per_ip_threat.len() >= self.cfg.max_tracked_keys
                {
                    continue;
                }
                let e = self.per_ip_threat.entry(ip).or_default();
                // Raise (never lower) the representative verdict; reseed evidence from the
                // finding when it strictly raises so the retained strings justify the new card,
                // exactly as observe_scored_flow does for a strictly-raising flow.
                if f.severity > e.max_sev || (f.severity == e.max_sev && f.score > e.max_score) {
                    e.max_sev = f.severity;
                    e.max_score = f.score;
                    e.evidence.clear();
                    for ev in &f.evidence {
                        if e.evidence.len() >= self.cfg.max_evidence_per_ip {
                            break;
                        }
                        if !e.evidence.contains(ev) {
                            e.evidence.push(ev.clone());
                        }
                    }
                }
                for a in &f.attack {
                    e.attack.insert(a.clone());
                }
                for ev in &f.evidence {
                    if e.evidence.len() < self.cfg.max_evidence_per_ip && !e.evidence.contains(ev) {
                        e.evidence.push(ev.clone());
                    }
                }
            }
        }
    }

    /// Whether `src` exceeded `threshold` distinct destination ports (scan signal).
    pub fn is_scanner(&self, src: IpAddr, threshold: u32) -> bool {
        match self.scan_spread.get(&src) {
            Some(ports) => ports.len() as u64 >= u64::from(threshold),
            None => false,
        }
    }

    /// Consume the accumulator and materialize the [`Summary`] (sorts + top-k truncation,
    /// per-second histogram in ascending order, fixed category order).
    pub fn finish(self) -> Summary {
        let duration_ns = if self.total_packets < 2 {
            0
        } else {
            match (self.first_ts, self.last_ts) {
                (Some(a), Some(b)) => b.saturating_sub(a).max(0),
                _ => 0,
            }
        };

        let unique_hosts = self.per_ip.len() as u64;

        // Top talkers: desc by bytes, tie-break desc pkts, then asc by canonical IP for
        // determinism.
        let mut talkers: Vec<TopTalker> = self
            .per_ip
            .iter()
            .map(|(ip, s)| TopTalker {
                ip: ip.to_string(),
                pkts: s.pkts,
                bytes: s.bytes,
                flows: s.flows,
            })
            .collect();
        talkers.sort_by(|a, b| {
            b.bytes
                .cmp(&a.bytes)
                .then(b.pkts.cmp(&a.pkts))
                .then(a.ip.cmp(&b.ip))
        });
        talkers.truncate(self.cfg.top_k_talkers);

        // Protocol hierarchy: desc by bytes, tie-break desc pkts, then asc by path.
        let mut hierarchy: Vec<ProtoCount> = self
            .per_proto_path
            .iter()
            .map(|(path, s)| ProtoCount {
                path: path.clone(),
                pkts: s.pkts,
                bytes: s.bytes,
            })
            .collect();
        hierarchy.sort_by(|a, b| {
            b.bytes
                .cmp(&a.bytes)
                .then(b.pkts.cmp(&a.pkts))
                .then(a.path.cmp(&b.path))
        });
        hierarchy.truncate(self.cfg.top_k_protos);

        // Port histogram: desc by pkts, tie-break desc bytes, then asc (port, transport).
        let mut ports: Vec<PortCount> = self
            .per_port
            .iter()
            .map(|((port, ip_proto), s)| PortCount {
                port: *port,
                transport: Transport::from_ip_proto(*ip_proto).as_str().to_string(),
                pkts: s.pkts,
                bytes: s.bytes,
            })
            .collect();
        ports.sort_by(|a, b| {
            b.pkts
                .cmp(&a.pkts)
                .then(b.bytes.cmp(&a.bytes))
                .then(a.port.cmp(&b.port))
                .then(a.transport.cmp(&b.transport))
        });
        ports.truncate(self.cfg.top_k_ports);

        // Time histogram: re-bucket the per-second tallies into at most `max_time_buckets`
        // buckets of an adaptive "nice" width so the emitted series (and the report sparkline)
        // stays bounded and readable regardless of capture length. Re-bucketing only re-groups
        // existing tallies, so Σ pkts/bytes is conserved.
        let (time, time_bucket_secs) =
            build_time_histogram(&self.per_second, self.cfg.max_time_buckets);

        // Category breakdown: fixed Category::all() order.
        let category_breakdown: Vec<CategoryCount> = Category::all()
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let s = self.per_category[i];
                CategoryCount {
                    category: *c,
                    flows: s.flows,
                    pkts: s.pkts,
                    bytes: s.bytes,
                }
            })
            .collect();

        // Per-IP threat rollups: desc by score, then severity, then flows, then asc IP.
        let mut ip_threats: Vec<IpThreat> = self
            .per_ip_threat
            .iter()
            .map(|(ip, s)| {
                let class = classify_ip(*ip);
                let mut tags = vec![if class.is_external() {
                    "public"
                } else {
                    "internal"
                }
                .to_string()];
                if s.ioc {
                    tags.push("ioc".to_string());
                }
                IpThreat {
                    ip: ip.to_string(),
                    ip_class: class,
                    severity: s.max_sev,
                    score: s.max_score,
                    flows: s.flows,
                    bytes: s.bytes,
                    ioc: s.ioc,
                    tags,
                    attack: s.attack.iter().cloned().collect(), // BTreeSet => sorted
                    evidence: s.evidence.clone(),
                    reputation: Vec::new(),
                    fingerprints: s.fingerprints.clone(),
                    score_terms: s.terms.clone(),
                }
            })
            .collect();
        ip_threats.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then(b.severity.rank().cmp(&a.severity.rank()))
                .then(b.flows.cmp(&a.flows))
                .then(a.ip.cmp(&b.ip))
        });
        ip_threats.truncate(self.cfg.top_k_ip_threats);

        // Domain (SNI) rollups: desc by bytes, tie-break desc flows, then asc host. Top-N.
        const TOP_K_DOMAINS: usize = 50;
        let mut domain_threats: Vec<crate::model::summary::DomainThreat> = self
            .per_domain
            .iter()
            .map(|(host, s)| crate::model::summary::DomainThreat {
                host: host.clone(),
                flows: s.flows,
                bytes: s.bytes,
                reputation: Vec::new(),
            })
            .collect();
        domain_threats.sort_by(|a, b| {
            b.bytes
                .cmp(&a.bytes)
                .then(b.flows.cmp(&a.flows))
                .then(a.host.cmp(&b.host))
        });
        domain_threats.truncate(TOP_K_DOMAINS);

        Summary {
            total_packets: self.total_packets,
            total_bytes: self.total_bytes,
            captured_bytes: self.captured_bytes,
            total_flows: self.total_flows,
            decode_errors: self.decode_errors,
            non_ip_frames: self.non_ip_frames,
            proto: self.proto,
            first_ts_ns: self.first_ts,
            last_ts_ns: self.last_ts,
            duration_ns,
            unique_hosts,
            top_talkers: talkers,
            protocol_hierarchy: hierarchy,
            port_histogram: ports,
            time_histogram: time,
            time_bucket_secs,
            category_breakdown,
            severity_counts: self.severity_counts,
            ip_threats,
            domain_threats,
            // Behavioral findings + their per-host correlation are produced by the `detect`
            // stage from the cross-flow tracker, not by this accumulator; the orchestrator fills
            // them in post-`finish`.
            findings: Vec::new(),
            incidents: Vec::new(),
        }
    }

    // ---- internal helpers -------------------------------------------------

    fn bump_ip(&mut self, ip: IpAddr, wire: u64) {
        bump_bounded(
            &mut self.per_ip,
            ip,
            self.cfg.max_tracked_keys,
            |s| {
                s.pkts += 1;
                s.bytes += wire;
            },
            |s| s.bytes,
            IpStat::default,
        );
    }

    fn bump_ip_flows(&mut self, ip: IpAddr) {
        bump_bounded(
            &mut self.per_ip,
            ip,
            self.cfg.max_tracked_keys,
            |s| {
                s.flows += 1;
            },
            |s| s.bytes,
            IpStat::default,
        );
    }

    fn bump_port(&mut self, port: u16, transport: Transport, wire: u64) {
        bump_bounded(
            &mut self.per_port,
            (port, transport.ip_proto()),
            self.cfg.max_tracked_keys,
            |s| {
                s.pkts += 1;
                s.bytes += wire;
            },
            |s| s.pkts,
            PortStat::default,
        );
    }

    fn bump_path(&mut self, path: String, wire: u64) {
        bump_bounded(
            &mut self.per_proto_path,
            path,
            self.cfg.max_tracked_keys,
            |s| {
                s.pkts += 1;
                s.bytes += wire;
            },
            |s| s.bytes,
            PathStat::default,
        );
    }

    fn record_scan_probe(&mut self, src: IpAddr, dst_port: u16) {
        // Bound the number of tracked sources. If a new source would exceed the cap and
        // it is not already tracked, drop it (graceful degradation): scan detection is a
        // best-effort heavy-hitter signal, not an exact set.
        if !self.scan_spread.contains_key(&src)
            && self.scan_spread.len() >= self.cfg.max_tracked_keys
        {
            return;
        }
        let entry = self.scan_spread.entry(src).or_default();
        if entry.len() < SCAN_PORTS_PER_SRC_CAP {
            entry.insert(dst_port);
        }
    }
}

/// App-proto bucket used for ProtoCounts refinement and protocol-path naming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppProto {
    Http,
    Tls,
    Dns,
    OtherTcp,
    OtherUdp,
}

impl AppProto {
    fn token(self) -> &'static str {
        match self {
            AppProto::Http => "http",
            AppProto::Tls => "https",
            AppProto::Dns => "dns",
            AppProto::OtherTcp => "other",
            AppProto::OtherUdp => "other",
        }
    }
}

/// Infer the application protocol for a TCP service port (the well-known side).
fn app_proto_tcp(port: u16) -> AppProto {
    match port {
        53 => AppProto::Dns,
        80 | 8080 | 8000 => AppProto::Http,
        443 | 8443 => AppProto::Tls,
        _ => AppProto::OtherTcp,
    }
}

/// Infer the application protocol for a UDP service port (the well-known side).
fn app_proto_udp(port: u16) -> AppProto {
    match port {
        53 => AppProto::Dns,
        80 => AppProto::Http,
        443 => AppProto::Tls, // QUIC / DTLS over the HTTPS port.
        _ => AppProto::OtherUdp,
    }
}

/// Build a dotted protocol-hierarchy path, e.g. `"ip.tcp.https"`.
fn proto_path(l4: &str, app: AppProto) -> String {
    format!("ip.{l4}.{}", app.token())
}

/// Path token for non-port transports under the IP node.
fn transport_path_token(t: Transport) -> &'static str {
    match t {
        Transport::Sctp => "sctp",
        Transport::Icmp => "icmp",
        Transport::Icmpv6 => "icmpv6",
        // Tcp/Udp are handled on their own paths; Other renders as its IANA token.
        Transport::Other(_) => "other",
        Transport::Tcp => "tcp",
        Transport::Udp => "udp",
    }
}

/// Fixed-order index of a category within `Category::all()`.
fn category_index(c: Category) -> usize {
    match c {
        Category::Web => 0,
        Category::Dns => 1,
        Category::Email => 2,
        Category::FileTransfer => 3,
        Category::RemoteAccess => 4,
        Category::Voip => 5,
        Category::IotOt => 6,
        Category::TunnelVpn => 7,
        Category::Scan => 8,
        Category::C2 => 9,
        Category::Anomalous => 10,
        Category::Unknown => 11,
    }
}

/// "Nice" time-bucket widths in seconds, strictly ascending. Chosen so the timeline axis lands
/// on human round numbers: sub-minute (1/2/5/10/15/30 s), minutes (1/2/5/10/15/30 min), hours
/// (1/2/3/6/12 h), then days/weeks. The accumulator picks the smallest width whose aligned
/// bucket count fits under the cap.
const NICE_BUCKET_WIDTHS_SECS: &[i64] = &[
    1, 2, 5, 10, 15, 30, // seconds
    60, 120, 300, 600, 900, 1800, // 1–30 min
    3600, 7200, 10800, 21600, 43200, // 1–12 h
    86400, 172800, 432000, 604800, // 1 d, 2 d, 5 d, 1 wk
];

/// Re-bucket per-second tallies into at most `max_buckets` buckets of an adaptive "nice" width,
/// returning `(buckets, width_secs)`. Buckets are ascending by start second, with empty windows
/// omitted; Σ pkts/bytes is conserved (this only re-groups existing per-second tallies). The
/// width is `1` for short captures and widens to a round interval as the span grows.
fn build_time_histogram(
    per_second: &HashMap<i64, SecStat>,
    max_buckets: usize,
) -> (Vec<TimeBucket>, i64) {
    if per_second.is_empty() {
        return (Vec::new(), 1);
    }
    // first/last second of the capture window (the per-second map is keyed by epoch second).
    let first = *per_second.keys().min().expect("per_second is non-empty");
    let last = *per_second.keys().max().expect("per_second is non-empty");
    let width = choose_bucket_width(first, last, max_buckets);

    if width <= 1 {
        // Per-second granularity already fits under the cap: emit buckets as-is.
        let mut time: Vec<TimeBucket> = per_second
            .iter()
            .map(|(sec, s)| TimeBucket {
                epoch_sec: *sec,
                pkts: s.pkts,
                bytes: s.bytes,
            })
            .collect();
        time.sort_by_key(|b| b.epoch_sec);
        return (time, 1);
    }

    // Merge per-second tallies into width-aligned buckets. `div_euclid` floors toward negative
    // infinity so pre-epoch seconds align consistently. BTreeMap keeps the output ascending.
    let mut merged: BTreeMap<i64, SecStat> = BTreeMap::new();
    for (sec, s) in per_second {
        let start = sec.div_euclid(width) * width;
        let e = merged.entry(start).or_default();
        e.pkts += s.pkts;
        e.bytes += s.bytes;
    }
    let time: Vec<TimeBucket> = merged
        .into_iter()
        .map(|(start, s)| TimeBucket {
            epoch_sec: start,
            pkts: s.pkts,
            bytes: s.bytes,
        })
        .collect();
    (time, width)
}

/// Smallest [`NICE_BUCKET_WIDTHS_SECS`] width whose aligned bucket count over `[first_sec,
/// last_sec]` is `<= max_buckets`. For spans too long for even the largest listed width, grows
/// in whole-week steps until the cap holds, so the bound is honored for any capture duration.
fn choose_bucket_width(first_sec: i64, last_sec: i64, max_buckets: usize) -> i64 {
    let cap = max_buckets.max(1) as i64;
    for &w in NICE_BUCKET_WIDTHS_SECS {
        if aligned_bucket_count(first_sec, last_sec, w) <= cap {
            return w;
        }
    }
    let largest = *NICE_BUCKET_WIDTHS_SECS
        .last()
        .expect("widths list is non-empty");
    let mut w = largest;
    while aligned_bucket_count(first_sec, last_sec, w) > cap {
        // Saturating so a pathological (i64-spanning) window can't overflow into a panic.
        w = w.saturating_add(largest);
    }
    w
}

/// Count of `width`-aligned buckets spanning `[first_sec, last_sec]` inclusive (>= 1, since
/// `last_sec >= first_sec`). Each endpoint is floored toward negative infinity so the count
/// matches how [`build_time_histogram`] aligns buckets.
fn aligned_bucket_count(first_sec: i64, last_sec: i64, width: i64) -> i64 {
    let width = width.max(1);
    last_sec.div_euclid(width) - first_sec.div_euclid(width) + 1
}

/// Insert-or-update a bounded map with a heavy-hitter-preserving eviction policy.
///
/// If `key` exists, `update` is applied. Otherwise, when the map is below `cap` the key is
/// inserted (then updated); when at/over `cap` the lightest existing entry (per `weight`)
/// is evicted only if it is lighter than the brand-new entry would be, otherwise the new
/// key is dropped. This keeps heavy hitters and bounds memory deterministically.
fn bump_bounded<K, V, U, W, D>(
    map: &mut HashMap<K, V>,
    key: K,
    cap: usize,
    update: U,
    weight: W,
    default: D,
) where
    K: std::hash::Hash + Eq + Clone + Ord,
    U: FnOnce(&mut V),
    W: Fn(&V) -> u64,
    D: Fn() -> V,
{
    if let Some(v) = map.get_mut(&key) {
        update(v);
        return;
    }

    if map.len() < cap.max(1) {
        let mut v = default();
        update(&mut v);
        map.insert(key, v);
        return;
    }

    // At capacity: build the candidate, then evict the lightest current entry only if it
    // is strictly lighter than the candidate (ties broken by key order for determinism).
    let mut candidate = default();
    update(&mut candidate);
    let cand_w = weight(&candidate);

    let lightest = map
        .iter()
        .map(|(k, v)| (weight(v), k.clone()))
        .min_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    if let Some((light_w, light_k)) = lightest {
        if light_w < cand_w {
            map.remove(&light_k);
            map.insert(key, candidate);
        }
        // else: candidate is no heavier than the lightest survivor -> drop it.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::model::flow::{Direction, FlowKey};
    use crate::model::packet::Protocol;

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    // Test helper: each arg maps to a distinct PacketMeta field; grouping them
    // into a struct would just duplicate PacketMeta and add noise.
    #[allow(clippy::too_many_arguments)]
    fn pkt(
        index: u64,
        ts_ns: i64,
        wire_len: u32,
        transport: Transport,
        src: Option<IpAddr>,
        dst: Option<IpAddr>,
        src_port: u16,
        dst_port: u16,
        tcp_flags: u8,
    ) -> PacketMeta {
        let l3 = match (src, dst) {
            (Some(IpAddr::V6(_)), _) | (_, Some(IpAddr::V6(_))) => Protocol::Ipv6,
            (Some(_), Some(_)) => Protocol::Ipv4,
            _ => Protocol::Arp,
        };
        PacketMeta {
            index,
            ts_ns,
            iface_id: 0,
            wire_len,
            cap_len: wire_len,
            l3,
            transport,
            src_ip: src,
            dst_ip: dst,
            src_port,
            dst_port,
            tcp_flags,
            ttl: 64,
            payload_len: 0,
            vlan: None,
            app_proto: crate::model::packet::AppProto::Unknown,
            sni: None,
            ja3: None,
            ja4: None,
            dns_qname: None,
            cleartext_cred: None,
            pii: None,
            icmp_type: None,
            tls_version: None,
            tls_cipher: None,
            hassh: None,
            hassh_server: None,
            arp: None,
            ja3s: None,
            http_host: None,
            http_ua: None,
        }
    }

    fn flow(
        transport: Transport,
        lo: IpAddr,
        hi: IpAddr,
        cat: Category,
        pkts_fwd: u64,
        bytes_fwd: u64,
    ) -> FlowRecord {
        let (key, _dir) = FlowKey::normalized(lo, 1000, hi, 80, transport);
        let mut r = FlowRecord::new(key, 0);
        // Use observe to keep totals consistent.
        let p = pkt(
            0,
            0,
            bytes_fwd as u32,
            transport,
            Some(key.lo_ip),
            Some(key.hi_ip),
            key.lo_port,
            key.hi_port,
            0,
        );
        for _ in 0..pkts_fwd {
            r.observe(&p, Direction::Forward);
        }
        r.category = cat;
        r
    }

    #[test]
    fn empty_capture_yields_zeroed_summary() {
        let acc = StatsAccumulator::new(StatsConfig::default());
        let s = acc.finish();
        assert_eq!(s.total_packets, 0);
        assert_eq!(s.duration_ns, 0);
        assert!(s.first_ts_ns.is_none());
        assert!(s.time_histogram.is_empty());
        assert_eq!(s.time_bucket_secs, 1);
        assert!(s.top_talkers.is_empty());
        // Category breakdown always covers all 12 categories in fixed order.
        assert_eq!(s.category_breakdown.len(), 12);
        assert_eq!(s.category_breakdown[0].category, Category::Web);
        assert_eq!(s.category_breakdown[11].category, Category::Unknown);
    }

    #[test]
    fn single_packet_has_zero_duration() {
        let mut acc = StatsAccumulator::new(StatsConfig::default());
        acc.observe_packet(&pkt(
            0,
            5_000_000_000,
            100,
            Transport::Tcp,
            Some(ip4(10, 0, 0, 1)),
            Some(ip4(10, 0, 0, 2)),
            1234,
            443,
            0,
        ));
        let s = acc.finish();
        assert_eq!(s.total_packets, 1);
        assert_eq!(s.duration_ns, 0);
        assert_eq!(s.first_ts_ns, Some(5_000_000_000));
        assert_eq!(s.last_ts_ns, Some(5_000_000_000));
    }

    #[test]
    fn totals_and_window_accumulate() {
        let mut acc = StatsAccumulator::new(StatsConfig::default());
        acc.observe_packet(&pkt(
            0,
            2_000_000_000,
            100,
            Transport::Tcp,
            Some(ip4(10, 0, 0, 1)),
            Some(ip4(10, 0, 0, 2)),
            1234,
            443,
            0,
        ));
        acc.observe_packet(&pkt(
            1,
            1_000_000_000,
            200,
            Transport::Udp,
            Some(ip4(10, 0, 0, 3)),
            Some(ip4(10, 0, 0, 2)),
            5000,
            53,
            0,
        ));
        acc.observe_packet(&pkt(
            2,
            3_000_000_000,
            300,
            Transport::Tcp,
            Some(ip4(10, 0, 0, 1)),
            Some(ip4(10, 0, 0, 2)),
            1235,
            80,
            0,
        ));
        let s = acc.finish();
        assert_eq!(s.total_packets, 3);
        assert_eq!(s.total_bytes, 600);
        assert_eq!(s.captured_bytes, 600);
        // window spans min..max regardless of arrival order.
        assert_eq!(s.first_ts_ns, Some(1_000_000_000));
        assert_eq!(s.last_ts_ns, Some(3_000_000_000));
        assert_eq!(s.duration_ns, 2_000_000_000);
        // proto buckets.
        assert_eq!(s.proto.tcp, 2);
        assert_eq!(s.proto.udp, 1);
        assert_eq!(s.proto.tls, 1); // 443
        assert_eq!(s.proto.http, 1); // 80
        assert_eq!(s.proto.dns, 1); // 53 udp
    }

    #[test]
    fn non_ip_frames_counted_and_short_circuited() {
        let mut acc = StatsAccumulator::new(StatsConfig::default());
        // ARP: no IPs.
        acc.observe_packet(&pkt(0, 0, 60, Transport::Other(0), None, None, 0, 0, 0));
        let s = acc.finish();
        assert_eq!(s.total_packets, 1);
        assert_eq!(s.non_ip_frames, 1);
        assert_eq!(s.proto.non_ipv4, 1);
        assert_eq!(s.proto.tcp, 0);
        assert!(s.top_talkers.is_empty());
        assert!(s.port_histogram.is_empty());
    }

    #[test]
    fn decode_error_increments_separately() {
        let mut acc = StatsAccumulator::new(StatsConfig::default());
        acc.record_decode_error();
        acc.record_decode_error();
        let s = acc.finish();
        assert_eq!(s.decode_errors, 2);
        assert_eq!(s.proto.truncated, 2);
        // decode errors do NOT inflate total_packets.
        assert_eq!(s.total_packets, 0);
    }

    #[test]
    fn top_talkers_sorted_desc_by_bytes_with_deterministic_tiebreak() {
        let mut acc = StatsAccumulator::new(StatsConfig::default());
        // a sends 1000 bytes, b sends 1000 bytes (tie), c sends 500.
        acc.observe_packet(&pkt(
            0,
            0,
            1000,
            Transport::Tcp,
            Some(ip4(10, 0, 0, 2)),
            Some(ip4(192, 168, 0, 9)),
            1,
            443,
            0,
        ));
        acc.observe_packet(&pkt(
            1,
            1,
            1000,
            Transport::Tcp,
            Some(ip4(10, 0, 0, 1)),
            Some(ip4(192, 168, 0, 9)),
            1,
            443,
            0,
        ));
        acc.observe_packet(&pkt(
            2,
            2,
            500,
            Transport::Tcp,
            Some(ip4(10, 0, 0, 3)),
            Some(ip4(172, 16, 0, 9)),
            1,
            443,
            0,
        ));
        let s = acc.finish();
        // The destination 192.168.0.9 received 2000 bytes -> heaviest.
        assert_eq!(s.top_talkers[0].ip, "192.168.0.9");
        assert_eq!(s.top_talkers[0].bytes, 2000);
        // Then 10.0.0.1 and 10.0.0.2 tie at 1000 bytes; tie-break asc IP string.
        assert_eq!(s.top_talkers[1].ip, "10.0.0.1");
        assert_eq!(s.top_talkers[2].ip, "10.0.0.2");
    }

    #[test]
    fn port_histogram_sorted_desc_by_pkts() {
        let mut acc = StatsAccumulator::new(StatsConfig::default());
        // port 443 seen 3 times, port 53 seen once.
        for i in 0..3 {
            acc.observe_packet(&pkt(
                i,
                i as i64,
                100,
                Transport::Tcp,
                Some(ip4(10, 0, 0, 1)),
                Some(ip4(10, 0, 0, 2)),
                5000,
                443,
                0,
            ));
        }
        acc.observe_packet(&pkt(
            3,
            3,
            100,
            Transport::Udp,
            Some(ip4(10, 0, 0, 1)),
            Some(ip4(10, 0, 0, 2)),
            5000,
            53,
            0,
        ));
        let s = acc.finish();
        assert_eq!(s.port_histogram[0].port, 443);
        assert_eq!(s.port_histogram[0].transport, "TCP");
        assert_eq!(s.port_histogram[0].pkts, 3);
        assert_eq!(s.port_histogram[1].port, 53);
        assert_eq!(s.port_histogram[1].transport, "UDP");
    }

    #[test]
    fn time_histogram_is_ascending_with_gaps_omitted() {
        let mut acc = StatsAccumulator::new(StatsConfig::default());
        // seconds 5, 5, 2 -> buckets {2:1, 5:2}; second 3/4 omitted.
        acc.observe_packet(&pkt(
            0,
            5_000_000_000,
            10,
            Transport::Tcp,
            Some(ip4(10, 0, 0, 1)),
            Some(ip4(10, 0, 0, 2)),
            1,
            443,
            0,
        ));
        acc.observe_packet(&pkt(
            1,
            5_500_000_000,
            10,
            Transport::Tcp,
            Some(ip4(10, 0, 0, 1)),
            Some(ip4(10, 0, 0, 2)),
            1,
            443,
            0,
        ));
        acc.observe_packet(&pkt(
            2,
            2_000_000_000,
            10,
            Transport::Tcp,
            Some(ip4(10, 0, 0, 1)),
            Some(ip4(10, 0, 0, 2)),
            1,
            443,
            0,
        ));
        let s = acc.finish();
        // A 3-second span stays at per-second granularity (well under the bucket cap).
        assert_eq!(s.time_bucket_secs, 1);
        assert_eq!(s.time_histogram.len(), 2);
        assert_eq!(s.time_histogram[0].epoch_sec, 2);
        assert_eq!(s.time_histogram[0].pkts, 1);
        assert_eq!(s.time_histogram[1].epoch_sec, 5);
        assert_eq!(s.time_histogram[1].pkts, 2);
    }

    #[test]
    fn choose_bucket_width_picks_smallest_nice_interval_under_cap() {
        // A short span fits at per-second granularity.
        assert_eq!(choose_bucket_width(0, 100, 1_000), 1);
        // Exactly at the cap (1000 buckets) still fits per-second.
        assert_eq!(choose_bucket_width(0, 999, 1_000), 1);
        // One second past the cap bumps to the next nice width (2 s -> 501 buckets).
        assert_eq!(choose_bucket_width(0, 1_000, 1_000), 2);
        // A ~25 h span with a 1000 cap lands on 2-minute buckets.
        assert_eq!(choose_bucket_width(0, 90_000, 1_000), 120);
        // Every chosen width is one of the published "nice" intervals.
        for &last in &[5_000i64, 50_000, 500_000, 5_000_000] {
            let w = choose_bucket_width(0, last, 1_000);
            assert!(
                NICE_BUCKET_WIDTHS_SECS.contains(&w),
                "width {w} for span {last} is not a nice interval"
            );
            assert!(aligned_bucket_count(0, last, w) <= 1_000);
        }
        // Negative (pre-epoch) seconds align without panicking and still honor the cap.
        let w = choose_bucket_width(-50_000, 40_000, 1_000);
        assert!(w >= 1 && aligned_bucket_count(-50_000, 40_000, w) <= 1_000);
    }

    #[test]
    fn long_capture_histogram_is_capped_and_conserves_packets() {
        // A ~25 h capture at per-second granularity would be ~90k buckets; re-bucketing must
        // collapse it to <= max_time_buckets adaptive buckets while conserving Σ pkts/bytes
        // (the invariant the golden/e2e tests assert).
        let cap = 600usize;
        let cfg = StatsConfig {
            max_time_buckets: cap,
            ..StatsConfig::default()
        };
        let mut acc = StatsAccumulator::new(cfg);
        let base_ns = 1_700_000_000i64 * 1_000_000_000;
        let span_secs = 90_000i64; // 25 hours
        let step = 30i64; // a packet every 30 s -> ~3001 distinct seconds (>> cap)
        let mut n = 0u64;
        let mut sec = 0i64;
        while sec <= span_secs {
            acc.observe_packet(&pkt(
                n,
                base_ns + sec * 1_000_000_000,
                100,
                Transport::Tcp,
                Some(ip4(10, 0, 0, 1)),
                Some(ip4(10, 0, 0, 2)),
                1234,
                443,
                0,
            ));
            n += 1;
            sec += step;
        }
        let s = acc.finish();

        assert!(
            s.time_histogram.len() <= cap,
            "bucket count {} exceeds cap {cap}",
            s.time_histogram.len()
        );
        assert!(
            s.time_bucket_secs > 1,
            "adaptive width should widen beyond per-second, got {}",
            s.time_bucket_secs
        );
        assert!(
            NICE_BUCKET_WIDTHS_SECS.contains(&s.time_bucket_secs),
            "width {} is not a nice interval",
            s.time_bucket_secs
        );

        // Σ conservation across re-bucketing.
        let hist_pkts: u64 = s.time_histogram.iter().map(|b| b.pkts).sum();
        assert_eq!(hist_pkts, s.total_packets, "Σ bucket.pkts == total_packets");
        let hist_bytes: u64 = s.time_histogram.iter().map(|b| b.bytes).sum();
        assert_eq!(hist_bytes, s.total_bytes, "Σ bucket.bytes == total_bytes");

        // Buckets are width-aligned and strictly ascending.
        let w = s.time_bucket_secs;
        let mut prev: Option<i64> = None;
        for b in &s.time_histogram {
            assert_eq!(
                b.epoch_sec.rem_euclid(w),
                0,
                "bucket start {} not aligned to width {w}",
                b.epoch_sec
            );
            if let Some(p) = prev {
                assert!(b.epoch_sec > p, "buckets must be strictly ascending");
            }
            prev = Some(b.epoch_sec);
        }
    }

    #[test]
    fn protocol_hierarchy_paths_and_order() {
        let mut acc = StatsAccumulator::new(StatsConfig::default());
        // big https flow vs small dns flow.
        acc.observe_packet(&pkt(
            0,
            0,
            1000,
            Transport::Tcp,
            Some(ip4(10, 0, 0, 1)),
            Some(ip4(10, 0, 0, 2)),
            5000,
            443,
            0,
        ));
        acc.observe_packet(&pkt(
            1,
            1,
            50,
            Transport::Udp,
            Some(ip4(10, 0, 0, 1)),
            Some(ip4(10, 0, 0, 2)),
            5000,
            53,
            0,
        ));
        let s = acc.finish();
        assert_eq!(s.protocol_hierarchy[0].path, "ip.tcp.https");
        assert_eq!(s.protocol_hierarchy[0].bytes, 1000);
        assert_eq!(s.protocol_hierarchy[1].path, "ip.udp.dns");
    }

    #[test]
    fn observe_flow_partitions_categories_and_counts_flows() {
        let mut acc = StatsAccumulator::new(StatsConfig::default());
        let f1 = flow(
            Transport::Tcp,
            ip4(10, 0, 0, 1),
            ip4(10, 0, 0, 2),
            Category::Web,
            5,
            100,
        );
        let f2 = flow(
            Transport::Udp,
            ip4(10, 0, 0, 3),
            ip4(10, 0, 0, 2),
            Category::Dns,
            2,
            40,
        );
        acc.observe_flow(&f1);
        acc.observe_flow(&f2);
        let s = acc.finish();
        assert_eq!(s.total_flows, 2);
        // Web slot.
        let web = &s.category_breakdown[category_index(Category::Web)];
        assert_eq!(web.flows, 1);
        assert_eq!(web.pkts, 5);
        // Sum of all flowed packets across categories == individual flow pkts.
        let flowed_pkts: u64 = s.category_breakdown.iter().map(|c| c.pkts).sum();
        assert_eq!(flowed_pkts, f1.total_pkts() + f2.total_pkts());
    }

    #[test]
    fn is_scanner_tracks_distinct_dst_ports_on_syn_only() {
        let mut acc = StatsAccumulator::new(StatsConfig::default());
        let src = ip4(10, 0, 0, 9);
        let syn = 0x02u8; // SYN, no ACK.
        for port in 1000u16..1010 {
            acc.observe_packet(&pkt(
                port as u64,
                0,
                40,
                Transport::Tcp,
                Some(src),
                Some(ip4(10, 0, 0, 2)),
                40000,
                port,
                syn,
            ));
        }
        // 10 distinct dst ports.
        assert!(acc.is_scanner(src, 10));
        assert!(acc.is_scanner(src, 5));
        assert!(!acc.is_scanner(src, 11));
        // Unknown source.
        assert!(!acc.is_scanner(ip4(1, 1, 1, 1), 1));
        // Non-SYN-only packets don't add to the spread.
        let synack = 0x12u8;
        acc.observe_packet(&pkt(
            99,
            0,
            40,
            Transport::Tcp,
            Some(src),
            Some(ip4(10, 0, 0, 2)),
            40000,
            2000,
            synack,
        ));
        assert!(!acc.is_scanner(src, 11));
    }

    #[test]
    fn bounded_map_preserves_heavy_hitters() {
        // cap = 1: only the heaviest survivor should remain.
        let cfg = StatsConfig {
            top_k_talkers: 50,
            top_k_ports: 50,
            top_k_protos: 30,
            max_tracked_keys: 1,
            top_k_ip_threats: 50,
            max_evidence_per_ip: 6,
            max_time_buckets: 1_000,
        };
        let mut acc = StatsAccumulator::new(cfg);
        // Talkers are tracked per IP endpoint, so a packet needs BOTH a src and dst IP
        // (`endpoints()` returns None otherwise -> counted as a non-IP frame). src 10.0.0.1
        // is inserted first with a huge byte count.
        acc.observe_packet(&pkt(
            0,
            0,
            10_000,
            Transport::Tcp,
            Some(ip4(10, 0, 0, 1)),
            Some(ip4(10, 0, 0, 2)),
            1234,
            80,
            0,
        ));
        // A later, tiny conversation must NOT evict the heavy hitter.
        acc.observe_packet(&pkt(
            1,
            0,
            1,
            Transport::Tcp,
            Some(ip4(10, 0, 0, 3)),
            Some(ip4(10, 0, 0, 4)),
            1234,
            80,
            0,
        ));
        let s = acc.finish();
        // Only the heavy hitter remains.
        assert_eq!(s.top_talkers.len(), 1);
        assert_eq!(s.top_talkers[0].ip, "10.0.0.1");
        assert_eq!(s.top_talkers[0].bytes, 10_000);
    }

    #[test]
    fn ipv6_renders_lowercase_rfc5952() {
        let mut acc = StatsAccumulator::new(StatsConfig::default());
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        acc.observe_packet(&pkt(
            0,
            0,
            100,
            Transport::Tcp,
            Some(v6),
            Some(ip4(10, 0, 0, 1)),
            5000,
            443,
            0,
        ));
        let s = acc.finish();
        let found = s.top_talkers.iter().any(|t| t.ip == "2001:db8::1");
        assert!(found, "talkers: {:?}", s.top_talkers);
    }

    #[test]
    fn apply_findings_uplifts_both_endpoint_cards() {
        use crate::model::finding::{Finding, FindingKind};
        let mut acc = StatsAccumulator::new(StatsConfig::default());
        let bot = ip4(10, 0, 0, 5);
        let c2 = ip4(8, 8, 8, 8);
        // Seed both IPs with a benign Info-level flow so each has a baseline card.
        let f = flow(Transport::Tcp, bot, c2, Category::Web, 2, 100);
        let sc = ScoredFlow {
            severity: Severity::Info,
            score: 5,
            evidence: vec!["category web (+3)".to_string()],
            attack: vec![],
            terms: vec![],
        };
        acc.observe_scored_flow(&f, &sc);

        let finding = Finding {
            kind: FindingKind::Beacon,
            severity: Severity::High,
            score: 70,
            title: "Periodic beacon".to_string(),
            src_ip: "10.0.0.5".to_string(),
            dst_ip: Some("8.8.8.8".to_string()),
            dst_port: Some(443),
            attack: vec!["T1071".to_string()],
            evidence: vec!["periodic beaconing: 8 contacts to 8.8.8.8:443".to_string()],
            interval_ns: Some(60_000_000_000),
            jitter_cv: Some(0.01),
            contacts: Some(8),
        };
        acc.apply_findings(&[finding]);

        let s = acc.finish();
        for who in ["10.0.0.5", "8.8.8.8"] {
            let card = s
                .ip_threats
                .iter()
                .find(|t| t.ip == who)
                .unwrap_or_else(|| panic!("no threat card for {who}"));
            assert_eq!(card.severity, Severity::High, "{who} not uplifted to High");
            assert!(card.score >= 70, "{who} score {} < 70", card.score);
            assert!(
                card.attack.iter().any(|a| a == "T1071"),
                "{who} missing T1071: {:?}",
                card.attack
            );
            assert!(
                card.evidence.iter().any(|e| e.contains("beaconing")),
                "{who} missing beacon evidence: {:?}",
                card.evidence
            );
        }
    }

    #[test]
    fn apply_findings_never_lowers_a_higher_card() {
        use crate::model::finding::{Finding, FindingKind};
        let mut acc = StatsAccumulator::new(StatsConfig::default());
        let bot = ip4(10, 0, 0, 5);
        let c2 = ip4(8, 8, 8, 8);
        // Seed a Critical IOC flow for the pair.
        let mut f = flow(Transport::Tcp, bot, c2, Category::C2, 2, 100);
        f.severity = Severity::Critical;
        f.threat_score = 95;
        f.ioc = true;
        let sc = ScoredFlow {
            severity: Severity::Critical,
            score: 95,
            evidence: vec!["ioc: endpoint ip on threat feed (+35)".to_string()],
            attack: vec!["T1071".to_string()],
            terms: vec![],
        };
        acc.observe_scored_flow(&f, &sc);

        // A Medium beacon finding must NOT downgrade the Critical card.
        let finding = Finding {
            kind: FindingKind::Beacon,
            severity: Severity::Medium,
            score: 45,
            title: "Periodic beacon".to_string(),
            src_ip: "10.0.0.5".to_string(),
            dst_ip: Some("8.8.8.8".to_string()),
            dst_port: Some(443),
            attack: vec![],
            evidence: vec!["periodic beaconing".to_string()],
            interval_ns: Some(1),
            jitter_cv: Some(0.0),
            contacts: Some(8),
        };
        acc.apply_findings(&[finding]);

        let s = acc.finish();
        let card = s.ip_threats.iter().find(|t| t.ip == "8.8.8.8").unwrap();
        assert_eq!(card.severity, Severity::Critical);
        assert!(card.score >= 95);
    }

    #[test]
    fn sni_domains_aggregate_ranked_and_filtered() {
        use crate::score::ScoredFlow;

        let mut acc = StatsAccumulator::new(StatsConfig::default());

        // Helper: build a FlowRecord with total_bytes() == bytes_total (1 pkt).
        let make_flow = |lo: IpAddr, hi: IpAddr, bytes: u64, sni: Option<&str>| {
            let mut f = flow(Transport::Tcp, lo, hi, Category::Web, 1, bytes);
            f.sni = sni.map(|s| s.to_string());
            f
        };

        let sc = || ScoredFlow {
            severity: crate::model::severity::Severity::Info,
            score: 0,
            evidence: vec![],
            attack: vec![],
            terms: vec![],
        };

        // "a.example" — 200 bytes, 1 flow.
        let f1 = make_flow(ip4(10, 0, 0, 1), ip4(10, 0, 0, 2), 200, Some("a.example"));
        acc.observe_scored_flow(&f1, &sc());

        // "B.Example" — 100 bytes, 1 flow (should merge with "b.example" → 150 bytes, 2 flows).
        let f2 = make_flow(ip4(10, 0, 0, 3), ip4(10, 0, 0, 4), 100, Some("B.Example"));
        acc.observe_scored_flow(&f2, &sc());

        // "b.example" — 50 bytes, 1 flow (case-insensitive merge with "B.Example").
        let f3 = make_flow(ip4(10, 0, 0, 5), ip4(10, 0, 0, 6), 50, Some("b.example"));
        acc.observe_scored_flow(&f3, &sc());

        // "1.2.3.4" — IP literal, must be skipped.
        let f4 = make_flow(ip4(10, 0, 0, 7), ip4(10, 0, 0, 8), 99, Some("1.2.3.4"));
        acc.observe_scored_flow(&f4, &sc());

        // "" — empty, must be skipped.
        let f5 = make_flow(ip4(10, 0, 0, 9), ip4(10, 0, 0, 10), 99, Some(""));
        acc.observe_scored_flow(&f5, &sc());

        let summary = acc.finish();
        let hosts: Vec<&str> = summary
            .domain_threats
            .iter()
            .map(|d| d.host.as_str())
            .collect();
        assert_eq!(hosts, vec!["a.example", "b.example"]); // desc by bytes (200 > 150)
        let b = summary
            .domain_threats
            .iter()
            .find(|d| d.host == "b.example")
            .unwrap();
        assert_eq!(b.bytes, 150);
        assert_eq!(b.flows, 2);
        assert!(summary
            .domain_threats
            .iter()
            .all(|d| d.reputation.is_empty()));
    }

    #[test]
    fn ip_threat_evidence_reflects_worst_flow_not_arrival_order() {
        // An IP whose several benign flows close BEFORE its one Critical IOC flow must still
        // report evidence that justifies the Critical/score verdict (IOC + floor strings),
        // not the benign strings that arrived first and would otherwise fill the cap.
        let mut acc = StatsAccumulator::new(StatsConfig::default());
        let attacker = ip4(10, 0, 0, 7);
        let peer = ip4(10, 0, 0, 8);

        // Three benign web flows, each contributing two evidence strings (6 == the cap),
        // closing first.
        for _ in 0..3 {
            let mut f = flow(Transport::Tcp, attacker, peer, Category::Web, 4, 200);
            f.severity = Severity::Info;
            f.threat_score = 0;
            f.ioc = false;
            let sc = ScoredFlow {
                severity: Severity::Info,
                score: 0,
                evidence: vec![
                    "category web (+3)".to_string(),
                    "all-internal peers (-10)".to_string(),
                ],
                attack: vec![],
                terms: vec![],
            };
            acc.observe_scored_flow(&f, &sc);
        }

        // Then the worst flow: a Critical C2 flow with an IOC hit and the floor reasons.
        let mut worst = flow(Transport::Tcp, attacker, peer, Category::C2, 4, 200);
        worst.severity = Severity::Critical;
        worst.threat_score = 90;
        worst.ioc = true;
        let worst_sc = ScoredFlow {
            severity: Severity::Critical,
            score: 90,
            evidence: vec![
                "ioc: endpoint ip on threat feed (+35)".to_string(),
                "floor: ioc + c2/anomalous forces Critical (>= 90)".to_string(),
            ],
            attack: vec!["T1071".to_string()],
            terms: vec![],
        };
        acc.observe_scored_flow(&worst, &worst_sc);

        let s = acc.finish();
        let row = s
            .ip_threats
            .iter()
            .find(|t| t.ip == "10.0.0.7")
            .expect("attacker ip_threat row present");
        assert_eq!(row.severity, Severity::Critical);
        assert_eq!(row.score, 90);
        // The evidence must contain the IOC + Critical-floor strings of the worst flow.
        assert!(
            row.evidence
                .iter()
                .any(|e| e.contains("ioc: endpoint ip on threat feed")),
            "evidence missing IOC string: {:?}",
            row.evidence
        );
        assert!(
            row.evidence.iter().any(|e| e.contains("forces Critical")),
            "evidence missing Critical-floor string: {:?}",
            row.evidence
        );
    }

    #[test]
    fn ip_threat_rolls_up_matched_fingerprint() {
        let mut acc = StatsAccumulator::new(StatsConfig::default());
        // Build a TLS flow lo (10.0.0.1) -> hi (10.0.0.2) with a matched fingerprint.
        let mut f = flow(
            Transport::Tcp,
            ip4(10, 0, 0, 1),
            ip4(10, 0, 0, 2),
            Category::Web,
            2,
            100,
        );
        f.ja3 = Some("aaa".into());
        f.fingerprint_label = Some("CobaltStrike".into());
        let sc = ScoredFlow {
            severity: Severity::High,
            score: 80,
            evidence: vec![],
            attack: vec![],
            terms: vec![],
        };
        acc.observe_flow(&f);
        acc.observe_scored_flow(&f, &sc);
        // Observing the same flow again must NOT duplicate the fingerprint hit.
        acc.observe_flow(&f);
        acc.observe_scored_flow(&f, &sc);

        let summary = acc.finish();
        // lo_ip is the canonical lower address; look it up by string.
        let t = summary
            .ip_threats
            .iter()
            .find(|t| t.ip == "10.0.0.1")
            .expect("lo_ip threat card present");
        assert_eq!(
            t.fingerprints.len(),
            1,
            "dedup must collapse identical hits"
        );
        assert_eq!(t.fingerprints[0].label, "CobaltStrike");
        assert_eq!(t.fingerprints[0].ja3.as_deref(), Some("aaa"));
        assert!(t.fingerprints[0].ja4.is_none());
    }

    #[test]
    fn ip_threat_has_no_fingerprints_when_unmatched() {
        // A flow with ja3 set but fingerprint_label None must produce zero fingerprint hits.
        let mut acc = StatsAccumulator::new(StatsConfig::default());
        let mut f = flow(
            Transport::Tcp,
            ip4(10, 0, 0, 3),
            ip4(10, 0, 0, 4),
            Category::Web,
            2,
            100,
        );
        f.ja3 = Some("bbb".into());
        // fingerprint_label left as None (the default).
        let sc = ScoredFlow {
            severity: Severity::Info,
            score: 3,
            evidence: vec![],
            attack: vec![],
            terms: vec![],
        };
        acc.observe_flow(&f);
        acc.observe_scored_flow(&f, &sc);

        let summary = acc.finish();
        let t = summary
            .ip_threats
            .iter()
            .find(|t| t.ip == "10.0.0.3")
            .expect("threat card present");
        assert!(
            t.fingerprints.is_empty(),
            "unmatched ja3 must not produce fingerprint hits"
        );
    }

    #[test]
    fn ip_threat_carries_worst_flow_score_terms() {
        // Scenario: three benign Info flows close first (they have no meaningful terms),
        // then the worst C2 flow closes with additive terms. The IpThreat card must carry
        // the worst flow's terms — not the benign flows' empty/placeholder terms.
        use crate::model::summary::ScoreTerm;

        let mut acc = StatsAccumulator::new(StatsConfig::default());
        let attacker = ip4(10, 0, 0, 11);
        let c2_server = ip4(198, 51, 100, 1);

        // Benign Info flows (arrive first).
        for _ in 0..3 {
            let mut f = flow(Transport::Tcp, attacker, c2_server, Category::Web, 2, 100);
            f.severity = Severity::Info;
            f.threat_score = 3;
            let sc = ScoredFlow {
                severity: Severity::Info,
                score: 3,
                evidence: vec!["category web (+3)".to_string()],
                attack: vec![],
                terms: vec![ScoreTerm {
                    label: "category web".to_string(),
                    points: 3,
                }],
            };
            acc.observe_flow(&f);
            acc.observe_scored_flow(&f, &sc);
        }

        // Worst flow: C2, with additive terms matching the brief's assertion.
        let mut worst = flow(Transport::Tcp, attacker, c2_server, Category::C2, 4, 500);
        worst.severity = Severity::High;
        worst.threat_score = 45;
        let worst_sc = ScoredFlow {
            severity: Severity::High,
            score: 45,
            evidence: vec!["category c2 (+45)".to_string()],
            attack: vec!["T1071".to_string()],
            terms: vec![ScoreTerm {
                label: "category c2".to_string(),
                points: 45,
            }],
        };
        acc.observe_flow(&worst);
        acc.observe_scored_flow(&worst, &worst_sc);

        let s = acc.finish();
        let card = s
            .ip_threats
            .iter()
            .find(|c| c.ip == "10.0.0.11")
            .expect("attacker ip_threat row present");

        // The card must carry the worst flow's terms (category c2, +45).
        assert!(
            card.score_terms
                .iter()
                .any(|t| t.label == "category c2" && t.points == 45),
            "score_terms must reflect worst flow: {:?}",
            card.score_terms
        );
        // The benign "category web" term must NOT appear (terms are worst-flow only).
        assert!(
            !card.score_terms.iter().any(|t| t.label == "category web"),
            "benign terms must not appear in score_terms: {:?}",
            card.score_terms
        );
    }
}
