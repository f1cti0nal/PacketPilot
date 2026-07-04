//! Behavioral detection substrate.
//!
//! This module turns the engine from "classify flows" into "measure behavior". It holds the
//! streaming, bounded-memory primitives that cross-flow detectors (C2 beaconing, host sweeps,
//! data exfiltration) consume — none of which can be expressed on a single aggregated
//! [`FlowRecord`] row.
//!
//! The cornerstone primitive is [`StreamStats`]: an O(1)-memory running mean/variance over a
//! stream of samples (Welford's online algorithm). For beaconing, the samples are the
//! inter-arrival gaps between successive contacts from a host to a destination; a regular
//! beacon has a near-zero **coefficient of variation** (low jitter relative to its period),
//! while ad-hoc traffic does not. Retaining only five fixed-size fields — never the samples
//! themselves — keeps detection within the engine's bounded-memory contract regardless of how
//! many contacts a flow makes.

pub mod rules;

/// Streaming mean/variance over a stream of `i64` samples using Welford's online algorithm.
///
/// Memory is O(1): the individual samples are never retained, only five fixed-size running
/// fields. Variance is reported as the **population** variance (divide by `count`), which is
/// the appropriate jitter measure for a fixed observed series of inter-arrival gaps.
#[derive(Debug, Clone)]
pub struct StreamStats {
    count: u64,
    mean: f64,
    /// Sum of squares of differences from the running mean (Welford's M2).
    m2: f64,
    min: i64,
    max: i64,
}

impl Default for StreamStats {
    fn default() -> Self {
        StreamStats::new()
    }
}

impl StreamStats {
    /// An empty accumulator.
    pub fn new() -> StreamStats {
        StreamStats {
            count: 0,
            mean: 0.0,
            m2: 0.0,
            min: i64::MAX,
            max: i64::MIN,
        }
    }

    /// Fold one sample into the running statistics.
    pub fn push(&mut self, sample: i64) {
        self.count += 1;
        let x = sample as f64;
        let delta = x - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = x - self.mean;
        self.m2 += delta * delta2;
        if sample < self.min {
            self.min = sample;
        }
        if sample > self.max {
            self.max = sample;
        }
    }

    /// Number of samples observed.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Running arithmetic mean; `0.0` when empty.
    pub fn mean(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.mean
        }
    }

    /// Population variance (`M2 / count`); `0.0` when fewer than two samples.
    pub fn variance(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            self.m2 / self.count as f64
        }
    }

    /// Population standard deviation (`sqrt(variance)`).
    pub fn stddev(&self) -> f64 {
        self.variance().sqrt()
    }

    /// Coefficient of variation (`stddev / mean`); `0.0` when the mean is zero or empty.
    ///
    /// This is the periodicity discriminator: a regular beacon yields a value near zero, ad-hoc
    /// traffic yields a large one.
    pub fn cv(&self) -> f64 {
        if self.count == 0 || self.mean == 0.0 {
            0.0
        } else {
            self.stddev() / self.mean.abs()
        }
    }

    /// Smallest sample seen; `0` when empty.
    pub fn min(&self) -> i64 {
        if self.count == 0 {
            0
        } else {
            self.min
        }
    }

    /// Largest sample seen; `0` when empty.
    pub fn max(&self) -> i64 {
        if self.count == 0 {
            0
        } else {
            self.max
        }
    }
}

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::model::packet::{CredScheme, DownloadKind, PiiKind, StratumRole, Transport};
use crate::tls::{CertIssue, WeakTlsReason};

/// Identity of a directed "destination contact channel": one source reaching one
/// `(dst_ip, dst_port)` service. Beaconing periodicity is measured per channel because each
/// callback is a *separate* flow (new ephemeral source port), so the signal cannot live on a
/// single aggregated [`crate::model::flow::FlowRecord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContactKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dst_port: u16,
}

impl ContactKey {
    /// Construct a channel key.
    pub fn new(src: IpAddr, dst: IpAddr, dst_port: u16) -> ContactKey {
        ContactKey { src, dst, dst_port }
    }
}

/// The streaming inter-arrival series for one [`ContactKey`]: how regularly a source contacts
/// a destination. Holds only a counter, the previous timestamp, and a fixed-size
/// [`StreamStats`] over the gaps — O(1) memory per channel regardless of contact count.
#[derive(Debug, Clone, Default)]
pub struct ContactSeries {
    contacts: u64,
    prev_ts_ns: Option<i64>,
    gaps: StreamStats,
    /// Bytes sent client -> server across this channel (the exfil-relevant direction).
    bytes_out: u64,
    /// Bytes sent server -> client across this channel.
    bytes_in: u64,
}

impl ContactSeries {
    /// An empty series.
    pub fn new() -> ContactSeries {
        ContactSeries::default()
    }

    /// Record one contact at `ts_ns`. Out-of-order timestamps clamp the gap to zero so a
    /// non-monotonic capture never produces a negative interval.
    pub fn observe(&mut self, ts_ns: i64) {
        self.contacts += 1;
        if let Some(prev) = self.prev_ts_ns {
            self.gaps.push((ts_ns - prev).max(0));
        }
        self.prev_ts_ns = Some(ts_ns);
    }

    /// Number of contacts recorded.
    pub fn contacts(&self) -> u64 {
        self.contacts
    }

    /// Mean inter-contact gap in nanoseconds (the candidate beacon period); `0.0` with fewer
    /// than two contacts.
    pub fn interval_ns(&self) -> f64 {
        self.gaps.mean()
    }

    /// Coefficient of variation of the inter-contact gaps — the periodicity score (near zero
    /// == regular beacon).
    pub fn jitter_cv(&self) -> f64 {
        self.gaps.cv()
    }

    /// Fold directional byte counts for this channel.
    pub fn add_bytes(&mut self, out: u64, inb: u64) {
        self.bytes_out = self.bytes_out.saturating_add(out);
        self.bytes_in = self.bytes_in.saturating_add(inb);
    }

    /// Total bytes sent client -> server on this channel.
    pub fn bytes_out(&self) -> u64 {
        self.bytes_out
    }

    /// Total bytes sent server -> client on this channel.
    pub fn bytes_in(&self) -> u64 {
        self.bytes_in
    }
}

/// A destination channel that looks like a periodic beacon.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BeaconCandidate {
    pub key: ContactKey,
    pub contacts: u64,
    pub interval_ns: f64,
    pub jitter_cv: f64,
}

/// A destination channel with a large asymmetric outbound transfer (exfil shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExfilCandidate {
    pub key: ContactKey,
    pub bytes_out: u64,
    pub bytes_in: u64,
}

/// A `(source, port)` pair that reached many distinct hosts (horizontal sweep shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepCandidate {
    pub src: IpAddr,
    pub dst_port: u16,
    pub hosts: usize,
}

/// A `(source, host)` pair where the source probed many distinct ports — a vertical port scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortScanCandidate {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub ports: usize,
}

/// An established remote-administration session that crosses the internal↔external boundary — the
/// exposed-remote-access shape (the direction lateral movement excludes). One endpoint is a public
/// address, the other private, on a remote-admin port, with a real bidirectional session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExposedRemoteAccessCandidate {
    /// The public-side peer.
    pub external: IpAddr,
    /// The private-side peer.
    pub internal: IpAddr,
    /// The remote-administration service port.
    pub port: u16,
    /// `true` = external is the client (inbound exposure); `false` = internal is the client
    /// (outbound pivot / reverse channel).
    pub inbound: bool,
    /// Contacts (connections) observed on this channel.
    pub sessions: u64,
}

/// A flow that transferred at least this many *wire* bytes in BOTH directions is treated as a real
/// session, not a port-scan probe (a SYN/RST probe stays far below this each way). Mirrors the
/// lateral-movement detector's `min_session_bytes` floor.
const SCAN_SESSION_BYTES: u64 = 512;

/// A flow whose *client→server* wire bytes stay below this is a half-open / abandoned connection —
/// the client sent only handshake control (SYN/ACK/RST), never an application request. A real client
/// (even a tiny request, a health check, an HTTP 204) sends a request packet and exceeds the floor,
/// so this cleanly separates a SYN/TCP-DoS flood from a busy small-response service. Deliberately
/// far stricter than `SCAN_SESSION_BYTES` (and a different question — "did the client make a
/// request?", not "did the flow exchange a session?"). ~256 leaves headroom for a couple of
/// retransmitted SYNs while staying below any real request (≥ ~275 B with the handshake).
const SYN_FLOOD_HALF_OPEN_BYTES: u64 = 256;

/// An IP claimed by many distinct MAC addresses via ARP — an ARP cache-poisoning candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpSpoofCandidate {
    pub ip: IpAddr,
    /// Count of distinct MAC addresses observed claiming this IP.
    pub macs: usize,
}

/// A source that presented a known attack-tool HTTP User-Agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolUaCandidate {
    pub src: IpAddr,
    /// The matched tool label (e.g. `"sqlmap"`).
    pub tool: &'static str,
    /// Number of requests from this source carrying a tool User-Agent.
    pub hits: u64,
    /// One example User-Agent string.
    pub sample: String,
}

/// A `(client, server)` pair where the client downloaded a disguised executable (an executable body
/// served behind a benign `Content-Type`) — a file-type masquerade candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisguisedDownloadCandidate {
    pub client: IpAddr,
    pub server: IpAddr,
    /// The true (magic-derived) file class — always [`DownloadKind::Executable`] for now.
    pub kind: DownloadKind,
    /// Number of disguised responses on this channel.
    pub hits: u64,
}

/// A `(miner, pool)` channel running the cleartext Stratum mining protocol — a cryptomining candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptominingCandidate {
    /// The mining host (the Stratum client).
    pub miner: IpAddr,
    /// The mining pool (the Stratum server).
    pub pool: IpAddr,
    /// Total Stratum messages observed on this channel.
    pub messages: u64,
}

/// A `(target, port)` service hit by many half-open connections — a SYN-flood / TCP-DoS candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynFloodCandidate {
    pub dst: IpAddr,
    pub dst_port: u16,
    /// Number of incomplete (never-completed) connections to this service.
    pub incomplete: u64,
    /// Distinct source IPs involved (1 = single-source flood, many = distributed).
    pub sources: usize,
}

/// Cap on distinct MACs tracked per IP — far above the detection threshold, so the count is exact in
/// practice while peak memory stays bounded on a pathological capture.
const MAX_ARP_MACS: usize = 64;

/// A channel with many connection attempts to one authentication service (brute-force shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BruteForceCandidate {
    pub key: ContactKey,
    pub attempts: u64,
}

/// A `(source, admin-port)` pair that opened established sessions to several distinct hosts
/// (lateral-movement shape). `targets` are the distinct destinations whose channel carried a
/// real bidirectional session; internality is left to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LateralCandidate {
    pub src: IpAddr,
    pub dst_port: u16,
    pub targets: Vec<IpAddr>,
}

/// A `(source, dst, dst_port)` channel that transmitted credentials in cleartext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleartextCredCandidate {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dst_port: u16,
    pub scheme: CredScheme,
    pub exposures: u64,
}

/// A `(source, dst, dst_port)` channel that transmitted plaintext PII.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PiiCandidate {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dst_port: u16,
    pub kind: PiiKind,
    pub exposures: u64,
}

/// Per-`(source, resolver)` DNS query statistics.
#[derive(Debug, Clone, Default)]
struct DnsStats {
    queries: u64,
    /// Sum of the per-query most-dense-label Shannon entropy (avg = sum / queries).
    entropy_sum: f64,
    max_label_len: u16,
    /// One example qname for the finding evidence.
    sample: Option<String>,
}

/// Per-source DGA statistics: the set of distinct algorithmically-random *registered* domains a
/// host resolved. DGA malware cycles through many such domains hunting for its live C2 rendezvous,
/// so the load-bearing signal is the count of *distinct* suspect registered domains — not any single
/// random-looking name (a lone CDN hash is benign). The set is bounded to cap memory.
#[derive(Debug, Clone, Default)]
struct DgaStats {
    /// Distinct DGA-suspect registered domains seen from this source (bounded by `MAX_DGA_SUSPECT`).
    suspect: HashSet<String>,
    /// Total resolvable (>= 2-label) DNS queries from this source, for evidence context.
    queries: u64,
    /// One example suspect registered domain for the finding evidence.
    sample: Option<String>,
}

/// Cap on distinct suspect domains tracked per source — far above any detection threshold, so the
/// count is exact in practice while peak memory stays bounded on a pathological capture.
const MAX_DGA_SUSPECT: usize = 256;

/// Per-`(source, dst)` ICMP echo statistics for covert-channel (tunneling) detection.
#[derive(Debug, Clone, Default)]
struct IcmpStats {
    /// Number of echo request/reply messages seen on this channel.
    echoes: u64,
    /// Total ICMP echo *data* bytes (excluding the 8-byte ICMP header).
    data_bytes: u64,
    /// Largest single echo data payload.
    max_data: u32,
}

/// A `(source, dst)` channel whose ICMP echo traffic looks like a covert tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpTunnelCandidate {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub echoes: u64,
    pub data_bytes: u64,
    pub max_data: u32,
    /// Mean echo data payload (bytes).
    pub mean_data: u64,
}

/// A `(source, resolver)` channel whose DNS queries look like tunneling / DGA.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsTunnelCandidate {
    pub src: IpAddr,
    pub resolver: IpAddr,
    pub queries: u64,
    pub avg_entropy: f64,
    pub max_label_len: u16,
    pub sample: Option<String>,
}

/// A source whose DNS resolutions look like domain-generation-algorithm activity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DgaCandidate {
    pub src: IpAddr,
    /// Count of distinct algorithmically-random registered domains resolved.
    pub distinct_domains: u32,
    /// Total resolvable DNS queries from this source (context for the suspect ratio).
    pub queries: u64,
    /// One example suspect registered domain.
    pub sample: Option<String>,
}

/// A server's leaf certificate health issues, as observed on a `(client -> server:port)` flow.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TlsCertObservation {
    issues: Vec<CertIssue>,
    subject_cn: Option<String>,
    sni: Option<String>,
}

/// A `(client, server, server_port)` flow whose server presented a problematic TLS certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCertCandidate {
    pub client: IpAddr,
    pub server: IpAddr,
    pub server_port: u16,
    pub issues: Vec<CertIssue>,
    pub subject_cn: Option<String>,
    pub sni: Option<String>,
}

/// The weak / deprecated TLS a server negotiated on a `(client -> server:port)` flow.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WeakTlsObservation {
    version: u16,
    cipher: u16,
    reasons: Vec<WeakTlsReason>,
}

/// A `(client, server, server_port)` flow that negotiated weak or deprecated TLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeakTlsCandidate {
    pub client: IpAddr,
    pub server: IpAddr,
    pub server_port: u16,
    pub version: u16,
    pub cipher: u16,
    pub reasons: Vec<WeakTlsReason>,
}

/// Tuning for the behavioral tracker. Both caps keep memory bounded on adversarial captures.
#[derive(Debug, Clone)]
pub struct DetectConfig {
    /// Cap on distinct contact channels (and distinct fan-out sources) tracked.
    pub max_tracked_keys: usize,
    /// Cap on distinct destination hosts retained per source for sweep detection.
    pub max_fanout_per_src: usize,
}

impl Default for DetectConfig {
    fn default() -> Self {
        DetectConfig {
            max_tracked_keys: 2_000_000,
            max_fanout_per_src: 4096,
        }
    }
}

/// Streaming, bounded cross-flow behavioral tracker.
///
/// Fed one *contact* (a new connection's directed `src -> dst:port` + timestamp) at a time, it
/// maintains (a) a per-channel inter-arrival series for beaconing and (b) a per-`(source, port)`
/// set of distinct destination hosts for horizontal sweep detection. Keying the fan-out on the
/// destination port (not the source alone) distinguishes a one-port-many-hosts sweep from a
/// busy client talking to many hosts across assorted ports. Both maps degrade gracefully at
/// capacity (a brand-new key is dropped) so peak memory stays bounded.
pub struct BehaviorTracker {
    cfg: DetectConfig,
    channels: HashMap<ContactKey, ContactSeries>,
    fanout: HashMap<(IpAddr, u16), HashSet<IpAddr>>,
    /// Per-`(source, host)` set of distinct destination ports probed — the vertical port-scan
    /// signal (the orthogonal axis to `fanout`'s horizontal sweep). Bounded in both dimensions.
    port_scan: HashMap<(IpAddr, IpAddr), HashSet<u16>>,
    /// Per-`(source, resolver)` DNS query statistics for tunneling / DGA detection.
    dns: HashMap<(IpAddr, IpAddr), DnsStats>,
    /// Per-`(source, dst, dst_port)` cleartext credential exposures: the sniffed scheme and the
    /// number of packets that exposed a credential on that channel.
    creds: HashMap<(IpAddr, IpAddr, u16), (CredScheme, u64)>,
    /// Per-`(source, dst, dst_port)` plaintext PII exposures: the sniffed kind and the number of
    /// packets that exposed PII on that channel.
    pii: HashMap<(IpAddr, IpAddr, u16), (PiiKind, u64)>,
    /// Per-`(client, server, server_port)` TLS server-certificate health observations.
    tls_certs: HashMap<(IpAddr, IpAddr, u16), TlsCertObservation>,
    /// Per-`(client, server, server_port)` weak / deprecated TLS observations.
    weak_tls: HashMap<(IpAddr, IpAddr, u16), WeakTlsObservation>,
    /// Per-`(source, dst)` ICMP echo statistics for covert-channel detection.
    icmp: HashMap<(IpAddr, IpAddr), IcmpStats>,
    /// Per-source DGA statistics (distinct algorithmically-random registered domains resolved).
    dga: HashMap<IpAddr, DgaStats>,
    /// Per-IP set of distinct MAC addresses that claimed it via ARP — the ARP cache-poisoning
    /// signal (one IP claimed by multiple MACs). Bounded in both dimensions.
    arp: HashMap<IpAddr, HashSet<[u8; 6]>>,
    /// Per-`(target, port)` count of half-open / never-completed connections + the distinct sources
    /// — the SYN-flood / TCP-DoS signal. Bounded (the source set is capped).
    syn_flood: HashMap<(IpAddr, u16), SynFloodStat>,
    /// Per-source attack-tool identified by its HTTP User-Agent. Bounded by `max_tracked_keys`.
    tool_ua: HashMap<IpAddr, ToolUaStat>,
    /// Per-`(client, server)` count of disguised executable downloads (an executable body served
    /// behind a benign `Content-Type`). Bounded by `max_tracked_keys`.
    disguised_dl: HashMap<(IpAddr, IpAddr), DisguisedDlStat>,
    /// Per-`(miner, pool)` cleartext Stratum (mining) message tallies. Bounded by `max_tracked_keys`.
    mining: HashMap<(IpAddr, IpAddr), StratumStat>,
}

/// Per-`(miner, pool)` Stratum statistics: how many miner-side and pool-side messages were seen. A
/// pool-side message (only a real pool sends `mining.notify`) is the strong confirmation of mining.
#[derive(Debug, Clone, Default)]
struct StratumStat {
    /// Miner→pool messages (subscribe / authorize / submit).
    miner_msgs: u64,
    /// Pool→miner messages (notify / set_difficulty) — only a real pool sends these.
    pool_msgs: u64,
}

/// Per-`(client, server)` disguised-download observation: the true (magic-derived) file class and how
/// many such masquerading responses were seen.
#[derive(Debug, Clone)]
struct DisguisedDlStat {
    kind: DownloadKind,
    hits: u64,
}

/// Per-source attack-tool User-Agent observation: the matched tool, how many requests carried it,
/// and one example User-Agent string for the evidence.
#[derive(Debug, Clone)]
struct ToolUaStat {
    tool: &'static str,
    hits: u64,
    sample: String,
}

/// High-confidence attack-tool / scanner User-Agent substrings (matched case-insensitively) → the
/// tool label. Deliberately limited to *unambiguous* tool signatures — no dual-use client
/// (`curl` / `python-requests` / `wget`) a legitimate script also uses — so a match is a real
/// indicator, not noise.
#[rustfmt::skip]
const TOOL_USER_AGENTS: &[(&str, &str)] = &[
    ("sqlmap", "sqlmap"),
    ("nikto", "Nikto"),
    ("nmap scripting engine", "Nmap NSE"),
    ("masscan", "masscan"),
    ("zgrab", "zgrab"),
    ("nuclei", "Nuclei"),
    ("gobuster", "Gobuster"),
    ("dirbuster", "DirBuster"),
    ("feroxbuster", "feroxbuster"),
    ("wpscan", "WPScan"),
    // NB: "hydra" is deliberately NOT listed — it is an ordinary word / product name (the Hydra
    // livecoding tool, config frameworks, CI systems) that collides with benign User-Agents, and
    // THC-Hydra is a login brute-forcer (caught by the brute-force detector) that rarely emits an
    // HTTP UA. Every entry here must be a *coined* tool token with no realistic benign collision.
    ("nessus", "Nessus"),
    ("openvas", "OpenVAS"),
    ("acunetix", "Acunetix"),
    ("() {", "Shellshock probe"),
];

/// Match a User-Agent against the known-tool table, returning the tool label of the first hit.
fn match_tool_ua(ua: &str) -> Option<&'static str> {
    let lower = ua.to_ascii_lowercase();
    TOOL_USER_AGENTS
        .iter()
        .find(|(needle, _)| lower.contains(needle))
        .map(|(_, label)| *label)
}

/// Per-`(target, port)` SYN-flood statistics: how many half-open connections, from how many sources.
#[derive(Debug, Clone, Default)]
struct SynFloodStat {
    /// Count of incomplete (no completed bidirectional session) connections to this target service.
    incomplete: u64,
    /// Distinct source IPs (bounded) — distinguishes a single-source flood from a distributed one.
    sources: HashSet<IpAddr>,
}

impl BehaviorTracker {
    /// Create an empty tracker.
    pub fn new(cfg: DetectConfig) -> BehaviorTracker {
        BehaviorTracker {
            cfg,
            channels: HashMap::new(),
            fanout: HashMap::new(),
            port_scan: HashMap::new(),
            dns: HashMap::new(),
            creds: HashMap::new(),
            pii: HashMap::new(),
            tls_certs: HashMap::new(),
            weak_tls: HashMap::new(),
            icmp: HashMap::new(),
            dga: HashMap::new(),
            arp: HashMap::new(),
            syn_flood: HashMap::new(),
            tool_ua: HashMap::new(),
            disguised_dl: HashMap::new(),
            mining: HashMap::new(),
        }
    }

    /// Fold one plaintext PII exposure: `src` sent PII (`kind`) to `dst:port` in the clear. Counts
    /// exposures per channel and keeps the first kind seen. Bounded: a brand-new channel at
    /// capacity is dropped.
    pub fn observe_pii(&mut self, src: IpAddr, dst: IpAddr, dst_port: u16, kind: PiiKind) {
        let key = (src, dst, dst_port);
        if !self.pii.contains_key(&key) && self.pii.len() >= self.cfg.max_tracked_keys.max(1) {
            return;
        }
        let e = self.pii.entry(key).or_insert((kind, 0));
        e.1 += 1;
    }

    /// Fold one cleartext credential exposure: `src` sent a credential (`scheme`) to `dst:port` in
    /// the clear. Counts exposures per channel and keeps the first scheme seen. Bounded: a
    /// brand-new channel at capacity is dropped.
    pub fn observe_cleartext_cred(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        dst_port: u16,
        scheme: CredScheme,
    ) {
        let key = (src, dst, dst_port);
        if !self.creds.contains_key(&key) && self.creds.len() >= self.cfg.max_tracked_keys.max(1) {
            return;
        }
        let e = self.creds.entry(key).or_insert((scheme, 0));
        e.1 += 1;
    }

    /// Fold one server TLS certificate observation: `client` reached `server:port` and the server
    /// presented a certificate with the given health `issues`. Keeps the first observation per
    /// channel. Bounded: a brand-new channel at capacity is dropped.
    pub fn observe_tls_cert(
        &mut self,
        client: IpAddr,
        server: IpAddr,
        server_port: u16,
        issues: Vec<CertIssue>,
        subject_cn: Option<String>,
        sni: Option<String>,
    ) {
        if issues.is_empty() {
            return;
        }
        let key = (client, server, server_port);
        if !self.tls_certs.contains_key(&key)
            && self.tls_certs.len() >= self.cfg.max_tracked_keys.max(1)
        {
            return;
        }
        self.tls_certs.entry(key).or_insert(TlsCertObservation {
            issues,
            subject_cn,
            sni,
        });
    }

    /// Fold one weak / deprecated TLS observation: `client` reached `server:port` and the server
    /// negotiated weak TLS (`version`, `cipher`, `reasons`). Keeps the first observation per
    /// channel. Bounded: a brand-new channel at capacity is dropped.
    pub fn observe_weak_tls(
        &mut self,
        client: IpAddr,
        server: IpAddr,
        server_port: u16,
        version: u16,
        cipher: u16,
        reasons: Vec<WeakTlsReason>,
    ) {
        if reasons.is_empty() {
            return;
        }
        let key = (client, server, server_port);
        if !self.weak_tls.contains_key(&key)
            && self.weak_tls.len() >= self.cfg.max_tracked_keys.max(1)
        {
            return;
        }
        self.weak_tls.entry(key).or_insert(WeakTlsObservation {
            version,
            cipher,
            reasons,
        });
    }

    /// Fold one ARP claim: `ip` was announced as belonging to `mac`. Accumulates the set of distinct
    /// MACs seen claiming each IP — the cache-poisoning signal. Bounded: a brand-new IP at capacity
    /// is dropped, and the per-IP MAC set is capped.
    pub fn observe_arp(&mut self, ip: IpAddr, mac: [u8; 6]) {
        if let Some(set) = self.arp.get_mut(&ip) {
            if set.len() < MAX_ARP_MACS {
                set.insert(mac);
            }
        } else if self.arp.len() < self.cfg.max_tracked_keys.max(1) {
            let mut set = HashSet::new();
            set.insert(mac);
            self.arp.insert(ip, set);
        }
    }

    /// All IPs claimed by at least `min_macs` distinct MAC addresses — the ARP-spoofing signal.
    /// Returned most-MACs first, then by IP for determinism.
    pub fn arp_spoof_candidates(&self, min_macs: usize) -> Vec<ArpSpoofCandidate> {
        let mut out: Vec<ArpSpoofCandidate> = self
            .arp
            .iter()
            .filter(|(_, macs)| macs.len() >= min_macs)
            .map(|(&ip, macs)| ArpSpoofCandidate {
                ip,
                macs: macs.len(),
            })
            .collect();
        out.sort_by(|a, b| b.macs.cmp(&a.macs).then(a.ip.cmp(&b.ip)));
        out
    }

    /// Fold one DNS query: `src` asked `resolver` for `qname`. Accumulates the volume, the
    /// distribution of the most-information-dense label's Shannon entropy, and the longest label
    /// length — the signals that separate tunneling / DGA from ordinary lookups. Bounded: a
    /// brand-new `(src, resolver)` at capacity is dropped.
    pub fn observe_dns_query(&mut self, src: IpAddr, resolver: IpAddr, qname: &str) {
        let key = (src, resolver);
        if !self.dns.contains_key(&key) && self.dns.len() >= self.cfg.max_tracked_keys.max(1) {
            return;
        }
        // The data-carrying label is the longest one; measure its entropy and length.
        let longest = qname.split('.').max_by_key(|l| l.len()).unwrap_or("");
        let entropy = shannon_entropy(longest);
        let label_len = longest.len().min(u16::MAX as usize) as u16;
        let e = self.dns.entry(key).or_default();
        e.queries += 1;
        e.entropy_sum += entropy;
        if label_len > e.max_label_len {
            e.max_label_len = label_len;
        }
        if e.sample.is_none() && !qname.is_empty() {
            e.sample = Some(qname.to_string());
        }

        // DGA: score the *registered* label (not subdomains) so a CDN host like
        // `d1a2b3.cloudfront.net` — random subdomain, ordinary registered label — is not flagged.
        // Track distinct suspect registered domains per source; the detector gates on the count.
        if let Some((reg_domain, reg_label)) = registered_domain(qname) {
            let track =
                self.dga.contains_key(&src) || self.dga.len() < self.cfg.max_tracked_keys.max(1);
            if track {
                let d = self.dga.entry(src).or_default();
                d.queries += 1;
                if is_dga_label(&reg_label) && d.suspect.len() < MAX_DGA_SUSPECT {
                    if d.sample.is_none() {
                        d.sample = Some(reg_domain.clone());
                    }
                    d.suspect.insert(reg_domain);
                }
            }
        }
    }

    /// Fold one ICMP echo request/reply: `src -> dst` carrying `data_bytes` of echo payload (the
    /// ICMP message minus its 8-byte header). Accumulates count, total and peak data per channel —
    /// the signal that separates a covert ICMP tunnel from ordinary ping. Bounded: a brand-new
    /// channel at capacity is dropped.
    pub fn observe_icmp_echo(&mut self, src: IpAddr, dst: IpAddr, data_bytes: u64) {
        let key = (src, dst);
        if !self.icmp.contains_key(&key) && self.icmp.len() >= self.cfg.max_tracked_keys.max(1) {
            return;
        }
        let e = self.icmp.entry(key).or_default();
        e.echoes += 1;
        e.data_bytes = e.data_bytes.saturating_add(data_bytes);
        let d = data_bytes.min(u32::MAX as u64) as u32;
        if d > e.max_data {
            e.max_data = d;
        }
    }

    /// Fold one contact: a new `src -> dst:dst_port` connection observed at `ts_ns`. Timing-only
    /// convenience wrapper over [`observe_flow_contact`](Self::observe_flow_contact).
    pub fn observe_contact(&mut self, src: IpAddr, dst: IpAddr, dst_port: u16, ts_ns: i64) {
        self.observe_flow_contact(src, dst, dst_port, ts_ns, 0, 0);
    }

    /// Fold one closed flow's contact assuming a TCP transport. Thin wrapper over
    /// [`observe_flow_contact_with`](Self::observe_flow_contact_with) — used by the timing-only
    /// [`observe_contact`](Self::observe_contact) helper and by tests, which are all TCP scenarios.
    pub fn observe_flow_contact(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        dst_port: u16,
        ts_ns: i64,
        bytes_out: u64,
        bytes_in: u64,
    ) {
        self.observe_flow_contact_with(
            src,
            dst,
            dst_port,
            ts_ns,
            bytes_out,
            bytes_in,
            Transport::Tcp,
        );
    }

    /// Fold one closed flow's contact: directed `src -> dst:dst_port` at `ts_ns` plus the
    /// directional byte counts (`bytes_out` = client->server, `bytes_in` = server->client) and the
    /// flow's `transport`. The SYN-flood half-open signal is TCP-only (UDP and other connectionless
    /// transports have no handshake), so non-TCP flows never contribute to it — otherwise a busy
    /// small-request UDP service (DNS, NTP, SNMP) would be mistaken for a flood of half-opens.
    #[allow(clippy::too_many_arguments)] // directed contact fold: src/dst/port/ts/bytes x2/transport
    pub fn observe_flow_contact_with(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        dst_port: u16,
        ts_ns: i64,
        bytes_out: u64,
        bytes_in: u64,
        transport: Transport,
    ) {
        // Per-channel inter-arrival series + byte totals (bounded: a brand-new channel at
        // capacity is dropped — best-effort heavy-hitter signal, not an exact set).
        let key = ContactKey::new(src, dst, dst_port);
        if let Some(series) = self.channels.get_mut(&key) {
            series.observe(ts_ns);
            series.add_bytes(bytes_out, bytes_in);
        } else if self.channels.len() < self.cfg.max_tracked_keys.max(1) {
            let mut series = ContactSeries::new();
            series.observe(ts_ns);
            series.add_bytes(bytes_out, bytes_in);
            self.channels.insert(key, series);
        }

        // Per-(source, port) distinct destination-host set (sweep signal), bounded in both the
        // number of (src, port) keys and the hosts retained per key.
        let fkey = (src, dst_port);
        if let Some(set) = self.fanout.get_mut(&fkey) {
            if set.len() < self.cfg.max_fanout_per_src {
                set.insert(dst);
            }
        } else if self.fanout.len() < self.cfg.max_tracked_keys.max(1) {
            let mut set = HashSet::new();
            set.insert(dst);
            self.fanout.insert(fkey, set);
        }

        // Per-(source, host) distinct destination-port set (vertical port-scan signal), bounded the
        // same way. Count a port ONLY for a *probe* flow — one that did not complete a real
        // bidirectional session. A scan (SYN/RST, half-open) exchanges almost nothing each way,
        // while a busy legit client to one host (passive-FTP data ports, health checks, mesh calls)
        // completes real sessions with bytes in both directions. Without this gate, a busy FTP
        // client looks identical to a scanner; the port count alone cannot separate them.
        let completed_session = bytes_out >= SCAN_SESSION_BYTES && bytes_in >= SCAN_SESSION_BYTES;
        if !completed_session {
            let pkey = (src, dst);
            if let Some(set) = self.port_scan.get_mut(&pkey) {
                if set.len() < self.cfg.max_fanout_per_src {
                    set.insert(dst_port);
                }
            } else if self.port_scan.len() < self.cfg.max_tracked_keys.max(1) {
                let mut set = HashSet::new();
                set.insert(dst_port);
                self.port_scan.insert(pkey, set);
            }
        }

        // SYN flood / TCP DoS: count HALF-OPEN connections per *target* (dst, port) using a MUCH
        // stricter gate than the port-scan probe gate above. A genuine flood / abandoned connection
        // has the CLIENT send no real request (only SYN / handshake control), so its client->server
        // wire bytes stay below the handshake floor; a real client — even a tiny request, a health
        // check, or an HTTP 204 — always pushes a request and exceeds it, so busy small-response
        // services do NOT count. We key on "the client sent nothing real", NOT on `bytes_in == 0`: a
        // flood to an OPEN port still draws a SYN-ACK back, so its `bytes_in` is ~60, not 0. Orthogonal
        // to the port scan (many ports on one host); here the signal is many half-opens to one service.
        // TCP-only: a "half-open handshake" is meaningless for connectionless transports, so a busy
        // small-request UDP service (DNS/NTP/SNMP) is never miscounted as a flood.
        if transport == Transport::Tcp && bytes_out < SYN_FLOOD_HALF_OPEN_BYTES {
            let tkey = (dst, dst_port);
            if let Some(stat) = self.syn_flood.get_mut(&tkey) {
                stat.incomplete = stat.incomplete.saturating_add(1);
                if stat.sources.len() < self.cfg.max_fanout_per_src {
                    stat.sources.insert(src);
                }
            } else if self.syn_flood.len() < self.cfg.max_tracked_keys.max(1) {
                let mut sources = HashSet::new();
                sources.insert(src);
                self.syn_flood.insert(
                    tkey,
                    SynFloodStat {
                        incomplete: 1,
                        sources,
                    },
                );
            }
        }
    }

    /// Borrow the inter-arrival series for a channel, if tracked.
    pub fn series(&self, key: ContactKey) -> Option<&ContactSeries> {
        self.channels.get(&key)
    }

    /// Number of distinct destination hosts `src` contacted on `dst_port` (the sweep fan-out).
    pub fn fanout(&self, src: IpAddr, dst_port: u16) -> usize {
        self.fanout.get(&(src, dst_port)).map_or(0, |set| set.len())
    }

    /// Whether `src` contacted at least `threshold` distinct hosts on `dst_port`.
    pub fn is_sweeper(&self, src: IpAddr, dst_port: u16, threshold: usize) -> bool {
        self.fanout(src, dst_port) >= threshold
    }

    /// All `(src, port)` pairs that reached at least `min_hosts` distinct destination hosts — a
    /// horizontal sweep. Port gating is left to the caller. Returned in deterministic order.
    pub fn sweep_candidates(&self, min_hosts: usize) -> Vec<SweepCandidate> {
        let mut out: Vec<SweepCandidate> = self
            .fanout
            .iter()
            .filter(|(_, hosts)| hosts.len() >= min_hosts)
            .map(|(&(src, dst_port), hosts)| SweepCandidate {
                src,
                dst_port,
                hosts: hosts.len(),
            })
            .collect();
        out.sort_by(|a, b| {
            b.hosts
                .cmp(&a.hosts)
                .then(a.src.cmp(&b.src))
                .then(a.dst_port.cmp(&b.dst_port))
        });
        out
    }

    /// All `(src, host)` pairs where the source probed at least `min_ports` distinct ports — a
    /// vertical port scan. Returned most-ports first, then by source/host for determinism.
    pub fn port_scan_candidates(&self, min_ports: usize) -> Vec<PortScanCandidate> {
        let mut out: Vec<PortScanCandidate> = self
            .port_scan
            .iter()
            .filter(|(_, ports)| ports.len() >= min_ports)
            .map(|(&(src, dst), ports)| PortScanCandidate {
                src,
                dst,
                ports: ports.len(),
            })
            .collect();
        out.sort_by(|a, b| {
            b.ports
                .cmp(&a.ports)
                .then(a.src.cmp(&b.src))
                .then(a.dst.cmp(&b.dst))
        });
        out
    }

    /// All `(target, port)` services hit by at least `min_incomplete` half-open connections — the
    /// SYN-flood signal. Returned most-incomplete first, then by target/port for determinism.
    pub fn syn_flood_candidates(&self, min_incomplete: u64) -> Vec<SynFloodCandidate> {
        let mut out: Vec<SynFloodCandidate> = self
            .syn_flood
            .iter()
            .filter(|(_, s)| s.incomplete >= min_incomplete)
            .map(|(&(dst, dst_port), s)| SynFloodCandidate {
                dst,
                dst_port,
                incomplete: s.incomplete,
                sources: s.sources.len(),
            })
            .collect();
        out.sort_by(|a, b| {
            b.incomplete
                .cmp(&a.incomplete)
                .then(a.dst.cmp(&b.dst))
                .then(a.dst_port.cmp(&b.dst_port))
        });
        out
    }

    /// Fold one HTTP `User-Agent` from `src`. If it matches a known attack-tool signature, record the
    /// tool (keeping the first example UA) and bump the per-source hit count. Non-tool UAs are
    /// ignored. Bounded: a brand-new source at capacity is dropped.
    pub fn observe_user_agent(&mut self, src: IpAddr, ua: &str) {
        let Some(tool) = match_tool_ua(ua) else {
            return;
        };
        if let Some(stat) = self.tool_ua.get_mut(&src) {
            stat.hits = stat.hits.saturating_add(1);
        } else if self.tool_ua.len() < self.cfg.max_tracked_keys.max(1) {
            let sample: String = ua.chars().take(120).collect();
            self.tool_ua.insert(
                src,
                ToolUaStat {
                    tool,
                    hits: 1,
                    sample,
                },
            );
        }
    }

    /// All sources that presented a known attack-tool User-Agent. Returned most-active first, then
    /// by source for determinism.
    pub fn tool_ua_candidates(&self) -> Vec<ToolUaCandidate> {
        let mut out: Vec<ToolUaCandidate> = self
            .tool_ua
            .iter()
            .map(|(&src, s)| ToolUaCandidate {
                src,
                tool: s.tool,
                hits: s.hits,
                sample: s.sample.clone(),
            })
            .collect();
        out.sort_by(|a, b| b.hits.cmp(&a.hits).then(a.src.cmp(&b.src)));
        out
    }

    /// Fold one disguised executable download: the `client` received an executable body (`kind`) from
    /// `server` behind a benign `Content-Type`. Counts masquerading responses per channel. Bounded: a
    /// brand-new channel at capacity is dropped.
    pub fn observe_disguised_download(
        &mut self,
        client: IpAddr,
        server: IpAddr,
        kind: DownloadKind,
    ) {
        let key = (client, server);
        if let Some(stat) = self.disguised_dl.get_mut(&key) {
            stat.hits = stat.hits.saturating_add(1);
        } else if self.disguised_dl.len() < self.cfg.max_tracked_keys.max(1) {
            self.disguised_dl
                .insert(key, DisguisedDlStat { kind, hits: 1 });
        }
    }

    /// All `(client, server)` channels that delivered a disguised executable. Returned most-active
    /// first, then by endpoints for determinism.
    pub fn disguised_download_candidates(&self) -> Vec<DisguisedDownloadCandidate> {
        let mut out: Vec<DisguisedDownloadCandidate> = self
            .disguised_dl
            .iter()
            .map(|(&(client, server), s)| DisguisedDownloadCandidate {
                client,
                server,
                kind: s.kind,
                hits: s.hits,
            })
            .collect();
        out.sort_by(|a, b| {
            b.hits
                .cmp(&a.hits)
                .then(a.client.cmp(&b.client))
                .then(a.server.cmp(&b.server))
        });
        out
    }

    /// Fold one cleartext Stratum message. `role` says who sent it (miner vs pool); together with the
    /// packet's `src`/`dst` it resolves the miner and pool, keyed identically for both directions so
    /// the two halves of one channel merge. Bounded: a brand-new channel at capacity is dropped.
    pub fn observe_stratum(&mut self, role: StratumRole, src: IpAddr, dst: IpAddr) {
        let (miner, pool) = match role {
            StratumRole::Miner => (src, dst),
            StratumRole::Pool => (dst, src),
        };
        let key = (miner, pool);
        let at_cap = !self.mining.contains_key(&key)
            && self.mining.len() >= self.cfg.max_tracked_keys.max(1);
        if at_cap {
            return;
        }
        let stat = self.mining.entry(key).or_default();
        match role {
            StratumRole::Miner => stat.miner_msgs = stat.miner_msgs.saturating_add(1),
            StratumRole::Pool => stat.pool_msgs = stat.pool_msgs.saturating_add(1),
        }
    }

    /// All `(miner, pool)` channels confirmed as cryptomining: a **real pool engaged** —
    /// `pool_msgs > 0`, i.e. a `mining.notify` / `mining.set_difficulty` that only an actual pool
    /// sends to a subscribed miner. Requiring the pool response (rather than miner-side messages
    /// alone) both filters scanner/probe traffic that merely emits Stratum tokens and *guarantees*
    /// the attribution — the pool is definitively the notify sender, the miner its peer. Returned
    /// most-active first, then by endpoints for determinism.
    pub fn cryptomining_candidates(&self) -> Vec<CryptominingCandidate> {
        let mut out: Vec<CryptominingCandidate> = self
            .mining
            .iter()
            .filter(|(_, s)| s.pool_msgs > 0)
            .map(|(&(miner, pool), s)| CryptominingCandidate {
                miner,
                pool,
                messages: s.miner_msgs.saturating_add(s.pool_msgs),
            })
            .collect();
        out.sort_by(|a, b| {
            b.messages
                .cmp(&a.messages)
                .then(a.miner.cmp(&b.miner))
                .then(a.pool.cmp(&b.pool))
        });
        out
    }

    /// All `(src, resolver)` channels whose DNS queries look like tunneling / DGA: at least
    /// `min_queries` queries, an average most-dense-label entropy at or above `min_avg_entropy`,
    /// and a longest label at or above `min_label_len`. Returned strongest (most queries) first.
    pub fn dns_tunnel_candidates(
        &self,
        min_queries: u64,
        min_avg_entropy: f64,
        min_label_len: u16,
    ) -> Vec<DnsTunnelCandidate> {
        let mut out: Vec<DnsTunnelCandidate> = self
            .dns
            .iter()
            .filter(|(_, s)| {
                s.queries >= min_queries
                    && s.max_label_len >= min_label_len
                    && s.entropy_sum / s.queries as f64 >= min_avg_entropy
            })
            .map(|(&(src, resolver), s)| DnsTunnelCandidate {
                src,
                resolver,
                queries: s.queries,
                avg_entropy: s.entropy_sum / s.queries as f64,
                max_label_len: s.max_label_len,
                sample: s.sample.clone(),
            })
            .collect();
        out.sort_by(|a, b| {
            b.queries
                .cmp(&a.queries)
                .then(a.src.cmp(&b.src))
                .then(a.resolver.cmp(&b.resolver))
        });
        out
    }

    /// All sources that resolved at least `min_distinct_domains` distinct DGA-suspect registered
    /// domains — the domain-generation-algorithm C2-rendezvous signature. Returned most-suspect
    /// first, then by source for determinism.
    pub fn dga_candidates(&self, min_distinct_domains: u32) -> Vec<DgaCandidate> {
        let mut out: Vec<DgaCandidate> = self
            .dga
            .iter()
            .filter(|(_, s)| s.suspect.len() as u32 >= min_distinct_domains)
            .map(|(&src, s)| DgaCandidate {
                src,
                distinct_domains: s.suspect.len() as u32,
                queries: s.queries,
                sample: s.sample.clone(),
            })
            .collect();
        out.sort_by(|a, b| {
            b.distinct_domains
                .cmp(&a.distinct_domains)
                .then(a.src.cmp(&b.src))
        });
        out
    }

    /// Number of distinct contact channels currently tracked (for bound assertions).
    pub fn tracked_channels(&self) -> usize {
        self.channels.len()
    }

    /// All channels that look like a periodic beacon: at least `min_contacts` contacts with a
    /// jitter CV at or below `max_cv`. Returned in deterministic key order.
    pub fn beacon_candidates(&self, min_contacts: u64, max_cv: f64) -> Vec<BeaconCandidate> {
        let mut out: Vec<BeaconCandidate> = self
            .channels
            .iter()
            .filter(|(_, s)| {
                s.contacts() >= min_contacts && s.interval_ns() > 0.0 && s.jitter_cv() <= max_cv
            })
            .map(|(k, s)| BeaconCandidate {
                key: *k,
                contacts: s.contacts(),
                interval_ns: s.interval_ns(),
                jitter_cv: s.jitter_cv(),
            })
            .collect();
        out.sort_by_key(|c| c.key);
        out
    }

    /// All channels that look like data exfiltration: outbound bytes at or above `min_bytes_out`
    /// with an out/in ratio at or above `min_ratio` (an asymmetric upload). Externality is left
    /// to the caller. Returned in deterministic key order.
    pub fn exfil_candidates(&self, min_bytes_out: u64, min_ratio: f64) -> Vec<ExfilCandidate> {
        let mut out: Vec<ExfilCandidate> = self
            .channels
            .iter()
            .filter(|(_, s)| {
                s.bytes_out() >= min_bytes_out
                    && s.bytes_out() as f64 >= min_ratio * (s.bytes_in() as f64 + 1.0)
            })
            .map(|(k, s)| ExfilCandidate {
                key: *k,
                bytes_out: s.bytes_out(),
                bytes_in: s.bytes_in(),
            })
            .collect();
        out.sort_by_key(|c| c.key);
        out
    }

    /// All channels that look like a credential brute force: at least `min_attempts` separate
    /// connection attempts to a destination service whose port is in `auth_ports`. Each login
    /// attempt is a distinct flow (new ephemeral source port), so the signal lives on the
    /// cross-flow contact count, not a single [`crate::model::flow::FlowRecord`]. Returned
    /// strongest (most attempts) first.
    pub fn brute_force_candidates(
        &self,
        min_attempts: u64,
        auth_ports: &[u16],
    ) -> Vec<BruteForceCandidate> {
        let mut out: Vec<BruteForceCandidate> = self
            .channels
            .iter()
            .filter(|(k, s)| s.contacts() >= min_attempts && auth_ports.contains(&k.dst_port))
            .map(|(k, s)| BruteForceCandidate {
                key: *k,
                attempts: s.contacts(),
            })
            .collect();
        out.sort_by(|a, b| b.attempts.cmp(&a.attempts).then(a.key.cmp(&b.key)));
        out
    }

    /// All `(source, admin-port)` pairs that opened an *established* session — at least
    /// `min_session_bytes` in **each** direction, which a SYN scan / bare handshake never reaches —
    /// to one or more distinct destinations on a port in `lateral_ports`. The byte floor per
    /// direction is what separates lateral movement (real remote-admin sessions) from a horizontal
    /// probe sweep. Internality of the endpoints and the host-count threshold are left to the
    /// caller. Returned in deterministic order; `targets` are sorted and deduplicated.
    pub fn lateral_candidates(
        &self,
        min_session_bytes: u64,
        lateral_ports: &[u16],
    ) -> Vec<LateralCandidate> {
        use std::collections::{BTreeMap, BTreeSet};
        let mut groups: BTreeMap<(IpAddr, u16), BTreeSet<IpAddr>> = BTreeMap::new();
        for (k, s) in &self.channels {
            if lateral_ports.contains(&k.dst_port)
                && s.bytes_out() >= min_session_bytes
                && s.bytes_in() >= min_session_bytes
            {
                groups.entry((k.src, k.dst_port)).or_default().insert(k.dst);
            }
        }
        groups
            .into_iter()
            .map(|((src, dst_port), set)| LateralCandidate {
                src,
                dst_port,
                targets: set.into_iter().collect(),
            })
            .collect()
    }

    /// All established remote-admin channels (real bidirectional sessions on `ports`) whose two
    /// endpoints straddle the internal↔external boundary — the exposed-remote-access signal, the
    /// complement of [`lateral_candidates`] (which is east-west only). A both-internal channel is
    /// lateral movement's domain; a both-external channel is transit we don't own. Returned
    /// busiest-first, then by endpoints/port for determinism.
    pub fn exposed_remote_access_candidates(
        &self,
        min_session_bytes: u64,
        ports: &[u16],
    ) -> Vec<ExposedRemoteAccessCandidate> {
        let mut out: Vec<ExposedRemoteAccessCandidate> = self
            .channels
            .iter()
            .filter_map(|(k, s)| {
                if !ports.contains(&k.dst_port) {
                    return None;
                }
                // Real bidirectional session, not a bare handshake / scan probe.
                if s.bytes_out() < min_session_bytes || s.bytes_in() < min_session_bytes {
                    return None;
                }
                // Boundary-crossing: exactly one endpoint must be a routable public address.
                match (
                    classify_ip(k.src).is_external(),
                    classify_ip(k.dst).is_external(),
                ) {
                    // External client reached INTO an internal admin service (inbound exposure).
                    (true, false) => Some(ExposedRemoteAccessCandidate {
                        external: k.src,
                        internal: k.dst,
                        port: k.dst_port,
                        inbound: true,
                        sessions: s.contacts(),
                    }),
                    // Internal client reached OUT to an external admin service (outbound pivot).
                    (false, true) => Some(ExposedRemoteAccessCandidate {
                        external: k.dst,
                        internal: k.src,
                        port: k.dst_port,
                        inbound: false,
                        sessions: s.contacts(),
                    }),
                    _ => None,
                }
            })
            .collect();
        out.sort_by(|a, b| {
            b.sessions
                .cmp(&a.sessions)
                .then(a.external.cmp(&b.external))
                .then(a.internal.cmp(&b.internal))
                .then(a.port.cmp(&b.port))
        });
        out
    }

    /// All `(src, dst, dst_port)` channels that exposed at least `min_exposures` cleartext
    /// credentials. Returned strongest (most exposures) first, then by channel for determinism.
    pub fn cleartext_cred_candidates(&self, min_exposures: u64) -> Vec<CleartextCredCandidate> {
        let mut out: Vec<CleartextCredCandidate> = self
            .creds
            .iter()
            .filter(|(_, (_, n))| *n >= min_exposures)
            .map(
                |(&(src, dst, dst_port), &(scheme, exposures))| CleartextCredCandidate {
                    src,
                    dst,
                    dst_port,
                    scheme,
                    exposures,
                },
            )
            .collect();
        out.sort_by(|a, b| {
            b.exposures
                .cmp(&a.exposures)
                .then(a.src.cmp(&b.src))
                .then(a.dst.cmp(&b.dst))
                .then(a.dst_port.cmp(&b.dst_port))
        });
        out
    }

    /// All `(src, dst, dst_port)` channels that exposed at least `min_exposures` plaintext PII
    /// values. Returned strongest (most exposures) first, then by channel for determinism.
    pub fn pii_candidates(&self, min_exposures: u64) -> Vec<PiiCandidate> {
        let mut out: Vec<PiiCandidate> = self
            .pii
            .iter()
            .filter(|(_, (_, n))| *n >= min_exposures)
            .map(|(&(src, dst, dst_port), &(kind, exposures))| PiiCandidate {
                src,
                dst,
                dst_port,
                kind,
                exposures,
            })
            .collect();
        out.sort_by(|a, b| {
            b.exposures
                .cmp(&a.exposures)
                .then(a.src.cmp(&b.src))
                .then(a.dst.cmp(&b.dst))
                .then(a.dst_port.cmp(&b.dst_port))
        });
        out
    }

    /// All `(client, server, server_port)` flows whose server presented a problematic TLS
    /// certificate. Returned worst (highest single-issue severity, then most issues) first, then
    /// by channel for determinism.
    pub fn tls_cert_candidates(&self) -> Vec<TlsCertCandidate> {
        let mut out: Vec<TlsCertCandidate> = self
            .tls_certs
            .iter()
            .map(|(&(client, server, server_port), obs)| TlsCertCandidate {
                client,
                server,
                server_port,
                issues: obs.issues.clone(),
                subject_cn: obs.subject_cn.clone(),
                sni: obs.sni.clone(),
            })
            .collect();
        out.sort_by(|a, b| {
            worst_issue_rank(&b.issues)
                .cmp(&worst_issue_rank(&a.issues))
                .then(b.issues.len().cmp(&a.issues.len()))
                .then(a.client.cmp(&b.client))
                .then(a.server.cmp(&b.server))
                .then(a.server_port.cmp(&b.server_port))
        });
        out
    }

    /// All `(client, server, server_port)` flows that negotiated weak / deprecated TLS. Returned
    /// worst (highest single-reason severity, then most reasons) first, then by channel.
    pub fn weak_tls_candidates(&self) -> Vec<WeakTlsCandidate> {
        let mut out: Vec<WeakTlsCandidate> = self
            .weak_tls
            .iter()
            .map(|(&(client, server, server_port), obs)| WeakTlsCandidate {
                client,
                server,
                server_port,
                version: obs.version,
                cipher: obs.cipher,
                reasons: obs.reasons.clone(),
            })
            .collect();
        out.sort_by(|a, b| {
            worst_reason_rank(&b.reasons)
                .cmp(&worst_reason_rank(&a.reasons))
                .then(b.reasons.len().cmp(&a.reasons.len()))
                .then(a.client.cmp(&b.client))
                .then(a.server.cmp(&b.server))
                .then(a.server_port.cmp(&b.server_port))
        });
        out
    }

    /// All `(src, dst)` ICMP echo channels meeting the covert-tunnel thresholds: at least
    /// `min_echoes` echo messages AND either a peak or mean data payload of at least
    /// `min_large_data` bytes (ordinary ping is small and low-volume). Worst (most data) first.
    pub fn icmp_tunnel_candidates(
        &self,
        min_echoes: u64,
        min_large_data: u32,
    ) -> Vec<IcmpTunnelCandidate> {
        let mut out: Vec<IcmpTunnelCandidate> = self
            .icmp
            .iter()
            .filter_map(|(&(src, dst), s)| {
                let mean = s.data_bytes / s.echoes.max(1);
                // A covert tunnel sustains large payloads, so gate on the MEAN — a single large
                // probe (e.g. one PMTU/jumbo-frame ping among normal pings) must not trip it.
                let sustained_large = mean >= min_large_data as u64;
                (s.echoes >= min_echoes && sustained_large).then_some(IcmpTunnelCandidate {
                    src,
                    dst,
                    echoes: s.echoes,
                    data_bytes: s.data_bytes,
                    max_data: s.max_data,
                    mean_data: mean,
                })
            })
            .collect();
        out.sort_by(|a, b| {
            b.data_bytes
                .cmp(&a.data_bytes)
                .then(a.src.cmp(&b.src))
                .then(a.dst.cmp(&b.dst))
        });
        out
    }
}

/// The seriousness of the worst single issue in a set (0 if empty).
fn worst_issue_rank(issues: &[CertIssue]) -> u8 {
    issues.iter().map(|i| i.severity_rank()).max().unwrap_or(0)
}

/// The seriousness of the worst single weak-TLS reason in a set (0 if empty).
fn worst_reason_rank(reasons: &[WeakTlsReason]) -> u8 {
    reasons.iter().map(|r| r.severity_rank()).max().unwrap_or(0)
}

use crate::enrich::classify_ip;
use crate::model::finding::{Finding, FindingKind};
use crate::model::flow::FlowRecord;
use crate::model::incident::Incident;
use crate::model::severity::Severity;

/// Interactive remote-login service ports treated as credential-brute-force targets. Repeated
/// separate connections to one of these from a single source is anomalous (you reuse one SSH/RDP
/// session, you do not open twenty), and benign churn on them is low — unlike high-volume service
/// ports (SMB 445, LDAP 389, the database ports) where a workstation legitimately opens many
/// connections to a file server / DC. Used as both [`BruteForceParams::auth_ports`] and
/// [`BeaconParams::ignore_ports`] so the two detectors never disagree about a channel.
pub const INTERACTIVE_AUTH_PORTS: &[u16] = &[
    21,   // FTP
    22,   // SSH
    23,   // Telnet
    3389, // RDP
    5900, // VNC
];

/// Tuning for the beaconing detector.
#[derive(Debug, Clone)]
pub struct BeaconParams {
    /// Master switch.
    pub enabled: bool,
    /// Minimum contacts on a channel before it can be called a beacon.
    pub min_contacts: u64,
    /// Maximum jitter (coefficient of variation) to still count as "regular".
    pub max_jitter_cv: f64,
    /// Ignore channels whose period is below this (sub-second chatter is not a beacon).
    pub min_interval_ns: i64,
    /// Ignore channels whose period is above this (too sparse to call periodic).
    pub max_interval_ns: i64,
    /// Destination ports excluded from beacon detection. A throttled credential guesser or a
    /// periodic remote-admin agent produces a regular, low-jitter series to an auth / admin
    /// service that would otherwise satisfy the beacon predicate too; excluding the auth AND
    /// lateral-movement ports keeps a brute force / lateral fan-out from also being reported as a
    /// C2 beacon (legitimate C2 rarely beacons over an interactive-login or remote-admin port).
    pub ignore_ports: Vec<u16>,
}

impl Default for BeaconParams {
    fn default() -> Self {
        BeaconParams {
            enabled: true,
            // A low jitter CV is only trustworthy with enough samples; too few contacts let
            // benign traffic look periodic by chance (a multiple-comparisons effect across many
            // channels). Real beacons check in many times, so require a solid minimum.
            min_contacts: 12,
            max_jitter_cv: 0.15,
            min_interval_ns: 1_000_000_000,              // 1 s
            max_interval_ns: 24 * 3_600 * 1_000_000_000, // 24 h
            // The union of the auth ports (brute-force territory) and the remote-admin ports
            // (lateral-movement territory): a regular series to any of these is owned by the
            // more-specific detector, never reported as a beacon.
            ignore_ports: merged_ports(INTERACTIVE_AUTH_PORTS, LATERAL_PORTS),
        }
    }
}

/// Sorted, deduplicated union of two port lists (for default ignore sets).
fn merged_ports(a: &[u16], b: &[u16]) -> Vec<u16> {
    let mut v: Vec<u16> = a.iter().chain(b.iter()).copied().collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// One closed flow reduced to a directed contact: the initiating client, the service it
/// reached, the connection-start time, and the directional byte totals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Contact {
    pub client: IpAddr,
    pub server: IpAddr,
    pub server_port: u16,
    pub ts_ns: i64,
    /// Bytes client -> server (the exfil-relevant "outbound" direction).
    pub bytes_out: u64,
    /// Bytes server -> client.
    pub bytes_in: u64,
}

/// Derive the directed [`Contact`] from a closed flow, or `None` for a non-port transport.
///
/// The server is the well-known (numerically smaller) port side — matching how `stats` picks
/// the service port — and the client is the ephemeral side. The contact time is the flow's
/// first timestamp, i.e. the connection-initiation instant, which is the correct sample for
/// beacon periodicity.
pub fn contact_from_flow(record: &FlowRecord) -> Option<Contact> {
    if !record.key.transport.has_ports() {
        return None;
    }
    // The smaller port is the well-known service side (the server); the other endpoint is the
    // ephemeral client that initiated the connection. `bytes_out` is client->server (the
    // exfil-relevant direction); FlowRecord stores bytes as fwd = lo->hi, rev = hi->lo.
    let (client, server, server_port, bytes_out, bytes_in) =
        if record.key.lo_port <= record.key.hi_port {
            // server = lo, client = hi -> client->server is hi->lo = bytes_rev.
            (
                record.key.hi_ip,
                record.key.lo_ip,
                record.key.lo_port,
                record.bytes_rev,
                record.bytes_fwd,
            )
        } else {
            // server = hi, client = lo -> client->server is lo->hi = bytes_fwd.
            (
                record.key.lo_ip,
                record.key.hi_ip,
                record.key.hi_port,
                record.bytes_fwd,
                record.bytes_rev,
            )
        };
    Some(Contact {
        client,
        server,
        server_port,
        ts_ns: record.first_ts_ns,
        bytes_out,
        bytes_in,
    })
}

/// Detect periodic C2 beaconing from the behavioral tracker: one [`Finding`] per destination
/// channel whose contacts are frequent enough ([`BeaconParams::min_contacts`]), regular enough
/// ([`BeaconParams::max_jitter_cv`]), and within the plausible period window. Severity is High
/// for an external destination, Medium for an internal one. Returned in deterministic order.
pub fn detect_beacons(tracker: &BehaviorTracker, params: &BeaconParams) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.beacon_candidates(params.min_contacts, params.max_jitter_cv) {
        // Reject periods outside the plausible beacon window (sub-second chatter / too sparse).
        if c.interval_ns < params.min_interval_ns as f64
            || c.interval_ns > params.max_interval_ns as f64
        {
            continue;
        }
        // A regular, low-jitter series to an auth service is a (throttled) brute force, not a C2
        // beacon — skip the auth ports so the two detectors never double-report one channel.
        if params.ignore_ports.contains(&c.key.dst_port) {
            continue;
        }
        let dst = c.key.dst;
        let external = classify_ip(dst).is_external();
        // A periodic beacon to an external peer is High; to an internal one, Medium. The score
        // is a representative point inside the matching band (parallels per-flow threat_score).
        let (severity, score) = if external {
            (Severity::High, 70)
        } else {
            (Severity::Medium, 45)
        };
        let interval_secs = c.interval_ns / 1e9;
        let evidence = vec![
            format!(
                "periodic beaconing: {} contacts to {}:{}",
                c.contacts, dst, c.key.dst_port
            ),
            format!(
                "interval ~{interval_secs:.0}s, jitter CV {:.3} (low = machine-regular)",
                c.jitter_cv
            ),
            if external {
                "external destination".to_string()
            } else {
                "internal destination".to_string()
            },
        ];
        findings.push(Finding {
            kind: FindingKind::Beacon,
            severity,
            score,
            title: format!(
                "Periodic beacon: {} -> {}:{} every ~{interval_secs:.0}s",
                c.key.src, dst, c.key.dst_port
            ),
            src_ip: c.key.src.to_string(),
            dst_ip: Some(dst.to_string()),
            dst_port: Some(c.key.dst_port),
            attack: vec!["T1071".to_string()],
            evidence,
            interval_ns: Some(c.interval_ns.round() as i64),
            jitter_cv: Some(c.jitter_cv),
            contacts: Some(c.contacts),
        });
    }
    findings
}

/// Tuning for the data-exfiltration detector.
#[derive(Debug, Clone)]
pub struct ExfilParams {
    /// Master switch.
    pub enabled: bool,
    /// Minimum outbound bytes on a channel to consider it exfil.
    pub min_bytes_out: u64,
    /// Minimum out/in ratio (asymmetry): outbound must dominate inbound by this factor.
    pub min_ratio: f64,
    /// Outbound bytes at or above this escalate the finding to Critical.
    pub critical_bytes_out: u64,
}

impl Default for ExfilParams {
    fn default() -> Self {
        ExfilParams {
            enabled: true,
            min_bytes_out: 1_000_000,        // 1 MB
            min_ratio: 4.0,                  // 4x more out than in
            critical_bytes_out: 100_000_000, // 100 MB
        }
    }
}

/// Detect data exfiltration from the behavioral tracker: one [`Finding`] per channel with a
/// large, asymmetric outbound transfer to an **external** peer. Severity is High, escalating to
/// Critical past [`ExfilParams::critical_bytes_out`]. Returned in deterministic order.
pub fn detect_exfil(tracker: &BehaviorTracker, params: &ExfilParams) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.exfil_candidates(params.min_bytes_out, params.min_ratio) {
        let dst = c.key.dst;
        // Only data leaving the network counts as exfiltration.
        if !classify_ip(dst).is_external() {
            continue;
        }
        let (severity, score) = if c.bytes_out >= params.critical_bytes_out {
            (Severity::Critical, 90)
        } else {
            (Severity::High, 72)
        };
        let ratio = c.bytes_out as f64 / (c.bytes_in as f64 + 1.0);
        findings.push(Finding {
            kind: FindingKind::DataExfil,
            severity,
            score,
            title: format!(
                "Data exfiltration: {} -> {}:{} ({} out)",
                c.key.src,
                dst,
                c.key.dst_port,
                human_bytes(c.bytes_out)
            ),
            src_ip: c.key.src.to_string(),
            dst_ip: Some(dst.to_string()),
            dst_port: Some(c.key.dst_port),
            attack: vec!["T1048".to_string()],
            evidence: vec![
                format!(
                    "outbound {} to external {}:{}",
                    human_bytes(c.bytes_out),
                    dst,
                    c.key.dst_port
                ),
                format!(
                    "{ratio:.0}x more out than in (asymmetric upload; {} in)",
                    human_bytes(c.bytes_in)
                ),
                "external destination".to_string(),
            ],
            interval_ns: None,
            jitter_cv: None,
            contacts: None,
        });
    }
    findings
}

/// Tuning for the host-sweep detector.
#[derive(Debug, Clone)]
pub struct SweepParams {
    /// Master switch.
    pub enabled: bool,
    /// Minimum distinct destination hosts on one `(src, port)` to call it a sweep.
    pub min_hosts: usize,
    /// Ports excluded from sweep detection — ordinary client traffic (web/DNS/NTP) routinely
    /// fans out to many hosts and is not a scan. A sweep of these is indistinguishable from a
    /// busy browser without payload analysis, so they are skipped to avoid false positives.
    pub ignore_ports: Vec<u16>,
}

impl Default for SweepParams {
    fn default() -> Self {
        SweepParams {
            enabled: true,
            min_hosts: 16,
            ignore_ports: vec![80, 443, 8080, 8443, 53, 123],
        }
    }
}

/// Detect horizontal host sweeps from the behavioral tracker: one [`Finding`] per `(src, port)`
/// that reached at least [`SweepParams::min_hosts`] distinct hosts on a non-ignored port. These
/// are network-service / remote-system discovery; severity is High, ATT&CK T1046. Deterministic
/// order.
pub fn detect_sweeps(tracker: &BehaviorTracker, params: &SweepParams) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.sweep_candidates(params.min_hosts) {
        if params.ignore_ports.contains(&c.dst_port) {
            continue;
        }
        findings.push(Finding {
            kind: FindingKind::HostSweep,
            severity: Severity::High,
            score: 65,
            title: format!(
                "Host sweep: {} probed {} hosts on port {}",
                c.src, c.hosts, c.dst_port
            ),
            src_ip: c.src.to_string(),
            dst_ip: None,
            dst_port: Some(c.dst_port),
            attack: vec!["T1046".to_string()],
            evidence: vec![
                format!(
                    "{} distinct destination hosts contacted on port {}",
                    c.hosts, c.dst_port
                ),
                "horizontal scan / remote-system discovery".to_string(),
            ],
            interval_ns: None,
            jitter_cv: None,
            contacts: None,
        });
    }
    findings
}

/// Tuning for the vertical port-scan detector.
#[derive(Debug, Clone)]
pub struct PortScanParams {
    /// Master switch.
    pub enabled: bool,
    /// Minimum distinct *probed* ports on one `(src, host)` to call it a scan. Only probe flows
    /// (no completed bidirectional session — see `SCAN_SESSION_BYTES`) count, so a busy legit client
    /// with real sessions to many ports of one host (passive-FTP data ports, health checks) does not
    /// accumulate toward the floor. Set well above ordinary client behavior all the same.
    pub min_ports: usize,
    /// Sources never flagged — vulnerability scanners / monitoring probes whose job *is* to scan.
    /// Empty by default; populate per deployment to silence the sanctioned scanner.
    pub ignore_src: Vec<IpAddr>,
}

impl Default for PortScanParams {
    fn default() -> Self {
        PortScanParams {
            enabled: true,
            min_ports: 30,
            ignore_src: Vec::new(),
        }
    }
}

/// Detect vertical port scans from the behavioral tracker: one [`Finding`] per `(src, host)` where
/// the source probed at least [`PortScanParams::min_ports`] distinct ports on a single host — the
/// orthogonal axis to a horizontal host sweep. Network-service / remote-system discovery; High
/// severity, ATT&CK T1046. Deterministic order.
pub fn detect_port_scan(tracker: &BehaviorTracker, params: &PortScanParams) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.port_scan_candidates(params.min_ports) {
        if params.ignore_src.contains(&c.src) {
            continue;
        }
        findings.push(Finding {
            kind: FindingKind::PortScan,
            severity: Severity::High,
            score: 64,
            title: format!("Port scan: {} probed {} ports on {}", c.src, c.ports, c.dst),
            src_ip: c.src.to_string(),
            dst_ip: Some(c.dst.to_string()),
            dst_port: None,
            attack: vec!["T1046".to_string()],
            evidence: vec![
                format!("{} distinct ports contacted on {}", c.ports, c.dst),
                "vertical scan / network-service discovery".to_string(),
            ],
            interval_ns: None,
            jitter_cv: None,
            contacts: Some(c.ports as u64),
        });
    }
    findings
}

/// Tuning for the ARP-spoofing detector.
#[derive(Debug, Clone)]
pub struct ArpSpoofParams {
    /// Master switch.
    pub enabled: bool,
    /// Minimum distinct MACs claiming one IP before it is flagged. 2 is the canonical cache-poisoning
    /// signal (the real host plus the attacker); raise it to tolerate environments with deliberate
    /// IP/MAC churn.
    pub min_macs: usize,
    /// IPs never flagged — virtual IPs that legitimately migrate between MACs (VRRP/CARP/HSRP
    /// failover, NIC-teaming, a DHCP-churned address). Empty by default; populate per deployment.
    pub ignore_ips: Vec<IpAddr>,
}

impl Default for ArpSpoofParams {
    fn default() -> Self {
        ArpSpoofParams {
            enabled: true,
            min_macs: 2,
            ignore_ips: Vec::new(),
        }
    }
}

/// Detect ARP spoofing / cache poisoning from the behavioral tracker: one [`Finding`] per IP claimed
/// by at least [`ArpSpoofParams::min_macs`] distinct MAC addresses — the adversary-in-the-middle
/// signature on a local segment. High severity, ATT&CK T1557.002. Deterministic order.
pub fn detect_arp_spoof(tracker: &BehaviorTracker, params: &ArpSpoofParams) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.arp_spoof_candidates(params.min_macs.max(2)) {
        if params.ignore_ips.contains(&c.ip) {
            continue;
        }
        findings.push(Finding {
            kind: FindingKind::ArpSpoof,
            severity: Severity::High,
            score: 70,
            title: format!("ARP spoofing: {} claimed by {} MACs", c.ip, c.macs),
            src_ip: c.ip.to_string(),
            dst_ip: None,
            dst_port: None,
            attack: vec!["T1557.002".to_string()],
            evidence: vec![
                format!("{} distinct MAC addresses claimed {} via ARP", c.macs, c.ip),
                "one IP, multiple MACs — ARP cache poisoning / adversary-in-the-middle".to_string(),
            ],
            interval_ns: None,
            jitter_cv: None,
            contacts: Some(c.macs as u64),
        });
    }
    findings
}

/// Tuning for the SYN-flood / TCP-DoS detector.
#[derive(Debug, Clone)]
pub struct SynFloodParams {
    /// Master switch.
    pub enabled: bool,
    /// Minimum half-open connections to one `(target, port)` before it is flagged. A real flood is
    /// thousands; the floor sits well above the handful of incomplete connects a busy public service
    /// sees from ordinary churn.
    pub min_incomplete: u64,
    /// Targets never flagged. Empty by default; populate per deployment for a known load-tested host.
    pub ignore_dst: Vec<IpAddr>,
}

impl Default for SynFloodParams {
    fn default() -> Self {
        SynFloodParams {
            enabled: true,
            min_incomplete: 200,
            ignore_dst: Vec::new(),
        }
    }
}

/// Detect SYN floods / TCP DoS from the behavioral tracker: one [`Finding`] per `(target, port)`
/// service hit by at least [`SynFloodParams::min_incomplete`] half-open (never-completed)
/// connections. High severity, ATT&CK T1499.001 (Endpoint DoS: OS Exhaustion Flood). Deterministic
/// order.
pub fn detect_syn_flood(tracker: &BehaviorTracker, params: &SynFloodParams) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.syn_flood_candidates(params.min_incomplete) {
        if params.ignore_dst.contains(&c.dst) {
            continue;
        }
        let distributed = c.sources > 1;
        findings.push(Finding {
            kind: FindingKind::SynFlood,
            severity: Severity::High,
            score: 68,
            title: format!(
                "SYN flood: {}:{} hit by {} half-open connections",
                c.dst, c.dst_port, c.incomplete
            ),
            src_ip: c.dst.to_string(),
            dst_ip: None,
            dst_port: Some(c.dst_port),
            attack: vec!["T1499.001".to_string()],
            evidence: vec![
                format!(
                    "{} half-open connections from {} source{} to {}:{}",
                    c.incomplete,
                    c.sources,
                    if c.sources == 1 { "" } else { "s" },
                    c.dst,
                    c.dst_port
                ),
                if distributed {
                    "many sources, never-completed handshakes — distributed TCP DoS".to_string()
                } else {
                    "never-completed handshakes flooding one service — TCP DoS".to_string()
                },
            ],
            interval_ns: None,
            jitter_cv: None,
            contacts: Some(c.incomplete),
        });
    }
    findings
}

/// Tuning for the suspicious-User-Agent (attack-tool) detector.
#[derive(Debug, Clone)]
pub struct SuspiciousUaParams {
    /// Master switch.
    pub enabled: bool,
}

impl Default for SuspiciousUaParams {
    fn default() -> Self {
        SuspiciousUaParams { enabled: true }
    }
}

/// Detect attack tools / scanners from the behavioral tracker: one [`Finding`] per source that sent
/// an HTTP request with a known attack-tool [`User-Agent`](TOOL_USER_AGENTS) (sqlmap, Nikto, Nmap NSE,
/// masscan, …). High severity, ATT&CK T1595 (Active Scanning). Deterministic order.
pub fn detect_suspicious_ua(
    tracker: &BehaviorTracker,
    params: &SuspiciousUaParams,
) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.tool_ua_candidates() {
        let shown: String = c.sample.chars().take(80).collect();
        findings.push(Finding {
            kind: FindingKind::SuspiciousUa,
            severity: Severity::High,
            score: 66,
            title: format!("Attack tool {} from {}", c.tool, c.src),
            src_ip: c.src.to_string(),
            dst_ip: None,
            dst_port: None,
            attack: vec!["T1595".to_string()],
            evidence: vec![
                format!(
                    "{} request(s) with a {} User-Agent — a known attack tool / scanner",
                    c.hits, c.tool
                ),
                format!("User-Agent: {shown}"),
            ],
            interval_ns: None,
            jitter_cv: None,
            contacts: Some(c.hits),
        });
    }
    findings
}

/// Tuning for the disguised-download (file-type masquerade) detector.
#[derive(Debug, Clone)]
pub struct DisguisedDownloadParams {
    /// Master switch.
    pub enabled: bool,
}

impl Default for DisguisedDownloadParams {
    fn default() -> Self {
        DisguisedDownloadParams { enabled: true }
    }
}

/// Detect file-type masquerades: one [`Finding`] per `(client, server)` that delivered an executable
/// body over HTTP behind a benign `Content-Type` (e.g. an `.exe` served as `image/jpeg`) — a strong,
/// low-false-positive malware-delivery signal. High severity, ATT&CK T1036 (Masquerading) + T1105
/// (Ingress Tool Transfer). Deterministic order.
pub fn detect_disguised_download(
    tracker: &BehaviorTracker,
    params: &DisguisedDownloadParams,
) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.disguised_download_candidates() {
        findings.push(Finding {
            kind: FindingKind::DisguisedDownload,
            severity: Severity::High,
            score: 70,
            title: format!("Disguised {} download by {}", c.kind.as_str(), c.client),
            src_ip: c.client.to_string(),
            dst_ip: Some(c.server.to_string()),
            dst_port: None,
            attack: vec!["T1036".to_string(), "T1105".to_string()],
            evidence: vec![
                format!(
                    "{} response(s) from {} carried {} content behind a benign Content-Type",
                    c.hits,
                    c.server,
                    c.kind.as_str()
                ),
                "the file's magic bytes contradict the server's declared type — a deliberate masquerade".to_string(),
            ],
            interval_ns: None,
            jitter_cv: None,
            contacts: Some(c.hits),
        });
    }
    findings
}

/// Tuning for the cryptomining (Stratum) detector.
#[derive(Debug, Clone)]
pub struct CryptominingParams {
    /// Master switch.
    pub enabled: bool,
}

impl Default for CryptominingParams {
    fn default() -> Self {
        CryptominingParams { enabled: true }
    }
}

/// Detect cryptomining: one [`Finding`] per `(miner, pool)` channel running the cleartext Stratum
/// protocol (confirmed by a real pool response or sustained miner activity). High severity, ATT&CK
/// T1496 (Resource Hijacking). Deterministic order.
pub fn detect_cryptomining(tracker: &BehaviorTracker, params: &CryptominingParams) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.cryptomining_candidates() {
        findings.push(Finding {
            kind: FindingKind::Cryptomining,
            severity: Severity::High,
            score: 62,
            title: format!("Cryptomining: {} to pool {}", c.miner, c.pool),
            src_ip: c.miner.to_string(),
            dst_ip: Some(c.pool.to_string()),
            dst_port: None,
            attack: vec!["T1496".to_string()],
            evidence: vec![
                format!(
                    "{} cleartext Stratum mining message(s) exchanged with pool {}",
                    c.messages, c.pool
                ),
                "the Stratum JSON-RPC methods (mining.subscribe / mining.notify) identify a mining channel".to_string(),
            ],
            interval_ns: None,
            jitter_cv: None,
            contacts: Some(c.messages),
        });
    }
    findings
}

/// Tuning for the credential brute-force detector.
#[derive(Debug, Clone)]
pub struct BruteForceParams {
    /// Master switch.
    pub enabled: bool,
    /// Minimum connection attempts to one auth service before it counts as a brute force.
    pub min_attempts: u64,
    /// Destination ports treated as authentication services. Gating on these is the
    /// false-positive guard. The default is the *interactive remote-login* services
    /// ([`INTERACTIVE_AUTH_PORTS`]) where many separate connections from one source is
    /// unambiguously anomalous; high-churn services (SMB, LDAP, the databases) are deliberately
    /// left out of the default to avoid firing on legitimate enterprise service churn — the same
    /// "skip what you cannot cleanly disambiguate" stance as [`SweepParams::ignore_ports`]. Add
    /// them here when the deployment warrants it.
    pub auth_ports: Vec<u16>,
}

impl Default for BruteForceParams {
    fn default() -> Self {
        BruteForceParams {
            enabled: true,
            min_attempts: 20,
            auth_ports: INTERACTIVE_AUTH_PORTS.to_vec(),
        }
    }
}

/// Human service name for a well-known authentication port (for evidence/title text).
fn auth_service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        110 => "POP3",
        143 => "IMAP",
        389 => "LDAP",
        445 => "SMB",
        636 => "LDAPS",
        1433 => "MSSQL",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        5985 => "WinRM",
        _ => "auth service",
    }
}

/// Detect credential brute force from the behavioral tracker: one [`Finding`] per `(src, dst)`
/// channel that made at least [`BruteForceParams::min_attempts`] connection attempts to an
/// authentication service ([`BruteForceParams::auth_ports`]). High severity, ATT&CK T1110.
/// Deterministic order.
pub fn detect_brute_force(tracker: &BehaviorTracker, params: &BruteForceParams) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.brute_force_candidates(params.min_attempts, &params.auth_ports) {
        let dst = c.key.dst;
        let port = c.key.dst_port;
        let service = auth_service_name(port);
        findings.push(Finding {
            kind: FindingKind::BruteForce,
            severity: Severity::High,
            score: 68,
            title: format!(
                "Brute force: {} -> {}:{} ({} {} attempts)",
                c.key.src, dst, port, c.attempts, service
            ),
            src_ip: c.key.src.to_string(),
            dst_ip: Some(dst.to_string()),
            dst_port: Some(port),
            attack: vec!["T1110".to_string()],
            evidence: vec![
                format!(
                    "{} connection attempts to {} {}:{}",
                    c.attempts, service, dst, port
                ),
                "many separate logins to one auth service — password guessing".to_string(),
            ],
            interval_ns: None,
            jitter_cv: None,
            contacts: Some(c.attempts),
        });
    }
    findings
}

/// Remote-administration / remote-execution service ports used to pivot between hosts (the MITRE
/// T1021 sub-techniques): SSH, RPC/DCOM, SMB, RDP, VNC, WinRM. Established sessions to several
/// internal peers on these is the lateral-movement signature.
pub const LATERAL_PORTS: &[u16] = &[
    22,   // SSH (T1021.004)
    23,   // Telnet — cleartext remote login (T1021)
    135,  // RPC / DCOM / WMI (T1021.003)
    445,  // SMB / admin shares (T1021.002)
    3389, // RDP (T1021.001)
    5900, // VNC (T1021.005)
    5985, // WinRM HTTP (T1021.006)
    5986, // WinRM HTTPS
];

/// Human service name for a well-known lateral-movement port (for evidence/title text).
fn lateral_service_name(port: u16) -> &'static str {
    match port {
        22 => "SSH",
        23 => "Telnet",
        135 => "RPC",
        445 => "SMB",
        3389 => "RDP",
        5900 => "VNC",
        5985 | 5986 => "WinRM",
        _ => "remote-admin",
    }
}

/// Tuning for the lateral-movement detector.
///
/// **False-positive note.** This detector recognizes a *behavior* (an internal host opening admin
/// sessions to many internal peers), and that behavior is shared by legitimate east-west
/// infrastructure: backup / imaging servers, configuration management (SCCM, Ansible, WinRM),
/// patch/WSUS, monitoring and inventory collectors, jump hosts, and domain controllers all fan out
/// over SMB/RPC/RDP/WinRM by design. No purely network-level signal separates those from an
/// attacker pivot — it needs asset-role context the engine does not have. The session-byte floor
/// only excludes scans/handshakes; it does **not** distinguish benign from malicious admin fan-out.
/// The intended workflow is therefore: surface the finding with explainable evidence, and let the
/// operator exempt known management sources via [`LateralMovementParams::ignore_src`]. Treat a
/// standalone finding as "review this east-west fan-out", and trust the kill-chain correlation to
/// escalate it only when it sits alongside Discovery / Credential Access / C2 / Exfiltration.
#[derive(Debug, Clone)]
pub struct LateralMovementParams {
    /// Master switch.
    pub enabled: bool,
    /// Minimum distinct internal hosts reached with an established admin session.
    pub min_hosts: usize,
    /// Minimum bytes in **each** direction for a channel to count as an established session
    /// (rather than a SYN scan / bare handshake). A real remote-admin session moves well past
    /// this both ways; a probe does not.
    pub min_session_bytes: u64,
    /// Remote-administration ports considered. Defaults to [`LATERAL_PORTS`].
    pub lateral_ports: Vec<u16>,
    /// Source IPs exempt from lateral-movement detection — the escape hatch for known management
    /// infrastructure (backup / SCCM / monitoring / jump hosts / DCs) whose admin fan-out is
    /// expected. Empty by default; populate it per deployment to silence the recurring benign
    /// east-west finding without disabling the detector.
    pub ignore_src: Vec<IpAddr>,
}

impl Default for LateralMovementParams {
    fn default() -> Self {
        LateralMovementParams {
            enabled: true,
            // Below the host-sweep floor (16) so a few established admin sessions read as a
            // pivot, not a broad probe; high enough that a single targeted RDP/SSH is not flagged.
            min_hosts: 4,
            min_session_bytes: 512,
            lateral_ports: LATERAL_PORTS.to_vec(),
            ignore_src: Vec::new(),
        }
    }
}

/// Detect lateral movement from the behavioral tracker: one [`Finding`] per **internal** source
/// that opened an established admin session to at least [`LateralMovementParams::min_hosts`]
/// distinct **internal** hosts on one remote-administration port. East-west only (an external peer
/// is exfil/C2, not lateral movement) and session-gated (a SYN sweep is Discovery, not movement).
/// High severity, ATT&CK T1021. Deterministic order.
pub fn detect_lateral_movement(
    tracker: &BehaviorTracker,
    params: &LateralMovementParams,
) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.lateral_candidates(params.min_session_bytes, &params.lateral_ports) {
        // Lateral movement is east-west: the actor must be internal.
        if classify_ip(c.src).is_external() {
            continue;
        }
        // Known management infrastructure (backup / SCCM / monitoring / jump hosts) fans out over
        // these ports by design — let the operator exempt those sources rather than disable the
        // detector wholesale.
        if params.ignore_src.contains(&c.src) {
            continue;
        }
        // Count only internal targets (an internal host reaching out to external admin services is
        // not lateral movement within the network).
        let internal: Vec<IpAddr> = c
            .targets
            .into_iter()
            .filter(|d| !classify_ip(*d).is_external())
            .collect();
        if internal.len() < params.min_hosts {
            continue;
        }
        let port = c.dst_port;
        let service = lateral_service_name(port);
        // A couple of representative targets for the evidence, without unbounding the string.
        let sample: Vec<String> = internal.iter().take(3).map(|ip| ip.to_string()).collect();
        findings.push(Finding {
            kind: FindingKind::LateralMovement,
            severity: Severity::High,
            score: 70,
            title: format!(
                "Lateral movement: {} -> {} internal hosts over {} ({})",
                c.src,
                internal.len(),
                service,
                port
            ),
            src_ip: c.src.to_string(),
            // A fan-out finding implicates many destinations; like a sweep, it has no single dst.
            dst_ip: None,
            dst_port: Some(port),
            attack: vec!["T1021".to_string()],
            evidence: vec![
                format!(
                    "established {} sessions to {} distinct internal hosts on port {}",
                    service,
                    internal.len(),
                    port
                ),
                format!("e.g. {}", sample.join(", ")),
                "east-west admin sessions across hosts — pivoting / remote execution".to_string(),
            ],
            interval_ns: None,
            jitter_cv: None,
            contacts: Some(internal.len() as u64),
        });
    }
    findings
}

/// Drop host-sweep findings that lateral movement already explains: an established admin
/// fan-out to many internal hosts on a port is movement (real sessions), not a probe sweep, so
/// the more-specific lateral-movement finding wins for that `(src, port)`. Sweep findings carry no
/// `dst_ip` (fan-out), so the match is on `(src_ip, dst_port)`.
pub fn suppress_swept_by_lateral(sweeps: Vec<Finding>, lateral: &[Finding]) -> Vec<Finding> {
    use std::collections::HashSet;
    let claimed: HashSet<(&str, Option<u16>)> = lateral
        .iter()
        .map(|f| (f.src_ip.as_str(), f.dst_port))
        .collect();
    sweeps
        .into_iter()
        .filter(|s| !claimed.contains(&(s.src_ip.as_str(), s.dst_port)))
        .collect()
}

/// Tuning for the exposed-remote-access detector.
///
/// The complement of the lateral-movement detector: where lateral movement is east-west
/// (internal→internal), this flags a remote-admin session that crosses the internal↔external
/// boundary in either direction — an external peer reaching an internal admin service (exposed
/// RDP/SMB/VNC, a top ransomware entry vector) or an internal host opening a remote-admin session
/// out to a public address (reverse channel / pivot). The signature is tight (admin port +
/// boundary crossing + a real bidirectional session), so the FP surface is small; the allowlists
/// exist for sanctioned bastions / VPN concentrators / managed remote-access providers.
#[derive(Debug, Clone)]
pub struct ExposedRemoteAccessParams {
    /// Master switch.
    pub enabled: bool,
    /// Minimum bytes in **each** direction for a channel to count as a real session (not a bare
    /// handshake / scan). Mirrors the lateral-movement session floor.
    pub min_session_bytes: u64,
    /// Remote-administration ports considered. Defaults to [`LATERAL_PORTS`].
    pub ports: Vec<u16>,
    /// External peers never flagged — sanctioned remote-access providers / managed gateways.
    pub ignore_external: Vec<IpAddr>,
    /// Internal peers never flagged — published bastions / jump hosts / VPN concentrators.
    pub ignore_internal: Vec<IpAddr>,
}

impl Default for ExposedRemoteAccessParams {
    fn default() -> Self {
        ExposedRemoteAccessParams {
            enabled: true,
            // Same floor as lateral movement: real admin sessions move well past it both ways.
            min_session_bytes: 512,
            ports: LATERAL_PORTS.to_vec(),
            ignore_external: Vec::new(),
            ignore_internal: Vec::new(),
        }
    }
}

/// Detect exposed remote access from the behavioral tracker: one [`Finding`] per established
/// remote-administration session (RDP/VNC/SMB/SSH/WinRM/Telnet) that crosses the internal↔external
/// boundary — the direction [`detect_lateral_movement`] excludes (an external peer is exposure /
/// pivot, not east-west movement). High severity, ATT&CK T1133 (External Remote Services).
/// Deterministic order.
pub fn detect_exposed_remote_access(
    tracker: &BehaviorTracker,
    params: &ExposedRemoteAccessParams,
) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.exposed_remote_access_candidates(params.min_session_bytes, &params.ports) {
        if params.ignore_external.contains(&c.external)
            || params.ignore_internal.contains(&c.internal)
        {
            continue;
        }
        let service = lateral_service_name(c.port);
        // The actor (connection initiator) is the client side: external for inbound, internal for
        // outbound. `dst_ip` is the service side.
        let (src_ip, dst_ip) = if c.inbound {
            (c.external, c.internal)
        } else {
            (c.internal, c.external)
        };
        let title = if c.inbound {
            format!(
                "Exposed remote access: {} reached {} on {}:{}",
                c.external, service, c.internal, c.port
            )
        } else {
            format!(
                "Exposed remote access: {} opened {} to external {}:{}",
                c.internal, service, c.external, c.port
            )
        };
        let direction_line = if c.inbound {
            format!(
                "inbound: external {} connected to internal {}",
                c.external, c.internal
            )
        } else {
            format!(
                "outbound: internal {} connected to external {}",
                c.internal, c.external
            )
        };
        findings.push(Finding {
            kind: FindingKind::ExposedRemoteAccess,
            severity: Severity::High,
            score: 66,
            title,
            src_ip: src_ip.to_string(),
            dst_ip: Some(dst_ip.to_string()),
            dst_port: Some(c.port),
            attack: vec!["T1133".to_string()],
            evidence: vec![
                format!(
                    "established {} session on port {} crossing the internal↔external boundary",
                    service, c.port
                ),
                direction_line,
                "remote-administration service exposed across the perimeter (T1021)".to_string(),
            ],
            interval_ns: None,
            jitter_cv: None,
            contacts: Some(c.sessions),
        });
    }
    findings
}

/// Tuning for the cleartext-credential-exposure detector.
#[derive(Debug, Clone)]
pub struct CleartextCredsParams {
    /// Master switch.
    pub enabled: bool,
    /// Minimum exposures on a `(src, dst, port)` channel before it is reported. One exposed
    /// credential is already a finding, so the default is 1.
    pub min_exposures: u64,
}

impl Default for CleartextCredsParams {
    fn default() -> Self {
        CleartextCredsParams {
            enabled: true,
            min_exposures: 1,
        }
    }
}

/// Detect cleartext credential exposure from the behavioral tracker: one [`Finding`] per
/// `(src, dst, port)` channel that transmitted credentials in the clear (HTTP Basic/Digest, FTP
/// USER/PASS). The credential itself is never captured — only that an exposure occurred, its
/// scheme, the endpoints, and the count. High severity, ATT&CK T1552. Deterministic order.
pub fn detect_cleartext_creds(
    tracker: &BehaviorTracker,
    params: &CleartextCredsParams,
) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.cleartext_cred_candidates(params.min_exposures) {
        let scheme = c.scheme.label();
        let plural = if c.exposures == 1 { "" } else { "s" };
        findings.push(Finding {
            kind: FindingKind::CleartextCreds,
            severity: Severity::High,
            score: 66,
            title: format!(
                "Cleartext credentials: {} -> {}:{} ({})",
                c.src, c.dst, c.dst_port, scheme
            ),
            src_ip: c.src.to_string(),
            dst_ip: Some(c.dst.to_string()),
            dst_port: Some(c.dst_port),
            attack: vec!["T1552".to_string()],
            evidence: vec![
                format!(
                    "{} sent in cleartext to {}:{} ({} exposure{})",
                    scheme, c.dst, c.dst_port, c.exposures, plural
                ),
                "credentials are readable to anyone on-path — use an encrypted protocol (TLS)"
                    .to_string(),
            ],
            interval_ns: None,
            jitter_cv: None,
            contacts: Some(c.exposures),
        });
    }
    findings
}

/// Tuning for the plaintext-PII-exposure detector.
#[derive(Debug, Clone)]
pub struct PiiExposureParams {
    /// Master switch.
    pub enabled: bool,
    /// Minimum exposures on a `(src, dst, port)` channel before it is reported. One exposed PII
    /// value is already a finding, so the default is 1.
    pub min_exposures: u64,
}

impl Default for PiiExposureParams {
    fn default() -> Self {
        PiiExposureParams {
            enabled: true,
            min_exposures: 1,
        }
    }
}

/// Detect plaintext PII exposure from the behavioral tracker: one [`Finding`] per
/// `(src, dst, port)` channel that transmitted PII (a credit-card number or US SSN) in the clear.
/// The PII value itself is never captured — only that an exposure occurred, its kind, the
/// endpoints, and the count. High severity; mapped to the Collection stage (ATT&CK T1040, the
/// network-sniffing technique that harvests such cleartext data). Deterministic order.
pub fn detect_pii_exposure(tracker: &BehaviorTracker, params: &PiiExposureParams) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.pii_candidates(params.min_exposures) {
        let kind = c.kind.label();
        let plural = if c.exposures == 1 { "" } else { "s" };
        findings.push(Finding {
            kind: FindingKind::PiiExposure,
            severity: Severity::High,
            score: 64,
            title: format!(
                "Plaintext PII: {} -> {}:{} ({})",
                c.src, c.dst, c.dst_port, kind
            ),
            src_ip: c.src.to_string(),
            dst_ip: Some(c.dst.to_string()),
            dst_port: Some(c.dst_port),
            attack: vec!["T1040".to_string()],
            evidence: vec![
                format!(
                    "{}{} sent in cleartext to {}:{} ({} exposure{})",
                    kind,
                    if c.exposures == 1 { "" } else { "s" },
                    c.dst,
                    c.dst_port,
                    c.exposures,
                    plural
                ),
                "sensitive data is readable to anyone on-path — use an encrypted protocol (TLS)"
                    .to_string(),
            ],
            interval_ns: None,
            jitter_cv: None,
            contacts: Some(c.exposures),
        });
    }
    findings
}

/// Tuning for the DNS tunneling / DGA detector.
#[derive(Debug, Clone)]
pub struct DnsTunnelParams {
    /// Master switch.
    pub enabled: bool,
    /// Minimum DNS queries on a `(src, resolver)` channel to consider it.
    pub min_queries: u64,
    /// Minimum average most-dense-label Shannon entropy (bits/char). Random tunnel/DGA labels
    /// run high (~3.8+); ordinary domains run lower.
    pub min_avg_entropy: f64,
    /// Minimum longest-label length — encoded payloads use long labels.
    pub min_label_len: u16,
}

impl Default for DnsTunnelParams {
    fn default() -> Self {
        DnsTunnelParams {
            enabled: true,
            min_queries: 30,
            min_avg_entropy: 3.5,
            min_label_len: 20,
        }
    }
}

/// Detect DNS tunneling / DGA from the behavioral tracker: one [`Finding`] per `(src, resolver)`
/// channel whose DNS queries are high-volume and high-entropy with long labels — the signature
/// of data/C2 smuggled inside DNS names. High severity, ATT&CK T1071.004. Deterministic order.
pub fn detect_dns_tunnel(tracker: &BehaviorTracker, params: &DnsTunnelParams) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.dns_tunnel_candidates(
        params.min_queries,
        params.min_avg_entropy,
        params.min_label_len,
    ) {
        let mut evidence = vec![
            format!(
                "{} DNS queries to {} with avg label entropy {:.2} (max label {} chars)",
                c.queries, c.resolver, c.avg_entropy, c.max_label_len
            ),
            "high-entropy, long-label queries — data/C2 tunneled over DNS".to_string(),
        ];
        if let Some(sample) = &c.sample {
            // Bound the shown sample so a giant label cannot bloat the evidence.
            let shown: String = sample.chars().take(80).collect();
            evidence.push(format!("example: {shown}"));
        }
        findings.push(Finding {
            kind: FindingKind::DnsTunnel,
            severity: Severity::High,
            score: 74,
            title: format!(
                "DNS tunneling: {} -> {} ({} high-entropy queries)",
                c.src, c.resolver, c.queries
            ),
            src_ip: c.src.to_string(),
            dst_ip: Some(c.resolver.to_string()),
            dst_port: Some(53),
            attack: vec!["T1071.004".to_string()],
            evidence,
            interval_ns: None,
            jitter_cv: None,
            contacts: Some(c.queries),
        });
    }
    findings
}

/// Tuning for the DGA (domain-generation-algorithm) detector.
#[derive(Debug, Clone)]
pub struct DgaParams {
    /// Master switch.
    pub enabled: bool,
    /// Minimum distinct DGA-suspect registered domains from one source to flag it. DGA malware
    /// cycles through dozens-to-hundreds of generated domains; a healthy floor keeps the occasional
    /// random-looking SaaS/CDN apex from ever producing a finding.
    pub min_distinct_domains: u32,
    /// Sources to never flag — recursive resolvers, NAT/CGNAT gateways and DNS appliances, whose
    /// apparent source IP aggregates *many* clients' lookups into one bucket and would otherwise
    /// self-flag from the union of everyone's random-looking apexes. Per-source attribution
    /// collapses at any capture point upstream of a resolver, so the allowlist — not an
    /// external/internal gate (internal resolvers are internal) — is the load-bearing FP control.
    /// Empty by default; populate it per deployment.
    pub ignore_src: Vec<IpAddr>,
}

impl Default for DgaParams {
    fn default() -> Self {
        DgaParams {
            enabled: true,
            min_distinct_domains: 10,
            ignore_src: Vec::new(),
        }
    }
}

/// Detect domain-generation-algorithm activity: one [`Finding`] per source that resolved many
/// distinct algorithmically-random *registered* domains — the rendezvous pattern of DGA malware
/// hunting for its live C2. Distinct from DNS tunneling (which smuggles data in long high-entropy
/// labels of a *single* domain); here the signal is the *breadth* of random registered domains.
/// ATT&CK T1568.002. Deterministic order.
pub fn detect_dga(tracker: &BehaviorTracker, params: &DgaParams) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.dga_candidates(params.min_distinct_domains) {
        // A recursive resolver / NAT gateway aggregates many clients' lookups under one source and
        // would self-flag — let the operator exempt those rather than disable the detector.
        if params.ignore_src.contains(&c.src) {
            continue;
        }
        // Many distinct random domains is a stronger signal than a few; escalate accordingly.
        let (severity, score) = if c.distinct_domains >= 25 {
            (Severity::High, 76)
        } else {
            (Severity::Medium, 58)
        };
        let mut evidence = vec![
            format!(
                "{} distinct algorithmically-random registered domains resolved ({} DNS queries total)",
                c.distinct_domains, c.queries
            ),
            "breadth of random registered domains — DGA C2 rendezvous (not a single tunnel)"
                .to_string(),
        ];
        if let Some(sample) = &c.sample {
            let shown: String = sample.chars().take(80).collect();
            evidence.push(format!("example: {shown}"));
        }
        findings.push(Finding {
            kind: FindingKind::Dga,
            severity,
            score,
            title: format!(
                "DGA activity: {} ({} random domains)",
                c.src, c.distinct_domains
            ),
            src_ip: c.src.to_string(),
            dst_ip: None,
            dst_port: Some(53),
            attack: vec!["T1568.002".to_string()],
            evidence,
            interval_ns: None,
            jitter_cv: None,
            contacts: Some(c.distinct_domains as u64),
        });
    }
    findings
}

/// Extract a domain's `(registered_domain, registered_label)` — the registrable name and its
/// leftmost label — or `None` for inputs that have no such part (single-label names, IP literals,
/// reverse-DNS `.arpa` lookups). Without a public-suffix list the registered label is approximated
/// as the second-from-last label, which is correct for ordinary `name.tld` domains; multi-part
/// public suffixes (`.co.uk`) are approximated and not a DGA target in practice.
fn registered_domain(qname: &str) -> Option<(String, String)> {
    let trimmed = qname.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        return None;
    }
    // Reverse-DNS PTR lookups are never DGA.
    if trimmed.ends_with(".arpa") {
        return None;
    }
    let labels: Vec<&str> = trimmed.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() < 2 {
        return None;
    }
    let reg_label = labels[labels.len() - 2];
    let tld = labels[labels.len() - 1];
    // An all-numeric "label.tld" is an IP literal fragment, not a domain.
    if reg_label.bytes().all(|b| b.is_ascii_digit()) && tld.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((format!("{reg_label}.{tld}"), reg_label.to_string()))
}

/// Heuristic: does a registered label look algorithmically generated? Conservative per-label test —
/// the detector's reliability comes from requiring *many distinct* such labels per source, so this
/// only needs to separate "plausibly random" from "obviously wordlike". Signals: a long run of
/// consonants, a very low vowel ratio, or heavy digit use, on a label of generated length.
fn is_dga_label(label: &str) -> bool {
    let n = label.len();
    if !(8..=40).contains(&n) {
        return false;
    }
    // Punycode (IDNA ASCII-Compatible-Encoding): an `xn--` label is encoded non-Latin text, not
    // generated randomness. Its encoding artifact is structurally consonant-heavy / vowel-poor, so
    // scoring it raw flags every IDN domain. Exempt it (decoding is out of scope without an IDNA dep).
    if label.starts_with("xn--") {
        return false;
    }
    // Domain labels are LDH (letters/digits/hyphen); anything else is not a generated label here.
    if !label
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return false;
    }
    let letters = label.chars().filter(|c| c.is_ascii_alphabetic()).count();
    let vowels = label
        .chars()
        .filter(|c| matches!(c, 'a' | 'e' | 'i' | 'o' | 'u'))
        .count();
    let digits = label.chars().filter(|c| c.is_ascii_digit()).count();
    let digit_ratio = digits as f64 / n as f64;
    let vowel_ratio = if letters > 0 {
        vowels as f64 / letters as f64
    } else {
        1.0
    };

    let low_vowel = letters >= 6 && vowel_ratio < 0.26;
    let long_consonant_run = max_consonant_run(label) >= 5;
    let digit_heavy = digits >= 3 && digit_ratio >= 0.30;
    low_vowel || long_consonant_run || digit_heavy
}

/// Longest run of consecutive consonant letters; digits, hyphens and vowels reset the run.
fn max_consonant_run(label: &str) -> usize {
    let mut max = 0usize;
    let mut run = 0usize;
    for c in label.chars() {
        let is_consonant = c.is_ascii_alphabetic() && !matches!(c, 'a' | 'e' | 'i' | 'o' | 'u');
        if is_consonant {
            run += 1;
            if run > max {
                max = run;
            }
        } else {
            run = 0;
        }
    }
    max
}

/// Shannon entropy (bits per byte) of a string's byte distribution; `0.0` for empty input.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    h
}

/// Tuning for the TLS certificate-health detector.
#[derive(Debug, Clone)]
pub struct TlsCertHealthParams {
    /// Master switch.
    pub enabled: bool,
}

impl Default for TlsCertHealthParams {
    fn default() -> Self {
        TlsCertHealthParams { enabled: true }
    }
}

/// Detect suspicious server TLS certificates (self-signed / expired / not-yet-valid / hostname
/// mismatch) reassembled from cleartext TLS (≤ 1.2) handshakes. One [`Finding`] per
/// `(client, server, server_port)` flow, attributed to the **client** so it correlates with any
/// beacon / exfil to the same destination. Base severity tracks the worst single issue; two or
/// more distinct issues escalate one band. ATT&CK T1573 (Encrypted Channel); T1557
/// (Adversary-in-the-Middle) is added when the certificate name does not match the requested host.
/// Deterministic order.
pub fn detect_tls_cert_health(
    tracker: &BehaviorTracker,
    params: &TlsCertHealthParams,
) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.tls_cert_candidates() {
        // Distinct issue kinds, preserving the deterministic order the issues arrive in.
        let mut kinds: Vec<&str> = Vec::new();
        for issue in &c.issues {
            if !kinds.contains(&issue.kind_str()) {
                kinds.push(issue.kind_str());
            }
        }
        let mut severity = match worst_issue_rank(&c.issues) {
            3 => Severity::High,
            2 => Severity::Medium,
            _ => Severity::Low,
        };
        // Multiple distinct problems on one certificate raise confidence — bump one band, but cap
        // at High: a certificate anomaly alone is never Critical (incident correlation escalates a
        // host that *also* beacons / exfils to the same destination).
        let multi = kinds.len() >= 2;
        if multi && severity != Severity::High {
            severity = escalate(severity);
        }
        let mut score = match severity {
            Severity::Critical => 82,
            Severity::High => 68,
            Severity::Medium => 48,
            Severity::Low => 30,
            Severity::Info => 12,
        };
        if multi {
            score = (score + 6).min(100);
        }

        let mut attack = vec!["T1573".to_string()];
        if c.issues
            .iter()
            .any(|i| matches!(i, CertIssue::NameMismatch { .. }))
        {
            attack.push("T1557".to_string());
        }

        let mut evidence: Vec<String> = c.issues.iter().map(|i| i.evidence()).collect();
        if let Some(cn) = &c.subject_cn {
            evidence.push(format!("certificate subject CN: {cn}"));
        }
        if let Some(sni) = &c.sni {
            evidence.push(format!("requested host (SNI): {sni}"));
        }
        evidence.push(
            "verify the server's identity — self-signed/expired/mismatched TLS is common in C2 and on-path interception"
                .to_string(),
        );

        findings.push(Finding {
            kind: FindingKind::TlsCertHealth,
            severity,
            score,
            title: format!(
                "Suspicious TLS certificate: {} -> {}:{} ({})",
                c.client,
                c.server,
                c.server_port,
                kinds.join(", ")
            ),
            src_ip: c.client.to_string(),
            dst_ip: Some(c.server.to_string()),
            dst_port: Some(c.server_port),
            attack,
            evidence,
            interval_ns: None,
            jitter_cv: None,
            contacts: None,
        });
    }
    findings
}

/// Tuning for the weak / deprecated TLS detector.
#[derive(Debug, Clone)]
pub struct WeakTlsParams {
    /// Master switch.
    pub enabled: bool,
}

impl Default for WeakTlsParams {
    fn default() -> Self {
        WeakTlsParams { enabled: true }
    }
}

/// Detect weak / deprecated TLS negotiated by a server (SSLv3 / TLS 1.0-1.1, or a NULL / anon /
/// EXPORT / RC4 / DES / 3DES cipher suite), read from the cleartext ServerHello. One [`Finding`]
/// per `(client, server, server_port)` flow, attributed to the client so it correlates with any
/// beacon / exfil to the same destination. Severity tracks the worst single reason (NULL/anon/
/// EXPORT/SSLv3 = High, RC4/DES = Medium, 3DES/TLS1.0-1.1 = Low). ATT&CK T1040 (the weak channel
/// is interceptable). Deterministic order.
pub fn detect_weak_tls(tracker: &BehaviorTracker, params: &WeakTlsParams) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.weak_tls_candidates() {
        let severity = match worst_reason_rank(&c.reasons) {
            3 => Severity::High,
            2 => Severity::Medium,
            _ => Severity::Low,
        };
        let score = match severity {
            Severity::High => 64,
            Severity::Medium => 44,
            _ => 28,
        };
        let summary: Vec<&str> = c.reasons.iter().map(|r| r.kind_str()).collect();
        let mut evidence: Vec<String> = c.reasons.iter().map(|r| r.evidence()).collect();
        evidence.push(
            "weak or deprecated TLS leaves the session interceptable — require TLS 1.2+ with a strong cipher"
                .to_string(),
        );
        findings.push(Finding {
            kind: FindingKind::WeakTls,
            severity,
            score,
            title: format!(
                "Weak TLS: {} -> {}:{} ({})",
                c.client,
                c.server,
                c.server_port,
                summary.join(", ")
            ),
            src_ip: c.client.to_string(),
            dst_ip: Some(c.server.to_string()),
            dst_port: Some(c.server_port),
            attack: vec!["T1040".to_string()],
            evidence,
            interval_ns: None,
            jitter_cv: None,
            contacts: None,
        });
    }
    findings
}

/// Tuning for the ICMP tunneling (covert-channel) detector.
#[derive(Debug, Clone)]
pub struct IcmpTunnelParams {
    /// Master switch.
    pub enabled: bool,
    /// Minimum echo messages on a channel before it is considered (sustained, not a one-off ping).
    pub min_echoes: u64,
    /// Minimum peak/mean echo *data* payload (bytes). Ordinary ping carries 32-56 bytes.
    pub min_large_data: u32,
}

impl Default for IcmpTunnelParams {
    fn default() -> Self {
        IcmpTunnelParams {
            enabled: true,
            // A real tunnel sustains many echoes carrying ~1 KB each; these floors sit well above
            // ordinary ping (32-56 B) and routine large-payload diagnostics (`ping -s 200`).
            min_echoes: 32,
            min_large_data: 512,
        }
    }
}

/// Detect ICMP tunneling: a sustained `(src -> dst)` ICMP echo channel carrying large data
/// payloads — the shape of covert C2 / exfil over ICMP (ptunnel, icmptunnel, Loki). One [`Finding`]
/// per channel, High severity, ATT&CK T1095 (Non-Application Layer Protocol) + T1048.003 (exfil
/// over an unencrypted non-C2 protocol). Deterministic order.
pub fn detect_icmp_tunnel(tracker: &BehaviorTracker, params: &IcmpTunnelParams) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.icmp_tunnel_candidates(params.min_echoes, params.min_large_data) {
        // Covert ICMP tunnels reach an external endpoint; sustained large pings to an internal host
        // are overwhelmingly diagnostics (PMTU / jumbo-frame / latency monitoring). Gate to
        // external destinations, matching detect_exfil.
        if !classify_ip(c.dst).is_external() {
            continue;
        }
        let kb = c.data_bytes as f64 / 1024.0;
        findings.push(Finding {
            kind: FindingKind::IcmpTunnel,
            severity: Severity::High,
            score: 70,
            title: format!(
                "ICMP tunnel: {} -> {} ({} echoes, {:.1} KB)",
                c.src, c.dst, c.echoes, kb
            ),
            src_ip: c.src.to_string(),
            dst_ip: Some(c.dst.to_string()),
            dst_port: None,
            attack: vec!["T1095".to_string(), "T1048.003".to_string()],
            evidence: vec![
                format!(
                    "{} ICMP echo messages to {} carrying {:.1} KB of data (mean {} B, peak {} B per echo)",
                    c.echoes, c.dst, kb, c.mean_data, c.max_data
                ),
                "ICMP echo is not a data-transfer protocol — sustained large echo payloads indicate a covert channel / exfil".to_string(),
            ],
            interval_ns: None,
            jitter_cv: None,
            contacts: Some(c.echoes),
        });
    }
    findings
}

/// Correlate behavioral findings into per-host incidents, ordered along the kill chain
/// (discovery -> command-and-control -> exfiltration). A host exhibiting two or more distinct
/// stages is escalated one severity band — a multi-stage chain is a confirmed incident.
/// Incidents are returned worst-first.
pub fn correlate_incidents(findings: &[Finding]) -> Vec<Incident> {
    use std::collections::{BTreeMap, BTreeSet};

    // Group every finding under its actor host (the source it is attributed to).
    let mut by_host: BTreeMap<&str, Vec<Finding>> = BTreeMap::new();
    for f in findings {
        by_host
            .entry(f.src_ip.as_str())
            .or_default()
            .push(f.clone());
    }

    let mut incidents: Vec<Incident> = by_host
        .into_iter()
        .map(|(host, mut fs)| {
            // Order the contributing findings along the kill chain (then strongest first).
            fs.sort_by(|a, b| {
                stage_ordinal(a.kind)
                    .cmp(&stage_ordinal(b.kind))
                    .then(b.score.cmp(&a.score))
            });

            let distinct_kinds: BTreeSet<FindingKind> = fs.iter().map(|f| f.kind).collect();
            let multi_stage = distinct_kinds.len() >= 2;

            let base_sev = fs
                .iter()
                .map(|f| f.severity)
                .max()
                .unwrap_or(Severity::Info);
            let base_score = fs.iter().map(|f| f.score).max().unwrap_or(0);
            // A multi-stage chain is a confirmed incident: escalate one band / bump the score.
            let severity = if multi_stage {
                escalate(base_sev)
            } else {
                base_sev
            };
            let score = if multi_stage {
                (base_score + 15).min(100)
            } else {
                base_score
            };

            // Distinct stage labels, in kill-chain order.
            let mut stages: Vec<String> = Vec::new();
            for f in &fs {
                let label = stage_label(f.kind).to_string();
                if !stages.contains(&label) {
                    stages.push(label);
                }
            }

            // ATT&CK union, sorted + deduped.
            let attack: BTreeSet<String> =
                fs.iter().flat_map(|f| f.attack.iter().cloned()).collect();

            let (title, narrative) = if fs.len() == 1 {
                (fs[0].title.clone(), fs[0].title.clone())
            } else {
                let mut seen = BTreeSet::new();
                let phrases: Vec<&str> = fs
                    .iter()
                    .filter(|f| seen.insert(f.kind))
                    .map(|f| kind_phrase(f.kind))
                    .collect();
                (
                    format!("Multi-stage incident on {host}"),
                    format!("{host} {}.", join_phrases(&phrases)),
                )
            };

            Incident {
                host: host.to_string(),
                severity,
                score,
                title,
                narrative,
                stages,
                attack: attack.into_iter().collect(),
                findings: fs,
            }
        })
        .collect();

    incidents.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then(b.score.cmp(&a.score))
            .then(a.host.cmp(&b.host))
    });
    incidents
}

/// Kill-chain stage of a finding kind (lower = earlier in the chain).
fn stage_ordinal(kind: FindingKind) -> u8 {
    match kind {
        FindingKind::HostSweep => 0,           // discovery
        FindingKind::CleartextCreds => 1,      // credential access (exposure)
        FindingKind::BruteForce => 1,          // credential access
        FindingKind::LateralMovement => 2,     // lateral movement
        FindingKind::PiiExposure => 3,         // collection (data at risk on the wire)
        FindingKind::Beacon => 4,              // command-and-control
        FindingKind::DataExfil => 5,           // exfiltration
        FindingKind::DnsTunnel => 5,           // exfiltration / C2 over DNS
        FindingKind::RuleMatch => 4,           // imported signature — treat as C2-stage by default
        FindingKind::TlsCertHealth => 4, // command-and-control (suspicious C2 / interception cert)
        FindingKind::WeakTls => 3,       // collection (weak crypto -> interceptable traffic)
        FindingKind::IcmpTunnel => 5,    // exfiltration / C2 over a non-application protocol
        FindingKind::Dga => 4,           // command-and-control (C2 domain rendezvous)
        FindingKind::PortScan => 0,      // discovery (vertical service enumeration)
        FindingKind::ArpSpoof => 3,      // collection (adversary-in-the-middle positioning)
        FindingKind::SynFlood => 6,      // impact (service denial)
        FindingKind::SuspiciousUa => 0,  // discovery (active scanning with a known tool)
        FindingKind::DisguisedDownload => 4, // command-and-control (malware payload delivery)
        FindingKind::Cryptomining => 6,  // impact (resource hijacking)
        FindingKind::MalwareDownload => 4, // command-and-control (confirmed malware delivery)
        FindingKind::MalwareSignature => 4, // command-and-control (signature-matched payload)
        FindingKind::ExposedRemoteAccess => 2, // lateral movement / external remote services (pivot)
    }
}

/// Human kill-chain stage label for a finding kind.
fn stage_label(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::HostSweep => "Discovery",
        FindingKind::CleartextCreds => "Credential Access",
        FindingKind::BruteForce => "Credential Access",
        FindingKind::LateralMovement => "Lateral Movement",
        FindingKind::PiiExposure => "Collection",
        FindingKind::Beacon => "Command & Control",
        FindingKind::DataExfil => "Exfiltration",
        FindingKind::DnsTunnel => "Exfiltration",
        FindingKind::RuleMatch => "Signature Match",
        FindingKind::TlsCertHealth => "Command & Control",
        FindingKind::WeakTls => "Collection",
        FindingKind::IcmpTunnel => "Exfiltration",
        FindingKind::Dga => "Command & Control",
        FindingKind::PortScan => "Discovery",
        FindingKind::ArpSpoof => "Collection",
        FindingKind::SynFlood => "Impact",
        FindingKind::SuspiciousUa => "Discovery",
        FindingKind::DisguisedDownload => "Command & Control",
        FindingKind::Cryptomining => "Impact",
        FindingKind::MalwareDownload => "Command & Control",
        FindingKind::MalwareSignature => "Command & Control",
        FindingKind::ExposedRemoteAccess => "Lateral Movement",
    }
}

/// Narrative verb phrase for a finding kind.
fn kind_phrase(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::HostSweep => "swept the network",
        FindingKind::CleartextCreds => "exposed credentials in cleartext",
        FindingKind::BruteForce => "brute-forced credentials",
        FindingKind::LateralMovement => "moved laterally",
        FindingKind::PiiExposure => "exposed PII in cleartext",
        FindingKind::Beacon => "beaconed to a C2",
        FindingKind::DataExfil => "exfiltrated data",
        FindingKind::DnsTunnel => "tunneled data over DNS",
        FindingKind::RuleMatch => "triggered a signature rule",
        FindingKind::TlsCertHealth => "presented a suspicious TLS certificate",
        FindingKind::WeakTls => "negotiated weak or deprecated TLS",
        FindingKind::IcmpTunnel => "tunneled data over ICMP",
        FindingKind::Dga => "resolved algorithmically-generated C2 domains",
        FindingKind::PortScan => "scanned ports on a host",
        FindingKind::ArpSpoof => "poisoned ARP caches",
        FindingKind::SynFlood => "flooded a service with half-open connections",
        FindingKind::SuspiciousUa => "used a known attack tool",
        FindingKind::DisguisedDownload => "downloaded a disguised executable",
        FindingKind::Cryptomining => "mined cryptocurrency to a pool",
        FindingKind::MalwareDownload => "downloaded a known-malicious file",
        FindingKind::MalwareSignature => "downloaded a file matching a malware signature",
        FindingKind::ExposedRemoteAccess => "exposed remote access across the perimeter",
    }
}

/// Raise a severity by one band, saturating at `Critical`.
fn escalate(sev: Severity) -> Severity {
    match sev {
        Severity::Info => Severity::Low,
        Severity::Low => Severity::Medium,
        Severity::Medium => Severity::High,
        Severity::High | Severity::Critical => Severity::Critical,
    }
}

/// Join phrases as "a, then b, then c".
fn join_phrases(phrases: &[&str]) -> String {
    match phrases {
        [] => String::new(),
        [only] => only.to_string(),
        [first, rest @ ..] => {
            let mut s = first.to_string();
            for p in rest {
                s.push_str(", then ");
                s.push_str(p);
            }
            s
        }
    }
}

/// Compact base-1024 byte rendering for evidence strings (e.g. `5.0 MB`).
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// Fold post-hoc rule-match findings into a built [`Summary`]: uplift the implicated IP threat
/// cards, append the findings, and re-correlate incidents so the matches join their host's
/// incident. Re-running [`correlate_incidents`] over `summary.findings` reproduces the original
/// incidents plus the rule matches (`analyze` sets `summary.findings` to the same input).
pub fn fold_rule_findings(summary: &mut crate::model::summary::Summary, rule_findings: &[Finding]) {
    summary.apply_findings(rule_findings);
    summary.findings.extend_from_slice(rule_findings);
    summary.incidents = correlate_incidents(&summary.findings);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// Absolute-tolerance float compare for the statistical assertions.
    fn approx(a: f64, b: f64) {
        assert!((a - b).abs() < 1e-9, "expected ~{b}, got {a}");
    }

    #[test]
    fn empty_stats_are_zeroed() {
        let s = StreamStats::new();
        assert_eq!(s.count(), 0);
        approx(s.mean(), 0.0);
        approx(s.variance(), 0.0);
        approx(s.stddev(), 0.0);
        approx(s.cv(), 0.0);
        assert_eq!(s.min(), 0);
        assert_eq!(s.max(), 0);
    }

    #[test]
    fn single_sample_reports_mean_and_zero_variance() {
        let mut s = StreamStats::new();
        s.push(100);
        assert_eq!(s.count(), 1);
        approx(s.mean(), 100.0);
        approx(s.variance(), 0.0);
        approx(s.cv(), 0.0);
        assert_eq!(s.min(), 100);
        assert_eq!(s.max(), 100);
    }

    #[test]
    fn constant_stream_has_zero_variance_and_cv() {
        let mut s = StreamStats::new();
        for _ in 0..5 {
            s.push(60);
        }
        assert_eq!(s.count(), 5);
        approx(s.mean(), 60.0);
        approx(s.variance(), 0.0);
        approx(s.stddev(), 0.0);
        approx(s.cv(), 0.0);
    }

    #[test]
    fn known_sequence_matches_population_variance() {
        // Classic worked example: [2,4,4,4,5,5,7,9] -> mean 5, population variance 4,
        // stddev 2, cv 0.4.
        let mut s = StreamStats::new();
        for x in [2, 4, 4, 4, 5, 5, 7, 9] {
            s.push(x);
        }
        assert_eq!(s.count(), 8);
        approx(s.mean(), 5.0);
        approx(s.variance(), 4.0);
        approx(s.stddev(), 2.0);
        approx(s.cv(), 0.4);
    }

    #[test]
    fn min_and_max_track_extremes() {
        let mut s = StreamStats::new();
        for x in [5, 1, 9, 3] {
            s.push(x);
        }
        assert_eq!(s.min(), 1);
        assert_eq!(s.max(), 9);
    }

    #[test]
    fn periodic_series_has_lower_cv_than_irregular() {
        // A near-periodic beacon: ~60s period with tiny jitter -> tiny CV.
        let mut beacon = StreamStats::new();
        for gap in [60, 61, 59, 60, 60] {
            beacon.push(gap);
        }
        // Ad-hoc human traffic: wildly varying inter-arrival gaps -> large CV.
        let mut irregular = StreamStats::new();
        for gap in [5, 120, 30, 200, 1] {
            irregular.push(gap);
        }
        assert!(
            beacon.cv() < 0.1,
            "periodic CV should be near zero, got {}",
            beacon.cv()
        );
        assert!(
            beacon.cv() < irregular.cv(),
            "beacon CV {} should be below irregular CV {}",
            beacon.cv(),
            irregular.cv()
        );
    }

    // 60-second period expressed in nanoseconds (the engine's time unit).
    const SEC: i64 = 1_000_000_000;

    #[test]
    fn first_contact_has_no_interval() {
        let mut s = ContactSeries::new();
        s.observe(1_000 * SEC);
        assert_eq!(s.contacts(), 1);
        approx(s.interval_ns(), 0.0);
        approx(s.jitter_cv(), 0.0);
    }

    #[test]
    fn periodic_contacts_yield_low_jitter() {
        let mut s = ContactSeries::new();
        // Callbacks every ~60s with a little jitter.
        for &t in &[0, 60, 121, 179, 240, 301] {
            s.observe(t * SEC);
        }
        assert_eq!(s.contacts(), 6);
        // Mean gap is about one minute.
        assert!(
            (s.interval_ns() - 60.0 * SEC as f64).abs() < 2.0 * SEC as f64,
            "interval {} not ~60s",
            s.interval_ns()
        );
        assert!(
            s.jitter_cv() < 0.1,
            "jitter CV {} not near zero",
            s.jitter_cv()
        );
    }

    #[test]
    fn out_of_order_contact_clamps_gap_to_zero() {
        let mut s = ContactSeries::new();
        s.observe(100 * SEC);
        s.observe(40 * SEC); // earlier than the previous timestamp
        assert_eq!(s.contacts(), 2);
        // The negative raw gap must be clamped, never producing a negative interval.
        assert!(
            s.interval_ns() >= 0.0,
            "interval went negative: {}",
            s.interval_ns()
        );
    }

    #[test]
    fn tracks_distinct_destination_hosts_per_source() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let attacker = ip(10, 0, 0, 9);
        // One source touches 20 distinct destination hosts on port 445 (SMB sweep).
        for last in 1..=20u8 {
            t.observe_contact(attacker, ip(10, 0, 1, last), 445, 0);
        }
        assert_eq!(t.fanout(attacker, 445), 20);
        assert!(t.is_sweeper(attacker, 445, 15));
        assert!(!t.is_sweeper(attacker, 445, 21));
        // Fan-out is per-port: nothing was seen on 443.
        assert_eq!(t.fanout(attacker, 443), 0);
        // An unrelated source has no fan-out.
        assert_eq!(t.fanout(ip(10, 0, 0, 1), 445), 0);
        assert!(!t.is_sweeper(ip(1, 1, 1, 1), 445, 1));
    }

    #[test]
    fn detect_sweeps_flags_service_port_and_ignores_web() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let attacker = ip(10, 0, 0, 9);
        // SMB sweep: 20 distinct hosts on 445.
        for last in 1..=20u8 {
            t.observe_contact(attacker, ip(10, 0, 1, last), 445, 0);
        }
        // A busy browser: 20 hosts on 443 must NOT be flagged (ignored port).
        for last in 1..=20u8 {
            t.observe_contact(attacker, ip(10, 0, 2, last), 443, 0);
        }

        let findings = detect_sweeps(&t, &SweepParams::default());
        assert_eq!(findings.len(), 1, "findings: {findings:?}");
        let f = &findings[0];
        assert_eq!(f.kind, FindingKind::HostSweep);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.src_ip, "10.0.0.9");
        assert_eq!(f.dst_port, Some(445));
        assert!(f.dst_ip.is_none()); // a fan-out finding has no single destination
        assert!(
            f.attack.iter().any(|a| a == "T1046"),
            "attack: {:?}",
            f.attack
        );
    }

    #[test]
    fn detect_sweeps_below_threshold_or_disabled_yield_nothing() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let attacker = ip(10, 0, 0, 9);
        // Only 5 hosts on 445 — below min_hosts.
        for last in 1..=5u8 {
            t.observe_contact(attacker, ip(10, 0, 1, last), 445, 0);
        }
        assert!(detect_sweeps(&t, &SweepParams::default()).is_empty());

        // Now well above threshold, but disabled.
        for last in 6..=25u8 {
            t.observe_contact(attacker, ip(10, 0, 1, last), 445, 0);
        }
        let params = SweepParams {
            enabled: false,
            ..SweepParams::default()
        };
        assert!(detect_sweeps(&t, &params).is_empty());
    }

    // ── vertical port scan ──────────────────────────────────────────────────────

    #[test]
    fn detect_port_scan_flags_many_ports_on_one_host() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let attacker = ip(10, 0, 0, 9);
        let victim = ip(10, 0, 1, 5);
        // One source probes 40 distinct ports on a single host (nmap-style vertical scan).
        for port in 1..=40u16 {
            t.observe_contact(attacker, victim, port, 0);
        }
        let findings = detect_port_scan(&t, &PortScanParams::default());
        assert_eq!(findings.len(), 1, "findings: {findings:?}");
        let f = &findings[0];
        assert_eq!(f.kind, FindingKind::PortScan);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.src_ip, "10.0.0.9");
        assert_eq!(f.dst_ip.as_deref(), Some("10.0.1.5"));
        assert!(f.dst_port.is_none()); // the scan spans many ports, not one
        assert!(f.attack.iter().any(|a| a == "T1046"));
        assert!(f.contacts.unwrap() >= 30);
    }

    #[test]
    fn port_scan_not_flagged_below_threshold_or_when_fanned_across_hosts() {
        // Below the floor: a client hits a handful of ports on one host (web + a few services).
        let mut few = BehaviorTracker::new(DetectConfig::default());
        for port in [80u16, 443, 22, 8080, 3000] {
            few.observe_contact(ip(10, 0, 0, 5), ip(10, 0, 1, 5), port, 0);
        }
        assert!(detect_port_scan(&few, &PortScanParams::default()).is_empty());

        // Many ports, but spread one-per-host (a horizontal sweep, not a vertical scan): each
        // (src, host) pair sees a single port, so the port-scan signal stays at 1.
        let mut spread = BehaviorTracker::new(DetectConfig::default());
        for last in 1..=40u8 {
            spread.observe_contact(ip(10, 0, 0, 5), ip(10, 0, 1, last), 1000 + last as u16, 0);
        }
        assert!(detect_port_scan(&spread, &PortScanParams::default()).is_empty());
    }

    #[test]
    fn port_scan_ignores_completed_sessions_only_probes_count() {
        // A busy legit client opens REAL bidirectional sessions to 40 distinct ports of one host
        // (e.g. a passive-FTP mirror's data ports): bytes flow both ways, so none are scan probes.
        let mut busy = BehaviorTracker::new(DetectConfig::default());
        let client = ip(10, 0, 0, 5);
        let server = ip(10, 0, 1, 5);
        for port in 1..=40u16 {
            busy.observe_flow_contact(client, server, port, 0, 8_000, 64_000);
        }
        assert!(
            detect_port_scan(&busy, &PortScanParams::default()).is_empty(),
            "completed sessions must not be a scan"
        );

        // The same 40 ports as bare probes (no session bytes) ARE a scan.
        let mut scan = BehaviorTracker::new(DetectConfig::default());
        for port in 1..=40u16 {
            scan.observe_flow_contact(client, server, port, 0, 60, 40);
        }
        assert_eq!(detect_port_scan(&scan, &PortScanParams::default()).len(), 1);
    }

    #[test]
    fn port_scan_ignore_src_exempts_a_sanctioned_scanner() {
        let scanner = ip(10, 0, 0, 9);
        let victim = ip(10, 0, 1, 5);
        let mut t = BehaviorTracker::new(DetectConfig::default());
        for port in 1..=40u16 {
            t.observe_contact(scanner, victim, port, 0);
        }
        assert_eq!(detect_port_scan(&t, &PortScanParams::default()).len(), 1);
        let params = PortScanParams {
            ignore_src: vec![scanner],
            ..PortScanParams::default()
        };
        assert!(detect_port_scan(&t, &params).is_empty());
    }

    // ── ARP spoofing ────────────────────────────────────────────────────────────

    #[test]
    fn detect_arp_spoof_flags_one_ip_claimed_by_multiple_macs() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let gateway = ip(10, 0, 0, 1);
        // The real gateway MAC, then an attacker's MAC claiming the same IP (cache poisoning).
        t.observe_arp(gateway, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        t.observe_arp(gateway, [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        t.observe_arp(gateway, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // repeat real MAC

        let f = detect_arp_spoof(&t, &ArpSpoofParams::default());
        assert_eq!(f.len(), 1, "findings: {f:?}");
        assert_eq!(f[0].kind, FindingKind::ArpSpoof);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].src_ip, "10.0.0.1");
        assert!(f[0].attack.iter().any(|a| a == "T1557.002"));
        assert_eq!(f[0].contacts, Some(2));
    }

    #[test]
    fn arp_spoof_not_flagged_for_stable_or_ignored_bindings() {
        // A normal segment: each IP has exactly one MAC.
        let mut stable = BehaviorTracker::new(DetectConfig::default());
        for last in 1..=10u8 {
            stable.observe_arp(ip(10, 0, 0, last), [0, 0, 0, 0, 0, last]);
        }
        assert!(detect_arp_spoof(&stable, &ArpSpoofParams::default()).is_empty());

        // A virtual IP that legitimately migrates between MACs (failover) is exempted via ignore_ips.
        let vip = ip(10, 0, 0, 254);
        let mut churn = BehaviorTracker::new(DetectConfig::default());
        churn.observe_arp(vip, [0, 0, 0, 0, 0, 1]);
        churn.observe_arp(vip, [0, 0, 0, 0, 0, 2]);
        assert_eq!(
            detect_arp_spoof(&churn, &ArpSpoofParams::default()).len(),
            1
        );
        let params = ArpSpoofParams {
            ignore_ips: vec![vip],
            ..ArpSpoofParams::default()
        };
        assert!(detect_arp_spoof(&churn, &params).is_empty());
    }

    // ── SYN flood / TCP DoS ──────────────────────────────────────────────────────

    #[test]
    fn detect_syn_flood_flags_many_half_open_connections_to_one_service() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let target = ip(10, 0, 0, 80);
        // 300 half-open connections (no completed session) from many spoofed-looking sources to 80.
        for i in 0..300u32 {
            let src = ip(192, 168, (i >> 8) as u8, i as u8);
            t.observe_flow_contact(src, target, 80, 0, 60, 60); // ~SYN/SYN-ACK only, no data
        }
        let f = detect_syn_flood(&t, &SynFloodParams::default());
        assert_eq!(f.len(), 1, "findings: {f:?}");
        assert_eq!(f[0].kind, FindingKind::SynFlood);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].src_ip, "10.0.0.80");
        assert_eq!(f[0].dst_port, Some(80));
        assert!(f[0].attack.iter().any(|a| a == "T1499.001"));
        assert!(f[0].contacts.unwrap() >= 200);
    }

    #[test]
    fn syn_flood_not_flagged_for_completed_sessions_or_below_threshold() {
        // Many COMPLETED sessions to one service (a busy web server) — not a flood.
        let mut busy = BehaviorTracker::new(DetectConfig::default());
        let server = ip(10, 0, 0, 80);
        for i in 0..300u32 {
            let src = ip(192, 168, (i >> 8) as u8, i as u8);
            busy.observe_flow_contact(src, server, 443, 0, 4_000, 40_000); // real sessions, bytes both ways
        }
        assert!(detect_syn_flood(&busy, &SynFloodParams::default()).is_empty());

        // A busy SMALL-RESPONSE service (health checks / HTTP 204 / OCSP): the server's bytes are
        // tiny, but each client SENT a real request, so client->server bytes exceed the half-open
        // floor and none count — the review's worst false-positive case.
        let mut healthz = BehaviorTracker::new(DetectConfig::default());
        for i in 0..300u32 {
            let src = ip(192, 168, (i >> 8) as u8, i as u8);
            healthz.observe_flow_contact(src, server, 80, 0, 400, 120); // real request, tiny response
        }
        assert!(detect_syn_flood(&healthz, &SynFloodParams::default()).is_empty());

        // A handful of half-open connections — below the flood floor.
        let mut few = BehaviorTracker::new(DetectConfig::default());
        for i in 0..20u32 {
            few.observe_flow_contact(ip(192, 168, 0, i as u8), server, 443, 0, 60, 60);
        }
        assert!(detect_syn_flood(&few, &SynFloodParams::default()).is_empty());
    }

    #[test]
    fn syn_flood_not_flagged_for_busy_udp_service() {
        // A busy internal DNS resolver: 300 small UDP queries, each from a distinct ephemeral
        // source port (its own flow), all with client->server bytes under the half-open floor.
        // UDP has no handshake, so these must NOT be counted as half-open TCP connections.
        let mut dns = BehaviorTracker::new(DetectConfig::default());
        let resolver = ip(10, 0, 0, 1);
        for i in 0..300u32 {
            let client = ip(10, 0, (i >> 8) as u8, i as u8);
            dns.observe_flow_contact_with(client, resolver, 53, 0, 80, 120, Transport::Udp);
        }
        assert!(
            detect_syn_flood(&dns, &SynFloodParams::default()).is_empty(),
            "busy UDP service must not be flagged as a SYN flood"
        );

        // The identical byte pattern over TCP (real half-opens) still fires, proving the gate is
        // transport-specific, not a blanket suppression.
        let mut tcp = BehaviorTracker::new(DetectConfig::default());
        let target = ip(10, 0, 0, 2);
        for i in 0..300u32 {
            let client = ip(10, 0, (i >> 8) as u8, i as u8);
            tcp.observe_flow_contact_with(client, target, 80, 0, 80, 120, Transport::Tcp);
        }
        assert!(!detect_syn_flood(&tcp, &SynFloodParams::default()).is_empty());
    }

    // ── suspicious User-Agent (attack tools) ─────────────────────────────────────

    #[test]
    fn detect_suspicious_ua_flags_known_attack_tools() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let attacker = ip(10, 0, 0, 9);
        // Two sqlmap requests + one nikto from a different host.
        t.observe_user_agent(attacker, "sqlmap/1.7.2#stable (https://sqlmap.org)");
        t.observe_user_agent(attacker, "sqlmap/1.7.2#stable (https://sqlmap.org)");
        t.observe_user_agent(ip(10, 0, 0, 5), "Mozilla/5.00 (Nikto/2.5.0)");
        // A benign browser UA is ignored.
        t.observe_user_agent(
            ip(10, 0, 0, 6),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
        );

        let f = detect_suspicious_ua(&t, &SuspiciousUaParams::default());
        assert_eq!(f.len(), 2, "findings: {f:?}");
        // Most-active first: sqlmap host (2 hits) before nikto (1).
        assert_eq!(f[0].kind, FindingKind::SuspiciousUa);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].src_ip, "10.0.0.9");
        assert!(f[0].attack.iter().any(|a| a == "T1595"));
        assert_eq!(f[0].contacts, Some(2));
        assert!(f[0].title.contains("sqlmap"));
        assert!(f[1].title.contains("Nikto"));
    }

    #[test]
    fn match_tool_ua_is_case_insensitive_and_ignores_dual_use_clients() {
        assert_eq!(match_tool_ua("SQLMAP/1.0"), Some("sqlmap"));
        assert_eq!(
            match_tool_ua("() { :; }; /bin/bash"),
            Some("Shellshock probe")
        );
        // Dual-use clients are NOT flagged (too noisy to be an indicator on their own).
        assert_eq!(match_tool_ua("curl/8.4.0"), None);
        assert_eq!(match_tool_ua("python-requests/2.31"), None);
        assert_eq!(match_tool_ua("Mozilla/5.0 Chrome/120"), None);
        // Ordinary words / product names that collide with a tool name are NOT flagged: only coined
        // tool tokens are listed (no bare "hydra", which is a real product/word).
        assert_eq!(
            match_tool_ua("Hydra-Livecoding/1.4 (https://hydra.ojack.xyz)"),
            None
        );
        assert_eq!(match_tool_ua("MyApp/2.0 (hydration-service)"), None);
    }

    // ── disguised download (file-type masquerade) ────────────────────────────────

    #[test]
    fn detect_disguised_download_flags_masquerading_executables() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let client = ip(10, 0, 0, 9);
        let server = ip(93, 184, 216, 34);
        // Two executable bodies served disguised from the same server to the same client.
        t.observe_disguised_download(client, server, DownloadKind::Executable);
        t.observe_disguised_download(client, server, DownloadKind::Executable);
        // An unrelated benign channel is not observed (the decode gate never calls observe for it).

        let f = detect_disguised_download(&t, &DisguisedDownloadParams::default());
        assert_eq!(f.len(), 1, "findings: {f:?}");
        assert_eq!(f[0].kind, FindingKind::DisguisedDownload);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].src_ip, "10.0.0.9"); // the receiving client
        assert_eq!(f[0].dst_ip.as_deref(), Some("93.184.216.34"));
        assert!(f[0].attack.iter().any(|a| a == "T1036"));
        assert_eq!(f[0].contacts, Some(2));
        // The disabled switch suppresses it.
        let off = DisguisedDownloadParams { enabled: false };
        assert!(detect_disguised_download(&t, &off).is_empty());
    }

    // ── cryptomining (Stratum) ───────────────────────────────────────────────────

    #[test]
    fn detect_cryptomining_flags_confirmed_stratum_channels() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let miner = ip(10, 0, 0, 9);
        let pool = ip(203, 0, 113, 7);
        // Miner subscribes/authorizes; the pool responds with notify (confirming a real pool). Note
        // the pool-side message arrives src=pool,dst=miner — keyed to the SAME (miner,pool) channel.
        t.observe_stratum(StratumRole::Miner, miner, pool);
        t.observe_stratum(StratumRole::Miner, miner, pool);
        t.observe_stratum(StratumRole::Pool, pool, miner);

        let f = detect_cryptomining(&t, &CryptominingParams::default());
        assert_eq!(f.len(), 1, "findings: {f:?}");
        assert_eq!(f[0].kind, FindingKind::Cryptomining);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].src_ip, "10.0.0.9"); // the miner
        assert_eq!(f[0].dst_ip.as_deref(), Some("203.0.113.7")); // the pool
        assert!(f[0].attack.iter().any(|a| a == "T1496"));
        assert_eq!(f[0].contacts, Some(3));
    }

    #[test]
    fn cryptomining_not_flagged_without_pool_confirmation() {
        // Miner-side messages with NO pool response — a scanner/probe emitting Stratum tokens, or a
        // one-sided capture. Without a real pool's mining.notify the channel is unconfirmed (and the
        // attribution unverifiable), so it must NOT raise a High finding — even at volume.
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let scanner = ip(10, 0, 0, 9);
        let victim = ip(1, 2, 3, 4);
        for _ in 0..5 {
            t.observe_stratum(StratumRole::Miner, scanner, victim);
        }
        assert!(detect_cryptomining(&t, &CryptominingParams::default()).is_empty());
        // The disabled switch suppresses confirmed channels too.
        let mut t2 = BehaviorTracker::new(DetectConfig::default());
        t2.observe_stratum(StratumRole::Pool, ip(203, 0, 113, 7), ip(10, 0, 0, 9));
        let off = CryptominingParams { enabled: false };
        assert!(detect_cryptomining(&t2, &off).is_empty());
    }

    #[test]
    fn detect_brute_force_flags_repeated_auth_attempts_high() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let attacker = ip(10, 0, 0, 9);
        let victim = ip(10, 0, 0, 5);
        // 25 separate connection attempts to the victim's SSH service (each a distinct flow).
        for i in 0..25i64 {
            t.observe_contact(attacker, victim, 22, i * SEC);
        }
        // A handful of benign HTTPS connections to the same victim must NOT be a brute force.
        for i in 0..3i64 {
            t.observe_contact(attacker, victim, 443, i * SEC);
        }

        let findings = detect_brute_force(&t, &BruteForceParams::default());
        assert_eq!(findings.len(), 1, "findings: {findings:?}");
        let f = &findings[0];
        assert_eq!(f.kind, FindingKind::BruteForce);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.src_ip, "10.0.0.9");
        assert_eq!(f.dst_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(f.dst_port, Some(22));
        assert!(
            f.attack.iter().any(|a| a == "T1110"),
            "attack: {:?}",
            f.attack
        );
        assert!(f.contacts.unwrap() >= 20);
        assert!(
            f.title.contains("SSH"),
            "title should name the service: {}",
            f.title
        );
    }

    #[test]
    fn detect_brute_force_ignores_non_auth_ports_and_below_threshold() {
        // Many attempts, but to a non-auth port (8080) — not a credential brute force.
        let mut high_vol = BehaviorTracker::new(DetectConfig::default());
        for i in 0..50i64 {
            high_vol.observe_contact(ip(10, 0, 0, 9), ip(10, 0, 0, 5), 8080, i * SEC);
        }
        assert!(detect_brute_force(&high_vol, &BruteForceParams::default()).is_empty());

        // An auth port, but only a few attempts — below the threshold.
        let mut few = BehaviorTracker::new(DetectConfig::default());
        for i in 0..5i64 {
            few.observe_contact(ip(10, 0, 0, 9), ip(10, 0, 0, 5), 3389, i * SEC);
        }
        assert!(detect_brute_force(&few, &BruteForceParams::default()).is_empty());

        // A high-churn service (SMB 445) is NOT in the default auth_ports — many connections to a
        // file server are ordinary, so the default must not flag them.
        let mut smb = BehaviorTracker::new(DetectConfig::default());
        for i in 0..50i64 {
            smb.observe_contact(ip(10, 0, 0, 9), ip(10, 0, 0, 5), 445, i * SEC);
        }
        assert!(detect_brute_force(&smb, &BruteForceParams::default()).is_empty());
    }

    #[test]
    fn detect_brute_force_disabled_yields_nothing() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        for i in 0..30i64 {
            t.observe_contact(ip(10, 0, 0, 9), ip(10, 0, 0, 5), 22, i * SEC);
        }
        let params = BruteForceParams {
            enabled: false,
            ..BruteForceParams::default()
        };
        assert!(detect_brute_force(&t, &params).is_empty());
    }

    #[test]
    fn regular_auth_channel_is_brute_force_not_beacon() {
        // A throttled credential guesser: 25 regular, low-jitter SSH attempts ~5 s apart. That
        // timing ALSO satisfies the beacon predicate (>=12 contacts, CV~0, interval in [1s,24h]),
        // so without a guard the one channel would be reported as BOTH a brute force AND a C2
        // beacon. BeaconParams.ignore_ports skips the auth ports, so it is only a brute force.
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let attacker = ip(10, 0, 0, 9);
        let victim = ip(10, 0, 0, 5);
        for i in 0..25i64 {
            t.observe_contact(attacker, victim, 22, i * 5 * SEC);
        }

        let beacons = detect_beacons(&t, &BeaconParams::default());
        let brutes = detect_brute_force(&t, &BruteForceParams::default());
        assert!(
            beacons.iter().all(|b| b.dst_port != Some(22)),
            "auth-port channel must not be reported as a beacon: {beacons:?}"
        );
        assert_eq!(brutes.len(), 1, "the channel is a brute force: {brutes:?}");
        assert_eq!(brutes[0].dst_port, Some(22));

        // Prove it is the GUARD, not the timing, that prevents the overlap: clear ignore_ports and
        // the identical channel now also trips the beacon detector.
        let no_ignore = BeaconParams {
            ignore_ports: vec![],
            ..BeaconParams::default()
        };
        assert!(
            detect_beacons(&t, &no_ignore)
                .iter()
                .any(|b| b.dst_port == Some(22)),
            "without the guard the auth channel would also look like a beacon"
        );
    }

    #[test]
    fn lateral_movement_flags_established_admin_fanout_high() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let attacker = ip(10, 0, 0, 9); // internal
                                        // Established RDP sessions (bytes both ways) to 5 distinct internal hosts.
        for h in 1..=5u8 {
            t.observe_flow_contact(attacker, ip(10, 0, 1, h), 3389, h as i64 * SEC, 4000, 4000);
        }

        let findings = detect_lateral_movement(&t, &LateralMovementParams::default());
        assert_eq!(findings.len(), 1, "findings: {findings:?}");
        let f = &findings[0];
        assert_eq!(f.kind, FindingKind::LateralMovement);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.src_ip, "10.0.0.9");
        assert!(f.dst_ip.is_none(), "fan-out finding has no single dst");
        assert_eq!(f.dst_port, Some(3389));
        assert!(
            f.attack.iter().any(|a| a == "T1021"),
            "attack: {:?}",
            f.attack
        );
        assert_eq!(f.contacts, Some(5));
        assert!(
            f.title.contains("RDP"),
            "title names the service: {}",
            f.title
        );
    }

    #[test]
    fn lateral_movement_ignores_probes_external_and_below_threshold() {
        // SYN-only fan-out: 8 hosts on 445, no bytes back (a sweep, not established sessions).
        let mut probes = BehaviorTracker::new(DetectConfig::default());
        for h in 1..=8u8 {
            probes.observe_flow_contact(ip(10, 0, 0, 9), ip(10, 0, 1, h), 445, 0, 60, 0);
        }
        assert!(detect_lateral_movement(&probes, &LateralMovementParams::default()).is_empty());

        // Established sessions, but to EXTERNAL hosts — that is C2/exfil, not lateral movement.
        let mut external = BehaviorTracker::new(DetectConfig::default());
        for h in 1..=6u8 {
            external.observe_flow_contact(ip(10, 0, 0, 9), ip(8, 8, 8, h), 22, 0, 4000, 4000);
        }
        assert!(detect_lateral_movement(&external, &LateralMovementParams::default()).is_empty());

        // Established internal sessions, but only to 2 hosts — below the host threshold.
        let mut few = BehaviorTracker::new(DetectConfig::default());
        for h in 1..=2u8 {
            few.observe_flow_contact(ip(10, 0, 0, 9), ip(10, 0, 1, h), 445, 0, 4000, 4000);
        }
        assert!(detect_lateral_movement(&few, &LateralMovementParams::default()).is_empty());
    }

    #[test]
    fn lateral_movement_disabled_yields_nothing() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        for h in 1..=6u8 {
            t.observe_flow_contact(ip(10, 0, 0, 9), ip(10, 0, 1, h), 445, 0, 4000, 4000);
        }
        let params = LateralMovementParams {
            enabled: false,
            ..LateralMovementParams::default()
        };
        assert!(detect_lateral_movement(&t, &params).is_empty());
    }

    #[test]
    fn suppress_swept_by_lateral_drops_overlapping_sweep_only() {
        // A sweep and a lateral-movement finding on the SAME (src, port): the established-session
        // interpretation (lateral) wins, so that sweep is dropped. An unrelated sweep survives.
        let overlap_sweep = mk_finding(
            FindingKind::HostSweep,
            "10.0.0.9",
            Severity::High,
            65,
            &["T1046"],
        );
        let other_sweep = mk_finding(
            FindingKind::HostSweep,
            "10.0.0.7",
            Severity::High,
            65,
            &["T1046"],
        );
        let lateral = mk_finding(
            FindingKind::LateralMovement,
            "10.0.0.9",
            Severity::High,
            70,
            &["T1021"],
        );
        // mk_finding sets dst_port = Some(443) for all; align the non-overlapping sweep to a
        // different port so only the matching (src, port) is suppressed.
        let mut other_sweep = other_sweep;
        other_sweep.dst_port = Some(445);

        let kept =
            suppress_swept_by_lateral(vec![overlap_sweep.clone(), other_sweep.clone()], &[lateral]);
        assert_eq!(
            kept.len(),
            1,
            "only the overlapping sweep is dropped: {kept:?}"
        );
        assert_eq!(kept[0].src_ip, "10.0.0.7");
    }

    #[test]
    fn lateral_movement_respects_source_allowlist() {
        // A benign internal admin server (e.g. backup / SCCM) fans out established SMB sessions to
        // several internal hosts — the dominant false-positive surface. By default it fires (the
        // behavior is real); exempting the known source via ignore_src silences it without
        // disabling the detector. This makes the FP tunable and the guard non-vacuous.
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let infra = ip(10, 0, 0, 9);
        for h in 1..=5u8 {
            t.observe_flow_contact(infra, ip(10, 0, 1, h), 445, h as i64 * SEC, 4000, 4000);
        }
        assert_eq!(
            detect_lateral_movement(&t, &LateralMovementParams::default()).len(),
            1,
            "established admin fan-out fires by default"
        );
        let params = LateralMovementParams {
            ignore_src: vec![infra],
            ..LateralMovementParams::default()
        };
        assert!(
            detect_lateral_movement(&t, &params).is_empty(),
            "an allowlisted source is exempt"
        );
    }

    #[test]
    fn exposed_remote_access_flags_inbound_and_outbound_boundary_crossing() {
        // Inbound: an external client reached an internal RDP service (exposed RDP).
        let mut inbound = BehaviorTracker::new(DetectConfig::default());
        inbound.observe_flow_contact(ip(8, 8, 8, 8), ip(10, 0, 0, 9), 3389, SEC, 4000, 8000);
        let f = detect_exposed_remote_access(&inbound, &ExposedRemoteAccessParams::default());
        assert_eq!(f.len(), 1, "findings: {f:?}");
        assert_eq!(f[0].kind, FindingKind::ExposedRemoteAccess);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].dst_port, Some(3389));
        assert!(f[0].attack.iter().any(|a| a == "T1133"));
        assert_eq!(f[0].src_ip, "8.8.8.8", "inbound: external is the actor");
        assert_eq!(f[0].dst_ip.as_deref(), Some("10.0.0.9"));
        assert!(
            f[0].title.contains("RDP"),
            "title names the service: {}",
            f[0].title
        );

        // Outbound: an internal host opened a VNC session out to a public address (pivot).
        let mut outbound = BehaviorTracker::new(DetectConfig::default());
        outbound.observe_flow_contact(ip(10, 0, 0, 9), ip(1, 1, 1, 1), 5900, SEC, 4000, 8000);
        let g = detect_exposed_remote_access(&outbound, &ExposedRemoteAccessParams::default());
        assert_eq!(g.len(), 1, "findings: {g:?}");
        assert_eq!(g[0].src_ip, "10.0.0.9", "outbound: internal is the actor");
        assert_eq!(g[0].dst_ip.as_deref(), Some("1.1.1.1"));
        assert!(
            g[0].title.contains("VNC"),
            "title names the service: {}",
            g[0].title
        );

        // Inbound Telnet (port 23) — the classic Mirai-style exposed-Telnet vector the detector's
        // doc claims to cover. It must be flagged and labelled "Telnet".
        let mut telnet = BehaviorTracker::new(DetectConfig::default());
        telnet.observe_flow_contact(ip(8, 8, 8, 8), ip(10, 0, 0, 9), 23, SEC, 4000, 8000);
        let h = detect_exposed_remote_access(&telnet, &ExposedRemoteAccessParams::default());
        assert_eq!(h.len(), 1, "exposed Telnet must be flagged: {h:?}");
        assert_eq!(h[0].dst_port, Some(23));
        assert!(
            h[0].title.contains("Telnet"),
            "title names the service: {}",
            h[0].title
        );
    }

    #[test]
    fn exposed_remote_access_excludes_internal_nonadmin_handshake_and_disabled() {
        // Internal-only admin session — that is lateral movement's domain, not exposed access.
        let mut internal = BehaviorTracker::new(DetectConfig::default());
        internal.observe_flow_contact(ip(10, 0, 0, 1), ip(10, 0, 0, 2), 3389, SEC, 4000, 8000);
        assert!(
            detect_exposed_remote_access(&internal, &ExposedRemoteAccessParams::default())
                .is_empty()
        );

        // Boundary-crossing but a NON-admin port (HTTPS) — not a remote-admin service.
        let mut web = BehaviorTracker::new(DetectConfig::default());
        web.observe_flow_contact(ip(8, 8, 8, 8), ip(10, 0, 0, 9), 443, SEC, 4000, 8000);
        assert!(
            detect_exposed_remote_access(&web, &ExposedRemoteAccessParams::default()).is_empty()
        );

        // Bare handshake: the reverse direction is below the session floor (a probe, not a session).
        let mut probe = BehaviorTracker::new(DetectConfig::default());
        probe.observe_flow_contact(ip(8, 8, 8, 8), ip(10, 0, 0, 9), 3389, SEC, 4000, 60);
        assert!(
            detect_exposed_remote_access(&probe, &ExposedRemoteAccessParams::default()).is_empty()
        );

        // Disabled switch yields nothing even on a qualifying session.
        let mut on = BehaviorTracker::new(DetectConfig::default());
        on.observe_flow_contact(ip(8, 8, 8, 8), ip(10, 0, 0, 9), 3389, SEC, 4000, 8000);
        let off = ExposedRemoteAccessParams {
            enabled: false,
            ..ExposedRemoteAccessParams::default()
        };
        assert!(detect_exposed_remote_access(&on, &off).is_empty());
    }

    #[test]
    fn exposed_remote_access_respects_allowlists() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        t.observe_flow_contact(ip(8, 8, 8, 8), ip(10, 0, 0, 9), 3389, SEC, 4000, 8000);
        assert_eq!(
            detect_exposed_remote_access(&t, &ExposedRemoteAccessParams::default()).len(),
            1,
            "a boundary-crossing admin session fires by default"
        );
        // Exempting the external provider (a sanctioned remote-access gateway) silences it.
        let by_ext = ExposedRemoteAccessParams {
            ignore_external: vec![ip(8, 8, 8, 8)],
            ..ExposedRemoteAccessParams::default()
        };
        assert!(detect_exposed_remote_access(&t, &by_ext).is_empty());
        // Exempting the internal bastion also silences it.
        let by_int = ExposedRemoteAccessParams {
            ignore_internal: vec![ip(10, 0, 0, 9)],
            ..ExposedRemoteAccessParams::default()
        };
        assert!(detect_exposed_remote_access(&t, &by_int).is_empty());
    }

    #[test]
    fn beacon_ignores_remote_admin_ports() {
        // A periodic, low-jitter ESTABLISHED series on SMB (445) — a remote-admin / monitoring
        // cadence — must not be reported as a C2 beacon. 445 is not an interactive-auth port, so
        // this guards extending BeaconParams.ignore_ports to the lateral-movement ports.
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let src = ip(10, 0, 0, 9);
        let dst = ip(10, 0, 0, 5);
        for i in 0..16i64 {
            t.observe_flow_contact(src, dst, 445, i * 30 * SEC, 2000, 2000);
        }
        assert!(
            detect_beacons(&t, &BeaconParams::default())
                .iter()
                .all(|b| b.dst_port != Some(445)),
            "admin-port cadence must not be a beacon"
        );
        // Prove it is the guard, not the timing: clear ignore_ports and 445 trips the beacon.
        let no_ignore = BeaconParams {
            ignore_ports: vec![],
            ..BeaconParams::default()
        };
        assert!(
            detect_beacons(&t, &no_ignore)
                .iter()
                .any(|b| b.dst_port == Some(445)),
            "without the guard the admin cadence would look like a beacon"
        );
    }

    #[test]
    fn established_admin_spray_reports_both_credential_access_and_lateral_movement() {
        // A source that opens many established SSH sessions to each of several internal hosts is a
        // credential spray AND a pivot. Both detectors fire (brute force per host, lateral movement
        // for the fan-out) and correlation orders them Credential Access -> Lateral Movement — the
        // intended kill-chain coexistence on the shared port 22 (not a double-count to suppress).
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let attacker = ip(10, 0, 0, 9);
        for h in 1..=4u8 {
            let victim = ip(10, 0, 1, h);
            for i in 0..22i64 {
                t.observe_flow_contact(attacker, victim, 22, i * SEC, 800, 800);
            }
        }
        let brutes = detect_brute_force(&t, &BruteForceParams::default());
        let lateral = detect_lateral_movement(&t, &LateralMovementParams::default());
        assert_eq!(
            brutes.len(),
            4,
            "one brute finding per sprayed host: {brutes:?}"
        );
        assert_eq!(lateral.len(), 1, "one lateral fan-out finding: {lateral:?}");
        // Port 22 is in the beacon ignore set, so the regular cadence is NOT also a beacon.
        assert!(detect_beacons(&t, &BeaconParams::default()).is_empty());

        let mut all = brutes;
        all.extend(lateral);
        let inc = correlate_incidents(&all);
        assert_eq!(inc.len(), 1);
        assert_eq!(inc[0].stages, vec!["Credential Access", "Lateral Movement"]);
    }

    #[test]
    fn detect_cleartext_creds_flags_exposure_high() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let victim = ip(10, 0, 0, 50);
        let server = ip(10, 0, 0, 80);
        // 3 HTTP Basic auth requests on one channel -> one finding with 3 exposures.
        for _ in 0..3 {
            t.observe_cleartext_cred(victim, server, 80, CredScheme::HttpBasic);
        }
        // An unrelated FTP login exposes credentials on a different channel.
        t.observe_cleartext_cred(ip(10, 0, 0, 51), ip(10, 0, 0, 90), 21, CredScheme::Ftp);

        let findings = detect_cleartext_creds(&t, &CleartextCredsParams::default());
        assert_eq!(findings.len(), 2, "findings: {findings:?}");
        // Strongest (most exposures) first: the 3-exposure HTTP Basic channel.
        let f = &findings[0];
        assert_eq!(f.kind, FindingKind::CleartextCreds);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.src_ip, "10.0.0.50");
        assert_eq!(f.dst_ip.as_deref(), Some("10.0.0.80"));
        assert_eq!(f.dst_port, Some(80));
        assert!(
            f.attack.iter().any(|a| a == "T1552"),
            "attack: {:?}",
            f.attack
        );
        assert_eq!(f.contacts, Some(3));
        assert!(f.title.contains("HTTP Basic"), "title: {}", f.title);
    }

    #[test]
    fn detect_cleartext_creds_disabled_or_below_threshold() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        t.observe_cleartext_cred(
            ip(10, 0, 0, 50),
            ip(10, 0, 0, 80),
            80,
            CredScheme::HttpBasic,
        );
        let off = CleartextCredsParams {
            enabled: false,
            ..CleartextCredsParams::default()
        };
        assert!(detect_cleartext_creds(&t, &off).is_empty());
        let hi = CleartextCredsParams {
            enabled: true,
            min_exposures: 2,
        };
        assert!(detect_cleartext_creds(&t, &hi).is_empty());
    }

    #[test]
    fn detect_pii_exposure_flags_high_t1040() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let victim = ip(10, 0, 0, 52);
        let server = ip(10, 0, 0, 80);
        // 3 POSTs leaking a card number on one channel -> one finding, 3 exposures.
        for _ in 0..3 {
            t.observe_pii(victim, server, 80, PiiKind::CreditCard);
        }
        // An unrelated SSN exposure on a different channel.
        t.observe_pii(ip(10, 0, 0, 53), ip(10, 0, 0, 81), 8080, PiiKind::Ssn);

        let findings = detect_pii_exposure(&t, &PiiExposureParams::default());
        assert_eq!(findings.len(), 2, "findings: {findings:?}");
        let f = &findings[0]; // strongest (most exposures) first
        assert_eq!(f.kind, FindingKind::PiiExposure);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.src_ip, "10.0.0.52");
        assert_eq!(f.dst_ip.as_deref(), Some("10.0.0.80"));
        assert_eq!(f.dst_port, Some(80));
        assert!(
            f.attack.iter().any(|a| a == "T1040"),
            "attack: {:?}",
            f.attack
        );
        assert_eq!(f.contacts, Some(3));
        assert!(f.title.contains("credit card"), "title: {}", f.title);
        // Disabled yields nothing.
        let off = PiiExposureParams {
            enabled: false,
            ..PiiExposureParams::default()
        };
        assert!(detect_pii_exposure(&t, &off).is_empty());
    }

    #[test]
    fn pii_exposure_sorts_into_collection_stage() {
        // A PII finding correlates as its own "Collection" stage; mixed with other stages it sorts
        // between Lateral Movement and Command & Control.
        let host = "10.0.0.52";
        let pii = mk_finding(
            FindingKind::PiiExposure,
            host,
            Severity::High,
            64,
            &["T1040"],
        );
        let lateral = mk_finding(
            FindingKind::LateralMovement,
            host,
            Severity::High,
            70,
            &["T1021"],
        );
        let beacon = mk_finding(FindingKind::Beacon, host, Severity::High, 70, &["T1071"]);
        let inc = correlate_incidents(&[beacon, pii, lateral]);
        assert_eq!(inc.len(), 1);
        assert_eq!(
            inc[0].stages,
            vec!["Lateral Movement", "Collection", "Command & Control"]
        );
    }

    #[test]
    fn beacon_candidate_surfaced_for_periodic_destination() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let bot = ip(10, 0, 0, 5);
        let c2 = ip(203, 0, 113, 7);
        // Regular callbacks to the C2 every ~60s.
        for i in 0..8i64 {
            t.observe_contact(bot, c2, 443, i * 60 * SEC + (i % 2) * SEC);
        }
        // A one-off connection to a benign host must NOT look like a beacon.
        t.observe_contact(bot, ip(10, 0, 0, 2), 80, 5 * SEC);

        let candidates = t.beacon_candidates(5, 0.15);
        assert_eq!(candidates.len(), 1, "candidates: {candidates:?}");
        let c = candidates[0];
        assert_eq!(c.key, ContactKey::new(bot, c2, 443));
        assert!(c.contacts >= 5);
        assert!(c.jitter_cv <= 0.15);

        // The channel is queryable directly too.
        let series = t
            .series(ContactKey::new(bot, c2, 443))
            .expect("series tracked");
        assert_eq!(series.contacts(), 8);
    }

    #[test]
    fn tracker_drops_new_channels_at_capacity() {
        let cfg = DetectConfig {
            max_tracked_keys: 1,
            max_fanout_per_src: 4096,
        };
        let mut t = BehaviorTracker::new(cfg);
        let src = ip(10, 0, 0, 5);
        // First channel is tracked.
        t.observe_contact(src, ip(203, 0, 113, 1), 443, 0);
        // A second distinct channel at capacity is dropped (graceful degradation).
        t.observe_contact(src, ip(203, 0, 113, 2), 443, 0);
        assert_eq!(t.tracked_channels(), 1);
        assert!(t
            .series(ContactKey::new(src, ip(203, 0, 113, 1), 443))
            .is_some());
        assert!(t
            .series(ContactKey::new(src, ip(203, 0, 113, 2), 443))
            .is_none());
    }

    /// Feed `n` near-periodic contacts (`period_s` seconds apart, +/- 1s jitter) into a channel.
    fn feed_periodic(
        t: &mut BehaviorTracker,
        src: IpAddr,
        dst: IpAddr,
        port: u16,
        n: i64,
        period_s: i64,
    ) {
        for i in 0..n {
            let ts = i * period_s * SEC + (i % 2) * SEC;
            t.observe_contact(src, dst, port, ts);
        }
    }

    #[test]
    fn periodic_external_channel_yields_high_beacon_finding() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let bot = ip(10, 0, 0, 5);
        let c2 = ip(8, 8, 8, 8); // a Public (external) address standing in for the C2
        feed_periodic(&mut t, bot, c2, 443, 16, 60);

        let findings = detect_beacons(&t, &BeaconParams::default());
        assert_eq!(findings.len(), 1, "findings: {findings:?}");
        let b = &findings[0];
        assert_eq!(b.kind, FindingKind::Beacon);
        assert_eq!(b.severity, Severity::High); // external destination
        assert_eq!(b.src_ip, "10.0.0.5");
        assert_eq!(b.dst_ip.as_deref(), Some("8.8.8.8"));
        assert_eq!(b.dst_port, Some(443));
        assert!(
            b.attack.iter().any(|a| a == "T1071"),
            "attack: {:?}",
            b.attack
        );
        assert!(b.contacts.unwrap() >= 6);
        assert!(b.jitter_cv.unwrap() < 0.15);
        assert!(b.interval_ns.unwrap() > 0);
        assert!(!b.evidence.is_empty());
    }

    #[test]
    fn beacon_score_sits_in_its_severity_band() {
        // External beacon -> High band (60..=84).
        let mut ext = BehaviorTracker::new(DetectConfig::default());
        feed_periodic(&mut ext, ip(10, 0, 0, 5), ip(8, 8, 8, 8), 443, 16, 60);
        let f = detect_beacons(&ext, &BeaconParams::default());
        assert_eq!(f.len(), 1);
        assert!(
            (60..=84).contains(&f[0].score),
            "external score {} not in High band",
            f[0].score
        );

        // Internal beacon -> Medium band (35..=59).
        let mut int = BehaviorTracker::new(DetectConfig::default());
        feed_periodic(&mut int, ip(10, 0, 0, 5), ip(10, 0, 0, 9), 8080, 16, 30);
        let g = detect_beacons(&int, &BeaconParams::default());
        assert_eq!(g.len(), 1);
        assert!(
            (35..=59).contains(&g[0].score),
            "internal score {} not in Medium band",
            g[0].score
        );
    }

    #[test]
    fn internal_beacon_is_medium_severity() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        feed_periodic(&mut t, ip(10, 0, 0, 5), ip(10, 0, 0, 9), 8080, 16, 30);
        let findings = detect_beacons(&t, &BeaconParams::default());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium); // internal destination
    }

    #[test]
    fn subthreshold_or_irregular_channels_yield_no_finding() {
        // Too few contacts.
        let mut few = BehaviorTracker::new(DetectConfig::default());
        feed_periodic(&mut few, ip(10, 0, 0, 5), ip(203, 0, 113, 7), 443, 3, 60);
        assert!(detect_beacons(&few, &BeaconParams::default()).is_empty());

        // Enough contacts but wildly irregular timing (high CV) — not a beacon.
        let mut irregular = BehaviorTracker::new(DetectConfig::default());
        let bot = ip(10, 0, 0, 5);
        let c2 = ip(203, 0, 113, 7);
        for ts in [0, 5, 130, 140, 600, 605, 1800, 1810] {
            irregular.observe_contact(bot, c2, 443, ts * SEC);
        }
        assert!(detect_beacons(&irregular, &BeaconParams::default()).is_empty());
    }

    #[test]
    fn disabled_params_yield_no_findings() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        feed_periodic(&mut t, ip(10, 0, 0, 5), ip(203, 0, 113, 7), 443, 8, 60);
        let params = BeaconParams {
            enabled: false,
            ..BeaconParams::default()
        };
        assert!(detect_beacons(&t, &params).is_empty());
    }

    #[test]
    fn contact_from_flow_picks_service_port_and_initiator() {
        use crate::model::flow::FlowKey;
        // Client 10.0.0.5:50000 -> server 203.0.113.7:443.
        let (key, _dir) = FlowKey::normalized(
            ip(10, 0, 0, 5),
            50000,
            ip(203, 0, 113, 7),
            443,
            Transport::Tcp,
        );
        let rec = FlowRecord::new(key, 1234);
        let c = contact_from_flow(&rec).expect("port-bearing flow");
        assert_eq!(c.client, ip(10, 0, 0, 5));
        assert_eq!(c.server, ip(203, 0, 113, 7));
        assert_eq!(c.server_port, 443);
        assert_eq!(c.ts_ns, 1234);
    }

    #[test]
    fn contact_from_flow_is_none_for_portless_transport() {
        use crate::model::flow::FlowKey;
        let (key, _dir) =
            FlowKey::normalized(ip(10, 0, 0, 5), 0, ip(10, 0, 0, 6), 0, Transport::Icmp);
        let rec = FlowRecord::new(key, 0);
        assert!(contact_from_flow(&rec).is_none());
    }

    #[test]
    fn channel_folds_directional_bytes() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let src = ip(10, 0, 0, 5);
        let ext = ip(8, 8, 8, 8);
        t.observe_flow_contact(src, ext, 443, 0, 500_000, 1_000);
        t.observe_flow_contact(src, ext, 443, SEC, 700_000, 2_000);
        let s = t
            .series(ContactKey::new(src, ext, 443))
            .expect("channel tracked");
        assert_eq!(s.contacts(), 2);
        assert_eq!(s.bytes_out(), 1_200_000);
        assert_eq!(s.bytes_in(), 3_000);
    }

    #[test]
    fn exfil_candidate_for_large_asymmetric_outbound() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let src = ip(10, 0, 0, 5);
        let ext = ip(8, 8, 8, 8);
        // Big asymmetric upload — exfil shape.
        t.observe_flow_contact(src, ext, 443, 0, 5_000_000, 10_000);
        // A download (inbound-heavy) is NOT exfil.
        t.observe_flow_contact(src, ext, 80, 0, 10_000, 5_000_000);
        // A small channel is below the volume floor.
        t.observe_flow_contact(src, ip(10, 0, 0, 9), 445, 0, 1_000, 100);

        let cands = t.exfil_candidates(1_000_000, 4.0);
        assert_eq!(cands.len(), 1, "candidates: {cands:?}");
        assert_eq!(cands[0].key, ContactKey::new(src, ext, 443));
        assert!(cands[0].bytes_out >= 1_000_000);
    }

    #[test]
    fn detect_exfil_flags_external_upload_high() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let src = ip(10, 0, 0, 5);
        // Large asymmetric upload to an external peer.
        t.observe_flow_contact(src, ip(8, 8, 8, 8), 443, 0, 5_000_000, 10_000);
        // Same shape but to an INTERNAL peer — not exfil out of the network.
        t.observe_flow_contact(src, ip(10, 0, 0, 9), 445, 0, 5_000_000, 10_000);

        let findings = detect_exfil(&t, &ExfilParams::default());
        assert_eq!(findings.len(), 1, "findings: {findings:?}");
        let f = &findings[0];
        assert_eq!(f.kind, FindingKind::DataExfil);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.dst_ip.as_deref(), Some("8.8.8.8"));
        assert_eq!(f.dst_port, Some(443));
        assert!(
            f.attack.iter().any(|a| a == "T1048"),
            "attack: {:?}",
            f.attack
        );
        assert!(!f.evidence.is_empty());
    }

    #[test]
    fn detect_exfil_escalates_huge_volume_to_critical() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let src = ip(10, 0, 0, 5);
        t.observe_flow_contact(src, ip(8, 8, 8, 8), 443, 0, 200_000_000, 10_000);
        let findings = detect_exfil(&t, &ExfilParams::default());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn detect_exfil_disabled_yields_nothing() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        t.observe_flow_contact(ip(10, 0, 0, 5), ip(8, 8, 8, 8), 443, 0, 5_000_000, 10_000);
        let params = ExfilParams {
            enabled: false,
            ..ExfilParams::default()
        };
        assert!(detect_exfil(&t, &params).is_empty());
    }

    fn mk_finding(
        kind: FindingKind,
        src: &str,
        sev: Severity,
        score: u16,
        attack: &[&str],
    ) -> Finding {
        Finding {
            kind,
            severity: sev,
            score,
            title: format!("{} on {src}", kind.as_str()),
            src_ip: src.to_string(),
            dst_ip: Some("1.2.3.4".to_string()),
            dst_port: Some(443),
            attack: attack.iter().map(|s| s.to_string()).collect(),
            evidence: Vec::new(),
            interval_ns: None,
            jitter_cv: None,
            contacts: None,
        }
    }

    #[test]
    fn single_finding_yields_one_unescalated_incident() {
        let f = mk_finding(
            FindingKind::Beacon,
            "10.0.0.5",
            Severity::High,
            70,
            &["T1071"],
        );
        let inc = correlate_incidents(&[f]);
        assert_eq!(inc.len(), 1);
        assert_eq!(inc[0].host, "10.0.0.5");
        assert_eq!(inc[0].severity, Severity::High); // single stage — not escalated
        assert_eq!(inc[0].findings.len(), 1);
        assert_eq!(inc[0].stages, vec!["Command & Control"]);
    }

    #[test]
    fn multi_stage_chain_escalates_and_orders_by_kill_chain() {
        let host = "10.13.37.7";
        // Added out of kill-chain order: exfil, beacon, sweep.
        let exfil = mk_finding(FindingKind::DataExfil, host, Severity::High, 72, &["T1048"]);
        let beacon = mk_finding(FindingKind::Beacon, host, Severity::High, 70, &["T1071"]);
        let sweep = mk_finding(FindingKind::HostSweep, host, Severity::High, 65, &["T1046"]);

        let inc = correlate_incidents(&[exfil, beacon, sweep]);
        assert_eq!(inc.len(), 1);
        let i = &inc[0];
        assert_eq!(i.host, host);
        // Three distinct stages -> escalate High to Critical.
        assert_eq!(i.severity, Severity::Critical);
        assert_eq!(
            i.stages,
            vec!["Discovery", "Command & Control", "Exfiltration"]
        );
        // Contributing findings ordered along the kill chain.
        assert_eq!(i.findings.len(), 3);
        assert_eq!(i.findings[0].kind, FindingKind::HostSweep);
        assert_eq!(i.findings[1].kind, FindingKind::Beacon);
        assert_eq!(i.findings[2].kind, FindingKind::DataExfil);
        // ATT&CK union, sorted.
        assert_eq!(i.attack, vec!["T1046", "T1048", "T1071"]);
        assert!(i.narrative.contains("swept"), "narrative: {}", i.narrative);
    }

    #[test]
    fn brute_force_sorts_into_credential_access_between_discovery_and_c2() {
        let host = "10.13.37.7";
        // Added out of kill-chain order: beacon (C2), sweep (discovery), brute force (cred access).
        let beacon = mk_finding(FindingKind::Beacon, host, Severity::High, 70, &["T1071"]);
        let sweep = mk_finding(FindingKind::HostSweep, host, Severity::High, 65, &["T1046"]);
        let brute = mk_finding(
            FindingKind::BruteForce,
            host,
            Severity::High,
            68,
            &["T1110"],
        );

        let inc = correlate_incidents(&[beacon, sweep, brute]);
        assert_eq!(inc.len(), 1);
        let i = &inc[0];
        // Three distinct stages -> escalate High to Critical.
        assert_eq!(i.severity, Severity::Critical);
        assert_eq!(
            i.stages,
            vec!["Discovery", "Credential Access", "Command & Control"]
        );
        // Findings ordered along the kill chain: sweep -> brute force -> beacon.
        assert_eq!(i.findings[0].kind, FindingKind::HostSweep);
        assert_eq!(i.findings[1].kind, FindingKind::BruteForce);
        assert_eq!(i.findings[2].kind, FindingKind::Beacon);
        assert_eq!(i.attack, vec!["T1046", "T1071", "T1110"]);
    }

    #[test]
    fn full_five_stage_kill_chain_orders_and_escalates() {
        let host = "10.13.37.7";
        // Added out of order; correlation must sort them along the full kill chain.
        let exfil = mk_finding(FindingKind::DataExfil, host, Severity::High, 72, &["T1048"]);
        let lateral = mk_finding(
            FindingKind::LateralMovement,
            host,
            Severity::High,
            70,
            &["T1021"],
        );
        let beacon = mk_finding(FindingKind::Beacon, host, Severity::High, 70, &["T1071"]);
        let sweep = mk_finding(FindingKind::HostSweep, host, Severity::High, 65, &["T1046"]);
        let brute = mk_finding(
            FindingKind::BruteForce,
            host,
            Severity::High,
            68,
            &["T1110"],
        );

        let inc = correlate_incidents(&[exfil, lateral, beacon, sweep, brute]);
        assert_eq!(inc.len(), 1);
        let i = &inc[0];
        assert_eq!(i.severity, Severity::Critical);
        assert_eq!(
            i.stages,
            vec![
                "Discovery",
                "Credential Access",
                "Lateral Movement",
                "Command & Control",
                "Exfiltration"
            ]
        );
        let kinds: Vec<FindingKind> = i.findings.iter().map(|f| f.kind).collect();
        assert_eq!(
            kinds,
            vec![
                FindingKind::HostSweep,
                FindingKind::BruteForce,
                FindingKind::LateralMovement,
                FindingKind::Beacon,
                FindingKind::DataExfil,
            ]
        );
        assert!(
            i.narrative.contains("moved laterally"),
            "narrative: {}",
            i.narrative
        );
    }

    #[test]
    fn different_hosts_are_separate_incidents_ranked_worst_first() {
        let a = mk_finding(
            FindingKind::Beacon,
            "10.0.0.5",
            Severity::Medium,
            45,
            &["T1071"],
        );
        let b1 = mk_finding(
            FindingKind::HostSweep,
            "10.0.0.9",
            Severity::High,
            65,
            &["T1046"],
        );
        let b2 = mk_finding(
            FindingKind::Beacon,
            "10.0.0.9",
            Severity::High,
            70,
            &["T1071"],
        );

        let inc = correlate_incidents(&[a, b1, b2]);
        assert_eq!(inc.len(), 2);
        // 10.0.0.9 is multi-stage -> Critical, ranks first.
        assert_eq!(inc[0].host, "10.0.0.9");
        assert_eq!(inc[0].severity, Severity::Critical);
        assert_eq!(inc[1].host, "10.0.0.5");
        assert_eq!(inc[1].severity, Severity::Medium);
    }

    /// A 32-char base32 label with high entropy, deterministic per `seed`.
    fn tunnel_label(seed: u64) -> String {
        const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xDEAD_BEEF;
        (0..32)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                ALPHA[(x % 32) as usize] as char
            })
            .collect()
    }

    #[test]
    fn shannon_entropy_reflects_randomness() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert!(shannon_entropy("aaaaaaaa") < 1e-9); // one symbol -> zero entropy
                                                     // A normal label is low-entropy; a random tunnel label is clearly higher.
        assert!(shannon_entropy("example") < 3.0);
        assert!(
            shannon_entropy(&tunnel_label(1)) > 3.0,
            "entropy {}",
            shannon_entropy(&tunnel_label(1))
        );
    }

    #[test]
    fn dns_tunnel_detected_for_high_entropy_volume() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let bot = ip(10, 0, 0, 5);
        let resolver = ip(10, 0, 0, 1);
        for i in 0..40u64 {
            let qname = format!("{}.tunnel.evil.example", tunnel_label(i));
            t.observe_dns_query(bot, resolver, &qname);
        }
        let f = detect_dns_tunnel(&t, &DnsTunnelParams::default());
        assert_eq!(f.len(), 1, "findings: {f:?}");
        assert_eq!(f[0].kind, FindingKind::DnsTunnel);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].src_ip, "10.0.0.5");
        assert_eq!(f[0].dst_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(f[0].dst_port, Some(53));
        assert!(f[0].attack.iter().any(|a| a == "T1071.004"));
        assert!(f[0].contacts.unwrap() >= 30);
    }

    #[test]
    fn benign_or_low_volume_dns_is_not_flagged() {
        // Ordinary domains: short, low-entropy labels.
        let mut benign = BehaviorTracker::new(DetectConfig::default());
        for _ in 0..60 {
            benign.observe_dns_query(ip(10, 0, 0, 5), ip(10, 0, 0, 1), "www.example.com");
        }
        assert!(detect_dns_tunnel(&benign, &DnsTunnelParams::default()).is_empty());

        // High-entropy but only a few queries -> below the volume floor.
        let mut few = BehaviorTracker::new(DetectConfig::default());
        for i in 0..5u64 {
            let q = format!("{}.t.evil.example", tunnel_label(i));
            few.observe_dns_query(ip(10, 0, 0, 5), ip(10, 0, 0, 1), &q);
        }
        assert!(detect_dns_tunnel(&few, &DnsTunnelParams::default()).is_empty());
    }

    // ── DGA detection ─────────────────────────────────────────────────────────

    /// A 12-char vowel-free pseudo-random label (deterministic per `seed`) — always DGA-suspect.
    fn dga_label(seed: u64) -> String {
        const ALPHA: &[u8] = b"bcdfghjklmnpqrstvwxz0123456789";
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x1234_5678;
        (0..12)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                ALPHA[(x as usize) % ALPHA.len()] as char
            })
            .collect()
    }

    #[test]
    fn dga_detected_for_many_distinct_random_domains() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let bot = ip(10, 0, 0, 5);
        let resolver = ip(10, 0, 0, 1);
        for i in 0..16u64 {
            let q = format!("{}.com", dga_label(i));
            t.observe_dns_query(bot, resolver, &q);
        }
        let f = detect_dga(&t, &DgaParams::default());
        assert_eq!(f.len(), 1, "findings: {f:?}");
        assert_eq!(f[0].kind, FindingKind::Dga);
        assert_eq!(f[0].src_ip, "10.0.0.5");
        assert_eq!(f[0].dst_port, Some(53));
        assert!(f[0].attack.iter().any(|a| a == "T1568.002"));
        assert!(f[0].contacts.unwrap() >= 10);
    }

    #[test]
    fn dga_not_flagged_below_threshold_or_for_normal_browsing() {
        // A handful of random domains -> below the distinct-domain floor.
        let mut few = BehaviorTracker::new(DetectConfig::default());
        for i in 0..5u64 {
            let q = format!("{}.com", dga_label(i));
            few.observe_dns_query(ip(10, 0, 0, 5), ip(10, 0, 0, 1), &q);
        }
        assert!(detect_dga(&few, &DgaParams::default()).is_empty());

        // Ordinary, wordlike registered domains -> never suspect, regardless of volume.
        let mut benign = BehaviorTracker::new(DetectConfig::default());
        for name in [
            "google.com",
            "facebook.com",
            "amazon.com",
            "wikipedia.org",
            "youtube.com",
            "twitter.com",
            "github.com",
            "netflix.com",
            "reddit.com",
            "apple.com",
            "microsoft.com",
            "cloudflare.com",
            "linkedin.com",
            "office.com",
        ] {
            for _ in 0..5 {
                benign.observe_dns_query(ip(10, 0, 0, 6), ip(10, 0, 0, 1), name);
            }
        }
        assert!(detect_dga(&benign, &DgaParams::default()).is_empty());
    }

    #[test]
    fn dga_ignores_random_cdn_subdomains() {
        // Random *subdomains* under one ordinary registered domain (the CDN pattern): the registered
        // label 'cloudfront' is wordlike, so none are suspect — even across many distinct subdomains.
        let mut t = BehaviorTracker::new(DetectConfig::default());
        for i in 0..40u64 {
            let q = format!("{}.cloudfront.net", dga_label(i));
            t.observe_dns_query(ip(10, 0, 0, 5), ip(10, 0, 0, 1), &q);
        }
        let f = detect_dga(&t, &DgaParams::default());
        assert!(f.is_empty(), "CDN subdomains must not flag: {f:?}");
    }

    #[test]
    fn dga_ignore_src_exempts_a_resolver_or_gateway() {
        // A recursive resolver / NAT gateway aggregates many clients' random apexes under one source
        // and would self-flag. By default it fires (the behavior is real); exempting it via
        // ignore_src silences the finding without disabling the detector. Keeps the guard non-vacuous.
        let gw = ip(10, 0, 0, 1);
        let mut t = BehaviorTracker::new(DetectConfig::default());
        for i in 0..16u64 {
            let q = format!("{}.com", dga_label(i));
            t.observe_dns_query(gw, gw, &q);
        }
        assert_eq!(detect_dga(&t, &DgaParams::default()).len(), 1);
        let params = DgaParams {
            ignore_src: vec![gw],
            ..DgaParams::default()
        };
        assert!(detect_dga(&t, &params).is_empty());
    }

    #[test]
    fn is_dga_label_separates_random_from_wordlike() {
        for w in [
            "google",
            "cloudfront",
            "facebook",
            "wikipedia",
            "example",
            "akamaihd",
            "microsoft",
            "xn--80akhbyknj4f", // punycode (IDN) — encoding artifact, not generated randomness
        ] {
            assert!(!is_dga_label(w), "{w} should not be DGA");
        }
        assert!(is_dga_label("kq3v9z2xph7w")); // vowel-free + digit-heavy
        assert!(is_dga_label("xkcdwbjmqrtz")); // long consonant run / no vowels
        assert!(!is_dga_label("abc")); // too short
    }

    #[test]
    fn registered_domain_extracts_or_skips() {
        assert_eq!(
            registered_domain("www.example.com"),
            Some(("example.com".into(), "example".into()))
        );
        assert_eq!(
            registered_domain("EXAMPLE.COM."),
            Some(("example.com".into(), "example".into()))
        );
        assert_eq!(registered_domain("localhost"), None); // single label
        assert_eq!(registered_domain("5.0.168.192.in-addr.arpa"), None); // PTR
        assert_eq!(registered_domain(""), None);
    }

    // ── fold_rule_findings ────────────────────────────────────────────────────

    fn rule_match_on(src: &str, dst: &str) -> Finding {
        Finding {
            kind: FindingKind::RuleMatch,
            severity: Severity::High,
            score: 70,
            title: "sig hit".into(),
            src_ip: src.into(),
            dst_ip: Some(dst.into()),
            dst_port: Some(443),
            attack: vec!["T1071".into()],
            evidence: vec!["rule sid:1001".into()],
            interval_ns: None,
            jitter_cv: None,
            contacts: None,
        }
    }

    #[test]
    fn fold_rule_findings_joins_same_host_incident() {
        // Seed a Beacon finding on 10.0.0.5 and correlate it into one incident.
        let beacon = mk_finding(
            FindingKind::Beacon,
            "10.0.0.5",
            Severity::High,
            70,
            &["T1071"],
        );
        let mut sum = crate::model::output::AnalysisOutput::default().summary;
        sum.findings = vec![beacon.clone()];
        sum.incidents = correlate_incidents(&sum.findings);

        // Seed an IpThreat card for 10.0.0.5 so apply_findings has a target to uplift.
        let low_card: crate::model::summary::IpThreat = serde_json::from_str(
            r#"{"ip":"10.0.0.5","ip_class":"private","severity":"low","score":20,
                "flows":2,"bytes":500,"ioc":false,"tags":["private"],"attack":[],"evidence":[]}"#,
        )
        .unwrap();
        sum.ip_threats = vec![low_card];

        fold_rule_findings(&mut sum, &[rule_match_on("10.0.0.5", "203.0.113.9")]);

        // The rule match must be joined into the host's existing incident.
        let inc = sum
            .incidents
            .iter()
            .find(|i| i.host == "10.0.0.5")
            .expect("incident for host 10.0.0.5");
        assert!(
            inc.findings
                .iter()
                .any(|f| f.kind == FindingKind::RuleMatch),
            "RuleMatch not found in incident findings: {:?}",
            inc.findings.iter().map(|f| f.kind).collect::<Vec<_>>()
        );

        // Card must have been uplifted from Low to High by apply_findings.
        let card = sum
            .ip_threats
            .iter()
            .find(|c| c.ip == "10.0.0.5")
            .expect("ip_threat card for 10.0.0.5");
        assert_eq!(card.severity, Severity::High);
    }

    #[test]
    fn fold_rule_findings_creates_incident_for_new_host() {
        // Empty summary — no prior findings or incidents.
        let mut sum = crate::model::output::AnalysisOutput::default().summary;

        fold_rule_findings(&mut sum, &[rule_match_on("10.9.9.9", "8.8.8.8")]);

        // A new incident must have been created for the rule-only host.
        assert!(
            sum.incidents.iter().any(|i| i.host == "10.9.9.9"),
            "no incident for 10.9.9.9; incidents: {:?}",
            sum.incidents.iter().map(|i| &i.host).collect::<Vec<_>>()
        );
        // The finding must have been appended to summary.findings.
        assert!(
            sum.findings
                .iter()
                .any(|f| f.kind == FindingKind::RuleMatch),
            "RuleMatch not in summary.findings"
        );
    }

    // ── tls cert health ───────────────────────────────────────────────────────

    #[test]
    fn tls_cert_health_flags_escalates_and_maps_attack() {
        let client = ip(10, 0, 0, 5);
        let server = ip(203, 0, 113, 9);

        // Two distinct issues (self-signed + name mismatch): Medium base escalates to High, and
        // the name mismatch adds the Adversary-in-the-Middle technique.
        let mut t = BehaviorTracker::new(DetectConfig::default());
        t.observe_tls_cert(
            client,
            server,
            443,
            vec![
                CertIssue::SelfSigned,
                CertIssue::NameMismatch {
                    sni: "good.example".into(),
                },
            ],
            Some("c2.evil".into()),
            Some("good.example".into()),
        );
        let f = detect_tls_cert_health(&t, &TlsCertHealthParams::default());
        assert_eq!(f.len(), 1, "findings: {f:?}");
        assert_eq!(f[0].kind, FindingKind::TlsCertHealth);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].src_ip, "10.0.0.5");
        assert_eq!(f[0].dst_ip.as_deref(), Some("203.0.113.9"));
        assert_eq!(f[0].dst_port, Some(443));
        assert!(f[0].attack.iter().any(|a| a == "T1573"));
        assert!(f[0].attack.iter().any(|a| a == "T1557"));

        // A single expired issue stays Low and carries only T1573.
        let mut t2 = BehaviorTracker::new(DetectConfig::default());
        t2.observe_tls_cert(
            client,
            server,
            443,
            vec![CertIssue::Expired {
                not_after: 20_190_101_000_000,
                observed: 20_250_101_000_000,
            }],
            None,
            None,
        );
        let f2 = detect_tls_cert_health(&t2, &TlsCertHealthParams::default());
        assert_eq!(f2.len(), 1);
        assert_eq!(f2[0].severity, Severity::Low);
        assert!(f2[0].attack.iter().all(|a| a != "T1557"));

        // Disabled -> nothing; an empty issue list is never recorded.
        assert!(detect_tls_cert_health(&t, &TlsCertHealthParams { enabled: false }).is_empty());
        let mut t3 = BehaviorTracker::new(DetectConfig::default());
        t3.observe_tls_cert(client, server, 443, vec![], None, None);
        assert!(detect_tls_cert_health(&t3, &TlsCertHealthParams::default()).is_empty());
    }

    #[test]
    fn weak_tls_flags_severity_by_worst_reason() {
        let client = ip(10, 0, 0, 5);
        let server = ip(203, 0, 113, 9);

        // SSL 3.0 + a NULL cipher -> two High reasons -> High finding, ATT&CK T1040.
        let mut t = BehaviorTracker::new(DetectConfig::default());
        t.observe_weak_tls(
            client,
            server,
            443,
            0x0300,
            0x0001,
            vec![
                WeakTlsReason::DeprecatedVersion { version: 0x0300 },
                WeakTlsReason::WeakCipher {
                    cipher: 0x0001,
                    name: "TLS_RSA_WITH_NULL_MD5",
                    rank: 3,
                },
            ],
        );
        let f = detect_weak_tls(&t, &WeakTlsParams::default());
        assert_eq!(f.len(), 1, "findings: {f:?}");
        assert_eq!(f[0].kind, FindingKind::WeakTls);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].src_ip, "10.0.0.5");
        assert_eq!(f[0].dst_ip.as_deref(), Some("203.0.113.9"));
        assert!(f[0].attack.iter().any(|a| a == "T1040"));

        // TLS 1.0 alone -> Low.
        let mut t2 = BehaviorTracker::new(DetectConfig::default());
        t2.observe_weak_tls(
            client,
            server,
            443,
            0x0301,
            0x002F,
            vec![WeakTlsReason::DeprecatedVersion { version: 0x0301 }],
        );
        let f2 = detect_weak_tls(&t2, &WeakTlsParams::default());
        assert_eq!(f2[0].severity, Severity::Low);

        // Disabled -> nothing; empty reasons never recorded.
        assert!(detect_weak_tls(&t, &WeakTlsParams { enabled: false }).is_empty());
        let mut t3 = BehaviorTracker::new(DetectConfig::default());
        t3.observe_weak_tls(client, server, 443, 0x0303, 0x009C, vec![]);
        assert!(detect_weak_tls(&t3, &WeakTlsParams::default()).is_empty());
    }

    #[test]
    fn icmp_tunnel_flagged_for_sustained_large_echoes() {
        let bot = ip(10, 0, 0, 5);
        let c2 = ip(45, 77, 13, 37); // public (external)

        // 40 echoes carrying ~1 KB each to an external host -> a covert tunnel.
        let mut t = BehaviorTracker::new(DetectConfig::default());
        for _ in 0..40 {
            t.observe_icmp_echo(bot, c2, 1024);
        }
        let f = detect_icmp_tunnel(&t, &IcmpTunnelParams::default());
        assert_eq!(f.len(), 1, "findings: {f:?}");
        assert_eq!(f[0].kind, FindingKind::IcmpTunnel);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].src_ip, "10.0.0.5");
        assert_eq!(f[0].dst_ip.as_deref(), Some("45.77.13.37"));
        assert!(f[0].attack.iter().any(|a| a == "T1095"));
        assert_eq!(f[0].contacts, Some(40));
    }

    #[test]
    fn ordinary_ping_is_not_flagged() {
        let c2 = ip(45, 77, 13, 37); // public

        // Many small pings (32-byte data) to an external host -> high volume, small mean.
        let mut small = BehaviorTracker::new(DetectConfig::default());
        for _ in 0..200 {
            small.observe_icmp_echo(ip(10, 0, 0, 5), c2, 32);
        }
        assert!(detect_icmp_tunnel(&small, &IcmpTunnelParams::default()).is_empty());

        // A few large echoes -> below the volume floor.
        let mut few = BehaviorTracker::new(DetectConfig::default());
        for _ in 0..3 {
            few.observe_icmp_echo(ip(10, 0, 0, 5), c2, 1200);
        }
        assert!(detect_icmp_tunnel(&few, &IcmpTunnelParams::default()).is_empty());

        // Mixed: 31 small pings + ONE large diagnostic probe. The mean stays small, so the single
        // peak must NOT trip the detector (regression for the dropped max-data OR-branch).
        let mut mixed = BehaviorTracker::new(DetectConfig::default());
        for _ in 0..31 {
            mixed.observe_icmp_echo(ip(10, 0, 0, 5), c2, 32);
        }
        mixed.observe_icmp_echo(ip(10, 0, 0, 5), c2, 4000);
        assert!(detect_icmp_tunnel(&mixed, &IcmpTunnelParams::default()).is_empty());

        // Sustained large pings to an INTERNAL host are diagnostics, not exfil: the external-only
        // gate suppresses it even though the volume/size thresholds are met.
        let mut internal = BehaviorTracker::new(DetectConfig::default());
        for _ in 0..64 {
            internal.observe_icmp_echo(ip(10, 0, 0, 5), ip(10, 0, 0, 6), 1024);
        }
        assert!(detect_icmp_tunnel(&internal, &IcmpTunnelParams::default()).is_empty());

        // Disabled -> nothing.
        let mut t = BehaviorTracker::new(DetectConfig::default());
        for _ in 0..40 {
            t.observe_icmp_echo(ip(10, 0, 0, 5), c2, 1024);
        }
        assert!(detect_icmp_tunnel(
            &t,
            &IcmpTunnelParams {
                enabled: false,
                ..Default::default()
            }
        )
        .is_empty());
    }
}
