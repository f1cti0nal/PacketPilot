//! Cross-flow behavioral findings. Fully implemented contract type.
//!
//! A [`Finding`] is a *named, explainable* conclusion drawn across many flows — "host X is
//! beaconing to Y", "host X swept N hosts on port P" — produced by the `detect` stage from the
//! behavioral substrate. Unlike a per-flow [`crate::model::severity::Severity`] verdict (which
//! is dominated by the IOC feed), a finding lets the engine reach a High/Critical conclusion
//! from *behavior alone*, with no threat-feed hit. Findings are surfaced in the summary JSON
//! and the UI alongside the per-IP threat cards.

use crate::model::severity::Severity;

/// The kind of behavioral detection.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// Periodic command-and-control beaconing (regular callbacks to a destination).
    Beacon,
    /// Horizontal sweep: one source touching many distinct destination hosts.
    HostSweep,
    /// Credential brute force: many connection attempts to one authentication service.
    BruteForce,
    /// Cleartext credential exposure: credentials sent over an unencrypted protocol.
    CleartextCreds,
    /// Plaintext PII exposure: sensitive data (credit card, SSN) sent over an unencrypted protocol.
    PiiExposure,
    /// Lateral movement: one internal host opening admin sessions to many internal hosts.
    LateralMovement,
    /// Data exfiltration: a large asymmetric outbound transfer to an external peer.
    DataExfil,
    /// DNS tunneling / DGA: high-volume, high-entropy DNS queries (C2 / exfil over DNS).
    DnsTunnel,
    /// User signature-rule match (imported Suricata-style ruleset).
    RuleMatch,
    /// Suspicious server TLS certificate (self-signed / expired / hostname-mismatched).
    TlsCertHealth,
    /// Weak or deprecated TLS negotiated (SSLv3 / TLS 1.0-1.1, or a weak cipher suite).
    WeakTls,
    /// ICMP tunneling: a sustained, large-payload ICMP echo channel (covert channel / C2 / exfil).
    IcmpTunnel,
    /// Domain-generation-algorithm activity: one host resolving many distinct algorithmically-random
    /// registered domains (the C2 rendezvous pattern of DGA malware).
    Dga,
    /// Vertical port scan: one source probing many distinct ports on a single host (service discovery).
    PortScan,
    /// ARP spoofing / cache poisoning: one IP address claimed by multiple MAC addresses (MITM).
    ArpSpoof,
    /// SYN flood / TCP DoS: one service hit by a flood of half-open (never-completed) connections.
    SynFlood,
    /// Known attack-tool / scanner identified by its HTTP User-Agent (sqlmap, nikto, nmap, …).
    SuspiciousUa,
    /// File-type masquerade: an executable body served over HTTP behind a benign `Content-Type`
    /// (e.g. an `.exe` delivered as `image/jpeg`) — malware-delivery evasion (T1036).
    DisguisedDownload,
    /// Cryptomining: a host running the cleartext Stratum mining protocol to a pool — resource
    /// hijacking / cryptojacking (T1496).
    Cryptomining,
    /// A file downloaded over cleartext HTTP whose carved SHA-256 matched a known-bad hash set —
    /// confirmed malware delivery (T1105).
    MalwareDownload,
    /// A carved cleartext download whose *content* matched a curated malware signature (packer,
    /// encoded script, known offensive tool) — a novel-hash detection the known-bad set misses.
    MalwareSignature,
    /// Exposed remote access: an established remote-administration session (RDP/VNC/SMB/WinRM/SSH/
    /// Telnet) crossing the internal↔external boundary — external remote services / pivot (T1133).
    ExposedRemoteAccess,
}

impl FindingKind {
    /// Stable snake_case token (matches the serde wire form).
    pub fn as_str(self) -> &'static str {
        match self {
            FindingKind::Beacon => "beacon",
            FindingKind::HostSweep => "host_sweep",
            FindingKind::BruteForce => "brute_force",
            FindingKind::CleartextCreds => "cleartext_creds",
            FindingKind::PiiExposure => "pii_exposure",
            FindingKind::LateralMovement => "lateral_movement",
            FindingKind::DataExfil => "data_exfil",
            FindingKind::DnsTunnel => "dns_tunnel",
            FindingKind::RuleMatch => "rule_match",
            FindingKind::TlsCertHealth => "tls_cert_health",
            FindingKind::WeakTls => "weak_tls",
            FindingKind::IcmpTunnel => "icmp_tunnel",
            FindingKind::Dga => "dga",
            FindingKind::PortScan => "port_scan",
            FindingKind::ArpSpoof => "arp_spoof",
            FindingKind::SynFlood => "syn_flood",
            FindingKind::SuspiciousUa => "suspicious_ua",
            FindingKind::DisguisedDownload => "disguised_download",
            FindingKind::Cryptomining => "cryptomining",
            FindingKind::MalwareDownload => "malware_download",
            FindingKind::MalwareSignature => "malware_signature",
            FindingKind::ExposedRemoteAccess => "exposed_remote_access",
        }
    }
}

/// A cross-flow behavioral detection with an explainable evidence trail.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: Severity,
    /// Representative 0..=100 threat score, in the band of `severity` (parallels the per-flow
    /// `threat_score`). Used when uplifting per-IP threat cards.
    pub score: u16,
    /// Human-readable one-line headline.
    pub title: String,
    /// The source host the behavior is attributed to.
    pub src_ip: String,
    /// Destination host; `None` for fan-out findings (e.g. a sweep hits many hosts).
    pub dst_ip: Option<String>,
    /// Destination service port, when the finding is tied to one.
    pub dst_port: Option<u16>,
    /// MITRE ATT&CK technique ids (e.g. `["T1071"]`).
    pub attack: Vec<String>,
    /// Explainable evidence bullets (mirrors the per-flow score evidence style).
    pub evidence: Vec<String>,
    /// Candidate beacon period in nanoseconds; `None` for non-beacon findings.
    pub interval_ns: Option<i64>,
    /// Beacon jitter (coefficient of variation of inter-contact gaps); `None` otherwise.
    pub jitter_cv: Option<f64>,
    /// Contributing contact / connection count.
    pub contacts: Option<u64>,
    /// First observed activity for this finding (ns since the capture epoch). `None` when the
    /// producing detector supplies no timestamp yet — temporal ordering then degrades gracefully
    /// to the kill-chain taxonomy rather than being wrong. `#[serde(default)]` keeps older
    /// summaries (written before this field existed) readable.
    #[serde(default)]
    pub first_seen_ns: Option<i64>,
    /// Last observed activity for this finding (ns since the capture epoch); `None` if unavailable.
    /// `#[serde(default)]` keeps older summaries readable.
    #[serde(default)]
    pub last_seen_ns: Option<i64>,
    /// Structured victim hosts for fan-out findings (lateral-movement targets, swept hosts),
    /// bounded and sorted before truncation. Empty for single-peer kinds (read `dst_ip` instead).
    /// `#[serde(default)]` keeps older summaries readable.
    #[serde(default)]
    pub victims: Vec<String>,
}
