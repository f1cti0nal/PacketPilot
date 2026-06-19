//! Per-packet decoded metadata and the L3/L4 enums. Fully implemented contract type.
//!
//! [`PacketMeta`] retains **no payload** — only fixed-size metadata — which is what keeps
//! the engine's memory bounded regardless of capture size.

use std::net::IpAddr;

/// Transport-layer protocol (L4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Transport {
    Tcp,
    Udp,
    Sctp,
    /// ICMPv4.
    Icmp,
    Icmpv6,
    /// Raw IP protocol number for anything not modeled.
    Other(u8),
}

impl Transport {
    /// Map an IANA IP protocol number to a [`Transport`].
    pub fn from_ip_proto(proto: u8) -> Transport {
        match proto {
            6 => Transport::Tcp,
            17 => Transport::Udp,
            132 => Transport::Sctp,
            1 => Transport::Icmp,
            58 => Transport::Icmpv6,
            other => Transport::Other(other),
        }
    }

    /// The IANA IP protocol number for this transport.
    pub fn ip_proto(self) -> u8 {
        match self {
            Transport::Tcp => 6,
            Transport::Udp => 17,
            Transport::Sctp => 132,
            Transport::Icmp => 1,
            Transport::Icmpv6 => 58,
            Transport::Other(n) => n,
        }
    }

    /// A short, stable display token. `Other(47)` renders as `"IP-47"`.
    ///
    /// Note: the `Other` arm returns a leaked `'static str` so the signature stays
    /// `&'static str` across all variants. This is only hit for unmodeled protocols and
    /// the set of distinct values is tiny and bounded, so the leak is negligible.
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Tcp => "TCP",
            Transport::Udp => "UDP",
            Transport::Sctp => "SCTP",
            Transport::Icmp => "ICMP",
            Transport::Icmpv6 => "ICMPv6",
            Transport::Other(n) => Box::leak(format!("IP-{n}").into_boxed_str()),
        }
    }

    /// Whether this transport carries L4 port numbers.
    pub fn has_ports(self) -> bool {
        matches!(self, Transport::Tcp | Transport::Udp | Transport::Sctp)
    }
}

/// Network-layer family / framing actually seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Protocol {
    Ipv4,
    Ipv6,
    Arp,
    NonIp,
}

impl Protocol {
    /// A stable display token.
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Ipv4 => "IPV4",
            Protocol::Ipv6 => "IPV6",
            Protocol::Arp => "ARP",
            Protocol::NonIp => "NONIP",
        }
    }
}

/// Cheap, fixed-size, payload-derived application-layer hint carried per packet. `Copy` and
/// tiny — the common (no-L7) path costs one enum discriminant, never a heap allocation. The
/// only per-packet heap allocation is the separate [`PacketMeta::sni`] string, populated
/// solely for a recognized TLS ClientHello. Specificity rank (see [`AppProto::rank`]) drives
/// flow aggregation.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum AppProto {
    #[default]
    Unknown,
    Dns,
    Http,
    Tls,
}

impl AppProto {
    /// Stable lowercase token used as the flow `app_proto` label when payload-derived.
    /// `Unknown` has no token (`""`) and is never written as a label.
    pub fn as_str(self) -> &'static str {
        match self {
            AppProto::Unknown => "",
            AppProto::Dns => "dns",
            AppProto::Http => "http",
            AppProto::Tls => "tls",
        }
    }

    /// True for any concrete payload-observed protocol; `Unknown` is the empty hint.
    pub fn is_known(self) -> bool {
        !matches!(self, AppProto::Unknown)
    }

    /// Specificity rank for flow aggregation: structural payload matches (Http/Tls) outrank
    /// a port-only match (Dns), which outranks Unknown. Keeps the most-specific hint seen.
    pub fn rank(self) -> u8 {
        match self {
            AppProto::Unknown => 0,
            AppProto::Dns => 1,
            AppProto::Http => 2,
            AppProto::Tls => 2,
        }
    }
}

// TCP flag bit positions (host-readable; matches the on-wire TCP flags byte).
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// One decoded packet's metadata. No payload retained (bounded memory).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PacketMeta {
    /// 0-based monotonic index within the capture.
    pub index: u64,
    /// Nanoseconds since the Unix epoch (normalized from any pcapng tsresol).
    pub ts_ns: i64,
    /// pcapng interface id; 0 for classic pcap.
    pub iface_id: u32,
    /// Bytes on the wire (orig_len).
    pub wire_len: u32,
    /// Bytes actually captured (caplen).
    pub cap_len: u32,
    pub l3: Protocol,
    pub transport: Transport,
    /// `None` for ARP / non-IP / counted-but-undecoded frames.
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    /// 0 when the transport has no ports.
    pub src_port: u16,
    pub dst_port: u16,
    /// SYN/ACK/FIN/RST/PSH/URG/ECE/CWR; 0 if not TCP.
    pub tcp_flags: u8,
    /// IPv4 TTL / IPv6 hop limit; 0 if unknown.
    pub ttl: u8,
    /// L4 payload bytes (excl. headers); 0 if unknown.
    pub payload_len: u32,
    /// 802.1Q VLAN id if present.
    pub vlan: Option<u16>,
    /// Payload-derived L7 hint (`Unknown` on the common path; no allocation).
    pub app_proto: AppProto,
    /// TLS SNI host, allocated ONLY for a recognized ClientHello carrying server_name;
    /// `None` otherwise. The sole per-packet heap allocation, rare by construction.
    pub sni: Option<String>,
    /// First DNS question name, allocated only for a DNS packet with a parseable QNAME; `None`
    /// otherwise. Transient (folded into per-resolver stats, then dropped) — used for DNS
    /// tunneling / DGA detection.
    pub dns_qname: Option<String>,
}

impl PacketMeta {
    /// Returns the 4-tuple `(src_ip, src_port, dst_ip, dst_port)` when both IPs are
    /// present, else `None` (ARP / non-IP).
    pub fn endpoints(&self) -> Option<(IpAddr, u16, IpAddr, u16)> {
        match (self.src_ip, self.dst_ip) {
            (Some(s), Some(d)) => Some((s, self.src_port, d, self.dst_port)),
            _ => None,
        }
    }

    /// True if the SYN flag is set (regardless of other flags).
    pub fn is_tcp_syn(&self) -> bool {
        self.transport == Transport::Tcp && (self.tcp_flags & TCP_SYN) != 0
    }

    /// True if SYN is set and ACK is clear — the classic connection-initiation / scan
    /// signal.
    pub fn is_tcp_syn_only(&self) -> bool {
        self.transport == Transport::Tcp
            && (self.tcp_flags & TCP_SYN) != 0
            && (self.tcp_flags & TCP_ACK) == 0
    }

    /// True if the RST flag is set.
    pub fn is_tcp_rst(&self) -> bool {
        self.transport == Transport::Tcp && (self.tcp_flags & TCP_RST) != 0
    }
}

// Re-exported flag constants for downstream decoders/classifiers (kept module-private to
// callers via the model facade; expose if a stage needs FIN detection).
#[allow(dead_code)]
pub(crate) const TCP_FIN_MASK: u8 = TCP_FIN;
