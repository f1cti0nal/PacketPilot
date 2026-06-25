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

/// A cleartext credential-exposure scheme sniffed from an L4 payload peek. Only the *derived*
/// scheme is retained — never the credential itself — so detection stays within the engine's
/// no-payload-retention / privacy contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredScheme {
    /// HTTP `Authorization: Basic` over cleartext (base64 user:pass, trivially reversible).
    HttpBasic,
    /// HTTP `Authorization: Digest` over cleartext (hashed, but replayable / crackable).
    HttpDigest,
    /// FTP `USER` / `PASS` control commands (credentials sent verbatim).
    Ftp,
}

impl CredScheme {
    /// Stable kebab-case token.
    pub fn as_str(self) -> &'static str {
        match self {
            CredScheme::HttpBasic => "http-basic",
            CredScheme::HttpDigest => "http-digest",
            CredScheme::Ftp => "ftp",
        }
    }

    /// Human label for evidence/title text.
    pub fn label(self) -> &'static str {
        match self {
            CredScheme::HttpBasic => "HTTP Basic auth",
            CredScheme::HttpDigest => "HTTP Digest auth",
            CredScheme::Ftp => "FTP login",
        }
    }
}

/// A class of personally-identifiable information sniffed from a cleartext L4 payload peek. Only
/// the *kind* is retained — never the value — so detection stays within the no-payload-retention /
/// privacy contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PiiKind {
    /// A payment card number (issuer-prefix + length + Luhn-valid).
    CreditCard,
    /// A US Social Security Number in the dashed `NNN-NN-NNNN` form.
    Ssn,
}

impl PiiKind {
    /// Stable kebab-case token.
    pub fn as_str(self) -> &'static str {
        match self {
            PiiKind::CreditCard => "credit-card",
            PiiKind::Ssn => "ssn",
        }
    }

    /// Human label for evidence/title text.
    pub fn label(self) -> &'static str {
        match self {
            PiiKind::CreditCard => "credit card number",
            PiiKind::Ssn => "US SSN",
        }
    }
}

/// A notable downloaded-file class inferred from an HTTP response's `Content-Type` / filename, for
/// the downloads overview. Only risky/notable classes are recognised; ordinary content (html, images,
/// json, …) is left unclassified (`None`). Derived metadata only — no body bytes are retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DownloadKind {
    /// A native executable or library (PE/ELF/Mach-O, `.exe`/`.dll`/`.scr`…).
    Executable,
    /// A script / interpreted payload (`.ps1`/`.bat`/`.vbs`/`.js`/`.sh`…).
    Script,
    /// A software installer / package (`.msi`/`.pkg`/`.dmg`/`.deb`/`.rpm`).
    Installer,
    /// A compressed archive (`.zip`/`.rar`/`.7z`/`.tar`/`.gz`…) — a common malware container.
    Archive,
}

impl DownloadKind {
    /// Stable kebab-case token.
    pub fn as_str(self) -> &'static str {
        match self {
            DownloadKind::Executable => "executable",
            DownloadKind::Script => "script",
            DownloadKind::Installer => "installer",
            DownloadKind::Archive => "archive",
        }
    }
}

// TCP flag bit positions (host-readable; matches the on-wire TCP flags byte).
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// An ARP sender's IP→MAC binding, extracted from an ARP request/reply. Used to detect ARP cache
/// poisoning (one IP claimed by multiple MACs). Derived flag — no frame bytes retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArpClaim {
    /// The sender's protocol (IPv4) address.
    pub sender_ip: std::net::Ipv4Addr,
    /// The sender's hardware (MAC) address.
    pub sender_mac: [u8; 6],
}

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
    /// TLS JA3 fingerprint of a ClientHello on this packet; `None` otherwise. Derived flag.
    pub ja3: Option<String>,
    /// TLS JA4 fingerprint of a ClientHello on this packet; `None` otherwise. Derived flag.
    pub ja4: Option<String>,
    /// TLS JA3S fingerprint of a ServerHello on this packet; `None` otherwise. The server-side
    /// counterpart to the client `ja3`. Derived flag.
    pub ja3s: Option<String>,
    /// First DNS question name, allocated only for a DNS packet with a parseable QNAME; `None`
    /// otherwise. Transient (folded into per-resolver stats, then dropped) — used for DNS
    /// tunneling / DGA detection.
    pub dns_qname: Option<String>,
    /// Resolved A/AAAA IPs from a DNS *response* answer section; empty otherwise. Transient — folded
    /// into the passive-DNS (IP→domain) rollup with `dns_qname`, then dropped.
    pub dns_answers: Vec<std::net::IpAddr>,
    /// Cleartext credential scheme sniffed from the payload (HTTP Basic/Digest, FTP USER/PASS);
    /// `None` on the common path. A derived flag only — the credential itself is never retained.
    pub cleartext_cred: Option<CredScheme>,
    /// Plaintext PII class sniffed from the payload (credit card, SSN); `None` on the common path.
    /// A derived flag only — the PII value itself is never retained.
    pub pii: Option<PiiKind>,
    /// ICMP/ICMPv6 message type (first byte of the ICMP header); `None` for non-ICMP. Used to
    /// isolate echo request/reply for covert-channel (ICMP tunneling) detection.
    pub icmp_type: Option<u8>,
    /// Negotiated TLS protocol version label ("TLS 1.2" …) from a server ServerHello; `None`
    /// otherwise. The server-side counterpart to the client `ja3`/`ja4`/`sni`.
    pub tls_version: Option<String>,
    /// Negotiated TLS cipher-suite label (IANA name or `0xNNNN`) from a server ServerHello; `None`
    /// otherwise.
    pub tls_cipher: Option<String>,
    /// SSH client HASSH (MD5) fingerprint from a client KEXINIT; `None` otherwise. The SSH analogue
    /// of the client `ja3`/`ja4`. Derived flag — no payload retained.
    pub hassh: Option<String>,
    /// SSH server HASSHServer (MD5) fingerprint from a server KEXINIT; `None` otherwise. The SSH
    /// analogue of the server-side `ja3s`. Derived flag — no payload retained.
    pub hassh_server: Option<String>,
    /// An ARP sender's IP→MAC claim for ARP-spoofing detection; `None` for non-ARP packets.
    pub arp: Option<ArpClaim>,
    /// HTTP request `Host` header (derived metadata, like `sni`); `None` otherwise.
    pub http_host: Option<String>,
    /// HTTP request `User-Agent` header (derived metadata); `None` otherwise.
    pub http_ua: Option<String>,
    /// Notable downloaded-file class from an HTTP response. Content-based (response-body magic bytes)
    /// where available, else the declared `Content-Type`/filename; `None` for requests, ordinary
    /// content, and non-HTTP.
    pub download: Option<DownloadKind>,
    /// True when the response body's magic bytes are a native **executable** but the declared
    /// `Content-Type` is a benign document/media/page type — a deliberate file-type masquerade (T1036).
    pub download_disguised: bool,
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
