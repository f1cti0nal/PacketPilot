//! Flow identity and the aggregated bidirectional flow record. Fully implemented
//! contract type.
//!
//! Normalization is symmetric: `FlowKey::normalized(s, d) == FlowKey::normalized(d, s)`,
//! with the [`Direction`] telling whether a given packet went lo->hi (`Forward`) or
//! hi->lo (`Reverse`). The "lo" endpoint is the canonical initiator and maps to the
//! `src_*` columns in the persisted table.

use std::cmp::Ordering;
use std::net::IpAddr;

use crate::model::category::Category;
use crate::model::packet::{AppProto, PacketMeta, Transport};

// TCP flag bits used for the established-handshake check.
const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;

/// Per-packet direction relative to canonical flow orientation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Direction {
    /// Packet src == lo endpoint (canonical "client -> server").
    Forward,
    /// Packet src == hi endpoint.
    Reverse,
}

/// Canonical, direction-independent flow identity.
///
/// Normalization compares endpoint A=`(src_ip,src_port)` with B=`(dst_ip,dst_port)` via
/// [`FlowKey::endpoint_cmp`] (all IPv4 sort before all IPv6, then address bytes, then
/// port); the smaller endpoint is stored as `lo`, the larger as `hi`. Hence
/// `key(p) == key(reverse(p))`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct FlowKey {
    pub lo_ip: IpAddr,
    pub hi_ip: IpAddr,
    pub lo_port: u16,
    pub hi_port: u16,
    pub transport: Transport,
}

impl FlowKey {
    /// Normalize a directed 5-tuple into a canonical key plus the packet's direction
    /// relative to that key.
    pub fn normalized(
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        transport: Transport,
    ) -> (FlowKey, Direction) {
        let a = (src_ip, src_port);
        let b = (dst_ip, dst_port);
        match FlowKey::endpoint_cmp(a, b) {
            // a <= b : src is the lo endpoint -> Forward.
            Ordering::Less | Ordering::Equal => (
                FlowKey {
                    lo_ip: a.0,
                    hi_ip: b.0,
                    lo_port: a.1,
                    hi_port: b.1,
                    transport,
                },
                Direction::Forward,
            ),
            // a > b : dst is the lo endpoint -> Reverse.
            Ordering::Greater => (
                FlowKey {
                    lo_ip: b.0,
                    hi_ip: a.0,
                    lo_port: b.1,
                    hi_port: a.1,
                    transport,
                },
                Direction::Reverse,
            ),
        }
    }

    /// Build a key from a decoded packet, or `None` if the packet has no IP endpoints
    /// (ARP / non-IP) — such frames are counted but never flowed.
    pub fn from_packet(p: &PacketMeta) -> Option<(FlowKey, Direction)> {
        let (s, sp, d, dp) = p.endpoints()?;
        Some(FlowKey::normalized(s, sp, d, dp, p.transport))
    }

    /// Total order for normalization: (family tag, address bytes, port).
    ///
    /// IPv4 sorts strictly before IPv6. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is treated as
    /// IPv6 (no un-mapping) so the family tag is consistent with the variant.
    pub fn endpoint_cmp(a: (IpAddr, u16), b: (IpAddr, u16)) -> Ordering {
        fn family_tag(ip: &IpAddr) -> u8 {
            match ip {
                IpAddr::V4(_) => 0,
                IpAddr::V6(_) => 1,
            }
        }
        fn addr_bytes(ip: &IpAddr) -> Vec<u8> {
            match ip {
                IpAddr::V4(v4) => v4.octets().to_vec(),
                IpAddr::V6(v6) => v6.octets().to_vec(),
            }
        }
        family_tag(&a.0)
            .cmp(&family_tag(&b.0))
            .then_with(|| addr_bytes(&a.0).cmp(&addr_bytes(&b.0)))
            .then_with(|| a.1.cmp(&b.1))
    }
}

/// Aggregated bidirectional flow. One row per [`FlowKey`] in Parquet output.
///
/// "Forward"/"fwd" == lo->hi == initiator->responder convention (== "c2s" in the table).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FlowRecord {
    pub key: FlowKey,
    pub first_ts_ns: i64,
    pub last_ts_ns: i64,
    pub pkts_fwd: u64,
    pub pkts_rev: u64,
    /// wire_len summed, lo->hi.
    pub bytes_fwd: u64,
    /// wire_len summed, hi->lo.
    pub bytes_rev: u64,
    /// Sticky OR of flags seen forward.
    pub tcp_flags_fwd: u8,
    pub tcp_flags_rev: u8,
    /// Set by the classify stage; `Unknown` until then.
    pub category: Category,
    /// `"dns"`,`"https"`,`"ssh"`,...; `""` if unknown.
    pub app_proto: String,
    /// Min TTL observed forward; 0 if none.
    pub ttl_min_fwd: u8,
    /// Most-specific payload-observed L7 hint across this flow's packets (`Unknown` until a
    /// packet carries one). Input to payload-aware classification; distinct from `app_proto`
    /// (the final label the classifier chooses from payload OR port).
    pub observed_app_proto: AppProto,
    /// First non-empty TLS SNI host observed on this flow; `None` if none seen.
    pub sni: Option<String>,
    /// First non-empty JA3 fingerprint observed on this flow; `None` if none seen.
    pub ja3: Option<String>,
    /// First non-empty JA4 fingerprint observed on this flow; `None` if none seen.
    pub ja4: Option<String>,
    /// First non-empty JA3S (server ServerHello) fingerprint observed on this flow; `None` if none.
    pub ja3s: Option<String>,
    /// Negotiated TLS version label ("TLS 1.2" …) from the server ServerHello; `None` if none seen.
    pub tls_version: Option<String>,
    /// Negotiated TLS cipher-suite label from the server ServerHello; `None` if none seen.
    pub tls_cipher: Option<String>,
    /// SSH client HASSH (MD5) fingerprint from a client KEXINIT; `None` if none seen. The SSH
    /// analogue of `ja3` — first non-empty value seen wins (sticky).
    pub hassh: Option<String>,
    /// SSH server HASSHServer (MD5) fingerprint from a server KEXINIT; `None` if none seen. The SSH
    /// analogue of `ja3s` — first non-empty value seen wins (sticky).
    pub hassh_server: Option<String>,
    /// Derivation of `app_proto`: `Some("payload")`, `Some("port")`, or `None` (unknown /
    /// shape-only). Set by the classify stage; written to the `app_proto_src` column.
    pub app_proto_src: Option<&'static str>,
    /// Phase-2 severity verdict; `Info` until the score stage runs.
    pub severity: crate::model::severity::Severity,
    /// Phase-2 transparent threat score 0..=100; 0 until scored.
    pub threat_score: u16,
    /// True when any endpoint IP/CIDR or the SNI matched the threat feed.
    pub ioc: bool,
    /// Transient: the fingerprint feed label that matched this flow's JA3/JA4 (`None` if no
    /// match). Set during the enrich pass; NOT written to Parquet / FlowDto.
    #[serde(default)]
    pub fingerprint_label: Option<String>,
}

impl FlowRecord {
    /// Create a fresh record for `key` whose window opens at `first_ts_ns`.
    pub fn new(key: FlowKey, first_ts_ns: i64) -> FlowRecord {
        FlowRecord {
            key,
            first_ts_ns,
            last_ts_ns: first_ts_ns,
            pkts_fwd: 0,
            pkts_rev: 0,
            bytes_fwd: 0,
            bytes_rev: 0,
            tcp_flags_fwd: 0,
            tcp_flags_rev: 0,
            category: Category::Unknown,
            app_proto: String::new(),
            ttl_min_fwd: 0,
            observed_app_proto: AppProto::Unknown,
            sni: None,
            ja3: None,
            ja4: None,
            ja3s: None,
            tls_version: None,
            tls_cipher: None,
            hassh: None,
            hassh_server: None,
            app_proto_src: None,
            severity: crate::model::severity::Severity::Info,
            threat_score: 0,
            ioc: false,
            fingerprint_label: None,
        }
    }

    /// Fold one packet into this record using its precomputed [`Direction`].
    pub fn observe(&mut self, p: &PacketMeta, dir: Direction) {
        if p.ts_ns < self.first_ts_ns {
            self.first_ts_ns = p.ts_ns;
        }
        if p.ts_ns > self.last_ts_ns {
            self.last_ts_ns = p.ts_ns;
        }
        // L7 aggregation (direction-independent: L7 is a flow property, not a direction).
        // Keep the most-specific hint seen (Http/Tls outrank Dns outrank Unknown); ties keep
        // the first. On a real flow only one of Http/Tls/Dns appears, so "most-specific" and
        // "first concrete" coincide.
        if p.app_proto.rank() > self.observed_app_proto.rank() {
            self.observed_app_proto = p.app_proto;
        }
        // First non-empty SNI wins and is then sticky (bounded: at most one String clone per
        // flow, only when a packet already carried an SNI — rare).
        if self.sni.is_none() {
            if let Some(host) = &p.sni {
                if !host.is_empty() {
                    self.sni = Some(host.clone());
                }
            }
        }
        if self.ja3.is_none() {
            if let Some(v) = &p.ja3 {
                if !v.is_empty() {
                    self.ja3 = Some(v.clone());
                }
            }
        }
        if self.ja4.is_none() {
            if let Some(v) = &p.ja4 {
                if !v.is_empty() {
                    self.ja4 = Some(v.clone());
                }
            }
        }
        if self.ja3s.is_none() {
            if let Some(v) = &p.ja3s {
                if !v.is_empty() {
                    self.ja3s = Some(v.clone());
                }
            }
        }
        if self.tls_version.is_none() {
            if let Some(v) = &p.tls_version {
                if !v.is_empty() {
                    self.tls_version = Some(v.clone());
                }
            }
        }
        if self.tls_cipher.is_none() {
            if let Some(v) = &p.tls_cipher {
                if !v.is_empty() {
                    self.tls_cipher = Some(v.clone());
                }
            }
        }
        // hassh / hassh_server: SSH fingerprints. Each is set by decode only on its own side's
        // KEXINIT, so direction-independent like ja3 — first non-empty value wins (sticky).
        if self.hassh.is_none() {
            if let Some(v) = &p.hassh {
                if !v.is_empty() {
                    self.hassh = Some(v.clone());
                }
            }
        }
        if self.hassh_server.is_none() {
            if let Some(v) = &p.hassh_server {
                if !v.is_empty() {
                    self.hassh_server = Some(v.clone());
                }
            }
        }
        match dir {
            Direction::Forward => {
                self.pkts_fwd += 1;
                self.bytes_fwd += p.wire_len as u64;
                self.tcp_flags_fwd |= p.tcp_flags;
                if p.ttl != 0 {
                    self.ttl_min_fwd = if self.ttl_min_fwd == 0 {
                        p.ttl
                    } else {
                        self.ttl_min_fwd.min(p.ttl)
                    };
                }
            }
            Direction::Reverse => {
                self.pkts_rev += 1;
                self.bytes_rev += p.wire_len as u64;
                self.tcp_flags_rev |= p.tcp_flags;
            }
        }
    }

    /// Total packets in both directions.
    pub fn total_pkts(&self) -> u64 {
        self.pkts_fwd + self.pkts_rev
    }

    /// Total wire bytes in both directions.
    pub fn total_bytes(&self) -> u64 {
        self.bytes_fwd + self.bytes_rev
    }

    /// Flow duration in ns, clamped to non-negative.
    pub fn duration_ns(&self) -> i64 {
        self.last_ts_ns.saturating_sub(self.first_ts_ns).max(0)
    }

    /// Heuristic: SYN seen forward AND SYN|ACK seen reverse (handshake observed).
    pub fn tcp_established(&self) -> bool {
        let fwd_syn = (self.tcp_flags_fwd & TCP_SYN) != 0;
        let rev_synack = (self.tcp_flags_rev & TCP_SYN) != 0 && (self.tcp_flags_rev & TCP_ACK) != 0;
        fwd_syn && rev_synack
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_aggregates_most_specific_l7_and_first_sni() {
        let (key, dir) = FlowKey::normalized(
            "10.0.0.1".parse().unwrap(),
            50000,
            "10.0.0.2".parse().unwrap(),
            443,
            Transport::Tcp,
        );
        let mut r = FlowRecord::new(key, 0);
        let base = PacketMeta {
            index: 0,
            ts_ns: 100,
            iface_id: 0,
            wire_len: 64,
            cap_len: 64,
            l3: crate::model::packet::Protocol::Ipv4,
            transport: Transport::Tcp,
            src_ip: Some("10.0.0.1".parse().unwrap()),
            dst_ip: Some("10.0.0.2".parse().unwrap()),
            src_port: 50000,
            dst_port: 443,
            tcp_flags: 0x02,
            ttl: 64,
            payload_len: 0,
            vlan: None,
            app_proto: AppProto::Unknown,
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
        };
        r.observe(&base, dir);
        assert_eq!(r.observed_app_proto, AppProto::Unknown);

        let mut tls = base.clone();
        tls.app_proto = AppProto::Tls;
        tls.sni = Some("first.example".to_string());
        r.observe(&tls, dir);
        assert_eq!(r.observed_app_proto, AppProto::Tls);
        assert_eq!(r.sni.as_deref(), Some("first.example"));

        // A later, different SNI does NOT overwrite the first.
        let mut tls2 = base.clone();
        tls2.app_proto = AppProto::Tls;
        tls2.sni = Some("second.example".to_string());
        r.observe(&tls2, dir);
        assert_eq!(r.sni.as_deref(), Some("first.example"));
    }

    #[test]
    fn observe_captures_first_ja3_ja4_sticky() {
        let (key, dir) = FlowKey::normalized(
            "10.0.0.1".parse().unwrap(),
            50000,
            "10.0.0.2".parse().unwrap(),
            443,
            Transport::Tcp,
        );
        let mut r = FlowRecord::new(key, 0);
        let base = PacketMeta {
            index: 0,
            ts_ns: 100,
            iface_id: 0,
            wire_len: 64,
            cap_len: 64,
            l3: crate::model::packet::Protocol::Ipv4,
            transport: Transport::Tcp,
            src_ip: Some("10.0.0.1".parse().unwrap()),
            dst_ip: Some("10.0.0.2".parse().unwrap()),
            src_port: 50000,
            dst_port: 443,
            tcp_flags: 0x02,
            ttl: 64,
            payload_len: 0,
            vlan: None,
            app_proto: AppProto::Unknown,
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
        };

        let mut p1 = base.clone();
        p1.ja3 = Some("aaa".into());
        p1.ja4 = Some("t13d0000".into());
        p1.tls_version = Some("TLS 1.2".into());
        p1.tls_cipher = Some("TLS_AES_128_GCM_SHA256".into());
        r.observe(&p1, dir);

        // Second packet has different ja3 / tls — first-seen value must win.
        let mut p2 = base.clone();
        p2.ja3 = Some("bbb".into());
        p2.tls_version = Some("TLS 1.0".into());
        r.observe(&p2, dir);

        assert_eq!(r.ja3.as_deref(), Some("aaa")); // first wins, sticky
        assert_eq!(r.ja4.as_deref(), Some("t13d0000"));
        assert_eq!(r.tls_version.as_deref(), Some("TLS 1.2"));
        assert_eq!(r.tls_cipher.as_deref(), Some("TLS_AES_128_GCM_SHA256"));
    }
}
