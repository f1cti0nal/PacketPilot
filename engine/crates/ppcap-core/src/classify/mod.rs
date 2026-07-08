//! Phase-0 traffic classification: deterministic port/proto heuristics.
//!
//! Sets each flow's [`Category`] and `app_proto` from its transport + service port (the
//! smaller of the two ports, which is the well-known side). Optional scan detection uplifts
//! a flow to [`Category::Scan`] when the source is a known scanner (per the stats
//! accumulator's per-source port-spread). `C2`/`Anomalous` are reachable only via these
//! heuristics in Phase 0; full DPI-based C2 detection is Phase 3.

use crate::model::category::Category;
use crate::model::flow::FlowRecord;
use crate::model::packet::{AppProto, Transport};

// ---------------------------------------------------------------------------
// Heuristic tuning constants.
//
// These are deliberately conservative: the authoritative scan decision is the
// per-source port-spread test owned by `StatsAccumulator::is_scanner`, applied
// at the analyze sink (see analyze::run_source). The flow-shape heuristics here
// only ever *uplift from* a non-confident classification, never override a
// confident port-based one, so the stage stays deterministic and idempotent.
// ---------------------------------------------------------------------------

/// A flow with at most this many total packets is "tiny" — consistent with a probe
/// (lone SYN, SYN/RST exchange, single unanswered datagram) rather than a session.
const PROBE_MAX_PKTS: u64 = 4;

/// A flow with no reverse packets at all is unanswered.
const UNANSWERED_REV_PKTS: u64 = 0;

/// Beaconing candidate: a flow must carry at least this many packets in each direction
/// (a real, repeated, answered exchange) yet stay under [`BEACON_MAX_BYTES`].
const BEACON_MIN_PKTS_EACH_WAY: u64 = 2;

/// Beaconing candidate: total bytes must stay below this ceiling (small, regular pings).
const BEACON_MAX_BYTES: u64 = 4_096;

/// Tunnel candidate: a long-lived flow on a non-standard port carrying at least this many
/// bytes. 1 MiB over a non-service port that we could not name is the Phase-0 signal.
const TUNNEL_MIN_BYTES: u64 = 1 << 20;

/// Tunnel candidate: minimum lifetime in nanoseconds (60 s) for "long-lived".
const TUNNEL_MIN_DURATION_NS: i64 = 60 * 1_000_000_000;

// TCP flag bits (mirrors model::packet; kept local so this module has no private deps).
const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;
const TCP_RST: u8 = 0x04;

/// Tuning for classification.
#[derive(Debug, Clone)]
pub struct ClassifyConfig {
    /// Enable the scan uplift.
    pub detect_scans: bool,
    /// Distinct-port threshold per source for the scan heuristic.
    pub scan_port_threshold: u32,
}

impl Default for ClassifyConfig {
    fn default() -> Self {
        ClassifyConfig {
            detect_scans: true,
            scan_port_threshold: 15,
        }
    }
}

/// Stateless (config-only) classifier.
pub struct Classifier {
    cfg: ClassifyConfig,
}

impl Classifier {
    /// Build a classifier from config.
    pub fn new(cfg: ClassifyConfig) -> Classifier {
        Classifier { cfg }
    }

    /// Access the configuration this classifier was built with.
    pub fn config(&self) -> &ClassifyConfig {
        &self.cfg
    }

    /// Classify a flow in place: set `record.category` and `record.app_proto`.
    /// Idempotent and infallible.
    ///
    /// Data flow:
    ///  1. `service_port = min(lo_port, hi_port)` yields a port guess `(category, app_proto)`.
    ///  2. A payload-observed L7 hint (`record.observed_app_proto`) takes PRECEDENCE over the
    ///     port guess (e.g. HTTP on a non-standard port still classifies as Web). The
    ///     `app_proto_src` field records the derivation: `Some("payload")` when the payload
    ///     named it, `Some("port")` when only the port table did, `None` otherwise.
    ///  3. When scans are enabled and neither payload nor port produced a confident category,
    ///     flow-shape heuristics may *uplift* the category (probe -> Scan, small/regular
    ///     -> C2 candidate, non-standard long-lived bulk -> TunnelVpn). The final scan
    ///     decision also consults `StatsAccumulator::is_scanner` at the analyze sink,
    ///     which may further override the category to `Scan`.
    ///
    /// Idempotency: running `classify` twice yields the same result because the port
    /// classification depends only on the key, and the heuristic uplift only fires when
    /// the port classification is non-confident — and the uplift targets
    /// (`Scan`/`C2`/`TunnelVpn`) are themselves treated as confident on a re-run, so they
    /// are preserved rather than re-derived.
    pub fn classify(&self, record: &mut FlowRecord) {
        let transport = record.key.transport;

        // 1. Port guess (authoritative baseline, unchanged).
        let (port_cat, port_app) = if transport.has_ports() {
            let service_port = record.key.lo_port.min(record.key.hi_port);
            Self::category_for_port(transport, service_port)
        } else {
            (Category::Unknown, "")
        };

        // 2. Payload-observed L7 takes PRECEDENCE over the port guess (e.g. HTTP on a
        //    non-standard port -> Web). The payload token is `AppProto::as_str()` ("http"/
        //    "tls"), distinct from port tokens like "https"/"quic".
        //
        //    Only structurally-sniffed protocols (Http/Tls) count as `payload` provenance.
        //    `AppProto::Dns` is a port-only hint (port 53; no DNS payload is ever parsed —
        //    see `decode::l7_hint`), so it must NOT fabricate "payload" provenance. DNS is
        //    instead named by the port table below, correctly recording src="port".
        let payload = match record.observed_app_proto {
            AppProto::Http | AppProto::Tls => {
                Some((Category::Web, record.observed_app_proto.as_str()))
            }
            // Structurally-identified OT/ICS protocols → the IoT/OT category, keeping the
            // specific protocol token (modbus/dnp3/s7comm/bacnet/ethernet-ip).
            p if p.is_ot() => Some((Category::IotOt, record.observed_app_proto.as_str())),
            AppProto::Dns | AppProto::Unknown => None,
            // Non-OT payload protocols are handled above; nothing else reaches here.
            _ => None,
        };

        let (category, app, src): (Category, &str, Option<&'static str>) = match payload {
            Some((cat, app)) => (cat, app, Some("payload")),
            None if !port_app.is_empty() => (port_cat, port_app, Some("port")),
            None => (port_cat, port_app, None), // Unknown / shape-only -> NULL derivation
        };

        record.category = category;
        record.app_proto = app.to_string();
        record.app_proto_src = src;

        // 3. Shape uplift only when STILL Unknown after port + payload. A payload-named flow
        //    (Web/Dns) is confident and is never uplifted; `app_proto_src` stays None for
        //    shape-only categories (Scan/C2/TunnelVpn have no L7 token).
        if self.cfg.detect_scans && record.category == Category::Unknown {
            if let Some(uplift) = Self::shape_uplift(record, transport) {
                record.category = uplift;
            }
        }
    }

    /// Derive a category purely from a flow's shape, used only when the port table could
    /// not name the service. Returns `None` to leave the flow `Unknown`.
    ///
    /// Precedence (most specific first):
    ///  - **Scan probe**: a tiny TCP flow that is a bare SYN attempt with no established
    ///    handshake — typically unanswered or answered only by a RST.
    ///  - **Tunnel**: a long-lived, high-volume flow on a non-standard port.
    ///  - **Beaconing candidate (C2)**: repeated, small, two-way exchanges.
    fn shape_uplift(record: &FlowRecord, transport: Transport) -> Option<Category> {
        if Self::looks_like_probe(record, transport) {
            return Some(Category::Scan);
        }
        if Self::looks_like_tunnel(record) {
            return Some(Category::TunnelVpn);
        }
        if Self::looks_like_beacon(record) {
            return Some(Category::C2);
        }
        None
    }

    /// A single source touching a port with a tiny TCP flow that never established:
    /// classic connect/SYN-scan probe shape. Per-source fan-out across many ports/hosts is
    /// confirmed separately by `StatsAccumulator::is_scanner`; here we only recognize the
    /// per-flow probe shape.
    fn looks_like_probe(record: &FlowRecord, transport: Transport) -> bool {
        if transport != Transport::Tcp {
            return false;
        }
        // Must be a forward SYN attempt that never completed the handshake.
        let saw_fwd_syn = (record.tcp_flags_fwd & TCP_SYN) != 0;
        if !saw_fwd_syn || record.tcp_established() {
            return false;
        }
        // Tiny flow: a handful of packets at most.
        if record.total_pkts() > PROBE_MAX_PKTS {
            return false;
        }
        // Either no reply at all, or the only reply was a RST (port closed) — and the
        // reverse side never carried a SYN/ACK (which `tcp_established` already excludes,
        // but we double-check the RST-only shape explicitly for clarity).
        let no_reply = record.pkts_rev == UNANSWERED_REV_PKTS;
        let rst_only_reply = record.pkts_rev > 0
            && (record.tcp_flags_rev & TCP_RST) != 0
            && (record.tcp_flags_rev & (TCP_SYN | TCP_ACK)) == 0;
        no_reply || rst_only_reply
    }

    /// Long-lived, high-volume flow whose service port we could not name: tunnel shape.
    fn looks_like_tunnel(record: &FlowRecord) -> bool {
        record.total_bytes() >= TUNNEL_MIN_BYTES && record.duration_ns() >= TUNNEL_MIN_DURATION_NS
    }

    /// Repeated, small, two-way exchanges to one peer: beaconing candidate. The "regular"
    /// part of beaconing (fixed inter-arrival period) is a cross-flow signal the analyze
    /// layer can refine; per single aggregated flow we recognize the small-and-repeated
    /// shape.
    fn looks_like_beacon(record: &FlowRecord) -> bool {
        record.pkts_fwd >= BEACON_MIN_PKTS_EACH_WAY
            && record.pkts_rev >= BEACON_MIN_PKTS_EACH_WAY
            && record.total_bytes() <= BEACON_MAX_BYTES
    }

    /// Map a `(transport, service_port)` to a `(Category, app_proto_token)`.
    /// Public for stats/tests. Service port = `min(lo_port, hi_port)`.
    ///
    /// The returned token is the `app_proto` value written to the Parquet `app_proto`
    /// column; `""` means "unknown service". A port that we recognize on the *wrong*
    /// transport (e.g. UDP/22) is not matched and falls through to `Unknown`.
    pub fn category_for_port(transport: Transport, port: u16) -> (Category, &'static str) {
        use Transport::{Tcp, Udp};

        // Ports valid on either TCP or UDP (DNS, SIP) are matched transport-agnostically
        // below; everything else is keyed on the specific transport.
        match (transport, port) {
            // --- DNS (TCP or UDP 53) -----------------------------------------------
            (Tcp, 53) | (Udp, 53) => (Category::Dns, "dns"),
            // mDNS / LLMNR / DoH-over-UDP land are out of Phase-0 scope; 5353 mDNS:
            (Udp, 5353) => (Category::Dns, "mdns"),
            // DNS-over-TLS (853/tcp) / DoQ (853/udp): named by PORT so a resolver flow whose TLS
            // handshake was not captured is still recognized as benign DNS (not shape-uplifted to
            // C2) — a public resolver must never look like an unknown beacon.
            (Tcp, 853) | (Udp, 853) => (Category::Dns, "dot"),

            // --- Web ----------------------------------------------------------------
            (Tcp, 80) | (Tcp, 8080) | (Tcp, 8000) | (Tcp, 8008) => (Category::Web, "http"),
            (Tcp, 443) | (Tcp, 8443) => (Category::Web, "https"),
            (Udp, 443) => (Category::Web, "quic"), // HTTP/3 over QUIC
            (Tcp, 3128) => (Category::Web, "http-proxy"),

            // --- Email --------------------------------------------------------------
            (Tcp, 25) | (Tcp, 465) | (Tcp, 587) => (Category::Email, "smtp"),
            (Tcp, 110) | (Tcp, 995) => (Category::Email, "pop3"),
            (Tcp, 143) | (Tcp, 993) => (Category::Email, "imap"),

            // --- File transfer / file sharing --------------------------------------
            (Tcp, 20) | (Tcp, 21) => (Category::FileTransfer, "ftp"),
            (Tcp, 69) | (Udp, 69) => (Category::FileTransfer, "tftp"),
            (Tcp, 445) => (Category::FileTransfer, "smb"),
            (Udp, 137) | (Udp, 138) | (Tcp, 139) => (Category::FileTransfer, "netbios"),
            (Tcp, 2049) | (Udp, 2049) => (Category::FileTransfer, "nfs"),
            (Tcp, 873) => (Category::FileTransfer, "rsync"),

            // --- Remote access ------------------------------------------------------
            (Tcp, 22) => (Category::RemoteAccess, "ssh"),
            (Tcp, 23) => (Category::RemoteAccess, "telnet"),
            (Tcp, 3389) | (Udp, 3389) => (Category::RemoteAccess, "rdp"),
            (Tcp, 5900) | (Tcp, 5901) => (Category::RemoteAccess, "vnc"),
            (Tcp, 5985) | (Tcp, 5986) => (Category::RemoteAccess, "winrm"),

            // --- VoIP ---------------------------------------------------------------
            (Tcp, 5060) | (Udp, 5060) | (Tcp, 5061) | (Udp, 5061) => (Category::Voip, "sip"),
            // RTP/RTCP dynamic media range (RFC 3551 / common ephemeral media ports).
            (Udp, p) if (16384..=32767).contains(&p) => (Category::Voip, "rtp"),

            // --- Tunnel / VPN -------------------------------------------------------
            (Udp, 500) | (Udp, 4500) => (Category::TunnelVpn, "ipsec"),
            (Udp, 1194) | (Tcp, 1194) => (Category::TunnelVpn, "openvpn"),
            (Udp, 51820) => (Category::TunnelVpn, "wireguard"),
            (Tcp, 1723) => (Category::TunnelVpn, "pptp"),
            (Udp, 1701) => (Category::TunnelVpn, "l2tp"),

            // --- VoIP / RTC signalling & NAT traversal ------------------------------
            // STUN/TURN set up interactive media (WebRTC / SIP), so they belong with VoIP. They
            // are small, two-way, and usually to a PUBLIC server, which is exactly the shape the
            // C2 beacon heuristic otherwise mislabels.
            // (Google STUN 19302 is already covered as VoIP by the RTP dynamic-media range below.)
            (Udp, 3478) | (Tcp, 3478) => (Category::Voip, "stun"),
            (Tcp, 5349) | (Udp, 5349) | (Udp, 5350) => (Category::Voip, "turn"),

            // --- Network infrastructure / management --------------------------------
            // Benign, ubiquitous service protocols. Named here so a small two-way exchange to a
            // PUBLIC server (e.g. NTP to pool.ntp.org) classifies as low-risk instead of falling
            // to Unknown and being shape-uplifted to C2.
            (Udp, 123) => (Category::NetworkService, "ntp"),
            (Udp, 67) | (Udp, 68) | (Udp, 546) | (Udp, 547) => (Category::NetworkService, "dhcp"),
            (Udp, 161) | (Udp, 162) => (Category::NetworkService, "snmp"),
            (Udp, 514) => (Category::NetworkService, "syslog"),

            // --- IoT / OT -----------------------------------------------------------
            (Tcp, 1883) => (Category::IotOt, "mqtt"),
            (Tcp, 8883) => (Category::IotOt, "mqtts"),
            (Tcp, 5683) | (Udp, 5683) => (Category::IotOt, "coap"),
            (Tcp, 502) | (Udp, 502) => (Category::IotOt, "modbus"),
            (Tcp, 47808) | (Udp, 47808) => (Category::IotOt, "bacnet"),
            (Tcp, 20000) | (Udp, 20000) => (Category::IotOt, "dnp3"),
            (Tcp, 44818) | (Udp, 2222) => (Category::IotOt, "ethernet-ip"),

            // --- Default ------------------------------------------------------------
            _ => (Category::Unknown, ""),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::flow::FlowKey;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// Build a TCP flow record with the given canonical ports. `lo_port`/`hi_port` are the
    /// stored (normalized) ports; the service port is their min.
    fn tcp_flow(lo_port: u16, hi_port: u16) -> FlowRecord {
        let key = FlowKey {
            lo_ip: ip(10, 0, 0, 1),
            hi_ip: ip(10, 0, 0, 2),
            lo_port,
            hi_port,
            transport: Transport::Tcp,
        };
        FlowRecord::new(key, 1_000)
    }

    fn udp_flow(lo_port: u16, hi_port: u16) -> FlowRecord {
        let key = FlowKey {
            lo_ip: ip(10, 0, 0, 1),
            hi_ip: ip(10, 0, 0, 2),
            lo_port,
            hi_port,
            transport: Transport::Udp,
        };
        FlowRecord::new(key, 1_000)
    }

    // ----- config defaults --------------------------------------------------

    #[test]
    fn default_config_enables_scans_threshold_15() {
        let c = ClassifyConfig::default();
        assert!(c.detect_scans);
        assert_eq!(c.scan_port_threshold, 15);
    }

    // ----- port table -------------------------------------------------------

    #[test]
    fn web_ports_map_to_web() {
        for p in [80u16, 8080, 8000, 8008] {
            assert_eq!(
                Classifier::category_for_port(Transport::Tcp, p),
                (Category::Web, "http"),
                "tcp/{p}"
            );
        }
        for p in [443u16, 8443] {
            assert_eq!(
                Classifier::category_for_port(Transport::Tcp, p),
                (Category::Web, "https"),
                "tcp/{p}"
            );
        }
        assert_eq!(
            Classifier::category_for_port(Transport::Udp, 443),
            (Category::Web, "quic")
        );
    }

    #[test]
    fn dns_matches_on_both_transports() {
        assert_eq!(
            Classifier::category_for_port(Transport::Tcp, 53),
            (Category::Dns, "dns")
        );
        assert_eq!(
            Classifier::category_for_port(Transport::Udp, 53),
            (Category::Dns, "dns")
        );
    }

    #[test]
    fn email_file_remote_voip_tunnel_iot_samples() {
        assert_eq!(
            Classifier::category_for_port(Transport::Tcp, 25),
            (Category::Email, "smtp")
        );
        assert_eq!(
            Classifier::category_for_port(Transport::Tcp, 993),
            (Category::Email, "imap")
        );
        assert_eq!(
            Classifier::category_for_port(Transport::Tcp, 21),
            (Category::FileTransfer, "ftp")
        );
        assert_eq!(
            Classifier::category_for_port(Transport::Tcp, 445),
            (Category::FileTransfer, "smb")
        );
        assert_eq!(
            Classifier::category_for_port(Transport::Tcp, 22),
            (Category::RemoteAccess, "ssh")
        );
        assert_eq!(
            Classifier::category_for_port(Transport::Tcp, 3389),
            (Category::RemoteAccess, "rdp")
        );
        assert_eq!(
            Classifier::category_for_port(Transport::Udp, 5060),
            (Category::Voip, "sip")
        );
        assert_eq!(
            Classifier::category_for_port(Transport::Udp, 20000),
            (Category::Voip, "rtp")
        );
        assert_eq!(
            Classifier::category_for_port(Transport::Udp, 51820),
            (Category::TunnelVpn, "wireguard")
        );
        assert_eq!(
            Classifier::category_for_port(Transport::Udp, 500),
            (Category::TunnelVpn, "ipsec")
        );
        assert_eq!(
            Classifier::category_for_port(Transport::Tcp, 1883),
            (Category::IotOt, "mqtt")
        );
        assert_eq!(
            Classifier::category_for_port(Transport::Tcp, 502),
            (Category::IotOt, "modbus")
        );
    }

    #[test]
    fn rtp_range_boundaries() {
        // Inclusive boundaries of the RTP/RTCP media range.
        assert_eq!(
            Classifier::category_for_port(Transport::Udp, 16384),
            (Category::Voip, "rtp")
        );
        assert_eq!(
            Classifier::category_for_port(Transport::Udp, 32767),
            (Category::Voip, "rtp")
        );
        // Just outside the range is not VoIP.
        assert_eq!(
            Classifier::category_for_port(Transport::Udp, 16383),
            (Category::Unknown, "")
        );
        assert_eq!(
            Classifier::category_for_port(Transport::Udp, 32768),
            (Category::Unknown, "")
        );
    }

    #[test]
    fn known_port_on_wrong_transport_is_unknown() {
        // SSH is TCP-only; UDP/22 must not match.
        assert_eq!(
            Classifier::category_for_port(Transport::Udp, 22),
            (Category::Unknown, "")
        );
        // SMB is TCP-only here.
        assert_eq!(
            Classifier::category_for_port(Transport::Udp, 445),
            (Category::Unknown, "")
        );
    }

    #[test]
    fn unknown_port_defaults_to_unknown_empty_token() {
        assert_eq!(
            Classifier::category_for_port(Transport::Tcp, 9999),
            (Category::Unknown, "")
        );
        assert_eq!(
            Classifier::category_for_port(Transport::Tcp, 0),
            (Category::Unknown, "")
        );
    }

    // ----- classify(): service-port selection -------------------------------

    #[test]
    fn classify_uses_min_port_as_service_port() {
        let cls = Classifier::new(ClassifyConfig::default());
        // Client ephemeral 50000 -> server 443. Service port must be 443 regardless of
        // which side ended up `lo`.
        let mut a = tcp_flow(443, 50_000);
        let mut b = tcp_flow(50_000, 443);
        cls.classify(&mut a);
        cls.classify(&mut b);
        assert_eq!(a.category, Category::Web);
        assert_eq!(a.app_proto, "https");
        assert_eq!(b.category, Category::Web);
        assert_eq!(b.app_proto, "https");
    }

    #[test]
    fn classify_sets_app_proto_string() {
        let cls = Classifier::new(ClassifyConfig::default());
        let mut f = udp_flow(53, 40_000);
        cls.classify(&mut f);
        assert_eq!(f.category, Category::Dns);
        assert_eq!(f.app_proto, "dns");
    }

    #[test]
    fn classify_is_idempotent() {
        let cls = Classifier::new(ClassifyConfig::default());
        let mut f = tcp_flow(22, 51_000);
        cls.classify(&mut f);
        let after_first = (f.category, f.app_proto.clone());
        cls.classify(&mut f);
        assert_eq!((f.category, f.app_proto.clone()), after_first);
    }

    // ----- portless transports never panic / stay Unknown -------------------

    #[test]
    fn icmp_flow_stays_unknown_and_does_not_panic() {
        let cls = Classifier::new(ClassifyConfig::default());
        let key = FlowKey {
            lo_ip: ip(10, 0, 0, 1),
            hi_ip: ip(10, 0, 0, 2),
            lo_port: 0,
            hi_port: 0,
            transport: Transport::Icmp,
        };
        let mut f = FlowRecord::new(key, 1_000);
        cls.classify(&mut f);
        assert_eq!(f.category, Category::Unknown);
        assert_eq!(f.app_proto, "");
    }

    #[test]
    fn other_transport_with_v6_endpoints_is_unknown() {
        let cls = Classifier::new(ClassifyConfig::default());
        let key = FlowKey {
            lo_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            hi_ip: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2)),
            lo_port: 0,
            hi_port: 0,
            transport: Transport::Other(47), // GRE
        };
        let mut f = FlowRecord::new(key, 1_000);
        cls.classify(&mut f);
        assert_eq!(f.category, Category::Unknown);
    }

    // ----- flow-shape heuristics --------------------------------------------

    #[test]
    fn unanswered_syn_on_unknown_port_is_scan() {
        let cls = Classifier::new(ClassifyConfig::default());
        let mut f = tcp_flow(54_000, 31_337); // non-service port
        f.pkts_fwd = 1;
        f.tcp_flags_fwd = TCP_SYN;
        // no reverse packets at all
        cls.classify(&mut f);
        assert_eq!(f.category, Category::Scan);
        assert_eq!(f.app_proto, "");
    }

    #[test]
    fn syn_then_rst_only_is_scan() {
        let cls = Classifier::new(ClassifyConfig::default());
        let mut f = tcp_flow(54_000, 31_337);
        f.pkts_fwd = 1;
        f.tcp_flags_fwd = TCP_SYN;
        f.pkts_rev = 1;
        f.tcp_flags_rev = TCP_RST; // port closed
        cls.classify(&mut f);
        assert_eq!(f.category, Category::Scan);
    }

    #[test]
    fn established_handshake_is_not_a_scan() {
        let cls = Classifier::new(ClassifyConfig::default());
        let mut f = tcp_flow(54_000, 31_337);
        f.pkts_fwd = 2;
        f.tcp_flags_fwd = TCP_SYN | TCP_ACK;
        f.pkts_rev = 2;
        f.tcp_flags_rev = TCP_SYN | TCP_ACK; // SYN/ACK => established
        cls.classify(&mut f);
        assert_ne!(f.category, Category::Scan);
    }

    #[test]
    fn scan_uplift_disabled_when_detect_scans_false() {
        let cls = Classifier::new(ClassifyConfig {
            detect_scans: false,
            scan_port_threshold: 15,
        });
        let mut f = tcp_flow(54_000, 31_337);
        f.pkts_fwd = 1;
        f.tcp_flags_fwd = TCP_SYN;
        cls.classify(&mut f);
        // With scan detection off, the probe shape must not uplift.
        assert_eq!(f.category, Category::Unknown);
    }

    #[test]
    fn named_service_is_not_overridden_by_probe_shape() {
        // A SYN to a *named* port (https) must stay Web even though it is unanswered:
        // confident port classification wins over the probe shape.
        let cls = Classifier::new(ClassifyConfig::default());
        let mut f = tcp_flow(443, 50_000);
        f.pkts_fwd = 1;
        f.tcp_flags_fwd = TCP_SYN;
        cls.classify(&mut f);
        assert_eq!(f.category, Category::Web);
        assert_eq!(f.app_proto, "https");
    }

    #[test]
    fn long_lived_bulk_on_unknown_port_is_tunnel() {
        let cls = Classifier::new(ClassifyConfig::default());
        let mut f = tcp_flow(40_000, 41_000); // non-service ports both ends
        f.pkts_fwd = 1000;
        f.pkts_rev = 1000;
        f.bytes_fwd = 2 * (1 << 20);
        f.bytes_rev = 2 * (1 << 20);
        f.first_ts_ns = 0;
        f.last_ts_ns = 120 * 1_000_000_000; // 120 s, > 60 s
        f.tcp_flags_fwd = TCP_SYN | TCP_ACK;
        f.tcp_flags_rev = TCP_SYN | TCP_ACK;
        cls.classify(&mut f);
        assert_eq!(f.category, Category::TunnelVpn);
    }

    #[test]
    fn short_bulk_on_unknown_port_is_not_tunnel() {
        let cls = Classifier::new(ClassifyConfig::default());
        let mut f = tcp_flow(40_000, 41_000);
        f.pkts_fwd = 1000;
        f.pkts_rev = 1000;
        f.bytes_fwd = 2 * (1 << 20);
        f.bytes_rev = 2 * (1 << 20);
        f.first_ts_ns = 0;
        f.last_ts_ns = 5 * 1_000_000_000; // only 5 s
        f.tcp_flags_fwd = TCP_SYN | TCP_ACK;
        f.tcp_flags_rev = TCP_SYN | TCP_ACK;
        cls.classify(&mut f);
        assert_ne!(f.category, Category::TunnelVpn);
    }

    #[test]
    fn small_regular_two_way_flow_is_beacon_candidate() {
        let cls = Classifier::new(ClassifyConfig::default());
        let mut f = tcp_flow(40_000, 41_000);
        f.pkts_fwd = 3;
        f.pkts_rev = 3;
        f.bytes_fwd = 300;
        f.bytes_rev = 300;
        f.first_ts_ns = 0;
        f.last_ts_ns = 5 * 1_000_000_000;
        // Established so it isn't caught by the probe rule.
        f.tcp_flags_fwd = TCP_SYN | TCP_ACK;
        f.tcp_flags_rev = TCP_SYN | TCP_ACK;
        cls.classify(&mut f);
        assert_eq!(f.category, Category::C2);
    }

    #[test]
    fn probe_takes_precedence_over_beacon_when_both_could_match() {
        // Tiny, unanswered SYN: probe rule should fire before any beacon consideration.
        let cls = Classifier::new(ClassifyConfig::default());
        let mut f = tcp_flow(40_000, 41_000);
        f.pkts_fwd = 1;
        f.tcp_flags_fwd = TCP_SYN;
        cls.classify(&mut f);
        assert_eq!(f.category, Category::Scan);
    }

    // ----- benign network-service + RTC ports (C2 shape-uplift guard) -------

    #[test]
    fn network_service_ports_map_to_network_service() {
        for (p, tok) in [
            (123u16, "ntp"),
            (67, "dhcp"),
            (68, "dhcp"),
            (546, "dhcp"),
            (547, "dhcp"),
            (161, "snmp"),
            (162, "snmp"),
            (514, "syslog"),
        ] {
            assert_eq!(
                Classifier::category_for_port(Transport::Udp, p),
                (Category::NetworkService, tok),
                "udp/{p}"
            );
        }
    }

    #[test]
    fn stun_turn_ports_map_to_voip() {
        assert_eq!(
            Classifier::category_for_port(Transport::Udp, 3478),
            (Category::Voip, "stun")
        );
        assert_eq!(
            Classifier::category_for_port(Transport::Tcp, 3478),
            (Category::Voip, "stun")
        );
        // Google STUN 19302 lands in the RTP dynamic-media range -> VoIP "rtp" (still not C2).
        assert_eq!(
            Classifier::category_for_port(Transport::Udp, 19302),
            (Category::Voip, "rtp")
        );
        assert_eq!(
            Classifier::category_for_port(Transport::Udp, 5349),
            (Category::Voip, "turn")
        );
        assert_eq!(
            Classifier::category_for_port(Transport::Tcp, 5349),
            (Category::Voip, "turn")
        );
        assert_eq!(
            Classifier::category_for_port(Transport::Udp, 5350),
            (Category::Voip, "turn")
        );
    }

    #[test]
    fn ntp_flow_shaped_like_beacon_stays_network_service_not_c2() {
        // The regression this guards: a small, two-way NTP exchange to a time server has the exact
        // shape `looks_like_beacon` fires on. Because port 123 now names it, the flow classifies as
        // NetworkService (confident, provenance "port") and the C2 shape-uplift never runs.
        let cls = Classifier::new(ClassifyConfig::default());
        let mut f = udp_flow(123, 40_000); // service port = 123 = NTP
        f.pkts_fwd = 3;
        f.pkts_rev = 3;
        f.bytes_fwd = 300;
        f.bytes_rev = 300;
        cls.classify(&mut f);
        assert_eq!(
            f.category,
            Category::NetworkService,
            "NTP must not be shape-uplifted to C2"
        );
        assert_eq!(f.app_proto, "ntp");
        assert_eq!(f.app_proto_src, Some("port"));
    }

    #[test]
    fn dot_flow_shaped_like_beacon_stays_named_dns_not_c2() {
        // Guards the evasive-beacon escalation: a DoT flow (853) whose TLS handshake was NOT
        // captured carries only small two-way app-data — the exact beacon shape. Port 853 must
        // name it as DNS (provenance "port") so the shape-uplift to C2 never runs and the
        // downstream `named_service` veto holds a public resolver at Medium, not High.
        let cls = Classifier::new(ClassifyConfig::default());
        let mut f = tcp_flow(853, 50_000); // service port = 853 = DoT, no observed_app_proto
        f.pkts_fwd = 3;
        f.pkts_rev = 3;
        f.bytes_fwd = 200;
        f.bytes_rev = 200;
        cls.classify(&mut f);
        assert_eq!(
            f.category,
            Category::Dns,
            "DoT must not be shape-uplifted to C2"
        );
        assert_eq!(f.app_proto, "dot");
        assert_eq!(f.app_proto_src, Some("port"));
    }

    // ----- payload precedence + app_proto_src derivation --------------------

    #[test]
    fn payload_http_on_nonstandard_port_is_web_via_payload() {
        let cls = Classifier::new(ClassifyConfig::default());
        let mut f = tcp_flow(40_000, 41_000); // neither side is a web port
        f.observed_app_proto = AppProto::Http;
        cls.classify(&mut f);
        assert_eq!(f.category, Category::Web);
        assert_eq!(f.app_proto, "http");
        assert_eq!(f.app_proto_src, Some("payload"));
    }

    #[test]
    fn payload_tls_labels_tls_and_keeps_sni() {
        let cls = Classifier::new(ClassifyConfig::default());
        let mut f = tcp_flow(50_000, 8443);
        f.observed_app_proto = AppProto::Tls;
        f.sni = Some("api.example".to_string());
        cls.classify(&mut f);
        assert_eq!(f.category, Category::Web);
        assert_eq!(f.app_proto, "tls"); // payload token, NOT port "https"
        assert_eq!(f.app_proto_src, Some("payload"));
        assert_eq!(f.sni.as_deref(), Some("api.example"));
    }

    #[test]
    fn payload_ot_labels_iot_ot_offport() {
        // A Modbus flow identified by payload on a NON-standard port classifies as IoT/OT
        // with the specific protocol token and "payload" provenance.
        let cls = Classifier::new(ClassifyConfig::default());
        let mut f = tcp_flow(50_000, 9999);
        f.observed_app_proto = AppProto::Modbus;
        cls.classify(&mut f);
        assert_eq!(f.category, Category::IotOt);
        assert_eq!(f.app_proto, "modbus");
        assert_eq!(f.app_proto_src, Some("payload"));

        // Each OT protocol keeps its own token.
        for (ap, tok) in [
            (AppProto::Dnp3, "dnp3"),
            (AppProto::S7comm, "s7comm"),
            (AppProto::Bacnet, "bacnet"),
            (AppProto::EnipCip, "ethernet-ip"),
        ] {
            let mut g = tcp_flow(50_000, 40_000);
            g.observed_app_proto = ap;
            cls.classify(&mut g);
            assert_eq!(g.category, Category::IotOt, "{tok} → IotOt");
            assert_eq!(g.app_proto, tok);
        }
    }

    #[test]
    fn dns_on_port_53_is_port_provenance_not_payload() {
        // DNS is recognized purely by L4 port 53 (no DNS payload is ever parsed), so a
        // UDP/53 flow must record app_proto_src="port" even when the decoder set the
        // port-derived AppProto::Dns hint. "payload" provenance is reserved for the
        // structurally-sniffed protocols (Http/Tls).
        let cls = Classifier::new(ClassifyConfig::default());
        let mut f = udp_flow(53, 40_000);
        f.observed_app_proto = AppProto::Dns; // port-derived hint from decode::l7_hint
        cls.classify(&mut f);
        assert_eq!(f.category, Category::Dns);
        assert_eq!(f.app_proto, "dns");
        assert_eq!(f.app_proto_src, Some("port"));
    }

    #[test]
    fn port_only_flow_marks_derivation_port() {
        let cls = Classifier::new(ClassifyConfig::default());
        let mut f = tcp_flow(443, 50_000); // named by port, no payload hint
        cls.classify(&mut f);
        assert_eq!(f.category, Category::Web);
        assert_eq!(f.app_proto, "https");
        assert_eq!(f.app_proto_src, Some("port"));
    }

    #[test]
    fn no_signal_flow_has_null_derivation() {
        let cls = Classifier::new(ClassifyConfig {
            detect_scans: false,
            scan_port_threshold: 15,
        });
        let mut f = tcp_flow(40_000, 41_000);
        cls.classify(&mut f);
        assert_eq!(f.category, Category::Unknown);
        assert_eq!(f.app_proto, "");
        assert_eq!(f.app_proto_src, None);
    }

    #[test]
    fn payload_precedence_does_not_break_scan_uplift() {
        let cls = Classifier::new(ClassifyConfig::default());
        let mut f = tcp_flow(54_000, 31_337);
        f.pkts_fwd = 1;
        f.tcp_flags_fwd = TCP_SYN; // probe shape, observed_app_proto stays Unknown
        cls.classify(&mut f);
        assert_eq!(f.category, Category::Scan);
        assert_eq!(f.app_proto_src, None);
    }

    #[test]
    fn classify_is_idempotent_for_payload_flow() {
        let cls = Classifier::new(ClassifyConfig::default());
        let mut f = tcp_flow(50_000, 9999);
        f.observed_app_proto = AppProto::Tls;
        cls.classify(&mut f);
        let after = (f.category, f.app_proto.clone(), f.app_proto_src);
        cls.classify(&mut f);
        assert_eq!((f.category, f.app_proto.clone(), f.app_proto_src), after);
    }
}
