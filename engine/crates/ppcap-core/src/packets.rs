//! On-demand per-flow packet extraction (re-reads a capture; nothing stored).
//!
//! [`extract_flow_packets`] streams a [`PacketSource`] once and returns the packets belonging
//! to a single 5-tuple flow (both directions) within a time window, each with its TCP seq/ack
//! and a bounded, base64-encoded payload slice for the UI to hexdump. Nothing is retained
//! across the call — the source is re-read on demand, keeping memory bounded.

use base64::Engine as _;
use serde::Serialize;
use std::net::IpAddr;

use crate::decode::{decode_frame, l4_payload};
use crate::error::Result;
use crate::model::packet::Transport;
use crate::reader::PacketSource;

/// Hard cap on the number of packets returned for a single flow (the UI paginates).
pub const MAX_PACKETS_PER_FLOW: usize = 2000;
/// Hard cap on the per-packet payload bytes recorded (base64-encoded for the UI hexdump).
pub const PAYLOAD_CAP_BYTES: usize = 512;
/// Timestamp slop applied to both ends of the query window (±1 ms), absorbing the
/// microsecond-resolution rounding of classic pcap timestamps so boundary packets are kept.
const WINDOW_TOL_NS: i64 = 1_000_000;

/// The flow to extract: a directed 5-tuple plus an inclusive `[start_ns, end_ns]` time window.
/// Matching is bidirectional — packets in either direction of the tuple are returned.
#[derive(Clone, Debug)]
pub struct PacketQuery {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub transport: Transport,
    pub start_ns: i64,
    pub end_ns: i64,
}

/// Extraction caps. [`Default`] uses [`MAX_PACKETS_PER_FLOW`] / [`PAYLOAD_CAP_BYTES`].
#[derive(Clone, Copy, Debug)]
pub struct PacketCaps {
    pub max_packets: usize,
    pub payload_cap: usize,
}

impl Default for PacketCaps {
    fn default() -> Self {
        Self {
            max_packets: MAX_PACKETS_PER_FLOW,
            payload_cap: PAYLOAD_CAP_BYTES,
        }
    }
}

/// One extracted packet: fixed metadata, TCP seq/ack (when TCP), and a bounded base64 payload.
#[derive(Serialize, Clone, Debug)]
pub struct PacketRecord {
    /// 0-based index within the capture.
    pub index: u32,
    pub ts_ns: i64,
    /// `"c2s"` (query src→dst) or `"s2c"` (the reverse direction).
    pub direction: &'static str,
    pub wire_len: u32,
    pub cap_len: u32,
    pub tcp_flags: u8,
    /// TCP sequence / acknowledgement numbers; `None` for non-TCP.
    pub seq: Option<u32>,
    pub ack: Option<u32>,
    /// The full L4 payload length (before capping) — what the UI labels the packet with.
    pub payload_len: u32,
    /// Base64 of up to [`PacketCaps::payload_cap`] payload bytes.
    pub payload_b64: String,
    /// True when the real payload exceeded the cap and `payload_b64` is a prefix.
    pub payload_truncated: bool,
}

/// The result of an extraction: how many matched in total, whether the packet list was capped,
/// and the (bounded) per-packet records.
#[derive(Serialize, Clone, Debug)]
pub struct FlowPackets {
    /// Every matching packet, counted even past the `max_packets` cap.
    pub total: u64,
    /// True when fewer packets were returned than matched (the list was capped).
    pub truncated: bool,
    pub packets: Vec<PacketRecord>,
}

/// Stream `source` once and return the packets belonging to the flow described by `q`, in both
/// directions, within `[start_ns - 1ms, end_ns + 1ms]`. `total` counts every match (even those
/// dropped by `caps.max_packets`); each kept packet's payload is capped to `caps.payload_cap`.
///
/// Re-reads the capture; nothing is stored across the call. Decode errors on individual frames
/// are skipped (the frame is simply not a match), never propagated.
pub fn extract_flow_packets(
    mut source: Box<dyn PacketSource>,
    q: &PacketQuery,
    caps: &PacketCaps,
) -> Result<FlowPackets> {
    let lo = q.start_ns.saturating_sub(WINDOW_TOL_NS);
    let hi = q.end_ns.saturating_add(WINDOW_TOL_NS);
    let mut packets: Vec<PacketRecord> = Vec::new();
    let mut total: u64 = 0;

    while let Some(frame) = source.next_frame()? {
        if frame.ts_ns < lo || frame.ts_ns > hi {
            continue;
        }
        let meta = match decode_frame(&frame) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.transport != q.transport {
            continue;
        }
        let (s, d) = match (meta.src_ip, meta.dst_ip) {
            (Some(s), Some(d)) => (s, d),
            _ => continue,
        };
        let fwd = s == q.src_ip
            && d == q.dst_ip
            && meta.src_port == q.src_port
            && meta.dst_port == q.dst_port;
        let rev = s == q.dst_ip
            && d == q.src_ip
            && meta.src_port == q.dst_port
            && meta.dst_port == q.src_port;
        if !fwd && !rev {
            continue;
        }
        total += 1;

        // Past the cap we keep counting `total` but stop materializing records.
        if packets.len() >= caps.max_packets {
            continue;
        }

        let l4 = l4_payload(&frame);
        let payload: &[u8] = l4.as_ref().map(|x| x.payload).unwrap_or(&[]);
        let (seq, ack) = l4.as_ref().map(|x| (x.seq, x.ack)).unwrap_or((None, None));
        let payload_truncated = payload.len() > caps.payload_cap;
        let take = payload.len().min(caps.payload_cap);

        packets.push(PacketRecord {
            index: frame.index as u32,
            ts_ns: frame.ts_ns,
            direction: if fwd { "c2s" } else { "s2c" },
            wire_len: frame.wire_len,
            cap_len: frame.cap_len,
            tcp_flags: meta.tcp_flags,
            seq,
            ack,
            payload_len: payload.len() as u32,
            payload_b64: base64::engine::general_purpose::STANDARD.encode(&payload[..take]),
            payload_truncated,
        });
    }

    let truncated = (total as usize) > packets.len();
    Ok(FlowPackets {
        total,
        truncated,
        packets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gen::{container, frames};
    use crate::reader::{open_reader, LinkType};
    use std::io::{Cursor, Write};
    use std::net::Ipv4Addr;

    fn tcp_pcap() -> Vec<u8> {
        let client = Ipv4Addr::new(10, 0, 0, 1);
        let server = Ipv4Addr::new(93, 184, 216, 34);
        let mk = |src, dst, sp, dp, flags, payload: &[u8], ts: i64, buf: &mut Vec<u8>| {
            let tcp = frames::build_tcp(src, dst, sp, dp, flags, payload);
            let ip = frames::build_ipv4(src, dst, 6, 64, tcp.len());
            let eth = frames::build_ethernet([2; 6], [4; 6], 0x0800);
            let frame: Vec<u8> = eth.into_iter().chain(ip).chain(tcp).collect();
            container::write_legacy_record(buf, ts, frame.len() as u32, frame.len() as u32)
                .unwrap();
            buf.write_all(&frame).unwrap();
        };
        let mut buf = Vec::new();
        container::write_pcap_header(&mut buf, LinkType::Ethernet).unwrap();
        mk(
            client,
            server,
            1234,
            443,
            frames::TCP_SYN,
            b"",
            1_000_000_000,
            &mut buf,
        );
        mk(
            server,
            client,
            443,
            1234,
            frames::TCP_SYN | frames::TCP_ACK,
            b"",
            1_000_000_100,
            &mut buf,
        );
        mk(
            client,
            server,
            1234,
            443,
            frames::TCP_PSH | frames::TCP_ACK,
            b"GET / HTTP/1.1\r\n",
            1_000_000_200,
            &mut buf,
        );
        mk(
            server,
            client,
            443,
            1234,
            frames::TCP_PSH | frames::TCP_ACK,
            b"HTTP/1.1 200 OK\r\n",
            1_000_000_300,
            &mut buf,
        );
        // unrelated UDP that must NOT match:
        let udp = frames::build_udp(client, Ipv4Addr::new(8, 8, 8, 8), 5000, 53, b"x");
        let ip = frames::build_ipv4(client, Ipv4Addr::new(8, 8, 8, 8), 17, 64, udp.len());
        let eth = frames::build_ethernet([2; 6], [4; 6], 0x0800);
        let f: Vec<u8> = eth.into_iter().chain(ip).chain(udp).collect();
        container::write_legacy_record(&mut buf, 1_000_000_400, f.len() as u32, f.len() as u32)
            .unwrap();
        buf.write_all(&f).unwrap();
        buf
    }

    fn query() -> PacketQuery {
        PacketQuery {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "93.184.216.34".parse().unwrap(),
            src_port: 1234,
            dst_port: 443,
            transport: Transport::Tcp,
            start_ns: 1_000_000_000,
            end_ns: 1_000_000_300,
        }
    }

    #[test]
    fn extracts_only_the_matching_flow_both_directions() {
        let src = open_reader(Cursor::new(tcp_pcap()), None).unwrap();
        let fp = extract_flow_packets(src, &query(), &PacketCaps::default()).unwrap();
        assert_eq!(fp.total, 4); // 4 TCP, UDP excluded
        assert_eq!(fp.packets.len(), 4);
        assert!(!fp.truncated);
        assert_eq!(fp.packets[0].direction, "c2s"); // client SYN
        assert_eq!(fp.packets[1].direction, "s2c"); // server SYN-ACK
        assert!(fp.packets[0].seq.is_some()); // TCP seq present
        assert!(fp.packets[0].ack.is_some());
        // payload bytes decode back
        let b = base64::engine::general_purpose::STANDARD
            .decode(&fp.packets[2].payload_b64)
            .unwrap();
        assert_eq!(&b, b"GET / HTTP/1.1\r\n");
        assert_eq!(fp.packets[2].payload_len, 16);
        assert!(!fp.packets[2].payload_truncated);
        // The two handshake packets carry no payload.
        assert_eq!(fp.packets[0].payload_len, 0);
        assert_eq!(fp.packets[0].payload_b64, "");
    }

    #[test]
    fn caps_packets_and_payload() {
        let src = open_reader(Cursor::new(tcp_pcap()), None).unwrap();
        let caps = PacketCaps {
            max_packets: 2,
            payload_cap: 4,
        };
        let fp = extract_flow_packets(src, &query(), &caps).unwrap();
        // total still counts every matching packet even past the cap.
        assert_eq!(fp.total, 4);
        assert_eq!(fp.packets.len(), 2);
        assert!(fp.truncated);
    }

    #[test]
    fn payload_cap_truncates_recorded_bytes() {
        // A wider window + a generous packet cap, but a tiny payload cap, so the PSH packet
        // is kept and its recorded payload is truncated to `payload_cap` bytes.
        let src = open_reader(Cursor::new(tcp_pcap()), None).unwrap();
        let caps = PacketCaps {
            max_packets: 100,
            payload_cap: 4,
        };
        let fp = extract_flow_packets(src, &query(), &caps).unwrap();
        let psh = &fp.packets[2];
        assert_eq!(psh.payload_len, 16); // the real (full) payload length is reported
        assert!(psh.payload_truncated); // but the recorded bytes were capped
        let b = base64::engine::general_purpose::STANDARD
            .decode(&psh.payload_b64)
            .unwrap();
        assert_eq!(&b, b"GET "); // first 4 bytes only
    }

    #[test]
    fn window_excludes_packets_outside_the_one_ms_tolerance() {
        // A query window that ends well before the flow's timestamps: only the ±1ms tolerance
        // around start/end lets the first packet through; everything later is excluded.
        let src = open_reader(Cursor::new(tcp_pcap()), None).unwrap();
        let q = PacketQuery {
            start_ns: 1_000_000_000,
            end_ns: 1_000_000_000,
            ..query()
        };
        let fp = extract_flow_packets(src, &q, &PacketCaps::default()).unwrap();
        // All four flow packets fall within 1_000_000_000 ± 1ms, so all match.
        assert_eq!(fp.total, 4);
    }
}
