//! Payload byte-entropy for flows no protocol sniffer identified.
//!
//! The discriminator this supplies is "unknown *ciphertext* vs unknown cleartext": a custom-crypto
//! C2 channel or a hand-rolled tunnel looks like random bytes, while an unrecognized text/binary
//! protocol does not. Every identified protocol (TLS/HTTP/DNS/QUIC/OT) is excluded, so this only
//! ever measures traffic the rest of the engine cannot name.
//!
//! # Why a per-flow histogram, not per-packet entropy
//!
//! Shannon entropy over an `n`-byte sample is bounded by `log2(n)`, so a 64-byte C2 packet could
//! never measure above 6 bits/byte — per-packet entropy is structurally blind to exactly the
//! traffic that matters. (A per-packet `f64` on `PacketMeta` would also break its `Eq` derive.)
//! Instead each tracked flow accumulates a 256-bin histogram per direction, capped at
//! [`EntropyConfig::sample_bytes_per_dir`] bytes, and entropy is computed once at flow close.
//!
//! # Identification is flow state, not a packet property
//!
//! `decode::l7_hint` recognizes handshake- and request-*shaped* payloads, so packet 3+ of an
//! ordinary TLS/HTTP flow decodes as `AppProto::Unknown`. Gating on the current packet alone would
//! therefore fill the map with identified flows' ciphertext and starve the detector. The sampler
//! keeps its own per-flow memory instead: a known `app_proto` (or an SSH HASSH, or a STUN packet)
//! parks the flow on a bin-free [`SampleState::Identified`] sentinel, and only flows still unknown
//! accumulate histograms.
//!
//! Bounded and payload-free by construction: only the derived `f32` entropy leaves this module.

use std::collections::HashMap;

use crate::model::flow::{Direction, FlowKey};
use crate::model::packet::PacketMeta;

/// Tuning for the entropy substrate. Defaults are sized so the worst case stays well inside the
/// engine's ≤ 64 MiB peak-heap budget (see the module memory note in the plan): 4096 sampling
/// flows × 2 directions × 256 × `u16` ≈ 4 MiB, plus the sentinel map.
#[derive(Debug, Clone)]
pub struct EntropyConfig {
    pub enabled: bool,
    /// Cap on flows tracked at all (sentinel or sampling). Sized to the live-flow table so an
    /// identified-heavy capture cannot push unknown flows out.
    pub max_sample_states: usize,
    /// Cap on flows holding histograms concurrently.
    pub max_entropy_flows: usize,
    /// Bytes sampled per direction before a direction stops accumulating.
    pub sample_bytes_per_dir: usize,
    /// Packets with less payload than this are skipped (keeps ACK-sized noise out of the sample).
    pub min_packet_payload: usize,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        EntropyConfig {
            enabled: true,
            max_sample_states: 32_768,
            max_entropy_flows: 4_096,
            sample_bytes_per_dir: 2_048,
            min_packet_payload: 64,
        }
    }
}

/// Per-direction byte histograms for one sampled flow.
struct DirHists {
    /// `[forward, reverse]` 256-bin byte counts. `u16` cannot overflow: a direction stops at
    /// `sample_bytes_per_dir` (2048 by default), far below `u16::MAX`.
    bins: [[u16; 256]; 2],
    /// Bytes sampled so far, per direction.
    sampled: [u32; 2],
}

impl DirHists {
    fn new() -> Box<DirHists> {
        Box::new(DirHists {
            bins: [[0u16; 256]; 2],
            sampled: [0, 0],
        })
    }
}

/// What the sampler knows about a flow.
enum SampleState {
    /// Some evidence named the protocol — no histograms, no further work.
    Identified,
    /// The stream begins with a known compressed-container magic. Compressed bytes are as
    /// high-entropy as ciphertext, so this is tracked separately and excluded from the
    /// high-entropy verdict rather than silently inflating it.
    Compressed,
    /// Still unidentified: accumulating.
    Sampling(Box<DirHists>),
}

/// The per-flow entropy result, read at flow close.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FlowEntropy {
    /// Shannon entropy (bits/byte) of the sampled forward (lo->hi) payload; `None` if nothing
    /// was sampled in that direction.
    pub fwd_bits: Option<f32>,
    /// Shannon entropy (bits/byte) of the sampled reverse (hi->lo) payload.
    pub rev_bits: Option<f32>,
    /// Bytes sampled forward / reverse — a payload-aware "both ways" test that raw packet counts
    /// cannot give (those are satisfied by pure ACKs).
    pub sampled_fwd: u32,
    pub sampled_rev: u32,
    /// The stream started with a compressed-container magic.
    pub compressed: bool,
}

/// Bounded, streaming payload-entropy sampler. Fed at the raw-frame seam (the only point where
/// payload bytes and `PacketMeta` coexist), drained per flow at close.
pub struct EntropySampler {
    cfg: EntropyConfig,
    states: HashMap<FlowKey, SampleState>,
    /// Flows currently holding histograms (a subset of `states`), tracked so the histogram cap is
    /// enforced without scanning the map.
    sampling: usize,
}

impl EntropySampler {
    pub fn new(cfg: EntropyConfig) -> EntropySampler {
        EntropySampler {
            cfg,
            states: HashMap::new(),
            sampling: 0,
        }
    }

    /// Fold one packet. Cheap on the common path: an identified flow costs one map probe that
    /// hits a bin-free sentinel.
    pub fn observe(&mut self, meta: &PacketMeta, frame: &crate::reader::RawFrame<'_>) {
        if !self.cfg.enabled {
            return;
        }
        // Only port-bearing transports form the flows this measures.
        if !meta.transport.has_ports() {
            return;
        }
        let Some((key, dir)) = FlowKey::from_packet(meta) else {
            return;
        };

        // Any evidence that names the protocol parks the flow permanently.
        if identifies_protocol(meta) {
            self.mark(key, SampleState::Identified);
            return;
        }

        // Everything below needs the payload bytes.
        if (meta.payload_len as usize) < self.cfg.min_packet_payload {
            return;
        }
        let Some(info) = crate::decode::l4_payload(frame) else {
            return;
        };
        let payload = info.payload;
        if payload.len() < self.cfg.min_packet_payload {
            return;
        }

        // A STUN binding request/response means this 5-tuple is an ICE candidate pair, i.e. the
        // WebRTC media (SRTP) that follows is encrypted by design — not an unknown channel.
        if looks_like_stun(payload) {
            self.mark(key, SampleState::Identified);
            return;
        }

        match self.states.get_mut(&key) {
            Some(SampleState::Identified) | Some(SampleState::Compressed) => {}
            Some(SampleState::Sampling(h)) => fold(h, dir, payload, self.cfg.sample_bytes_per_dir),
            None => {
                // First sampled payload for this flow: screen for a compressed container before
                // allocating bins, then start sampling if there is room.
                if self.states.len() >= self.cfg.max_sample_states {
                    return;
                }
                if starts_with_compressed_magic(payload) {
                    self.states.insert(key, SampleState::Compressed);
                    return;
                }
                if self.sampling >= self.cfg.max_entropy_flows {
                    return;
                }
                let mut h = DirHists::new();
                fold(&mut h, dir, payload, self.cfg.sample_bytes_per_dir);
                self.states.insert(key, SampleState::Sampling(h));
                self.sampling += 1;
            }
        }
    }

    /// Record a terminal state for `key`, freeing any histograms it held.
    fn mark(&mut self, key: FlowKey, state: SampleState) {
        match self.states.get(&key) {
            Some(SampleState::Identified) => return,
            Some(SampleState::Sampling(_)) => self.sampling -= 1,
            _ => {
                if self.states.len() >= self.cfg.max_sample_states
                    && !self.states.contains_key(&key)
                {
                    return;
                }
            }
        }
        self.states.insert(key, state);
    }

    /// Take this flow's entropy result and free its state. Returns `None` for flows that were
    /// never sampled (identified, or past a cap) — those keep NULL entropy columns.
    pub fn take(&mut self, key: &FlowKey) -> Option<FlowEntropy> {
        match self.states.remove(key) {
            Some(SampleState::Sampling(h)) => {
                self.sampling -= 1;
                Some(FlowEntropy {
                    fwd_bits: shannon_bits(&h.bins[0]),
                    rev_bits: shannon_bits(&h.bins[1]),
                    sampled_fwd: h.sampled[0],
                    sampled_rev: h.sampled[1],
                    compressed: false,
                })
            }
            Some(SampleState::Compressed) => Some(FlowEntropy {
                fwd_bits: None,
                rev_bits: None,
                sampled_fwd: 0,
                sampled_rev: 0,
                compressed: true,
            }),
            _ => None,
        }
    }

    /// Live tracked-flow count (tests / bounding assertions).
    #[cfg(test)]
    pub(crate) fn tracked(&self) -> usize {
        self.states.len()
    }
}

/// True when this packet carries evidence naming the flow's protocol.
///
/// `app_proto` covers TLS/HTTP/DNS/QUIC/OT. HASSH matters because SSH has no `AppProto` variant:
/// without this, SSH on a non-22 port is unidentified, high-entropy, and a guaranteed false
/// positive for the unknown-protocol detector.
fn identifies_protocol(meta: &PacketMeta) -> bool {
    meta.app_proto.is_known() || meta.hassh.is_some() || meta.hassh_server.is_some()
}

/// STUN (RFC 5389): 2-byte type with the top two bits clear, a length, then the magic cookie
/// `0x2112A442` at offset 4. ICE connectivity checks always precede WebRTC SRTP on the same
/// 5-tuple, so this is the cheap tell that a UDP flow is sanctioned encrypted media.
fn looks_like_stun(payload: &[u8]) -> bool {
    payload.len() >= 20 && payload[0] & 0xc0 == 0 && payload[4..8] == [0x21, 0x12, 0xa4, 0x42]
}

/// Known compressed-container magics. Compressed bytes measure as high-entropy as ciphertext, so a
/// stream that *announces* itself as an archive is excluded from the encrypted-unknown verdict.
fn starts_with_compressed_magic(payload: &[u8]) -> bool {
    const MAGICS: &[&[u8]] = &[
        &[0x1f, 0x8b],                         // gzip
        &[0x28, 0xb5, 0x2f, 0xfd],             // zstd
        b"PK",                                 // zip / jar / docx
        b"Rar!",                               // rar
        &[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], // 7z
        &[0xfd, b'7', b'z', b'X', b'Z', 0x00], // xz
        b"BZh",                                // bzip2
    ];
    MAGICS.iter().any(|m| payload.starts_with(m))
}

/// Fold one packet's payload into a direction's histogram, respecting the per-direction cap.
fn fold(h: &mut DirHists, dir: Direction, payload: &[u8], cap: usize) {
    let idx = match dir {
        Direction::Forward => 0,
        Direction::Reverse => 1,
    };
    let room = cap.saturating_sub(h.sampled[idx] as usize);
    if room == 0 {
        return;
    }
    let take = payload.len().min(room);
    for &b in &payload[..take] {
        h.bins[idx][b as usize] = h.bins[idx][b as usize].saturating_add(1);
    }
    h.sampled[idx] = h.sampled[idx].saturating_add(take as u32);
}

/// Shannon entropy in bits/byte over a 256-bin histogram; `None` when nothing was sampled.
/// Fixed-order arithmetic over a fixed-size array — deterministic, no clock, no RNG.
fn shannon_bits(bins: &[u16; 256]) -> Option<f32> {
    let total: u64 = bins.iter().map(|&c| u64::from(c)).sum();
    if total == 0 {
        return None;
    }
    let total_f = total as f64;
    let mut h = 0.0f64;
    for &c in bins.iter() {
        if c != 0 {
            let p = f64::from(c) / total_f;
            h -= p * p.log2();
        }
    }
    Some(h as f32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hists_from(fwd: &[u8], rev: &[u8]) -> Box<DirHists> {
        let mut h = DirHists::new();
        fold(&mut h, Direction::Forward, fwd, 2048);
        fold(&mut h, Direction::Reverse, rev, 2048);
        h
    }

    #[test]
    fn uniform_bytes_measure_near_eight_bits() {
        // Every byte value once → maximum entropy for a byte alphabet.
        let all: Vec<u8> = (0..=255u8).collect();
        let h = hists_from(&all, &[]);
        let bits = shannon_bits(&h.bins[0]).unwrap();
        assert!(bits > 7.99, "uniform bytes should be ~8.0 bits, got {bits}");
    }

    #[test]
    fn ascii_text_measures_mid_range_and_constant_bytes_measure_zero() {
        let text = b"the quick brown fox jumps over the lazy dog, again and again and again";
        let h = hists_from(text, &[0x41; 512]);
        let ascii = shannon_bits(&h.bins[0]).unwrap();
        assert!(
            (3.0..5.5).contains(&ascii),
            "english text should sit ~4 bits, got {ascii}"
        );
        // A single repeated byte carries no information at all.
        assert_eq!(shannon_bits(&h.bins[1]).unwrap(), 0.0);
    }

    #[test]
    fn empty_histogram_yields_none() {
        assert_eq!(shannon_bits(&[0u16; 256]), None);
    }

    /// Entropy over an `n`-byte sample cannot exceed `log2(n)` — the reason this measures a
    /// per-flow sample rather than individual packets.
    #[test]
    fn small_samples_are_bounded_by_log2_n() {
        let sixteen: Vec<u8> = (0..16u8).collect();
        let h = hists_from(&sixteen, &[]);
        let bits = shannon_bits(&h.bins[0]).unwrap();
        assert!(
            (bits - 4.0).abs() < 0.001,
            "16 distinct bytes → 4 bits, got {bits}"
        );
    }

    #[test]
    fn per_direction_sample_cap_is_respected() {
        let mut h = DirHists::new();
        fold(&mut h, Direction::Forward, &[0xAA; 4096], 2048);
        assert_eq!(h.sampled[0], 2048);
        // Further packets in a capped direction are ignored.
        fold(&mut h, Direction::Forward, &[0xBB; 512], 2048);
        assert_eq!(h.sampled[0], 2048);
        assert_eq!(h.bins[0][0xBB], 0);
    }

    #[test]
    fn stun_binding_request_is_recognized() {
        // type 0x0001, length 0, magic cookie, 12-byte transaction id.
        let mut pkt = vec![0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42];
        pkt.extend_from_slice(&[0x11; 12]);
        assert!(looks_like_stun(&pkt));
        // Random high-entropy bytes are not STUN.
        assert!(!looks_like_stun(&[0xff; 64]));
    }

    #[test]
    fn compressed_container_magics_are_screened() {
        assert!(starts_with_compressed_magic(&[0x1f, 0x8b, 0x08, 0x00]));
        assert!(starts_with_compressed_magic(b"PK\x03\x04rest"));
        assert!(starts_with_compressed_magic(&[
            0x28, 0xb5, 0x2f, 0xfd, 0x00
        ]));
        assert!(!starts_with_compressed_magic(b"GET / HTTP/1.1"));
    }

    // ── Sampler-level behavior (real frames through decode) ──────────────────

    /// A deterministic pseudo-random byte stream — genuinely high-entropy, unlike the engine's
    /// constant-byte synthetic payloads (which measure 0 bits).
    fn random_bytes(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                // SplitMix64 (the generator the repo's gen module already uses).
                x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = x;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                ((z ^ (z >> 31)) & 0xff) as u8
            })
            .collect()
    }

    fn tcp_frame(sp: u16, dp: u16, payload: &[u8], flags: u8) -> Vec<u8> {
        use crate::gen::frames::{build_ipv4, build_tcp, IP_PROTO_TCP};
        let (a, b) = (
            std::net::Ipv4Addr::new(10, 0, 0, 5),
            std::net::Ipv4Addr::new(203, 0, 113, 9),
        );
        let (s, d) = if sp > dp { (a, b) } else { (b, a) };
        let tcp = build_tcp(s, d, sp, dp, flags, payload);
        let mut pkt = build_ipv4(s, d, IP_PROTO_TCP, 64, tcp.len());
        pkt.extend_from_slice(&tcp);
        pkt
    }

    fn feed(sampler: &mut EntropySampler, bytes: &[u8]) -> PacketMeta {
        let frame = crate::reader::RawFrame {
            index: 0,
            ts_ns: 1,
            ts_known: true,
            iface_id: 0,
            wire_len: bytes.len() as u32,
            cap_len: bytes.len() as u32,
            link_type: crate::reader::LinkType::RawIpv4,
            data: bytes,
        };
        let meta = crate::decode::decode_frame(&frame).expect("decode");
        sampler.observe(&meta, &frame);
        meta
    }

    /// The load-bearing case: an unidentified, high-entropy channel on an unnamed port is
    /// sampled in both directions and measures as ciphertext.
    #[test]
    fn unidentified_high_entropy_flow_is_sampled_both_ways() {
        const TCP_PSH_ACK: u8 = 0x18;
        let mut s = EntropySampler::new(EntropyConfig::default());
        let up = tcp_frame(51000, 31337, &random_bytes(1200, 7), TCP_PSH_ACK);
        let down = tcp_frame(31337, 51000, &random_bytes(1200, 99), TCP_PSH_ACK);
        let meta = feed(&mut s, &up);
        feed(&mut s, &down);

        let (key, _) = FlowKey::from_packet(&meta).unwrap();
        let e = s.take(&key).expect("flow sampled");
        assert!(
            e.sampled_fwd > 0 && e.sampled_rev > 0,
            "both directions sampled"
        );
        assert!(
            e.fwd_bits.unwrap() > 7.2 && e.rev_bits.unwrap() > 7.2,
            "random bytes must read as ciphertext: {:?}/{:?}",
            e.fwd_bits,
            e.rev_bits
        );
        assert!(!e.compressed);
        // State is freed at take().
        assert_eq!(s.tracked(), 0);
    }

    /// The regression the review caught: an identified flow (TLS here) must never allocate
    /// histograms, no matter how many post-handshake packets decode as `Unknown`.
    #[test]
    fn identified_flow_is_never_sampled_even_after_opaque_packets() {
        const TCP_PSH_ACK: u8 = 0x18;
        let mut s = EntropySampler::new(EntropyConfig::default());
        // 1. A real ClientHello identifies the flow as TLS.
        let ch = crate::gen::frames::tls_client_hello_payload("example.com");
        let meta = feed(&mut s, &tcp_frame(51000, 443, &ch, TCP_PSH_ACK));
        assert_eq!(meta.app_proto, crate::model::packet::AppProto::Tls);
        // 2. Application data that decode cannot name — the shape that used to poison the map.
        for seed in 0..4 {
            feed(
                &mut s,
                &tcp_frame(51000, 443, &random_bytes(1200, seed), TCP_PSH_ACK),
            );
            feed(
                &mut s,
                &tcp_frame(443, 51000, &random_bytes(1200, seed + 50), TCP_PSH_ACK),
            );
        }
        let (key, _) = FlowKey::from_packet(&meta).unwrap();
        assert_eq!(s.take(&key), None, "identified flows carry no entropy");
    }

    /// Late identification frees an already-sampling flow (the self-cleaning path).
    #[test]
    fn late_identification_drops_a_sampling_flow() {
        const TCP_PSH_ACK: u8 = 0x18;
        let mut s = EntropySampler::new(EntropyConfig::default());
        let meta = feed(
            &mut s,
            &tcp_frame(51000, 9999, &random_bytes(600, 3), TCP_PSH_ACK),
        );
        let (key, _) = FlowKey::from_packet(&meta).unwrap();
        assert_eq!(s.tracked(), 1);
        // A ClientHello later on the same 5-tuple names the protocol.
        let ch = crate::gen::frames::tls_client_hello_payload("late.example");
        feed(&mut s, &tcp_frame(51000, 9999, &ch, TCP_PSH_ACK));
        assert_eq!(s.take(&key), None, "identification wins retroactively");
    }

    /// A compressed transfer is tracked but flagged, so the detector can exclude it instead of
    /// reading archive bytes as ciphertext.
    #[test]
    fn compressed_stream_is_flagged_not_sampled() {
        const TCP_PSH_ACK: u8 = 0x18;
        let mut s = EntropySampler::new(EntropyConfig::default());
        let mut body = vec![0x1f, 0x8b, 0x08, 0x00];
        body.extend_from_slice(&random_bytes(1000, 11));
        let meta = feed(&mut s, &tcp_frame(51000, 31337, &body, TCP_PSH_ACK));
        let (key, _) = FlowKey::from_packet(&meta).unwrap();
        let e = s.take(&key).expect("tracked");
        assert!(e.compressed && e.fwd_bits.is_none());
    }

    /// Histogram allocation is capped independently of the sentinel map.
    #[test]
    fn sampling_flows_are_capped() {
        const TCP_PSH_ACK: u8 = 0x18;
        let cfg = EntropyConfig {
            max_entropy_flows: 4,
            ..EntropyConfig::default()
        };
        let mut s = EntropySampler::new(cfg);
        for i in 0..20u16 {
            feed(
                &mut s,
                &tcp_frame(
                    51000 + i,
                    31337,
                    &random_bytes(200, u64::from(i)),
                    TCP_PSH_ACK,
                ),
            );
        }
        assert!(s.sampling <= 4, "histogram cap holds, got {}", s.sampling);
    }
}
