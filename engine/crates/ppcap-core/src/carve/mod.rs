//! Streaming, bounded **file carver** for cleartext HTTP downloads.
//!
//! Fed every decoded packet during the single analysis pass (like the TLS cert reassembler), it
//! watches for HTTP *responses* (`HTTP/…` status line, which only a server sends), reads the
//! `Content-Length`, then folds the response **body** bytes — in TCP sequence order — through a
//! streaming SHA-256. When the declared length is reached it emits a [`CarveObservation`]: the file's
//! hash and size, plus whether the hash is in an embedded known-bad set.
//!
//! Design constraints that keep it correct and cheap:
//! - **No buffering of the body** — the hash is computed incrementally, so memory is O(1) per flow
//!   regardless of file size (only the small header prefix is held, transiently).
//! - **In-order only** — bytes are placed by their TCP sequence number; a *gap* (missing segment)
//!   aborts the carve (no wrong hash is ever produced), a pure retransmit is skipped, and a partial
//!   overlap consumes only the fresh tail. Out-of-order / lossy captures simply yield no carve.
//! - **Length-delimited, uncompressed only** — a `Content-Encoding` (the body is compressed, so its
//!   hash would not be the file's) or `Transfer-Encoding: chunked` (not de-chunked here) aborts the
//!   carve rather than hashing the wrong bytes. The common malware-delivery case (a plain
//!   `Content-Length` binary) is covered.
//! - **Bounded** — capped number of tracked flows and a maximum carved size.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::analyze::Sha256 as Sha256Stream;
use crate::model::packet::{PacketMeta, Transport};

/// Max concurrent in-flight response carves.
const MAX_FLOWS: usize = 256;
/// Idle window (ns): a carve with no packet for this long may be evicted under cap pressure, so a
/// burst of stalled responses cannot permanently exhaust the table.
const IDLE_NS: i64 = 30_000_000_000;
/// Max bytes of response headers to buffer while looking for the CRLFCRLF terminator.
const MAX_HEADER: usize = 16 * 1024;
/// Largest body we will hash (a CPU bound; larger transfers are skipped, not truncated-and-hashed).
const MAX_BODY: u64 = 64 * 1024 * 1024;
/// Cap on retained carve observations (a memory bound — far above any realistic triage capture's
/// download count; the first this-many carved files, including any known-bad, are recorded).
const MAX_OBSERVATIONS: usize = 4096;

/// One carved file: the downloading client, the serving host, the body's SHA-256, its size, and
/// whether the hash matched the embedded known-bad set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CarveObservation {
    pub client: IpAddr,
    pub server: IpAddr,
    pub sha256: [u8; 32],
    pub size: u64,
    pub known_bad: bool,
}

/// Embedded known-bad SHA-256 set. Deliberately tiny and curated (the EICAR anti-malware test file
/// is the canonical, verifiable entry); a real deployment extends this. Kept as hex for readability;
/// parsed once into bytes via [`known_bad`].
const KNOWN_BAD_HEX: &[&str] = &[
    // EICAR standard anti-virus test file (68 bytes). Harmless; the universal "did detection fire?".
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
];

/// True if `hash` is in the embedded known-bad set.
fn known_bad(hash: &[u8; 32]) -> bool {
    KNOWN_BAD_HEX.iter().any(|h| hex32(h).as_ref() == Some(hash))
}

/// Parse a 64-char hex string into 32 bytes (`None` if malformed).
fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// The per-flow body plan, set once the response headers are parsed.
struct BodyPlan {
    content_len: u64,
    hasher: Option<Sha256Stream>,
    hashed: u64,
}

/// One in-flight response carve, keyed by `(server, server_port, client, client_port)`.
struct CarveState {
    server: IpAddr,
    client: IpAddr,
    /// TCP sequence number of the first response byte (the `H` of `HTTP/`).
    start_seq: u32,
    /// Stream bytes consumed in order so far (headers + body).
    consumed: u64,
    /// Response header bytes accumulated until the CRLFCRLF terminator (then freed).
    head: Vec<u8>,
    /// `None` until the headers are parsed; `Some` once the body length is known.
    body: Option<BodyPlan>,
    aborted: bool,
    /// Capture timestamp of the last packet on this flow — drives idle eviction so a stalled
    /// response cannot hold a slot for the whole capture.
    last_ts: i64,
}

impl CarveState {
    fn new(server: IpAddr, client: IpAddr, start_seq: u32, ts: i64) -> CarveState {
        CarveState {
            server,
            client,
            start_seq,
            consumed: 0,
            head: Vec::new(),
            body: None,
            aborted: false,
            last_ts: ts,
        }
    }

    fn done(&self) -> bool {
        self.aborted || self.body.as_ref().is_some_and(|b| b.hasher.is_none())
    }

    /// Place a server payload at its sequence offset and fold the in-order fresh bytes. Returns a
    /// completed [`CarveObservation`] when the declared body length is reached.
    fn feed(&mut self, seq: u32, payload: &[u8]) -> Option<CarveObservation> {
        if self.done() || payload.is_empty() {
            return None;
        }
        // Offset of this segment within the response stream. `wrapping_sub` handles 32-bit seq wrap;
        // a value in the top half of the range is "before start" (a stale/!-pre-head retransmit) and
        // is ignored rather than mistaken for a huge forward jump.
        let delta = seq.wrapping_sub(self.start_seq);
        if delta >= 0x8000_0000 {
            return None;
        }
        let off = u64::from(delta);
        let end = off + payload.len() as u64;
        if off > self.consumed {
            // A gap: we are missing bytes between `consumed` and `off`. Hashing now would be wrong.
            self.aborted = true;
            return None;
        }
        if end <= self.consumed {
            return None; // Pure retransmit — every byte already seen.
        }
        let skip = (self.consumed - off) as usize;
        let fresh = &payload[skip..];
        self.consumed = end;
        self.consume(fresh)
    }

    /// Route in-order fresh bytes: into the header buffer until the CRLFCRLF terminator, then into
    /// the body hasher.
    fn consume(&mut self, bytes: &[u8]) -> Option<CarveObservation> {
        if self.body.is_none() {
            self.head.extend_from_slice(bytes);
            match find_crlfcrlf(&self.head) {
                Some(pos) => {
                    let plan = parse_response_headers(&self.head[..pos]);
                    // Any bytes already past the header terminator are the start of the body.
                    let body_head: Vec<u8> = self.head[pos + 4..].to_vec();
                    self.head = Vec::new();
                    match plan {
                        Some(p) => {
                            self.body = Some(p);
                            self.feed_body(&body_head)
                        }
                        None => {
                            self.aborted = true;
                            None
                        }
                    }
                }
                None => {
                    if self.head.len() > MAX_HEADER {
                        self.aborted = true; // Headers never terminated — not a normal response.
                    }
                    None
                }
            }
        } else {
            self.feed_body(bytes)
        }
    }

    /// Fold body bytes through the streaming hash; finalize + emit once `content_len` is reached.
    fn feed_body(&mut self, bytes: &[u8]) -> Option<CarveObservation> {
        let p = self.body.as_mut()?;
        let hasher = p.hasher.as_mut()?;
        let remaining = p.content_len - p.hashed;
        let take = (bytes.len() as u64).min(remaining) as usize;
        hasher.update(&bytes[..take]);
        p.hashed += take as u64;
        if p.hashed < p.content_len {
            return None;
        }
        // Complete — finalize the hash (consumes the hasher).
        let sha256 = p.hasher.take()?.finalize_bytes();
        Some(CarveObservation {
            client: self.client,
            server: self.server,
            sha256,
            size: p.content_len,
            known_bad: known_bad(&sha256),
        })
    }
}

/// The streaming HTTP file carver. One instance per analysis pass.
pub(crate) struct HttpBodyCarver {
    states: HashMap<(IpAddr, u16, IpAddr, u16), CarveState>,
    observations: Vec<CarveObservation>,
}

impl HttpBodyCarver {
    pub(crate) fn new() -> HttpBodyCarver {
        HttpBodyCarver {
            states: HashMap::new(),
            observations: Vec::new(),
        }
    }

    /// Fold one decoded packet. Cheap on the common path (returns immediately unless this is a TCP
    /// payload that is, or continues, an HTTP response).
    pub(crate) fn observe(&mut self, meta: &PacketMeta, frame: &crate::reader::RawFrame) {
        if meta.transport != Transport::Tcp || meta.payload_len == 0 {
            return;
        }
        let Some((src, sport, dst, dport)) = meta.endpoints() else {
            return;
        };
        let Some(info) = crate::decode::l4_payload(frame) else {
            return;
        };
        let (Some(seq), payload) = (info.seq, info.payload) else {
            return;
        };
        if payload.is_empty() {
            return;
        }
        let key = (src, sport, dst, dport);
        // (Re)start a carve on a response status line (`HTTP/…`, which only a server sends) ONLY
        // when no carve is already in flight for this flow. Finished/aborted carves are removed
        // below, so a *present* state is always in-flight — and a body segment that merely *begins*
        // with `HTTP/` (TCP segmentation is sender-controlled, so this is attacker-steerable, and
        // benign `.http`/WARC downloads hit it too) must NOT clobber the real carve and surface a
        // wrong or missing hash. A request line (`GET …`) lacks the prefix and travels the other
        // way, so its key never collides with a response state.
        if payload.starts_with(b"HTTP/") && !self.states.contains_key(&key) {
            if self.states.len() >= MAX_FLOWS {
                self.evict_stale(meta.ts_ns);
            }
            if self.states.len() < MAX_FLOWS {
                self.states.insert(key, CarveState::new(src, dst, seq, meta.ts_ns));
            }
        }
        let done = if let Some(st) = self.states.get_mut(&key) {
            st.last_ts = meta.ts_ns;
            if let Some(obs) = st.feed(seq, payload) {
                if self.observations.len() < MAX_OBSERVATIONS {
                    self.observations.push(obs);
                }
            }
            st.done()
        } else {
            false
        };
        // Reclaim the slot the instant a carve completes or aborts, so the finite MAX_FLOWS cap
        // reflects only in-flight carves — not the cumulative count of HTTP response flows over the
        // whole capture (which would silently blind the carver after MAX_FLOWS distinct downloads).
        if done {
            self.states.remove(&key);
        }
    }

    /// Under cap pressure, drop the stalest carve if it has been idle past [`IDLE_NS`] — so a burst
    /// of never-completing responses cannot permanently exhaust the table. Leaves genuinely active
    /// carves in place (a new one is then simply not started).
    fn evict_stale(&mut self, now: i64) {
        if let Some((&k, _)) = self
            .states
            .iter()
            .filter(|(_, s)| now.saturating_sub(s.last_ts) > IDLE_NS)
            .min_by_key(|(_, s)| s.last_ts)
        {
            self.states.remove(&k);
        }
    }

    /// Drain the carved-file observations at end of capture.
    pub(crate) fn into_results(self) -> Vec<CarveObservation> {
        self.observations
    }
}

/// Index of the first `\r` of the `\r\n\r\n` header terminator (the caller adds 4 for the body
/// start). `None` if the terminator is not yet present in `buf`.
fn find_crlfcrlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Parse the response head (status line + headers, before the CRLFCRLF) into a [`BodyPlan`], or
/// `None` to abort the carve: not length-delimited, compressed, chunked, empty, or over the size cap.
fn parse_response_headers(head: &[u8]) -> Option<BodyPlan> {
    // A compressed body's hash would not be the file's hash → don't carve it.
    if header_present(head, b"content-encoding:") {
        return None;
    }
    // We only carve length-delimited bodies (chunked is not de-chunked here).
    if header_value_has(head, b"transfer-encoding:", b"chunked") {
        return None;
    }
    let content_len = header_u64(head, b"content-length:")?;
    if content_len == 0 || content_len > MAX_BODY {
        return None;
    }
    Some(BodyPlan {
        content_len,
        hasher: Some(Sha256Stream::new()),
        hashed: 0,
    })
}

/// Case-insensitively find a header line beginning with `name` and return its trimmed value bytes.
fn header_line<'a>(head: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    for line in head.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.len() >= name.len() && line[..name.len()].eq_ignore_ascii_case(name) {
            let val = &line[name.len()..];
            // Trim leading/trailing ASCII whitespace.
            let start = val.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(val.len());
            let endrel = val[start..]
                .iter()
                .rposition(|b| !b.is_ascii_whitespace())
                .map(|p| start + p + 1)
                .unwrap_or(start);
            return Some(&val[start..endrel]);
        }
    }
    None
}

fn header_present(head: &[u8], name: &[u8]) -> bool {
    header_line(head, name).is_some()
}

fn header_value_has(head: &[u8], name: &[u8], needle: &[u8]) -> bool {
    header_line(head, name)
        .map(|v| {
            v.windows(needle.len().max(1))
                .any(|w| w.eq_ignore_ascii_case(needle))
        })
        .unwrap_or(false)
}

fn header_u64(head: &[u8], name: &[u8]) -> Option<u64> {
    let v = header_line(head, name)?;
    // A valid Content-Length is decimal digits only.
    if v.is_empty() || !v.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(v).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::{hex_of, sha256_hex};
    use std::net::Ipv4Addr;

    fn srv() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
    }
    fn cli() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))
    }
    fn state() -> CarveState {
        CarveState::new(srv(), cli(), 1000, 0)
    }

    #[test]
    fn carves_single_packet_body_to_its_hash() {
        let body = b"hello world";
        let mut resp = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n".to_vec();
        resp.extend_from_slice(body);
        let obs = state().feed(1000, &resp).expect("carved");
        assert_eq!(obs.size, 11);
        assert_eq!(hex_of(&obs.sha256), sha256_hex(body));
        assert_eq!(obs.client, cli());
        assert_eq!(obs.server, srv());
        assert!(!obs.known_bad);
    }

    #[test]
    fn flags_the_eicar_test_file_as_known_bad() {
        // The EICAR standard anti-malware test string (68 bytes).
        let eicar = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;
        assert_eq!(eicar.len(), 68);
        let mut resp = b"HTTP/1.1 200 OK\r\nContent-Length: 68\r\n\r\n".to_vec();
        resp.extend_from_slice(eicar);
        let obs = state().feed(1000, &resp).expect("carved");
        assert!(obs.known_bad, "EICAR should match the known-bad set");
    }

    #[test]
    fn reassembles_a_body_split_across_packets() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello ";
        let rest = b"world";
        let mut st = state();
        assert!(st.feed(1000, head).is_none(), "incomplete body must not carve");
        let obs = st.feed(1000 + head.len() as u32, rest).expect("carved on completion");
        assert_eq!(hex_of(&obs.sha256), sha256_hex(b"hello world"));
    }

    #[test]
    fn aborts_on_a_sequence_gap_rather_than_hashing_wrong_bytes() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhel";
        let mut st = state();
        st.feed(1000, head);
        // A 2-byte gap (lost segment): seq jumps past the next expected offset.
        let gapped_seq = 1000 + head.len() as u32 + 2;
        assert!(st.feed(gapped_seq, b"world").is_none());
        assert!(st.aborted);
    }

    #[test]
    fn tolerates_an_overlapping_retransmit() {
        let full = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let mut st = state();
        // First segment is missing the last 2 body bytes...
        assert!(st.feed(1000, &full[..full.len() - 2]).is_none());
        // ...then the whole response is retransmitted (overlap); only the fresh tail is consumed.
        let obs = st.feed(1000, full).expect("carved");
        assert_eq!(hex_of(&obs.sha256), sha256_hex(b"hello"));
    }

    #[test]
    fn does_not_carve_compressed_or_chunked_bodies() {
        let gz = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Encoding: gzip\r\n\r\nhello";
        assert!(state().feed(1000, gz).is_none());
        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        assert!(state().feed(1000, chunked).is_none());
        // A response with no Content-Length is not length-delimited → no carve.
        let nolen = b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nhello";
        assert!(state().feed(1000, nolen).is_none());
    }

    #[test]
    fn feed_never_panics_on_arbitrary_bytes() {
        // Adversarial: garbage seq/payloads must never panic or mis-slice.
        for seed in 0u32..64 {
            let mut st = state();
            let junk: Vec<u8> = (0..seed).map(|i| (i.wrapping_mul(31)) as u8).collect();
            let _ = st.feed(seed.wrapping_mul(7), &junk);
            let _ = st.feed(seed, &junk);
            let _ = st.feed(0, &[]);
        }
    }

    // --- observe()-level regressions (the two adversarial-review findings) ---

    fn srv4() -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::new(203, 0, 113, 9)
    }
    fn cli4() -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::new(10, 0, 0, 5)
    }

    /// Build an Ethernet/IPv4/TCP frame with an explicit sequence number (the gen builder uses a
    /// fixed seq, so we patch it; decode does not validate the L4 checksum).
    fn seg(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr, sp: u16, dp: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        use crate::gen::frames::{
            build_ethernet, build_ipv4, build_tcp, ETHERTYPE_IPV4, IP_PROTO_TCP, TCP_ACK, TCP_PSH,
        };
        let mut tcp = build_tcp(src, dst, sp, dp, TCP_PSH | TCP_ACK, payload);
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        let ip = build_ipv4(src, dst, IP_PROTO_TCP, 64, tcp.len());
        let mut eth = build_ethernet([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2], ETHERTYPE_IPV4);
        eth.extend_from_slice(&ip);
        eth.extend_from_slice(&tcp);
        eth
    }

    fn raw(buf: &[u8], ts_ns: i64, index: u64) -> crate::reader::RawFrame<'_> {
        crate::reader::RawFrame {
            index,
            ts_ns,
            iface_id: 0,
            wire_len: buf.len() as u32,
            cap_len: buf.len() as u32,
            link_type: crate::reader::LinkType::Ethernet,
            data: buf,
        }
    }

    fn feed_frame(carver: &mut HttpBodyCarver, buf: &[u8], ts: i64, idx: u64) {
        let fr = raw(buf, ts, idx);
        let meta = crate::decode::decode_frame(&fr).expect("decode synthetic frame");
        carver.observe(&meta, &fr);
    }

    #[test]
    fn http_prefix_inside_a_body_segment_does_not_clobber_the_inflight_carve() {
        // The real downloaded file's body itself contains a nested "HTTP/…" response, and the TCP
        // segmentation places that "HTTP/" at the start of segment 2 (sender-controlled). The real
        // file's hash must be emitted — NOT the 2-byte interior "XY".
        let mut real_body = vec![b'A'; 30];
        real_body.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nXY");
        let clen = real_body.len();
        let mut resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {clen}\r\n\r\n").into_bytes();
        let split = resp.len() + 30; // exactly at the interior "HTTP/"
        resp.extend_from_slice(&real_body);

        let f1 = seg(srv4(), cli4(), 80, 49152, 1000, &resp[..split]);
        let f2 = seg(srv4(), cli4(), 80, 49152, 1000 + split as u32, &resp[split..]);

        let mut carver = HttpBodyCarver::new();
        feed_frame(&mut carver, &f1, 1, 0);
        feed_frame(&mut carver, &f2, 2, 1);
        let obs = carver.into_results();

        assert_eq!(obs.len(), 1, "one carve (the real file), not the interior nested response");
        assert_eq!(obs[0].size, clen as u64);
        assert_eq!(hex_of(&obs[0].sha256), sha256_hex(&real_body));
        assert!(obs.iter().all(|o| o.size != 2), "the interior 'XY' must not be carved");
    }

    #[test]
    fn reclaims_the_flow_slot_once_a_download_completes() {
        // A finite MAX_FLOWS cap must reflect only in-flight carves: a completed download's slot is
        // reclaimed immediately, so the cap is not exhausted by the cumulative count of downloads.
        let mut resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n".to_vec();
        resp.extend_from_slice(b"hello");
        let f = seg(srv4(), cli4(), 80, 49152, 1000, &resp);

        let mut carver = HttpBodyCarver::new();
        feed_frame(&mut carver, &f, 1, 0);
        assert!(carver.states.is_empty(), "completed carve's slot is reclaimed");
        assert_eq!(carver.observations.len(), 1, "the download was carved");
    }
}
