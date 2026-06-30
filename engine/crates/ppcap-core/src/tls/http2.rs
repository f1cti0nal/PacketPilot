//! HTTP/2 (RFC 7540) framing + HPACK (RFC 7541) header decompression over a decrypted TLS flow.
//!
//! Once key-log decryption reassembles a flow's two cleartext directions, an HTTP/2 connection is
//! a stream of 9-byte-framed messages with HPACK-compressed headers. This decodes just enough to
//! give the same view as the HTTP/1.1 path: per-stream requests (method/path/authority) paired with
//! responses (status/content-type), plus the response bodies (reassembled DATA frames) handed to
//! the file carver. Each direction has its own HPACK dynamic table.
//!
//! Best-effort and bounded — it parses attacker-influenced bytes and must never panic: every slice
//! is checked, every length is `checked_add`-guarded, and the dynamic table + outputs are capped.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::OnceLock;

use super::decrypted_http::HttpTxn;
use crate::carve::StreamCarve;

/// The HTTP/2 client connection preface (RFC 7540 §3.5).
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// Frame types (RFC 7540 §6) we care about; others are skipped.
const FT_DATA: u8 = 0x0;
const FT_HEADERS: u8 = 0x1;
const FT_CONTINUATION: u8 = 0x9;
// Frame flags.
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

/// Cap on transactions / carves surfaced per flow.
const MAX_TXN: usize = 256;
/// Cap on a reassembled HTTP/2 response body (matches the carver's body bound).
const MAX_BODY: usize = 64 * 1024 * 1024;
/// Hard cap on the HPACK dynamic table, regardless of any size-update instruction.
const MAX_DYN: usize = 64 * 1024;
/// Cap on header fields surfaced from one block. Bounds `out`, but NEVER stops parsing — every
/// table-mutating instruction (insert / size-update) past the cap is still applied so the dynamic
/// table stays in lock-step with the encoder for the rest of the connection.
const MAX_HEADERS: usize = 1024;

/// HPACK static table (RFC 7541 Appendix A): index 1..=61 → (name, value).
#[rustfmt::skip]
const STATIC: &[(&str, &str)] = &[
    (":authority", ""), (":method", "GET"), (":method", "POST"), (":path", "/"),
    (":path", "/index.html"), (":scheme", "http"), (":scheme", "https"), (":status", "200"),
    (":status", "204"), (":status", "206"), (":status", "304"), (":status", "400"),
    (":status", "404"), (":status", "500"), ("accept-charset", ""), ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""), ("accept-ranges", ""), ("accept", ""), ("access-control-allow-origin", ""),
    ("age", ""), ("allow", ""), ("authorization", ""), ("cache-control", ""),
    ("content-disposition", ""), ("content-encoding", ""), ("content-language", ""), ("content-length", ""),
    ("content-location", ""), ("content-range", ""), ("content-type", ""), ("cookie", ""),
    ("date", ""), ("etag", ""), ("expect", ""), ("expires", ""),
    ("from", ""), ("host", ""), ("if-match", ""), ("if-modified-since", ""),
    ("if-none-match", ""), ("if-range", ""), ("if-unmodified-since", ""), ("last-modified", ""),
    ("link", ""), ("location", ""), ("max-forwards", ""), ("proxy-authenticate", ""),
    ("proxy-authorization", ""), ("range", ""), ("referer", ""), ("refresh", ""),
    ("retry-after", ""), ("server", ""), ("set-cookie", ""), ("strict-transport-security", ""),
    ("transfer-encoding", ""), ("user-agent", ""), ("vary", ""), ("via", ""), ("www-authenticate", ""),
];

/// HPACK Huffman code table (RFC 7541 Appendix B): `(code, bit-length)` per symbol 0..=255,
/// then EOS at index 256. Generated from the RFC; do not hand-edit.
#[rustfmt::skip]
const HUFFMAN: [(u32, u8); 257] = [
    (0x1ff8,13),(0x7fffd8,23),(0xfffffe2,28),(0xfffffe3,28),(0xfffffe4,28),(0xfffffe5,28),
    (0xfffffe6,28),(0xfffffe7,28),(0xfffffe8,28),(0xffffea,24),(0x3ffffffc,30),(0xfffffe9,28),
    (0xfffffea,28),(0x3ffffffd,30),(0xfffffeb,28),(0xfffffec,28),(0xfffffed,28),(0xfffffee,28),
    (0xfffffef,28),(0xffffff0,28),(0xffffff1,28),(0xffffff2,28),(0x3ffffffe,30),(0xffffff3,28),
    (0xffffff4,28),(0xffffff5,28),(0xffffff6,28),(0xffffff7,28),(0xffffff8,28),(0xffffff9,28),
    (0xffffffa,28),(0xffffffb,28),(0x14,6),(0x3f8,10),(0x3f9,10),(0xffa,12),(0x1ff9,13),(0x15,6),
    (0xf8,8),(0x7fa,11),(0x3fa,10),(0x3fb,10),(0xf9,8),(0x7fb,11),(0xfa,8),(0x16,6),(0x17,6),
    (0x18,6),(0x0,5),(0x1,5),(0x2,5),(0x19,6),(0x1a,6),(0x1b,6),(0x1c,6),(0x1d,6),(0x1e,6),(0x1f,6),
    (0x5c,7),(0xfb,8),(0x7ffc,15),(0x20,6),(0xffb,12),(0x3fc,10),(0x1ffa,13),(0x21,6),(0x5d,7),
    (0x5e,7),(0x5f,7),(0x60,7),(0x61,7),(0x62,7),(0x63,7),(0x64,7),(0x65,7),(0x66,7),(0x67,7),
    (0x68,7),(0x69,7),(0x6a,7),(0x6b,7),(0x6c,7),(0x6d,7),(0x6e,7),(0x6f,7),(0x70,7),(0x71,7),
    (0x72,7),(0xfc,8),(0x73,7),(0xfd,8),(0x1ffb,13),(0x7fff0,19),(0x1ffc,13),(0x3ffc,14),(0x22,6),
    (0x7ffd,15),(0x3,5),(0x23,6),(0x4,5),(0x24,6),(0x5,5),(0x25,6),(0x26,6),(0x27,6),(0x6,5),
    (0x74,7),(0x75,7),(0x28,6),(0x29,6),(0x2a,6),(0x7,5),(0x2b,6),(0x76,7),(0x2c,6),(0x8,5),(0x9,5),
    (0x2d,6),(0x77,7),(0x78,7),(0x79,7),(0x7a,7),(0x7b,7),(0x7ffe,15),(0x7fc,11),(0x3ffd,14),
    (0x1ffd,13),(0xffffffc,28),(0xfffe6,20),(0x3fffd2,22),(0xfffe7,20),(0xfffe8,20),(0x3fffd3,22),
    (0x3fffd4,22),(0x3fffd5,22),(0x7fffd9,23),(0x3fffd6,22),(0x7fffda,23),(0x7fffdb,23),
    (0x7fffdc,23),(0x7fffdd,23),(0x7fffde,23),(0xffffeb,24),(0x7fffdf,23),(0xffffec,24),
    (0xffffed,24),(0x3fffd7,22),(0x7fffe0,23),(0xffffee,24),(0x7fffe1,23),(0x7fffe2,23),
    (0x7fffe3,23),(0x7fffe4,23),(0x1fffdc,21),(0x3fffd8,22),(0x7fffe5,23),(0x3fffd9,22),
    (0x7fffe6,23),(0x7fffe7,23),(0xffffef,24),(0x3fffda,22),(0x1fffdd,21),(0xfffe9,20),
    (0x3fffdb,22),(0x3fffdc,22),(0x7fffe8,23),(0x7fffe9,23),(0x1fffde,21),(0x7fffea,23),
    (0x3fffdd,22),(0x3fffde,22),(0xfffff0,24),(0x1fffdf,21),(0x3fffdf,22),(0x7fffeb,23),
    (0x7fffec,23),(0x1fffe0,21),(0x1fffe1,21),(0x3fffe0,22),(0x1fffe2,21),(0x7fffed,23),
    (0x3fffe1,22),(0x7fffee,23),(0x7fffef,23),(0xfffea,20),(0x3fffe2,22),(0x3fffe3,22),
    (0x3fffe4,22),(0x7ffff0,23),(0x3fffe5,22),(0x3fffe6,22),(0x7ffff1,23),(0x3ffffe0,26),
    (0x3ffffe1,26),(0xfffeb,20),(0x7fff1,19),(0x3fffe7,22),(0x7ffff2,23),(0x3fffe8,22),
    (0x1ffffec,25),(0x3ffffe2,26),(0x3ffffe3,26),(0x3ffffe4,26),(0x7ffffde,27),(0x7ffffdf,27),
    (0x3ffffe5,26),(0xfffff1,24),(0x1ffffed,25),(0x7fff2,19),(0x1fffe3,21),(0x3ffffe6,26),
    (0x7ffffe0,27),(0x7ffffe1,27),(0x3ffffe7,26),(0x7ffffe2,27),(0xfffff2,24),(0x1fffe4,21),
    (0x1fffe5,21),(0x3ffffe8,26),(0x3ffffe9,26),(0xffffffd,28),(0x7ffffe3,27),(0x7ffffe4,27),
    (0x7ffffe5,27),(0xfffec,20),(0xfffff3,24),(0xfffed,20),(0x1fffe6,21),(0x3fffe9,22),
    (0x1fffe7,21),(0x1fffe8,21),(0x7ffff3,23),(0x3fffea,22),(0x3fffeb,22),(0x1ffffee,25),
    (0x1ffffef,25),(0xfffff4,24),(0xfffff5,24),(0x3ffffea,26),(0x7ffff4,23),(0x3ffffeb,26),
    (0x7ffffe6,27),(0x3ffffec,26),(0x3ffffed,26),(0x7ffffe7,27),(0x7ffffe8,27),(0x7ffffe9,27),
    (0x7ffffea,27),(0x7ffffeb,27),(0xffffffe,28),(0x7ffffec,27),(0x7ffffed,27),(0x7ffffee,27),
    (0x7ffffef,27),(0x7fffff0,27),(0x3ffffee,26),(0x3fffffff,30),
];

/// `(bit-length, code) → symbol`, built once from [`HUFFMAN`]. HPACK codes are prefix-free, so the
/// first `(nbits, acc)` match while walking bits is unambiguous.
fn huffman_map() -> &'static HashMap<(u8, u32), u16> {
    static MAP: OnceLock<HashMap<(u8, u32), u16>> = OnceLock::new();
    MAP.get_or_init(|| {
        HUFFMAN
            .iter()
            .enumerate()
            .map(|(sym, &(code, len))| ((len, code), sym as u16))
            .collect()
    })
}

/// Decode an HPACK Huffman string (RFC 7541 §5.2). Returns `None` on a malformed encoding — an EOS
/// symbol in the data, an over-length code, or trailing padding that isn't the all-ones EOS prefix
/// (`< 8` bits). Rejecting malformed padding (rather than emitting the decoded prefix) keeps the
/// decode byte-faithful so a crafted non-canonical encoding can't smuggle in extra characters.
fn huffman_decode(raw: &[u8]) -> Option<Vec<u8>> {
    let map = huffman_map();
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut nbits: u8 = 0;
    for &byte in raw {
        for i in (0..8).rev() {
            acc = (acc << 1) | u32::from((byte >> i) & 1);
            nbits += 1;
            if let Some(&sym) = map.get(&(nbits, acc)) {
                if sym >= 256 {
                    return None; // EOS symbol inside the data is invalid
                }
                out.push(sym as u8);
                acc = 0;
                nbits = 0;
            } else if nbits >= 30 {
                return None; // no Huffman code is longer than 30 bits → malformed
            }
        }
    }
    // The trailing bits must be the most-significant bits of the all-ones EOS code: fewer than a
    // full octet, and all ones. Anything else is a malformed encoding.
    if nbits >= 8 || (nbits > 0 && acc != (1u32 << nbits) - 1) {
        return None;
    }
    Some(out)
}

/// Decode an HPACK variable-length integer with an `n`-bit prefix (RFC 7541 §5.1). Advances `pos`;
/// returns `None` on truncation or overflow.
fn decode_int(data: &[u8], pos: &mut usize, n: u32) -> Option<u64> {
    let mask = (1u64 << n) - 1;
    let first = u64::from(*data.get(*pos)?);
    *pos += 1;
    let mut value = first & mask;
    if value < mask {
        return Some(value);
    }
    let mut shift = 0u32;
    loop {
        let b = u64::from(*data.get(*pos)?);
        *pos += 1;
        value = value.checked_add((b & 0x7f).checked_shl(shift)?)?;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    Some(value)
}

/// Decode an HPACK string literal (RFC 7541 §5.2): a length-prefixed octet sequence, optionally
/// Huffman-coded. Advances `pos`; returns `None` on truncation or a malformed Huffman payload.
fn decode_string(data: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let huffman = (*data.get(*pos)? & 0x80) != 0;
    let len = decode_int(data, pos, 7)?;
    // Compare in u64 BEFORE narrowing to usize: on wasm32 (usize = 32-bit) a `len as usize` cast
    // would truncate an over-long declared length so the slice spuriously succeeds, decoding bytes
    // native (64-bit) rejects. Bounding against the remaining buffer first makes both targets agree.
    let avail = (data.len() - *pos) as u64;
    if len > avail {
        return None;
    }
    let len = len as usize;
    let end = *pos + len;
    let raw = &data[*pos..end];
    *pos = end;
    if huffman {
        huffman_decode(raw)
    } else {
        Some(raw.to_vec())
    }
}

type Header = (Vec<u8>, Vec<u8>);

/// One direction's HPACK decoder state (RFC 7541 §2.3).
struct Hpack {
    dynamic: VecDeque<Header>, // most-recently-added at the front
    size: usize,
    max_size: usize,
}

impl Hpack {
    fn new() -> Hpack {
        Hpack {
            dynamic: VecDeque::new(),
            size: 0,
            max_size: 4096, // HPACK default until a size update / SETTINGS says otherwise
        }
    }

    /// Resolve a table index (1-based): static for `1..=61`, then the dynamic table front-first.
    /// The index stays `u64` until it is known in range, so an out-of-range index can't truncate
    /// (on wasm32's 32-bit `usize`) into a valid slot and fabricate a header.
    fn lookup(&self, idx: u64) -> Option<Header> {
        if idx == 0 {
            return None;
        }
        let static_len = STATIC.len() as u64;
        if idx <= static_len {
            let (n, v) = STATIC[(idx - 1) as usize]; // idx ≤ 61, cast is exact
            return Some((n.as_bytes().to_vec(), v.as_bytes().to_vec()));
        }
        let dyn_idx = idx - static_len - 1;
        if dyn_idx >= self.dynamic.len() as u64 {
            return None;
        }
        self.dynamic.get(dyn_idx as usize).cloned() // dyn_idx < len ≤ usize, cast is exact
    }

    fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) {
        self.size += name.len() + value.len() + 32;
        self.dynamic.push_front((name, value));
        self.evict();
    }

    fn set_max(&mut self, m: usize) {
        self.max_size = m.min(MAX_DYN);
        self.evict();
    }

    fn evict(&mut self) {
        while self.size > self.max_size {
            match self.dynamic.pop_back() {
                Some((n, v)) => self.size = self.size.saturating_sub(n.len() + v.len() + 32),
                None => {
                    self.size = 0;
                    break;
                }
            }
        }
    }

    /// Decode a complete header block into `out` (RFC 7541 §6). Stops on any malformed octet. The
    /// `MAX_HEADERS` cap bounds `out` but not parsing: inserts keep flowing so the dynamic table
    /// can't desync if an (adversarially) oversized block runs past the cap.
    fn decode_block(&mut self, block: &[u8], out: &mut Vec<Header>) {
        let mut pos = 0;
        while pos < block.len() {
            let b = block[pos];
            if b & 0x80 != 0 {
                // Indexed header field.
                match decode_int(block, &mut pos, 7) {
                    Some(idx) => {
                        if let Some(h) = self.lookup(idx) {
                            emit(out, h);
                        }
                    }
                    None => return,
                }
            } else if b & 0x40 != 0 {
                // Literal with incremental indexing (adds to the dynamic table).
                if !self.literal(block, &mut pos, 6, true, out) {
                    return;
                }
            } else if b & 0x20 != 0 {
                // Dynamic table size update.
                match decode_int(block, &mut pos, 5) {
                    Some(m) => self.set_max(m as usize),
                    None => return,
                }
            } else {
                // Literal without indexing / never indexed (both decode the same).
                if !self.literal(block, &mut pos, 4, false, out) {
                    return;
                }
            }
        }
    }

    fn literal(
        &mut self,
        block: &[u8],
        pos: &mut usize,
        prefix: u32,
        index_it: bool,
        out: &mut Vec<Header>,
    ) -> bool {
        let idx = match decode_int(block, pos, prefix) {
            Some(i) => i,
            None => return false,
        };
        let name = if idx == 0 {
            match decode_string(block, pos) {
                Some(s) => s,
                None => return false,
            }
        } else {
            match self.lookup(idx) {
                Some((n, _)) => n,
                None => return false,
            }
        };
        let value = match decode_string(block, pos) {
            Some(s) => s,
            None => return false,
        };
        // Apply the table side effect FIRST so it survives even when the output is capped.
        if index_it {
            self.insert(name.clone(), value.clone());
        }
        emit(out, (name, value));
        true
    }
}

/// Push a header unless the per-block output cap is reached (the dynamic table is updated
/// separately, so capping output never desyncs it).
fn emit(out: &mut Vec<Header>, h: Header) {
    if out.len() < MAX_HEADERS {
        out.push(h);
    }
}

/// Strip a HEADERS frame's padding + priority prefix, returning the header-block fragment.
fn headers_fragment(payload: &[u8], flags: u8) -> &[u8] {
    let mut p = payload;
    let mut pad = 0usize;
    if flags & FLAG_PADDED != 0 {
        match p.split_first() {
            Some((&pl, rest)) => {
                pad = pl as usize;
                p = rest;
            }
            None => return &[],
        }
    }
    if flags & FLAG_PRIORITY != 0 {
        if p.len() < 5 {
            return &[];
        }
        p = &p[5..];
    }
    if pad <= p.len() {
        &p[..p.len() - pad]
    } else {
        &[]
    }
}

/// Strip a DATA frame's padding, returning the body bytes.
fn data_payload(payload: &[u8], flags: u8) -> &[u8] {
    if flags & FLAG_PADDED == 0 {
        return payload;
    }
    match payload.split_first() {
        Some((&pad, rest)) if (pad as usize) <= rest.len() => &rest[..rest.len() - pad as usize],
        _ => &[],
    }
}

/// Decode a buffered (possibly incomplete) header block and record it. Called both on END_HEADERS
/// and when another frame interrupts an open block, so an interrupted stream still surfaces rather
/// than being silently dropped. Decoding feeds the shared HPACK table, keeping it in wire order.
fn flush_pending(
    pending: &mut Option<(u32, Vec<u8>)>,
    hpack: &mut Hpack,
    headers: &mut BTreeMap<u32, Vec<Header>>,
) {
    if let Some((sid, buf)) = pending.take() {
        let mut hdrs = Vec::new();
        hpack.decode_block(&buf, &mut hdrs);
        record_block(headers, sid, hdrs);
    }
}

/// Record a stream's decoded header block, preferring the FINAL response over interim ones: an
/// existing 1xx block (RFC 8297 Early Hints / 100-continue) is replaced by the first non-1xx block
/// so the surfaced status/content-type are the real response, not the placeholder. A request's
/// single HEADERS (or an already-final response) is never overwritten by later trailers.
fn record_block(headers: &mut BTreeMap<u32, Vec<Header>>, sid: u32, hdrs: Vec<Header>) {
    match headers.get_mut(&sid) {
        None => {
            headers.insert(sid, hdrs);
        }
        Some(existing) => {
            if is_interim(existing) && !is_interim(&hdrs) {
                *existing = hdrs;
            }
        }
    }
}

/// Whether a decoded block is an interim (1xx informational) response.
fn is_interim(hdrs: &[Header]) -> bool {
    status_code(hdrs).is_some_and(|s| (100..200).contains(&s))
}

/// The `:status` pseudo-header as a number, if present and parseable.
fn status_code(hdrs: &[Header]) -> Option<u16> {
    for (n, v) in hdrs {
        if n.as_slice() == b":status" {
            return std::str::from_utf8(v).ok()?.parse().ok();
        }
    }
    None
}

/// Walk one direction's HTTP/2 frames: decode each stream's header block and reassemble its DATA
/// bodies. The connection preface, if present, is skipped.
fn decode_frames(stream: &[u8]) -> (BTreeMap<u32, Vec<Header>>, BTreeMap<u32, Vec<u8>>) {
    let mut headers: BTreeMap<u32, Vec<Header>> = BTreeMap::new();
    let mut bodies: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut hpack = Hpack::new();
    let mut pending: Option<(u32, Vec<u8>)> = None; // a HEADERS block awaiting END_HEADERS

    let mut pos = if stream.starts_with(PREFACE) {
        PREFACE.len()
    } else {
        0
    };

    while pos + 9 <= stream.len() {
        let len = ((stream[pos] as usize) << 16)
            | ((stream[pos + 1] as usize) << 8)
            | stream[pos + 2] as usize;
        let ftype = stream[pos + 3];
        let flags = stream[pos + 4];
        let stream_id = u32::from_be_bytes([
            stream[pos + 5] & 0x7f,
            stream[pos + 6],
            stream[pos + 7],
            stream[pos + 8],
        ]);
        let body_start = pos + 9;
        let body_end = match body_start.checked_add(len) {
            Some(e) if e <= stream.len() => e,
            _ => break, // truncated frame
        };
        let payload = &stream[body_start..body_end];
        pos = body_end;

        // A header block MUST continue with CONTINUATION on the same stream (RFC 7540 §6.10). Any
        // other frame breaks it — decode what we have first, so an interrupted stream isn't lost
        // and a later HEADERS can't clobber `pending` (which would drop a whole request/response).
        let continues =
            ftype == FT_CONTINUATION && pending.as_ref().is_some_and(|(sid, _)| *sid == stream_id);
        if !continues {
            flush_pending(&mut pending, &mut hpack, &mut headers);
        }

        match ftype {
            FT_HEADERS => {
                let frag = headers_fragment(payload, flags);
                if flags & FLAG_END_HEADERS != 0 {
                    let mut hdrs = Vec::new();
                    hpack.decode_block(frag, &mut hdrs);
                    record_block(&mut headers, stream_id, hdrs);
                } else {
                    pending = Some((stream_id, frag.to_vec()));
                }
            }
            FT_CONTINUATION => {
                // Only reached when it continues the pending stream; otherwise it was flushed and
                // this orphan fragment is dropped.
                if let Some((_, buf)) = pending.as_mut() {
                    buf.extend_from_slice(payload);
                    if flags & FLAG_END_HEADERS != 0 {
                        flush_pending(&mut pending, &mut hpack, &mut headers);
                    }
                }
            }
            FT_DATA => {
                let body = data_payload(payload, flags);
                let e = bodies.entry(stream_id).or_default();
                let room = MAX_BODY.saturating_sub(e.len());
                if room > 0 {
                    e.extend_from_slice(&body[..body.len().min(room)]);
                }
            }
            _ => {} // SETTINGS / WINDOW_UPDATE / PING / GOAWAY / RST_STREAM / PRIORITY / PUSH_PROMISE
        }
    }
    // A dangling block whose END_HEADERS never arrived still surfaces its stream.
    flush_pending(&mut pending, &mut hpack, &mut headers);
    (headers, bodies)
}

/// The value of header `name` in a decoded list (case-insensitive), or empty.
fn header_value(hdrs: Option<&Vec<Header>>, name: &[u8]) -> String {
    hdrs.and_then(|h| {
        h.iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
    })
    .unwrap_or_default()
}

/// Parse the HTTP/2 transactions + carve the response bodies hidden in a decrypted TLS flow.
pub(crate) fn parse_http2(c2s: &[u8], s2c: &[u8]) -> (Vec<HttpTxn>, Vec<StreamCarve>) {
    let (req_hdrs, _) = decode_frames(c2s);
    let (resp_hdrs, bodies) = decode_frames(s2c);

    let stream_ids: BTreeSet<u32> = req_hdrs.keys().chain(resp_hdrs.keys()).copied().collect();
    let mut txns = Vec::new();
    for sid in stream_ids.iter().take(MAX_TXN) {
        let req = req_hdrs.get(sid);
        let resp = resp_hdrs.get(sid);
        let resp_bytes = bodies
            .get(sid)
            .map(|b| b.len() as u64)
            .filter(|&n| n > 0)
            .unwrap_or_else(|| header_value(resp, b"content-length").parse().unwrap_or(0));
        txns.push(HttpTxn {
            method: header_value(req, b":method"),
            target: header_value(req, b":path"),
            host: header_value(req, b":authority"),
            status: header_value(resp, b":status").parse().unwrap_or(0),
            content_type: header_value(resp, b"content-type"),
            resp_bytes,
        });
    }

    let carves: Vec<StreamCarve> = bodies
        .values()
        .filter(|b| !b.is_empty())
        .take(MAX_TXN)
        .map(|b| crate::carve::carve_one(b))
        .collect();

    (txns, carves)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn s(b: &[u8]) -> String {
        String::from_utf8_lossy(b).into_owned()
    }

    /// RFC 7541 C.1.2: 1337 with a 5-bit prefix is `1f 9a 0a`.
    #[test]
    fn hpack_integer_rfc7541_c1_2() {
        let mut pos = 0;
        assert_eq!(decode_int(&[0x1f, 0x9a, 0x0a], &mut pos, 5), Some(1337));
        assert_eq!(pos, 3);
        // A value that fits the prefix.
        let mut p2 = 0;
        assert_eq!(decode_int(&[0x0a], &mut p2, 5), Some(10));
    }

    /// RFC 7541 C.4.1 Huffman value decodes to "www.example.com" (valid all-ones trailing padding).
    #[test]
    fn hpack_huffman_rfc7541_c4_1() {
        let raw = hex("f1e3c2e5f23a6ba0ab90f4ff");
        assert_eq!(s(&huffman_decode(&raw).unwrap()), "www.example.com");
    }

    /// Huffman padding validation (review finding): a trailing pad bit that isn't the all-ones EOS
    /// prefix is malformed and rejected, so a non-canonical encoding can't smuggle an extra char.
    /// `00 00` would otherwise decode to "000"; canonical "00" is `00 3f`.
    #[test]
    fn hpack_huffman_rejects_bad_padding() {
        assert_eq!(huffman_decode(&[0x00, 0x00]), None); // trailing 0 bit ≠ all-ones EOS prefix
        assert_eq!(s(&huffman_decode(&[0x00, 0x3f]).unwrap()), "00"); // canonical, accepted
    }

    /// RFC 7541 C.3.1: first request (no Huffman), exercising indexed + literal-incremental and the
    /// dynamic-table insert.
    #[test]
    fn hpack_request_rfc7541_c3_1() {
        let block = hex("828684410f7777772e6578616d706c652e636f6d");
        let mut h = Hpack::new();
        let mut out = Vec::new();
        h.decode_block(&block, &mut out);
        let got: Vec<(String, String)> = out.iter().map(|(n, v)| (s(n), s(v))).collect();
        assert_eq!(
            got,
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "http".into()),
                (":path".into(), "/".into()),
                (":authority".into(), "www.example.com".into()),
            ]
        );
        // :authority was added to the dynamic table (size 57 = 10 + 15 + 32).
        assert_eq!(h.size, 57);
    }

    /// RFC 7541 C.6.1: first response with Huffman (literal-indexed-name + Huffman values).
    #[test]
    fn hpack_response_rfc7541_c6_1() {
        let block = hex("488264025885aec3771a4b6196d07abe9410\
             54d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3");
        let mut h = Hpack::new();
        let mut out = Vec::new();
        h.decode_block(&block, &mut out);
        let got: Vec<(String, String)> = out.iter().map(|(n, v)| (s(n), s(v))).collect();
        assert_eq!(
            got,
            vec![
                (":status".into(), "302".into()),
                ("cache-control".into(), "private".into()),
                ("date".into(), "Mon, 21 Oct 2013 20:13:21 GMT".into()),
                ("location".into(), "https://www.example.com".into()),
            ]
        );
    }

    // ── frame parsing + end-to-end ───────────────────────────────────────────────

    /// Build a 9-byte-framed HTTP/2 frame.
    fn frame(ftype: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, ftype, flags];
        f.extend_from_slice(&sid.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn parses_http2_request_response_and_carves_the_body() {
        // Request on stream 1: GET / with :authority (C.3.1 block).
        let req_block = hex("828684410f7777772e6578616d706c652e636f6d");
        let mut c2s = PREFACE.to_vec();
        c2s.extend_from_slice(&frame(FT_HEADERS, FLAG_END_HEADERS, 1, &req_block));

        // Response on stream 1: a literal :status 200 (idx 8 indexed = 0x88) + content-type, then a
        // DATA frame carrying a PE with a UPX marker.
        // 0x88 = indexed :status 200; 0x5f = literal-incremental, name idx 31 (content-type), value.
        let mut resp_block = vec![0x88, 0x5f];
        let ct = b"application/octet-stream";
        resp_block.push(ct.len() as u8); // value length, not huffman
        resp_block.extend_from_slice(ct);
        let body = b"MZ\x90\x00 UPX! packed http2 payload";
        let mut s2c = frame(FT_HEADERS, FLAG_END_HEADERS, 1, &resp_block);
        s2c.extend_from_slice(&frame(FT_DATA, 0x1 /*END_STREAM*/, 1, body));

        let (txns, carves) = parse_http2(&c2s, &s2c);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].method, "GET");
        assert_eq!(txns[0].target, "/");
        assert_eq!(txns[0].host, "www.example.com");
        assert_eq!(txns[0].status, 200);
        assert_eq!(txns[0].content_type, "application/octet-stream");
        assert_eq!(txns[0].resp_bytes, body.len() as u64);

        assert_eq!(carves.len(), 1);
        assert!(carves[0]
            .signatures
            .iter()
            .any(|s| s.label == "PE/DOS executable"));
        assert!(carves[0]
            .signatures
            .iter()
            .any(|s| s.label == "UPX-packed executable"));
    }

    /// Review finding: an interleaved second HEADERS-without-END_HEADERS must NOT clobber the first
    /// stream's pending block. Both streams' requests must surface.
    #[test]
    fn interleaved_headers_does_not_drop_a_stream() {
        // Self-contained blocks: 0x82 = :method GET, 0x44 = literal-incremental name idx 4 (:path).
        let s1 = hex("8244022f61"); // :method GET, :path literal "/a"
        let s3 = hex("8244022f62"); // :method GET, :path literal "/b"
        let mut c2s = PREFACE.to_vec();
        c2s.extend_from_slice(&frame(FT_HEADERS, 0 /*no END_HEADERS*/, 1, &s1));
        c2s.extend_from_slice(&frame(FT_HEADERS, FLAG_END_HEADERS, 3, &s3));
        // Its CONTINUATION arrives late (orphaned) — must not crash or resurrect mis-streamed bytes.
        c2s.extend_from_slice(&frame(FT_CONTINUATION, FLAG_END_HEADERS, 1, &[]));

        let (txns, _) = parse_http2(&c2s, &[]);
        let targets: Vec<&str> = txns.iter().map(|t| t.target.as_str()).collect();
        assert!(
            targets.contains(&"/a"),
            "stream 1 must not be dropped: {targets:?}"
        );
        assert!(
            targets.contains(&"/b"),
            "stream 3 must surface: {targets:?}"
        );
    }

    /// Review finding: an out-of-range HPACK index must resolve to nothing on EVERY target — the
    /// u64→usize narrowing must not alias a >2^32 index onto a valid slot (wasm32 divergence).
    #[test]
    fn out_of_range_index_resolves_to_none() {
        let mut h = Hpack::new();
        h.insert(b":method".to_vec(), b"Z".to_vec()); // dynamic slot 0 (index 62)
                                                      // `ff bf ff ff ff 0f` = indexed field, 7-bit-prefix integer 4294967358 (low 32 bits = 62).
        let mut out = Vec::new();
        h.decode_block(&hex("ffbfffffff0f"), &mut out);
        assert!(
            out.is_empty(),
            "huge index must be dropped, not aliased to slot 0: {out:?}"
        );
        // The well-formed index 62 still resolves to the real entry.
        let mut out2 = Vec::new();
        h.decode_block(&[0xbe], &mut out2);
        assert_eq!(out2, vec![(b":method".to_vec(), b"Z".to_vec())]);
    }

    /// Review finding: an over-long declared string length is rejected on every target (the u64
    /// comparison must happen before the usize narrowing).
    #[test]
    fn over_long_string_length_is_rejected() {
        // Literal-without-indexing, name idx 1, value declared length 2^32+3 with only 3 bytes.
        let block = hex("017f84ffffff0f414243");
        let mut h = Hpack::new();
        let mut out = Vec::new();
        h.decode_block(&block, &mut out);
        assert!(
            out.is_empty(),
            "over-long literal must be rejected: {out:?}"
        );
    }

    /// Review finding: the output cap bounds `out` but must NOT skip dynamic-table inserts — an
    /// oversized block followed by an indexed reference must stay in sync with the encoder.
    #[test]
    fn output_cap_does_not_desync_dynamic_table() {
        // A block of 1100 literal-incremental fields (name "k", value = a unique 2-byte number),
        // exceeding MAX_HEADERS (1024). Then index 62 must resolve to the LAST inserted entry.
        let mut block = Vec::new();
        for i in 0u16..1100 {
            block.extend_from_slice(&[0x40, 0x01, b'k', 0x02]); // literal-incremental, name "k", 2-byte value
            block.extend_from_slice(&i.to_be_bytes());
        }
        let mut h = Hpack::new();
        let mut out = Vec::new();
        h.decode_block(&block, &mut out);
        assert_eq!(out.len(), MAX_HEADERS, "output is capped");
        // Index 62 = newest dynamic entry = the LAST field inserted (value = 1099), proving all
        // 1100 inserts were applied despite the output cap.
        let mut out2 = Vec::new();
        h.decode_block(&[0xbe], &mut out2);
        assert_eq!(out2, vec![(b"k".to_vec(), 1099u16.to_be_bytes().to_vec())]);
    }

    /// Review finding: an interim (1xx) response must not mask the final response — status and
    /// content-type come from the final ≥200 block, not the Early-Hints placeholder.
    #[test]
    fn interim_1xx_response_does_not_mask_the_final() {
        let req = hex("828684410f7777772e6578616d706c652e636f6d"); // GET / (C.3.1)
        let mut c2s = PREFACE.to_vec();
        c2s.extend_from_slice(&frame(FT_HEADERS, FLAG_END_HEADERS, 1, &req));
        // s2c: 103 Early Hints (literal :status "103"), then the final 200 + content-type.
        let mut s2c = frame(FT_HEADERS, FLAG_END_HEADERS, 1, &hex("0803313033")); // :status 103
        s2c.extend_from_slice(&frame(
            FT_HEADERS,
            FLAG_END_HEADERS,
            1,
            &hex("885f09746578742f68746d6c"),
        )); // :status 200, content-type text/html
        s2c.extend_from_slice(&frame(FT_DATA, 0x1, 1, b"<html></html>"));

        let (txns, _) = parse_http2(&c2s, &s2c);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].status, 200, "final status, not the 103 interim");
        assert_eq!(txns[0].content_type, "text/html");
    }

    #[test]
    fn never_panics_on_arbitrary_frames() {
        for seed in 0u16..256 {
            let junk: Vec<u8> = (0..seed).map(|i| (i.wrapping_mul(41)) as u8).collect();
            let _ = parse_http2(&junk, &junk);
            let _ = huffman_decode(&junk);
            let mut p = 0;
            let _ = decode_int(&junk, &mut p, 5);
        }
    }

    /// Deterministic structured fuzzer: builds many randomized HTTP/2 frame streams (well-formed
    /// 9-byte framing with hostile payloads, interleaved HEADERS/CONTINUATION/DATA across colliding
    /// stream ids, optional preface, then a random truncation) plus raw-byte HPACK blocks and
    /// Huffman strings, and runs the whole decoder on each. Debug builds enable overflow checks, so
    /// any panic, overflow, or non-termination aborts the test. This is the dynamic counterpart to
    /// the per-line panic-safety audit.
    #[test]
    fn fuzz_never_panics_structured() {
        struct Rng(u32);
        impl Rng {
            fn next_u32(&mut self) -> u32 {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                self.0 = x;
                x
            }
            fn byte(&mut self) -> u8 {
                (self.next_u32() & 0xff) as u8
            }
            fn below(&mut self, n: u32) -> u32 {
                self.next_u32() % n.max(1)
            }
        }

        // Bias frame types toward the ones with real logic; keep stream ids in a small set so
        // pairing, collisions, and CONTINUATION mis-streaming get exercised.
        let types = [
            FT_DATA,
            FT_HEADERS,
            FT_CONTINUATION,
            0x4, /*SETTINGS*/
            0x5, /*PUSH_PROMISE*/
        ];

        for seed in 1u32..6000 {
            let mut r = Rng(seed.wrapping_mul(2_654_435_761).max(1));

            let build = |r: &mut Rng| -> Vec<u8> {
                let mut s = Vec::new();
                if r.below(2) == 0 {
                    s.extend_from_slice(PREFACE);
                }
                let frames = r.below(10);
                for _ in 0..frames {
                    let ftype = types[r.below(types.len() as u32) as usize];
                    let flags = r.byte(); // exercises every flag combo incl. PADDED/PRIORITY/END_*
                    let sid = r.below(4); // collide streams 0..3
                    let plen = r.below(40) as usize;
                    let payload: Vec<u8> = (0..plen).map(|_| r.byte()).collect();
                    s.push((plen >> 16) as u8);
                    s.push((plen >> 8) as u8);
                    s.push(plen as u8);
                    s.push(ftype);
                    s.push(flags);
                    s.extend_from_slice(&(sid as u32).to_be_bytes());
                    s.extend_from_slice(&payload);
                }
                // Random truncation to hit the mid-frame `break` paths.
                let cut = r.below((s.len() as u32).max(1)) as usize;
                if r.below(3) == 0 {
                    s.truncate(cut);
                }
                s
            };

            let c2s = build(&mut r);
            let s2c = build(&mut r);
            let _ = parse_http2(&c2s, &s2c);

            // Raw HPACK block + Huffman + integer decoders directly on hostile bytes.
            let block: Vec<u8> = (0..r.below(64)).map(|_| r.byte()).collect();
            let mut h = Hpack::new();
            let mut out = Vec::new();
            h.decode_block(&block, &mut out);
            let _ = huffman_decode(&block);
            let mut pos = 0;
            let _ = decode_int(&block, &mut pos, 1 + r.below(7));
        }
    }
}
