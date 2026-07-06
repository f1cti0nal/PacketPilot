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
//!   regardless of file size (only the small header prefix is held, transiently). Chunked framing and
//!   gzip/deflate decompression are likewise *streamed* (a chunk state machine + a push-based
//!   inflater feeding the hash sink), so this holds even for compressed/chunked downloads.
//! - **In-order only** — bytes are placed by their TCP sequence number; a *gap* (missing segment)
//!   aborts the carve (no wrong hash is ever produced), a pure retransmit is skipped, and a partial
//!   overlap consumes only the fresh tail. Out-of-order / lossy captures simply yield no carve.
//! - **Decoded before hashing** — the body is de-framed (Content-Length or `Transfer-Encoding:
//!   chunked`) and content-decoded (`Content-Encoding: gzip`/`deflate`) on the fly, so the hash is
//!   the *file's* hash and content signatures match the real bytes even when it was delivered
//!   chunked or compressed. Malformed framing/compression aborts the carve (never a wrong hash).
//! - **Bounded** — capped tracked flows, a maximum carved size, and a bounded chunk-line buffer.

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

/// Finding severity tier a suspicious signature contributes (file-type tags use `None`).
/// Declared Medium-before-High so the derived ordering makes `High` the maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SigTier {
    /// Dual-use marker (e.g. a UPX packer, a PowerShell `-EncodedCommand`) — surfaced cautiously.
    Medium,
    /// Specific, low-false-positive malware/tooling marker — alarming.
    High,
}

/// A content signature matched against a carved file's bytes. File-type magic tags the real file
/// type for triage; a suspicious marker can raise a finding. To keep false positives low, a
/// binary-only marker (`exec_gated`) only counts toward a finding when the file is *also* an
/// executable — so the string "meterpreter" inside a benign PDF or source archive does not alarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SigHit {
    pub label: &'static str,
    /// MITRE technique id for a suspicious hit, else `""`.
    pub technique: &'static str,
    pub suspicious: bool,
    /// Only counts toward a finding when the file matched an executable file-type magic.
    pub exec_gated: bool,
    /// Finding severity tier when it fires; `None` for a file-type tag.
    pub tier: Option<SigTier>,
    /// This is executable file-type magic (PE/ELF/Mach-O) — satisfies another hit's `exec_gated`.
    pub executable: bool,
}

/// One carved file: the downloading client, the serving host, the body's SHA-256, its size,
/// whether the hash matched the embedded known-bad set, and any content signatures it matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CarveObservation {
    pub client: IpAddr,
    pub server: IpAddr,
    pub sha256: [u8; 32],
    pub size: u64,
    pub known_bad: bool,
    /// Content signatures the body matched, streamed alongside the hash (no bytes retained).
    pub signatures: Vec<SigHit>,
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
    KNOWN_BAD_HEX
        .iter()
        .any(|h| hex32(h).as_ref() == Some(hash))
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

// ---------------------------------------------------------------------------------------------
// Streaming content signatures
// ---------------------------------------------------------------------------------------------
//
// A curated, native-Rust signature set run over the carved body *as it streams* — the in-engine
// alternative to a YARA dependency (which is not viable on the C-compiler-free wasm toolchain). The
// scanner holds only a bounded rolling window (`OVERLAP` bytes) to catch matches that straddle a
// chunk boundary, plus a short prefix for offset-0 magic — so it keeps the carver's O(1)-per-flow,
// no-body-retention invariant. File-type magic (anchored at offset 0) tags the file's real type;
// suspicious markers (anywhere) flag packers / encoded scripts / known tooling and raise a finding.

/// Where a signature must appear in the body.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Anchor {
    /// Only at byte 0 — file-type magic.
    Start,
    /// Anywhere in the body — content markers.
    Anywhere,
}

/// One curated signature.
struct Sig {
    label: &'static str,
    /// MITRE technique id for a suspicious signature; `""` for a benign file-type tag.
    technique: &'static str,
    suspicious: bool,
    /// Only counts toward a finding when the file is also an executable (binary-only markers).
    exec_gated: bool,
    /// Finding severity tier when it fires; `None` for a file-type tag.
    tier: Option<SigTier>,
    /// True for an executable file-type magic (PE/ELF/Mach-O) — satisfies others' `exec_gated`.
    executable: bool,
    anchor: Anchor,
    pattern: &'static [u8],
}

/// A file-type magic signature (offset 0, never a finding by itself).
const fn ft(label: &'static str, executable: bool, pattern: &'static [u8]) -> Sig {
    Sig {
        label,
        technique: "",
        suspicious: false,
        exec_gated: false,
        tier: None,
        executable,
        anchor: Anchor::Start,
        pattern,
    }
}

/// A suspicious content marker (anywhere). `exec_gated` ⇒ only fires when the file is an executable.
const fn susp(
    label: &'static str,
    technique: &'static str,
    exec_gated: bool,
    tier: SigTier,
    pattern: &'static [u8],
) -> Sig {
    Sig {
        label,
        technique,
        suspicious: true,
        exec_gated,
        tier: Some(tier),
        executable: false,
        anchor: Anchor::Anywhere,
        pattern,
    }
}

/// The curated signature table. Deliberately small and high-confidence (low false-positive on
/// benign downloads); a real deployment extends it. Binary-only markers are `exec_gated` and
/// dual-use markers (UPX packing, a PowerShell `-EncodedCommand`) are `Medium`, so a benign
/// download that merely *mentions* a tool — a PDF, a source archive — does not raise a loud alarm.
#[rustfmt::skip]
const SIGNATURES: &[Sig] = &[
    // ── File-type magic (offset 0) — triage context, not a finding ──
    ft("PE/DOS executable",                 true,  b"MZ"),
    ft("ELF executable",                    true,  b"\x7fELF"),
    ft("Mach-O executable",                 true,  b"\xcf\xfa\xed\xfe"),
    ft("Java class file",                   false, b"\xca\xfe\xba\xbe"),
    ft("ZIP/Office archive",                false, b"PK\x03\x04"),
    ft("PDF document",                      false, b"%PDF"),
    ft("gzip archive",                      false, b"\x1f\x8b"),
    ft("7-Zip archive",                     false, b"7z\xbc\xaf\x27\x1c"),
    ft("RAR archive",                       false, b"Rar!\x1a\x07"),
    ft("OLE2 document (legacy Office/MSI)", false, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
    ft("Windows shortcut (.lnk)",           false, b"\x4c\x00\x00\x00\x01\x14\x02\x00"),
    ft("Microsoft Cabinet",                 false, b"MSCF"),
    // ── Suspicious content (anywhere). exec_gated markers only fire on an executable body. ──
    susp("EICAR test signature",          "T1105",     false, SigTier::High,   b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"),
    susp("UPX-packed executable",         "T1027.002", true,  SigTier::Medium, b"UPX!"),
    susp("Mimikatz credential tool",      "T1003",     true,  SigTier::High,   b"sekurlsa::"),
    susp("Meterpreter payload",           "T1059",     true,  SigTier::High,   b"meterpreter"),
    susp("Reflective loader (injection)", "T1055.001", true,  SigTier::High,   b"ReflectiveLoader"),
    susp("PowerShell download cradle",    "T1059.001", false, SigTier::High,   b").DownloadString("),
    susp("PowerShell encoded command",    "T1027",     false, SigTier::Medium, b"-EncodedCommand"),
];

/// Longest signature pattern (compile-time), bounding the prefix + cross-chunk overlap window.
const MAX_SIG_LEN: usize = {
    let mut m = 0;
    let mut i = 0;
    while i < SIGNATURES.len() {
        if SIGNATURES[i].pattern.len() > m {
            m = SIGNATURES[i].pattern.len();
        }
        i += 1;
    }
    m
};
const OVERLAP: usize = MAX_SIG_LEN - 1;

/// Streaming multi-pattern matcher over the carved body. Holds only `matched` flags, a short
/// `prefix` (for offset-0 magic), and a `tail` overlap window — never the body itself.
struct SigScanner {
    matched: Vec<bool>,
    prefix: Vec<u8>,
    tail: Vec<u8>,
}

impl SigScanner {
    fn new() -> SigScanner {
        SigScanner {
            matched: vec![false; SIGNATURES.len()],
            prefix: Vec::new(),
            tail: Vec::new(),
        }
    }

    /// Fold the next run of body bytes (the same slice the hasher sees).
    fn feed(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        // Start-anchored magic: accumulate the first MAX_SIG_LEN bytes and test from offset 0.
        if self.prefix.len() < MAX_SIG_LEN {
            let take = (MAX_SIG_LEN - self.prefix.len()).min(bytes.len());
            self.prefix.extend_from_slice(&bytes[..take]);
            for (i, sig) in SIGNATURES.iter().enumerate() {
                if sig.anchor == Anchor::Start
                    && !self.matched[i]
                    && self.prefix.starts_with(sig.pattern)
                {
                    self.matched[i] = true;
                }
            }
        }
        // Anywhere markers: search across the previous tail + this chunk so a match that straddles
        // the boundary is still found.
        let mut scan = Vec::with_capacity(self.tail.len() + bytes.len());
        scan.extend_from_slice(&self.tail);
        scan.extend_from_slice(bytes);
        for (i, sig) in SIGNATURES.iter().enumerate() {
            if sig.anchor == Anchor::Anywhere
                && !self.matched[i]
                && scan.windows(sig.pattern.len()).any(|w| w == sig.pattern)
            {
                self.matched[i] = true;
            }
        }
        // Carry the last OVERLAP bytes for the next chunk.
        let keep = scan.len().min(OVERLAP);
        self.tail = scan[scan.len() - keep..].to_vec();
    }

    /// The matched signatures, in table order.
    fn hits(&self) -> Vec<SigHit> {
        SIGNATURES
            .iter()
            .enumerate()
            .filter(|(i, _)| self.matched[*i])
            .map(|(_, s)| SigHit {
                label: s.label,
                technique: s.technique,
                suspicious: s.suspicious,
                exec_gated: s.exec_gated,
                tier: s.tier,
                executable: s.executable,
            })
            .collect()
    }
}

/// Write sink that streams response-body plaintext through the SHA-256 + signature scanner, bounded
/// by `MAX_BODY`. Owned by the content decoder, so decompressed output is hashed + scanned as it is
/// produced — the body is never buffered (preserving the carver's O(1)-per-flow invariant).
struct CarveSink {
    hasher: Sha256Stream,
    scanner: SigScanner,
    size: u64,
    /// Set once the (decoded) body would exceed `MAX_BODY` — the carve is then skipped rather than
    /// recorded under the hash of a truncated prefix (matching the "skip oversized, never hash wrong
    /// bytes" policy).
    overflow: bool,
}

impl CarveSink {
    fn new() -> CarveSink {
        CarveSink {
            hasher: Sha256Stream::new(),
            scanner: SigScanner::new(),
            size: 0,
            overflow: false,
        }
    }
    fn feed(&mut self, bytes: &[u8]) {
        let room = MAX_BODY.saturating_sub(self.size) as usize;
        if bytes.len() > room {
            self.overflow = true;
        }
        let take = bytes.len().min(room);
        self.hasher.update(&bytes[..take]);
        self.scanner.feed(&bytes[..take]);
        self.size += take as u64;
    }
}

impl std::io::Write for CarveSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.feed(buf); // bytes past MAX_BODY are dropped by `feed`, but we report them consumed
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Streaming zlib-wrapped DEFLATE decoder over a [`CarveSink`], built on the low-level
/// [`flate2::Decompress`] so a TRUNCATED stream is detected: `finish` only accepts a body that
/// reached the zlib end-of-stream marker (`StreamEnd`). The high-level `write::ZlibDecoder::finish`
/// returns `Ok` on truncation, which would emit a wrong hash — so it must not be used here.
struct Inflate {
    dec: flate2::Decompress,
    sink: CarveSink,
    ended: bool,
    errored: bool,
}

impl Inflate {
    fn new() -> Inflate {
        Inflate {
            dec: flate2::Decompress::new(true), // expect a zlib header (HTTP "deflate")
            sink: CarveSink::new(),
            ended: false,
            errored: false,
        }
    }
    fn feed(&mut self, mut input: &[u8]) -> bool {
        if self.errored {
            return false;
        }
        let mut scratch = [0u8; 16 * 1024];
        while !input.is_empty() && !self.ended {
            let in0 = self.dec.total_in();
            let out0 = self.dec.total_out();
            match self
                .dec
                .decompress(input, &mut scratch, flate2::FlushDecompress::None)
            {
                Ok(status) => {
                    let consumed = (self.dec.total_in() - in0) as usize;
                    let produced = (self.dec.total_out() - out0) as usize;
                    if produced > 0 {
                        self.sink.feed(&scratch[..produced]);
                    }
                    input = &input[consumed..];
                    if matches!(status, flate2::Status::StreamEnd) {
                        self.ended = true;
                    } else if self.sink.overflow {
                        return true; // oversized — finalize aborts (ended stays false anyway)
                    } else if consumed == 0 && produced == 0 {
                        break; // need more input
                    }
                }
                Err(_) => {
                    self.errored = true;
                    return false;
                }
            }
        }
        true
    }
}

/// Streaming content-decoder: raw (de-framed) body bytes in, plaintext hashed + scanned by the sink.
/// HTTP `deflate` is taken as zlib-wrapped (the spec-correct form); a non-conforming raw-DEFLATE
/// server simply errors out and yields no carve.
enum Decode {
    Plain(CarveSink),
    Gzip(flate2::write::GzDecoder<CarveSink>),
    Deflate(Inflate),
}

impl Decode {
    fn new(enc: Encoding) -> Decode {
        match enc {
            Encoding::Identity => Decode::Plain(CarveSink::new()),
            Encoding::Gzip => Decode::Gzip(flate2::write::GzDecoder::new(CarveSink::new())),
            Encoding::Deflate => Decode::Deflate(Inflate::new()),
        }
    }
    /// Feed de-framed body bytes. Returns `false` if the decoder errored (malformed compression).
    fn feed(&mut self, bytes: &[u8]) -> bool {
        use std::io::Write;
        match self {
            Decode::Plain(s) => {
                s.feed(bytes);
                true
            }
            Decode::Gzip(d) => d.write_all(bytes).is_ok(),
            Decode::Deflate(inf) => inf.feed(bytes),
        }
    }
    /// Flush + recover the sink. `None` aborts the carve: a truncated compressed stream (gzip CRC
    /// fails, or the zlib stream never reached `StreamEnd`) — so a wrong hash is never emitted.
    fn finish(self) -> Option<CarveSink> {
        match self {
            Decode::Plain(s) => Some(s),
            Decode::Gzip(d) => d.finish().ok(), // validates CRC32 + ISIZE → Err on truncation
            Decode::Deflate(inf) => (inf.ended && !inf.errored).then_some(inf.sink),
        }
    }
}

/// How the response body is framed on the wire.
enum Framing {
    /// Exactly `n` raw body bytes remain (Content-Length).
    Length(u64),
    /// Chunked transfer-encoding, de-framed by a streaming state machine.
    Chunked(ChunkDec),
}

/// Max bytes of a chunk-size / trailer line we buffer before declaring the framing malformed.
const MAX_CHUNK_LINE: usize = 1024;

/// Streaming `Transfer-Encoding: chunked` decoder (RFC 7230 §4.1): fed body bytes in arbitrary
/// splits, it emits the de-chunked body and reports completion at the zero-length chunk + trailers.
struct ChunkDec {
    state: ChunkState,
    line: Vec<u8>,
}

enum ChunkState {
    Size,        // accumulating the "size[;ext]\r\n" line
    Data(u64),   // `n` bytes of chunk data remain
    DataEnd(u8), // `n` bytes of the post-data CRLF remain to consume
    Trailer,     // accumulating a trailer line (empty line ends the body)
    Done,
}

fn trim_crlf(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

impl ChunkDec {
    fn new() -> ChunkDec {
        ChunkDec {
            state: ChunkState::Size,
            line: Vec::new(),
        }
    }
    /// Feed raw chunked bytes, pushing decoded body bytes to `out`. `Ok(true)` once the terminator
    /// is reached; `Err(())` on malformed framing.
    fn feed(&mut self, mut input: &[u8], out: &mut Vec<u8>) -> Result<bool, ()> {
        while !input.is_empty() {
            match self.state {
                ChunkState::Size | ChunkState::Trailer => {
                    let nl = input.iter().position(|&b| b == b'\n');
                    let end = nl.map(|i| i + 1).unwrap_or(input.len());
                    if self.line.len() + end > MAX_CHUNK_LINE {
                        return Err(());
                    }
                    self.line.extend_from_slice(&input[..end]);
                    input = &input[end..];
                    if nl.is_none() {
                        break; // need more bytes to complete the line
                    }
                    let is_size = matches!(self.state, ChunkState::Size);
                    let line = trim_crlf(&self.line);
                    if is_size {
                        let hexpart = line.split(|&b| b == b';').next().unwrap_or(&[]);
                        let size = parse_hex(hexpart).ok_or(())? as u64;
                        self.line.clear();
                        self.state = if size == 0 {
                            ChunkState::Trailer
                        } else {
                            ChunkState::Data(size)
                        };
                    } else {
                        let empty = line.is_empty();
                        self.line.clear();
                        if empty {
                            self.state = ChunkState::Done;
                            return Ok(true);
                        }
                        // else: another trailer line — stay in Trailer.
                    }
                }
                ChunkState::Data(n) => {
                    let take = n.min(input.len() as u64) as usize;
                    out.extend_from_slice(&input[..take]);
                    input = &input[take..];
                    let left = n - take as u64;
                    self.state = if left == 0 {
                        ChunkState::DataEnd(2)
                    } else {
                        ChunkState::Data(left)
                    };
                }
                ChunkState::DataEnd(n) => {
                    let take = (n as usize).min(input.len());
                    input = &input[take..];
                    let left = n - take as u8;
                    self.state = if left == 0 {
                        ChunkState::Size
                    } else {
                        ChunkState::DataEnd(left)
                    };
                }
                ChunkState::Done => return Ok(true),
            }
        }
        Ok(matches!(self.state, ChunkState::Done))
    }
}

/// The per-flow body plan, set once the response headers are parsed: how the body is framed, plus
/// the streaming content decoder (`None` once finalized).
struct BodyPlan {
    framing: Framing,
    decode: Option<Decode>,
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
        self.aborted || self.body.as_ref().is_some_and(|b| b.decode.is_none())
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

    /// De-frame body bytes (length limit or de-chunk), stream them through the content decoder into
    /// the hash + signature scanner, and finalize + emit once the body ends. Malformed framing or
    /// compression aborts the carve (no wrong hash is ever emitted).
    fn feed_body(&mut self, bytes: &[u8]) -> Option<CarveObservation> {
        let p = self.body.as_mut()?;
        p.decode.as_ref()?; // already finalized → nothing more to do
        let mut deframed = Vec::new();
        let framing_done = match &mut p.framing {
            Framing::Length(remaining) => {
                let take = (bytes.len() as u64).min(*remaining) as usize;
                deframed.extend_from_slice(&bytes[..take]);
                *remaining -= take as u64;
                *remaining == 0
            }
            Framing::Chunked(dec) => match dec.feed(bytes, &mut deframed) {
                Ok(done) => done,
                Err(()) => {
                    self.aborted = true;
                    return None;
                }
            },
        };
        if let Some(d) = p.decode.as_mut() {
            if !d.feed(&deframed) {
                self.aborted = true;
                return None;
            }
        }
        if !framing_done {
            return None;
        }
        // Body complete — flush the decoder and recover the hash + size + signatures.
        let sink = match p.decode.take()?.finish() {
            Some(s) => s,
            None => {
                self.aborted = true;
                return None;
            }
        };
        if sink.overflow {
            self.aborted = true; // decoded body exceeded MAX_BODY — skip, don't hash a prefix
            return None;
        }
        if sink.size == 0 {
            return None; // an empty decoded body is not a file
        }
        let sha256 = sink.hasher.finalize_bytes();
        Some(CarveObservation {
            client: self.client,
            server: self.server,
            sha256,
            size: sink.size,
            known_bad: known_bad(&sha256),
            signatures: sink.scanner.hits(),
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
                self.states
                    .insert(key, CarveState::new(src, dst, seq, meta.ts_ns));
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

/// Parse the response head (status line + headers, before the CRLFCRLF) into a streaming
/// [`BodyPlan`], or `None` to skip the carve: a bodyless response (1xx/204/304) or a length-delimited
/// body that is empty or over the size cap. The body is de-framed (Content-Length or chunked) and
/// content-decoded (gzip/deflate) on the fly, so a chunked or compressed download is still carved on
/// its real bytes.
fn parse_response_headers(head: &[u8]) -> Option<BodyPlan> {
    if is_bodyless(head) {
        return None;
    }
    let framing = if header_value_has(head, b"transfer-encoding:", b"chunked") {
        Framing::Chunked(ChunkDec::new())
    } else {
        let content_len = header_u64(head, b"content-length:")?;
        if content_len == 0 || content_len > MAX_BODY {
            return None;
        }
        Framing::Length(content_len)
    };
    Some(BodyPlan {
        framing,
        decode: Some(Decode::new(content_encoding(head))),
    })
}

/// Case-insensitively find a header line beginning with `name` and return its trimmed value bytes.
fn header_line<'a>(head: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    for line in head.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.len() >= name.len() && line[..name.len()].eq_ignore_ascii_case(name) {
            let val = &line[name.len()..];
            // Trim leading/trailing ASCII whitespace.
            let start = val
                .iter()
                .position(|b| !b.is_ascii_whitespace())
                .unwrap_or(val.len());
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

// ---------------------------------------------------------------------------------------------
// HTTP message-body decoding — de-chunk (Transfer-Encoding: chunked) + inflate (Content-Encoding:
// gzip/deflate) so a download delivered chunked or compressed is carved on its REAL content: its
// SHA-256 matches the file and content signatures (YARA-style) can match. Bounded at every stage so
// a compression bomb or a lying chunk size can't exhaust memory.
// ---------------------------------------------------------------------------------------------

/// A Content-Encoding we can reverse for carving.
#[derive(Clone, Copy, PartialEq)]
enum Encoding {
    Identity,
    Gzip,
    Deflate,
}

fn content_encoding(head: &[u8]) -> Encoding {
    match header_line(head, b"content-encoding:") {
        Some(v) if has_token(v, b"gzip") || has_token(v, b"x-gzip") => Encoding::Gzip,
        Some(v) if has_token(v, b"deflate") => Encoding::Deflate,
        _ => Encoding::Identity,
    }
}

/// Case-insensitive substring test within a header value.
fn has_token(v: &[u8], needle: &[u8]) -> bool {
    v.windows(needle.len().max(1))
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// Index of the first CRLF in `buf`.
fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// Parse an ASCII hex chunk size (chunk extensions after `;` are stripped by the caller).
fn parse_hex(b: &[u8]) -> Option<usize> {
    let end = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map(|p| p + 1)
        .unwrap_or(0);
    let b = &b[..end];
    if b.is_empty() || b.len() > 14 {
        return None; // empty, or so many digits it would dwarf any real body
    }
    let mut v: usize = 0;
    for &c in b {
        let d = (c as char).to_digit(16)?;
        v = v.checked_mul(16)?.checked_add(d as usize)?;
    }
    Some(v)
}

/// The numeric status code from a response's status line (`HTTP/x.y NNN …`).
fn status_of(head: &[u8]) -> Option<u16> {
    let line = head
        .split(|&b| b == b'\r' || b == b'\n')
        .next()
        .unwrap_or(head);
    line.split(|&b| b == b' ')
        .nth(1)
        .and_then(|c| std::str::from_utf8(c).ok())
        .and_then(|c| c.parse().ok())
}

/// Whether a response carries no message body per RFC 7230 §3.3.3 — 1xx informational, 204 No
/// Content, 304 Not Modified. The next keep-alive response follows immediately.
fn is_bodyless(head: &[u8]) -> bool {
    matches!(status_of(head), Some(c) if (100..200).contains(&c) || c == 204 || c == 304)
}

/// The raw on-wire byte length of a response body, so the caller can slice it and advance to the
/// next keep-alive response. Handles bodyless responses, Content-Length, and chunked framing;
/// `after` is the bytes right after the header CRLFCRLF. Returns `None` when the body can't be
/// delimited (no length, not chunked) or isn't fully present yet.
pub(crate) fn response_body_span(head: &[u8], after: &[u8]) -> Option<usize> {
    if is_bodyless(head) {
        return Some(0);
    }
    if header_value_has(head, b"transfer-encoding:", b"chunked") {
        chunked_span(after)
    } else {
        // Compare in u64 BEFORE narrowing to usize, so a huge Content-Length can't truncate on
        // wasm32 (32-bit usize) into an in-bounds slice.
        let cl = header_u64(head, b"content-length:")?;
        if cl <= after.len() as u64 {
            Some(cl as usize)
        } else {
            None
        }
    }
}

/// Total raw byte length of a chunked body through its terminating zero-length chunk AND any
/// RFC 7230 §4.1 trailer-part (`*(header-field CRLF) CRLF`), or `None` if the terminator isn't fully
/// present. Consuming the trailers is essential: otherwise keep-alive resync would land inside
/// attacker-controlled trailer bytes (a forged `HTTP/…` there yields a phantom response). Bounded by
/// `after.len()` and always advancing → terminates.
fn chunked_span(after: &[u8]) -> Option<usize> {
    let mut pos = 0usize;
    loop {
        let rel = find_crlf(after.get(pos..)?)?;
        let line = &after[pos..pos + rel];
        let hexpart = line.split(|&b| b == b';').next().unwrap_or(&[]);
        let size = parse_hex(hexpart)?;
        let after_line = pos + rel + 2;
        if size == 0 {
            // Last chunk: consume trailer-field lines up to the empty line that ends the body.
            let mut p = after_line;
            loop {
                match after.get(p..p + 2) {
                    Some(b"\r\n") => return Some(p + 2), // empty line — end of trailers + body
                    _ => p = p + find_crlf(after.get(p..)?)? + 2, // skip one trailer-field line
                }
            }
        }
        let next = after_line.checked_add(size)?.checked_add(2)?; // chunk data + trailing CRLF
        if next > after.len() {
            return None; // body not fully present
        }
        pos = next;
    }
}

/// De-chunk (if chunked) then inflate (if gzip/deflate) an HTTP body for carving. `head` is the
/// header block; `raw` is the raw body bytes. Bounded by `MAX_BODY` at every stage.
pub(crate) fn decode_http_body(head: &[u8], raw: &[u8]) -> Vec<u8> {
    let dechunked = if header_value_has(head, b"transfer-encoding:", b"chunked") {
        dechunk(raw)
    } else {
        raw.to_vec()
    };
    match content_encoding(head) {
        Encoding::Gzip => inflate(flate2::read::GzDecoder::new(&dechunked[..])),
        Encoding::Deflate => {
            // HTTP "deflate" is usually zlib-wrapped, but some servers send raw DEFLATE.
            let z = inflate(flate2::read::ZlibDecoder::new(&dechunked[..]));
            if z.is_empty() {
                inflate(flate2::read::DeflateDecoder::new(&dechunked[..]))
            } else {
                z
            }
        }
        Encoding::Identity => dechunked,
    }
}

/// De-chunk a chunked body's raw bytes into the message body, bounded by `MAX_BODY`. Best-effort:
/// stops at the terminator, a malformed size line, or the cap. (Trailers carry no body bytes, so
/// stopping at the zero-length chunk is correct here — [`chunked_span`] handles trailer framing.)
fn dechunk(raw: &[u8]) -> Vec<u8> {
    let cap = MAX_BODY as usize;
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < raw.len() && out.len() < cap {
        let rel = match find_crlf(&raw[pos..]) {
            Some(r) => r,
            None => break,
        };
        let line = &raw[pos..pos + rel];
        let hexpart = line.split(|&b| b == b';').next().unwrap_or(&[]);
        let size = match parse_hex(hexpart) {
            Some(s) => s,
            None => break,
        };
        let after_line = pos + rel + 2;
        if size == 0 {
            break; // last chunk
        }
        let data_end = match after_line.checked_add(size) {
            Some(e) => e.min(raw.len()),
            None => break,
        };
        let take = (data_end - after_line).min(cap - out.len());
        out.extend_from_slice(&raw[after_line..after_line + take]);
        pos = match data_end.checked_add(2) {
            Some(p) => p, // skip the chunk-data trailing CRLF
            None => break,
        };
    }
    out
}

/// Read a flate2 decoder to completion, bounded by `MAX_BODY`. Returns whatever decoded on a
/// malformed or truncated stream (best-effort) rather than erroring.
fn inflate<R: std::io::Read>(mut r: R) -> Vec<u8> {
    let cap = MAX_BODY as usize;
    let mut out = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    while out.len() < cap {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let take = n.min(cap - out.len());
                out.extend_from_slice(&buf[..take]);
            }
            Err(_) => break,
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Carving over an in-order cleartext HTTP stream (decrypted TLS)
// ---------------------------------------------------------------------------------------------

/// One file carved from an in-order cleartext HTTP stream — like [`CarveObservation`] but without
/// the flow IPs (the caller already knows which flow it decrypted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StreamCarve {
    pub sha256: [u8; 32],
    pub size: u64,
    pub known_bad: bool,
    pub signatures: Vec<SigHit>,
}

/// Cap on files carved from one decrypted stream.
const MAX_STREAM_CARVES: usize = 256;

/// Hash + signature-scan a complete file body into a [`StreamCarve`] (for a body already fully
/// reassembled — a decrypted HTTP/1.1 response body or HTTP/2 DATA stream).
pub(crate) fn carve_one(body: &[u8]) -> StreamCarve {
    let mut hasher = Sha256Stream::new();
    hasher.update(body);
    let sha256 = hasher.finalize_bytes();
    let mut scanner = SigScanner::new();
    scanner.feed(body);
    StreamCarve {
        sha256,
        size: body.len() as u64,
        known_bad: known_bad(&sha256),
        signatures: scanner.hits(),
    }
}

/// Carve files from an in-order cleartext **HTTP/1.1 response** stream — e.g. the decrypted
/// server→client direction of a TLS flow (key-log decryption). Walks responses keep-alive aware and,
/// for each, DECODES the body (de-chunks `Transfer-Encoding: chunked`, inflates `Content-Encoding:
/// gzip`/`deflate`) before hashing + signature-scanning, so a malware download hidden inside HTTPS
/// is surfaced on its real content — its SHA-256 matches the file and content signatures can match —
/// even when delivered chunked or compressed. Stops at a body it can't delimit (no length, not
/// chunked) rather than re-scanning body bytes for a status line (which a hostile body could forge).
/// Nothing is retained beyond the bounded decode.
pub(crate) fn carve_http_stream(stream: &[u8]) -> Vec<StreamCarve> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < stream.len() && out.len() < MAX_STREAM_CARVES {
        // Find the next response status line (`HTTP/…`).
        let rel = match stream[pos..].windows(5).position(|w| w == b"HTTP/") {
            Some(r) => r,
            None => break,
        };
        let start = pos + rel;
        let rest = &stream[start..];
        let hdr_end = match find_crlfcrlf(rest) {
            Some(p) => p,
            None => break, // headers not yet complete → stop
        };
        let head = &rest[..hdr_end];
        let body_start = start + hdr_end + 4;
        let after = &stream[body_start..];
        match response_body_span(head, after) {
            Some(span) => {
                let decoded = decode_http_body(head, &after[..span]);
                if !decoded.is_empty() {
                    out.push(carve_one(&decoded));
                }
                // `body_start > pos` (header bytes consumed), so progress holds even when span == 0.
                pos = body_start + span;
            }
            // Body can't be delimited (no Content-Length, not chunked) or isn't fully present: stop.
            // We do NOT re-scan the body for the next `HTTP/`, which a hostile body could forge into
            // a phantom response / bogus carve.
            None => break,
        }
    }
    out
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
        assert!(
            st.feed(1000, head).is_none(),
            "incomplete body must not carve"
        );
        let obs = st
            .feed(1000 + head.len() as u32, rest)
            .expect("carved on completion");
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
    fn aborts_on_malformed_compression_or_no_length() {
        // Content-Encoding: gzip but the body isn't valid gzip → decoder errors → no carve (never a
        // wrong hash).
        let bad_gz = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Encoding: gzip\r\n\r\nhello";
        assert!(state().feed(1000, bad_gz).is_none());
        // No Content-Length and not chunked → not delimitable → no carve.
        let nolen = b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nhello";
        assert!(state().feed(1000, nolen).is_none());
        // A bodyless 204 → no carve.
        let no_body = b"HTTP/1.1 204 No Content\r\n\r\n";
        assert!(state().feed(1000, no_body).is_none());
    }

    /// A chunked download is de-chunked on the fly and carved on its real (de-chunked) hash —
    /// including when the chunks arrive split across packets.
    #[test]
    fn carves_a_chunked_body_streamed_across_packets() {
        let mut st = state();
        let p1 = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";
        let p2 = b"lo\r\n6\r\n world\r\n0\r\n\r\n"; // " world" completes "hello world"
        assert!(
            st.feed(1000, p1).is_none(),
            "incomplete chunked body must not carve yet"
        );
        let obs = st
            .feed(1000 + p1.len() as u32, p2)
            .expect("carved on terminator");
        assert_eq!(hex_of(&obs.sha256), sha256_hex(b"hello world"));
        assert_eq!(obs.size, 11);
    }

    /// A gzip download is inflated on the fly: the carved hash is the decompressed file's hash and
    /// content signatures hit the real bytes.
    #[test]
    fn carves_a_gzip_body_to_the_decompressed_hash() {
        let body = b"MZ\x90\x00 gzipped UPX! payload for the streaming carver";
        let gz = {
            use std::io::Write;
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(body).unwrap();
            e.finish().unwrap()
        };
        let mut resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Encoding: gzip\r\n\r\n",
            gz.len()
        )
        .into_bytes();
        resp.extend_from_slice(&gz);
        let obs = state().feed(1000, &resp).expect("carved");
        assert_eq!(
            hex_of(&obs.sha256),
            sha256_hex(body),
            "hash is the inflated file"
        );
        assert_eq!(obs.size, body.len() as u64);
        assert!(obs
            .signatures
            .iter()
            .any(|s| s.label == "PE/DOS executable"));
        assert!(obs
            .signatures
            .iter()
            .any(|s| s.label == "UPX-packed executable"));
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// A complete `Content-Encoding: deflate` (zlib) body is inflated and carved on its real hash.
    #[test]
    fn carves_a_complete_deflate_body() {
        let body = b"MZ\x90\x00 deflate-compressed payload for the carver";
        let z = zlib(body);
        let mut resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Encoding: deflate\r\n\r\n",
            z.len()
        )
        .into_bytes();
        resp.extend_from_slice(&z);
        let obs = state().feed(1000, &resp).expect("carved");
        assert_eq!(hex_of(&obs.sha256), sha256_hex(body));
        assert!(obs
            .signatures
            .iter()
            .any(|s| s.label == "PE/DOS executable"));
    }

    /// Review finding: a TRUNCATED deflate body that is byte-complete per Content-Length must NOT be
    /// recorded under the hash of its partial decode — the zlib stream never reaches StreamEnd, so
    /// the carve aborts (never a wrong hash).
    #[test]
    fn aborts_on_truncated_deflate_body_no_wrong_hash() {
        let body =
            b"MZ\x90\x00 a longer payload so the compressed stream spans many bytes and truncates";
        let z = zlib(body);
        let cut = z.len() - 8; // drop the tail (incl. the adler32 trailer + end-of-stream)
        let truncated = &z[..cut];
        let mut resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Encoding: deflate\r\n\r\n",
            truncated.len()
        )
        .into_bytes();
        resp.extend_from_slice(truncated);
        assert!(
            state().feed(1000, &resp).is_none(),
            "a truncated deflate stream must abort, not emit a partial-decode hash"
        );
    }

    #[test]
    fn chunk_decoder_never_panics_on_garbage() {
        for seed in 0u16..400 {
            let junk: Vec<u8> = (0..seed).map(|i| (i.wrapping_mul(47)) as u8).collect();
            let mut dec = ChunkDec::new();
            let mut out = Vec::new();
            // Feed in two arbitrary splits to exercise the streaming state across a boundary.
            let mid = (seed as usize) / 2;
            let _ = dec.feed(&junk[..mid], &mut out);
            let _ = dec.feed(&junk[mid..], &mut out);
        }
    }

    fn http_resp(body: &[u8]) -> Vec<u8> {
        let mut resp =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        resp.extend_from_slice(body);
        resp
    }
    fn sig_labels(obs: &CarveObservation) -> Vec<&'static str> {
        obs.signatures.iter().map(|s| s.label).collect()
    }

    #[test]
    fn tags_file_type_magic_at_offset_zero() {
        // A PE executable: "MZ" magic at byte 0.
        let mut body = b"MZ\x90\x00\x03\x00\x00\x00".to_vec();
        body.extend_from_slice(&[0u8; 16]);
        let obs = state().feed(1000, &http_resp(&body)).expect("carved");
        assert!(sig_labels(&obs).contains(&"PE/DOS executable"));
        assert!(
            obs.signatures.iter().all(|s| !s.suspicious),
            "file-type magic is context, not suspicious"
        );
    }

    #[test]
    fn flags_a_suspicious_content_signature() {
        let body = b"\x00\x01garbage prefix UPX!  packed binary body \x90\x90".to_vec();
        let obs = state().feed(1000, &http_resp(&body)).expect("carved");
        let upx = obs
            .signatures
            .iter()
            .find(|s| s.label == "UPX-packed executable")
            .expect("UPX! matched");
        assert!(upx.suspicious);
        assert_eq!(upx.technique, "T1027.002");
    }

    #[test]
    fn matches_a_signature_straddling_a_segment_boundary() {
        let marker = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE";
        let mut body = vec![b'.'; 10];
        body.extend_from_slice(marker);
        body.extend_from_slice(&[b'.'; 10]);
        let resp = http_resp(&body);
        // Cut in the middle of the marker so it straddles two segments.
        let header_len = resp.len() - body.len();
        let cut = header_len + 10 + marker.len() / 2;

        let mut st = state();
        assert!(st.feed(1000, &resp[..cut]).is_none(), "incomplete body");
        let obs = st
            .feed(1000 + cut as u32, &resp[cut..])
            .expect("carved on completion");
        assert!(
            sig_labels(&obs).contains(&"EICAR test signature"),
            "a marker split across segments is still matched: {:?}",
            sig_labels(&obs)
        );
    }

    #[test]
    fn benign_text_matches_no_signatures() {
        let body = b"just a normal README with nothing special inside it whatsoever.\n";
        let obs = state().feed(1000, &http_resp(body)).expect("carved");
        assert!(
            obs.signatures.is_empty(),
            "benign text matched: {:?}",
            sig_labels(&obs)
        );
    }

    #[test]
    fn carve_http_stream_walks_keepalive_and_scans_bodies() {
        // Two responses on one (decrypted) stream: a benign one, then a PE with a UPX marker.
        let mut stream = http_resp(b"plain text first response").to_vec();
        stream.extend_from_slice(&http_resp(b"MZ\x90\x00 second file, UPX! packed payload"));
        let carves = carve_http_stream(&stream);
        assert_eq!(carves.len(), 2, "both responses carved");
        assert!(carves[0].signatures.is_empty());
        assert!(carves[1]
            .signatures
            .iter()
            .any(|s| s.label == "PE/DOS executable"));
        assert!(carves[1]
            .signatures
            .iter()
            .any(|s| s.label == "UPX-packed executable" && s.suspicious));
    }

    #[test]
    fn carve_http_stream_handles_oversized_content_length_without_panic() {
        // A Content-Length far over the cap is skipped (not carved) and does not overflow/loop.
        let stream = b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\nshort body";
        assert!(carve_http_stream(stream).is_empty());
    }

    // ── body decoding (de-chunk + inflate) ───────────────────────────────────────

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// A file delivered with `Transfer-Encoding: chunked` (with a trailer) is de-chunked, so its
    /// hash is the file's hash and content signatures match the real bytes.
    #[test]
    fn carve_http_stream_dechunks_a_chunked_download() {
        let body = b"MZ\x90\x00 chunked UPX! payload"; // PE + UPX markers
        let (a, b) = body.split_at(8);
        let mut stream = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        stream.extend_from_slice(format!("{:x}\r\n", a.len()).as_bytes());
        stream.extend_from_slice(a);
        stream.extend_from_slice(b"\r\n");
        stream.extend_from_slice(format!("{:x}\r\n", b.len()).as_bytes());
        stream.extend_from_slice(b);
        // Last chunk WITH a trailer header, then the empty line.
        stream.extend_from_slice(b"\r\n0\r\nX-Checksum: abc\r\n\r\n");

        let carves = carve_http_stream(&stream);
        assert_eq!(carves.len(), 1);
        assert_eq!(
            hex_of(&carves[0].sha256),
            sha256_hex(body),
            "hash is the de-chunked file"
        );
        assert_eq!(carves[0].size, body.len() as u64);
        assert!(carves[0]
            .signatures
            .iter()
            .any(|s| s.label == "PE/DOS executable"));
        assert!(carves[0]
            .signatures
            .iter()
            .any(|s| s.label == "UPX-packed executable"));
    }

    /// A file delivered `Content-Encoding: gzip` is inflated, so the hash matches the real file and
    /// signatures hit the decompressed content (not the gzip wrapper).
    #[test]
    fn carve_http_stream_inflates_a_gzip_download() {
        let body = b"MZ\x90\x00 gzipped UPX! payload bytes for the scanner";
        let gz = gzip(body);
        let mut stream = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            gz.len()
        )
        .into_bytes();
        stream.extend_from_slice(&gz);

        let carves = carve_http_stream(&stream);
        assert_eq!(carves.len(), 1);
        assert_eq!(
            hex_of(&carves[0].sha256),
            sha256_hex(body),
            "hash is the inflated file"
        );
        assert_eq!(carves[0].size, body.len() as u64);
        assert!(carves[0]
            .signatures
            .iter()
            .any(|s| s.label == "PE/DOS executable"));
        assert!(carves[0]
            .signatures
            .iter()
            .any(|s| s.label == "UPX-packed executable"));
    }

    /// Chunked AND gzip together: de-chunk first, then inflate.
    #[test]
    fn carve_http_stream_dechunks_then_inflates() {
        let body = b"MZ\x90\x00 chunked and gzipped UPX! payload";
        let gz = gzip(body);
        let mut stream =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n"
                .to_vec();
        stream.extend_from_slice(format!("{:x}\r\n", gz.len()).as_bytes());
        stream.extend_from_slice(&gz);
        stream.extend_from_slice(b"\r\n0\r\n\r\n");

        let carves = carve_http_stream(&stream);
        assert_eq!(carves.len(), 1);
        assert_eq!(hex_of(&carves[0].sha256), sha256_hex(body));
        assert!(carves[0]
            .signatures
            .iter()
            .any(|s| s.label == "PE/DOS executable"));
    }

    /// A chunked response with a trailer carrying a forged `HTTP/…` must NOT desync resync: the
    /// trailer is consumed and the genuine next response (a real download) is carved.
    #[test]
    fn carve_http_stream_consumes_chunked_trailers_no_phantom() {
        let mut stream = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        stream.extend_from_slice(
            b"3\r\nabc\r\n0\r\nX: HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n",
        );
        // The genuine next response carries a real PE download.
        stream.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nMZ\x90\x00");

        let carves = carve_http_stream(&stream);
        assert_eq!(carves.len(), 2, "chunked body + the genuine next file");
        assert_eq!(carves[0].size, 3); // "abc"
        assert_eq!(carves[1].size, 4); // the real MZ payload, carved as its own file
        assert!(carves[1]
            .signatures
            .iter()
            .any(|s| s.label == "PE/DOS executable"));
    }

    /// A truncated length-delimited body (Content-Length larger than what's present) must NOT be
    /// re-scanned into a phantom carve — the carver stops.
    #[test]
    fn carve_http_stream_truncated_body_makes_no_phantom_carve() {
        let stream =
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nZZ";
        assert!(
            carve_http_stream(stream).is_empty(),
            "no phantom from a truncated body"
        );
    }

    /// An interior EICAR string inside an undelimitable (no-length) response must NOT be carved as a
    /// fake known-bad download.
    #[test]
    fn carve_http_stream_no_length_body_makes_no_phantom_known_bad() {
        let eicar = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;
        let mut stream = b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nbody ".to_vec();
        stream.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 68\r\n\r\n");
        stream.extend_from_slice(eicar);
        assert!(
            carve_http_stream(&stream).is_empty(),
            "interior EICAR is not a real download"
        );
    }

    /// A bodyless response (204) does not stop keep-alive walking — the next response is carved.
    #[test]
    fn carve_http_stream_continues_past_a_bodyless_204() {
        let mut stream = b"HTTP/1.1 204 No Content\r\n\r\n".to_vec();
        stream.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nMZ\x90\x00");
        let carves = carve_http_stream(&stream);
        assert_eq!(carves.len(), 1, "the 200 after the 204 is carved");
        assert_eq!(carves[0].size, 4);
    }

    /// A decompression bomb is bounded: the decoded body never exceeds MAX_BODY and nothing OOMs.
    #[test]
    fn inflate_is_bounded_against_a_gzip_bomb() {
        let bomb = gzip(&vec![0u8; 100 * 1024 * 1024]); // ~100 MiB → tiny gzip
        let decoded = decode_http_body(b"content-encoding: gzip", &bomb);
        assert!(
            decoded.len() <= MAX_BODY as usize,
            "decoded body is capped at MAX_BODY"
        );
    }

    #[test]
    fn body_decoding_never_panics_on_garbage() {
        for seed in 0u16..400 {
            let junk: Vec<u8> = (0..seed).map(|i| (i.wrapping_mul(53)) as u8).collect();
            let _ = dechunk(&junk);
            let _ = decode_http_body(
                b"transfer-encoding: chunked\r\ncontent-encoding: gzip",
                &junk,
            );
            let _ = chunked_span(&junk);
            let _ = response_body_span(b"transfer-encoding: chunked", &junk);
        }
    }

    #[test]
    fn response_body_span_delimits_framings() {
        assert_eq!(
            response_body_span(b"content-length: 5", b"hello world"),
            Some(5)
        );
        assert_eq!(response_body_span(b"content-length: 99", b"hi"), None);
        // Huge Content-Length must not truncate into an in-bounds span (wasm32 32-bit usize).
        assert_eq!(
            response_body_span(b"content-length: 18446744073709551615", b"hi"),
            None
        );
        // Chunked: span runs through the zero terminator + trailers (13 raw bytes).
        assert_eq!(
            response_body_span(b"transfer-encoding: chunked", b"3\r\nabc\r\n0\r\n\r\n"),
            Some(13)
        );
        // Bodyless (204) → zero span regardless of (absent) length headers.
        assert_eq!(
            response_body_span(b"HTTP/1.1 204 No Content", b"next"),
            Some(0)
        );
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
    fn seg(
        src: std::net::Ipv4Addr,
        dst: std::net::Ipv4Addr,
        sp: u16,
        dp: u16,
        seq: u32,
        payload: &[u8],
    ) -> Vec<u8> {
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
            ts_known: true,
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
        let f2 = seg(
            srv4(),
            cli4(),
            80,
            49152,
            1000 + split as u32,
            &resp[split..],
        );

        let mut carver = HttpBodyCarver::new();
        feed_frame(&mut carver, &f1, 1, 0);
        feed_frame(&mut carver, &f2, 2, 1);
        let obs = carver.into_results();

        assert_eq!(
            obs.len(),
            1,
            "one carve (the real file), not the interior nested response"
        );
        assert_eq!(obs[0].size, clen as u64);
        assert_eq!(hex_of(&obs[0].sha256), sha256_hex(&real_body));
        assert!(
            obs.iter().all(|o| o.size != 2),
            "the interior 'XY' must not be carved"
        );
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
        assert!(
            carver.states.is_empty(),
            "completed carve's slot is reclaimed"
        );
        assert_eq!(carver.observations.len(), 1, "the download was carved");
    }
}
