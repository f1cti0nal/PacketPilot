//! Container reader: a magic-sniffing source factory plus a lending-iterator
//! [`PacketSource`] trait.
//!
//! The reader is the memory frontier of the engine. It owns a bounded refill buffer
//! (64 KiB via `pcap-parser`'s `create_reader`) and yields one [`RawFrame`] at a time,
//! borrowing from that buffer — so peak heap is independent of capture size. All concrete
//! sources (`pcap`, `pcapng`, `gzip`) live in submodules and are reached only through
//! [`open`] / [`open_reader`].
//!
//! ## Responsibilities
//! - Sniff the first bytes to pick the container (classic pcap LE/BE, ns-magic pcapng).
//! - Detect a `.gz`-wrapped capture and transparently inflate it via the pure-Rust
//!   `flate2` backend (no C compiler needed), then re-sniff the decompressed stream.
//! - Normalize per-packet timestamps to `i64` ns and expose the link type.
//!
//! ## Edge cases this layer must survive without panicking
//! - Both pcap endiannesses and the ns magic `0xa1b23c4d`.
//! - Truncated final record (return the frames read, then clean EOF or `Truncated`).
//! - `caplen > file remaining` (clamp / error, never over-read).
//! - Multi-interface pcapng with differing `tsresol` (per-interface scaling).
//! - Unknown pcapng blocks (skip by declared length).

use crate::{PpError, Result};

/// The bounded refill buffer size handed to `pcap-parser`'s readers. This is the engine's
/// memory frontier: a capture of any size is processed with at most this much buffered.
pub(crate) const REFILL_CAPACITY: usize = 65536;

/// Link-layer type (libpcap DLT values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// 1 — EN10MB (Ethernet).
    Ethernet,
    /// 228 — raw IPv4.
    RawIpv4,
    /// 229 — raw IPv6.
    RawIpv6,
    /// 101 — raw IP (sniff version from first nibble).
    Raw,
    /// 113 — Linux cooked v1.
    LinuxSll,
    /// 276 — Linux cooked v2.
    LinuxSll2,
    /// 0 — BSD loopback / null.
    Null,
    /// Any DLT the engine does not model.
    Unsupported(u32),
}

impl LinkType {
    /// Map a raw DLT number to a [`LinkType`]. Pure function; never errors.
    pub fn from_u32(v: u32) -> LinkType {
        match v {
            1 => LinkType::Ethernet,
            0 => LinkType::Null,
            101 => LinkType::Raw,
            113 => LinkType::LinuxSll,
            276 => LinkType::LinuxSll2,
            228 => LinkType::RawIpv4,
            229 => LinkType::RawIpv6,
            other => LinkType::Unsupported(other),
        }
    }

    /// A stable display token (e.g. `"EN10MB"`, `"RAW"`, `"LINUX_SLL"`). Used in
    /// `AnalysisOutput.link_type`.
    pub fn as_str(self) -> &'static str {
        match self {
            LinkType::Ethernet => "EN10MB",
            LinkType::RawIpv4 => "IPV4",
            LinkType::RawIpv6 => "IPV6",
            LinkType::Raw => "RAW",
            LinkType::LinuxSll => "LINUX_SLL",
            LinkType::LinuxSll2 => "LINUX_SLL2",
            LinkType::Null => "NULL",
            LinkType::Unsupported(_) => "UNSUPPORTED",
        }
    }
}

/// A borrowed view of one frame as read from the container. Valid only until the next
/// call to [`PacketSource::next_frame`] (lending-iterator semantics).
pub struct RawFrame<'a> {
    pub index: u64,
    pub ts_ns: i64,
    pub iface_id: u32,
    pub wire_len: u32,
    pub cap_len: u32,
    pub link_type: LinkType,
    /// Exactly `cap_len` bytes of L2 (or L3 for raw link types).
    pub data: &'a [u8],
}

/// A streaming source of frames. Implemented as a lending iterator so the data buffer can
/// be reused across calls (bounded memory).
pub trait PacketSource {
    /// The capture's link-layer type (per-interface link types in pcapng are surfaced on
    /// each [`RawFrame`]; this returns the first/primary interface's type).
    fn link_type(&self) -> LinkType;

    /// Advance to the next frame. `Ok(None)` signals clean EOF. The returned borrow is
    /// invalidated by the next call.
    fn next_frame(&mut self) -> Result<Option<RawFrame<'_>>>;

    /// Total source size in bytes if known (for progress reporting), else `None`.
    fn size_hint(&self) -> Option<u64>;
}

/// The set of container magics the engine recognizes, derived from the first four bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Magic {
    /// Classic pcap, little-endian, microsecond timestamps (`0xa1b2c3d4`).
    PcapLeUs,
    /// Classic pcap, big-endian, microsecond timestamps (`0xd4c3b2a1`).
    PcapBeUs,
    /// Classic pcap, little-endian, nanosecond timestamps (`0xa1b23c4d`).
    PcapLeNs,
    /// Classic pcap, big-endian, nanosecond timestamps (`0x4d3cb2a1`).
    PcapBeNs,
    /// pcapng Section Header Block (`0x0a0d0d0a`).
    PcapNg,
    /// gzip member (`0x1f 0x8b`).
    Gzip,
}

impl Magic {
    /// Classify a 4-byte prefix. `head` must contain at least the bytes available; for the
    /// gzip case only the first two bytes are inspected.
    fn sniff(head: &[u8; 4]) -> Option<Magic> {
        // gzip is identified by only the first two bytes (the 4-byte read still applies
        // because every supported magic is decided within the first four bytes).
        if head[0] == 0x1f && head[1] == 0x8b {
            return Some(Magic::Gzip);
        }
        match head {
            [0xa1, 0xb2, 0xc3, 0xd4] => Some(Magic::PcapLeUs),
            [0xd4, 0xc3, 0xb2, 0xa1] => Some(Magic::PcapBeUs),
            [0xa1, 0xb2, 0x3c, 0x4d] => Some(Magic::PcapLeNs),
            [0x4d, 0x3c, 0xb2, 0xa1] => Some(Magic::PcapBeNs),
            [0x0a, 0x0d, 0x0d, 0x0a] => Some(Magic::PcapNg),
            _ => None,
        }
    }

    /// True for the two nanosecond-resolution classic pcap variants.
    fn is_nanos(self) -> bool {
        matches!(self, Magic::PcapLeNs | Magic::PcapBeNs)
    }
}

/// A reader that re-emits a small already-consumed prefix before delegating to the inner
/// reader. Used to "un-peek" the sniffed magic bytes so the chosen `pcap-parser` reader sees
/// the stream from byte zero. Bounded: the prefix is at most four bytes.
struct PrefixReader<R: std::io::Read> {
    prefix: [u8; 4],
    /// Number of valid bytes in `prefix`.
    prefix_len: usize,
    /// How many prefix bytes have already been re-emitted.
    pos: usize,
    inner: R,
}

impl<R: std::io::Read> PrefixReader<R> {
    fn new(prefix: [u8; 4], prefix_len: usize, inner: R) -> Self {
        PrefixReader {
            prefix,
            prefix_len,
            pos: 0,
            inner,
        }
    }
}

impl<R: std::io::Read> std::io::Read for PrefixReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut written = 0;
        // First, drain any not-yet-re-emitted prefix bytes into the front of `buf`.
        if self.pos < self.prefix_len {
            let n = std::cmp::min(buf.len(), self.prefix_len - self.pos);
            buf[..n].copy_from_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            written += n;
        }
        // Then top up from the inner reader in the SAME call. Readers such as `pcap-parser`'s
        // eager header fill may parse after a single `read`, so returning only the 4 prefix
        // bytes would make a complete 24-byte global header look `Incomplete`. Coalescing the
        // prefix with an inner read prevents that.
        if written < buf.len() {
            match self.inner.read(&mut buf[written..]) {
                Ok(n) => written += n,
                // Surface the inner error only if nothing is buffered yet; otherwise return
                // the prefix bytes now and let the next call observe the error.
                Err(e) if written == 0 => return Err(e),
                Err(_) => {}
            }
        }
        Ok(written)
    }
}

/// Read up to four bytes from `reader` without losing them: returns the bytes plus a reader
/// that re-emits them first. Fewer than four bytes available is reported to the caller via
/// the returned length so the magic check can produce a precise `Truncated` error.
fn peek4<R: std::io::Read>(mut reader: R) -> std::io::Result<([u8; 4], usize, PrefixReader<R>)> {
    let mut buf = [0u8; 4];
    let mut filled = 0;
    while filled < 4 {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok((buf, filled, PrefixReader::new(buf, filled, reader)))
}

/// Open a capture file: sniff magic bytes and return the appropriate source. This is the
/// only place that decides container type; everything downstream keeps the bounded refill
/// buffer and never reads the whole file. Gzip-wrapped inputs are transparently inflated
/// (see [`open_reader`]).
pub fn open(path: &std::path::Path) -> Result<Box<dyn PacketSource>> {
    let file = std::fs::File::open(path)
        .map_err(|e| PpError::io(format!("open {}", path.display()), e))?;
    let size_hint = file.metadata().ok().map(|m| m.len());
    open_reader(file, size_hint)
}

/// Open a capture from an arbitrary reader (used by tests and `open`).
///
/// Sniffs the leading magic and dispatches to the appropriate container reader. Gzip-wrapped
/// inputs are transparently inflated using the pure-Rust `flate2` backend (no C compiler
/// needed) and then re-sniffed so a `.pcap.gz` or `.pcapng.gz` file works seamlessly.
/// Nested gzip (gzip-inside-gzip) is rejected with a clear error. Constructs
/// `pcap-parser`'s bounded reader directly so the 64 KiB refill buffer is the only large
/// allocation regardless of capture size.
pub fn open_reader<R: std::io::Read + 'static>(
    reader: R,
    size_hint: Option<u64>,
) -> Result<Box<dyn PacketSource>> {
    open_reader_depth(reader, size_hint, 0)
}

/// Internal implementation of [`open_reader`] that carries a recursion depth counter so
/// nested gzip (gzip-inside-gzip) can be detected and rejected without unbounded recursion.
/// `gzip_depth` is 0 on the first call and 1 after the first inflate step; any value ≥ 1
/// entering the gzip arm is a nested-gzip error.
fn open_reader_depth<R: std::io::Read + 'static>(
    reader: R,
    size_hint: Option<u64>,
    gzip_depth: u8,
) -> Result<Box<dyn PacketSource>> {
    let (head, filled, prefixed) =
        peek4(reader).map_err(|e| PpError::io("sniff container magic", e))?;

    if filled < 4 {
        // Not enough bytes to identify any container; the smallest magic we accept is the
        // 2-byte gzip prefix, but every pcap/pcapng magic needs four. Report precisely.
        return Err(PpError::Truncated {
            needed: 4,
            had: filled,
            offset: 0,
        });
    }

    match Magic::sniff(&head) {
        Some(Magic::Gzip) => {
            if gzip_depth >= 1 {
                return Err(PpError::UnknownFormat(
                    "nested gzip is not supported".to_string(),
                ));
            }
            // Inflate, then re-sniff the decompressed stream (a .pcap.gz unwraps to a
            // pcap/pcapng). Box the inflated reader before recursing so the recursive call
            // sees a concrete `Box<dyn Read>` rather than an ever-growing
            // `GunzipReader<PrefixReader<GunzipReader<...>>>` monomorphization.
            let inflated: Box<dyn std::io::Read + 'static> =
                Box::new(gzip::GunzipReader::new(prefixed));
            open_reader_depth(inflated, None, gzip_depth + 1)
        }
        Some(m @ (Magic::PcapLeUs | Magic::PcapBeUs | Magic::PcapLeNs | Magic::PcapBeNs)) => {
            let mut source = pcap::LegacyPcapSource::new(
                prefixed,
                LinkType::Unsupported(0), // real DLT is read from the global header
                m.is_nanos(),
                size_hint,
            );
            // Read the global header eagerly so `link_type()` is accurate before the first
            // `next_frame()` (the orchestrator queries it up front).
            source.prime()?;
            Ok(Box::new(source))
        }
        Some(Magic::PcapNg) => {
            let mut source = pcapng::PcapNgSource::new(prefixed, size_hint);
            // Read up to and including the first IDB so `link_type()` is accurate up front.
            source.prime()?;
            Ok(Box::new(source))
        }
        None => Err(PpError::UnknownFormat(format!(
            "0x{:02x}{:02x}{:02x}{:02x}",
            head[0], head[1], head[2], head[3]
        ))),
    }
}

pub(crate) mod gzip;
pub(crate) mod pcap;
pub(crate) mod pcapng;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    // ---------------------------------------------------------------------------
    // Synthetic-pcap helpers shared by multiple tests
    // ---------------------------------------------------------------------------

    /// Build a minimal classic pcap with `n` frames (Ethernet, 14-byte payload each).
    /// Returns the raw bytes of a valid, self-contained `.pcap` file.
    fn make_pcap_bytes(n: usize) -> Vec<u8> {
        use crate::gen::container::{write_legacy_record, write_pcap_header};
        use crate::reader::LinkType;
        let mut buf = Vec::new();
        write_pcap_header(&mut buf, LinkType::Ethernet).unwrap();
        let payload = [0u8; 14]; // minimal Ethernet frame stub
        for i in 0..n {
            let ts_ns = i as i64 * 1_000_000; // 1 ms apart
            write_legacy_record(&mut buf, ts_ns, payload.len() as u32, payload.len() as u32)
                .unwrap();
            buf.extend_from_slice(&payload);
        }
        buf
    }

    /// Count the frames returned by `open_reader` on a raw byte slice.
    fn count_frames(raw: &[u8]) -> u64 {
        let mut src =
            open_reader(std::io::Cursor::new(raw.to_vec()), Some(raw.len() as u64)).unwrap();
        let mut n = 0u64;
        while src.next_frame().unwrap().is_some() {
            n += 1;
        }
        n
    }

    #[test]
    fn linktype_roundtrips_known_dlts() {
        assert_eq!(LinkType::from_u32(1), LinkType::Ethernet);
        assert_eq!(LinkType::from_u32(0), LinkType::Null);
        assert_eq!(LinkType::from_u32(101), LinkType::Raw);
        assert_eq!(LinkType::from_u32(113), LinkType::LinuxSll);
        assert_eq!(LinkType::from_u32(276), LinkType::LinuxSll2);
        assert_eq!(LinkType::from_u32(228), LinkType::RawIpv4);
        assert_eq!(LinkType::from_u32(229), LinkType::RawIpv6);
        assert_eq!(LinkType::from_u32(9999), LinkType::Unsupported(9999));
    }

    #[test]
    fn linktype_display_tokens_are_canonical() {
        assert_eq!(LinkType::Ethernet.as_str(), "EN10MB");
        assert_eq!(LinkType::RawIpv4.as_str(), "IPV4");
        assert_eq!(LinkType::RawIpv6.as_str(), "IPV6");
        assert_eq!(LinkType::Raw.as_str(), "RAW");
        assert_eq!(LinkType::LinuxSll.as_str(), "LINUX_SLL");
        assert_eq!(LinkType::LinuxSll2.as_str(), "LINUX_SLL2");
        assert_eq!(LinkType::Null.as_str(), "NULL");
        assert_eq!(LinkType::Unsupported(7).as_str(), "UNSUPPORTED");
    }

    #[test]
    fn sniff_recognizes_all_magics_and_endiannesses() {
        assert_eq!(
            Magic::sniff(&[0xa1, 0xb2, 0xc3, 0xd4]),
            Some(Magic::PcapLeUs)
        );
        assert_eq!(
            Magic::sniff(&[0xd4, 0xc3, 0xb2, 0xa1]),
            Some(Magic::PcapBeUs)
        );
        assert_eq!(
            Magic::sniff(&[0xa1, 0xb2, 0x3c, 0x4d]),
            Some(Magic::PcapLeNs)
        );
        assert_eq!(
            Magic::sniff(&[0x4d, 0x3c, 0xb2, 0xa1]),
            Some(Magic::PcapBeNs)
        );
        assert_eq!(Magic::sniff(&[0x0a, 0x0d, 0x0d, 0x0a]), Some(Magic::PcapNg));
        // gzip is decided on the first two bytes only.
        assert_eq!(Magic::sniff(&[0x1f, 0x8b, 0x08, 0x00]), Some(Magic::Gzip));
        assert_eq!(Magic::sniff(&[0xde, 0xad, 0xbe, 0xef]), None);
    }

    #[test]
    fn nanos_flag_only_for_ns_magics() {
        assert!(Magic::PcapLeNs.is_nanos());
        assert!(Magic::PcapBeNs.is_nanos());
        assert!(!Magic::PcapLeUs.is_nanos());
        assert!(!Magic::PcapBeUs.is_nanos());
    }

    #[test]
    fn prefix_reader_replays_peeked_bytes_then_inner() {
        // Peek four bytes off a 6-byte stream, then read everything back via the
        // PrefixReader: the full original sequence must be reproduced byte-for-byte.
        let original = [10u8, 11, 12, 13, 14, 15];
        let (head, filled, mut prefixed) = peek4(&original[..]).unwrap();
        assert_eq!(filled, 4);
        assert_eq!(&head, &[10, 11, 12, 13]);

        let mut out = Vec::new();
        prefixed.read_to_end(&mut out).unwrap();
        assert_eq!(out, original);
    }

    #[test]
    fn prefix_reader_handles_tiny_buffers() {
        // Read one byte at a time to exercise the prefix/inner boundary.
        let original = [1u8, 2, 3, 4, 5];
        let (_h, _f, mut prefixed) = peek4(&original[..]).unwrap();
        let mut out = Vec::new();
        let mut one = [0u8; 1];
        loop {
            match prefixed.read(&mut one).unwrap() {
                0 => break,
                n => out.extend_from_slice(&one[..n]),
            }
        }
        assert_eq!(out, original);
    }

    #[test]
    fn peek4_reports_short_streams() {
        let original = [0xa1u8, 0xb2];
        let (_head, filled, _prefixed) = peek4(&original[..]).unwrap();
        assert_eq!(filled, 2);
    }

    #[test]
    fn open_reader_short_stream_is_truncated() {
        let data = [0x1fu8, 0x8b]; // only two bytes
        let err = match open_reader(std::io::Cursor::new(data.to_vec()), None) {
            Ok(_) => panic!("expected an error, got a reader"),
            Err(e) => e,
        };
        match err {
            PpError::Truncated {
                needed,
                had,
                offset,
            } => {
                assert_eq!(needed, 4);
                assert_eq!(had, 2);
                assert_eq!(offset, 0);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn open_reader_unknown_magic_is_unknown_format() {
        let data = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x00];
        let err = match open_reader(std::io::Cursor::new(data.to_vec()), None) {
            Ok(_) => panic!("expected an error, got a reader"),
            Err(e) => e,
        };
        match err {
            PpError::UnknownFormat(hex) => assert_eq!(hex, "0xdeadbeef"),
            other => panic!("expected UnknownFormat, got {other:?}"),
        }
    }

    #[test]
    fn open_reader_dispatches_pcap_magic_without_panicking() {
        // A bare classic-pcap global header (24 bytes, LE µs, DLT=1) and no records. The
        // reader must construct and yield a clean EOF on first frame, never panicking.
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic LE µs
        hdr.extend_from_slice(&2u16.to_le_bytes()); // version major
        hdr.extend_from_slice(&4u16.to_le_bytes()); // version minor
        hdr.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        hdr.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        hdr.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        hdr.extend_from_slice(&1u32.to_le_bytes()); // network = EN10MB

        let mut src = open_reader(std::io::Cursor::new(hdr), None).unwrap();
        assert_eq!(src.link_type(), LinkType::Ethernet);
        // No records: first frame is a clean EOF.
        let frame = src.next_frame().unwrap();
        assert!(frame.is_none());
    }

    // ---------------------------------------------------------------------------
    // Gzip transparency tests
    // ---------------------------------------------------------------------------

    #[test]
    fn open_reader_transparently_inflates_a_gzipped_pcap() {
        let raw = make_pcap_bytes(3);
        let n_raw = count_frames(&raw);
        assert!(n_raw > 0, "synth pcap must have frames");

        // Gzip the raw capture.
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&raw).unwrap();
        let gz = enc.finish().unwrap();

        // open_reader must transparently inflate and yield the same frame count.
        let mut src = open_reader(std::io::Cursor::new(gz.clone()), Some(gz.len() as u64)).unwrap();
        let mut n_gz = 0u64;
        while src.next_frame().unwrap().is_some() {
            n_gz += 1;
        }
        assert_eq!(n_gz, n_raw);
    }

    #[test]
    fn open_reader_rejects_nested_gzip() {
        let raw = make_pcap_bytes(1);
        let gz1 = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(&raw).unwrap();
            e.finish().unwrap()
        };
        let gz2 = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(&gz1).unwrap();
            e.finish().unwrap()
        };
        let err = open_reader(std::io::Cursor::new(gz2), None)
            .err()
            .expect("nested gzip must return an error");
        assert!(
            matches!(err, PpError::UnknownFormat(_)),
            "expected UnknownFormat for nested gzip"
        );
    }

    #[test]
    fn open_reader_corrupt_gzip_errors_without_panic() {
        // Valid gzip two-byte magic + garbage → inflate fails at read time → typed error, no panic.
        let bad = vec![
            0x1f, 0x8b, 0x08, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01, 0x02,
        ];
        let res = (|| -> Result<()> {
            let mut src = open_reader(std::io::Cursor::new(bad), None)?;
            while src.next_frame()?.is_some() {}
            Ok(())
        })();
        assert!(res.is_err(), "corrupt gzip must produce an error");
    }
}
