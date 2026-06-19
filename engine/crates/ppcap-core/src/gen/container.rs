//! pcap/pcapng container serialization for the generator.
//!
//! Writes the classic 24-byte global header + 16-byte per-record headers, or the pcapng
//! SHB/IDB/EPB block sequence. Byte layout must round-trip through both the engine's own
//! reader and the independent `pcap-file` crate (cross-validation test).

use crate::reader::LinkType;
use crate::PpError;
use crate::Result;

/// Classic pcap magic for microsecond-resolution timestamps, little-endian.
pub const PCAP_MAGIC_USEC_LE: u32 = 0xa1b2_c3d4;
/// pcapng Section Header Block type.
pub const NG_BLOCK_SHB: u32 = 0x0A0D_0D0A;
/// pcapng byte-order magic.
pub const NG_BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;
/// pcapng Interface Description Block type.
pub const NG_BLOCK_IDB: u32 = 0x0000_0001;
/// pcapng Enhanced Packet Block type.
pub const NG_BLOCK_EPB: u32 = 0x0000_0006;

const SNAPLEN: u32 = 65535;

/// Map a [`LinkType`] to its libpcap DLT number for the on-disk `network` field.
///
/// This mirrors the canonical libpcap values; it lives here (rather than depending on a
/// `LinkType::to_u32`, which the reader does not expose) so the generator is self-contained.
pub fn dlt_for(link: LinkType) -> u32 {
    match link {
        LinkType::Ethernet => 1,
        LinkType::Null => 0,
        LinkType::Raw => 101,
        LinkType::LinuxSll => 113,
        LinkType::LinuxSll2 => 276,
        LinkType::RawIpv4 => 228,
        LinkType::RawIpv6 => 229,
        LinkType::Unsupported(v) => v,
    }
}

/// Split an `i64` nanosecond timestamp into `(seconds, microseconds)` for the classic
/// microsecond magic. Negative timestamps (pre-epoch) are handled with floored division so
/// the microsecond remainder stays in `[0, 1_000_000)`.
fn split_secs_usec(ts_ns: i64) -> (u32, u32) {
    let secs = ts_ns.div_euclid(1_000_000_000);
    let sub_ns = ts_ns.rem_euclid(1_000_000_000);
    let usec = (sub_ns / 1_000) as u32;
    // Clamp seconds into u32 range defensively (captures use 2023-era stamps).
    let secs_u32 = secs.clamp(0, u32::MAX as i64) as u32;
    (secs_u32, usec)
}

/// Convert an `i64` nanosecond timestamp into raw nanosecond ticks since epoch for pcapng
/// `if_tsresol = 9`. Negative timestamps clamp to 0.
fn ns_ticks(ts_ns: i64) -> u64 {
    ts_ns.max(0) as u64
}

#[inline]
fn write_all<W: std::io::Write>(w: &mut W, buf: &[u8], ctx: &'static str) -> Result<()> {
    w.write_all(buf).map_err(|e| PpError::io(ctx, e))
}

/// Write the classic pcap 24-byte global header. Returns bytes written.
pub fn write_pcap_header<W: std::io::Write>(w: &mut W, link: LinkType) -> Result<usize> {
    let mut hdr = [0u8; 24];
    hdr[0..4].copy_from_slice(&PCAP_MAGIC_USEC_LE.to_le_bytes());
    hdr[4..6].copy_from_slice(&2u16.to_le_bytes()); // version_major
    hdr[6..8].copy_from_slice(&4u16.to_le_bytes()); // version_minor
    hdr[8..12].copy_from_slice(&0i32.to_le_bytes()); // thiszone
    hdr[12..16].copy_from_slice(&0u32.to_le_bytes()); // sigfigs
    hdr[16..20].copy_from_slice(&SNAPLEN.to_le_bytes()); // snaplen
    hdr[20..24].copy_from_slice(&dlt_for(link).to_le_bytes()); // network
    write_all(w, &hdr, "write pcap global header")?;
    Ok(24)
}

/// Write one classic 16-byte record header. Returns bytes written.
///
/// `caplen` bytes of frame data must be written by the caller immediately after.
pub fn write_legacy_record<W: std::io::Write>(
    w: &mut W,
    ts_ns: i64,
    caplen: u32,
    origlen: u32,
) -> Result<usize> {
    let (ts_sec, ts_usec) = split_secs_usec(ts_ns);
    let mut hdr = [0u8; 16];
    hdr[0..4].copy_from_slice(&ts_sec.to_le_bytes());
    hdr[4..8].copy_from_slice(&ts_usec.to_le_bytes());
    hdr[8..12].copy_from_slice(&caplen.to_le_bytes());
    hdr[12..16].copy_from_slice(&origlen.to_le_bytes());
    write_all(w, &hdr, "write pcap record header")?;
    Ok(16)
}

/// Write the pcapng SHB + a single IDB for `link`. Returns bytes written.
pub fn write_pcapng_shb_idb<W: std::io::Write>(w: &mut W, link: LinkType) -> Result<usize> {
    // --- Section Header Block (no options) ---
    // block_type(4) + block_total_len(4) + byte_order_magic(4) + major(2) + minor(2)
    //   + section_length(8) + block_total_len(4) = 28 bytes.
    let shb_len: u32 = 28;
    let mut shb = Vec::with_capacity(shb_len as usize);
    shb.extend_from_slice(&NG_BLOCK_SHB.to_le_bytes());
    shb.extend_from_slice(&shb_len.to_le_bytes());
    shb.extend_from_slice(&NG_BYTE_ORDER_MAGIC.to_le_bytes());
    shb.extend_from_slice(&1u16.to_le_bytes()); // version major
    shb.extend_from_slice(&0u16.to_le_bytes()); // version minor
    shb.extend_from_slice(&(-1i64).to_le_bytes()); // section length: unspecified
    shb.extend_from_slice(&shb_len.to_le_bytes());
    write_all(w, &shb, "write pcapng SHB")?;

    // --- Interface Description Block with one if_tsresol=9 option ---
    // block_type(4)+total_len(4)+linktype(2)+reserved(2)+snaplen(4) = 16 bytes base.
    // One option: code(2)+len(2)+value(1)+pad(3) = 8 bytes. opt_endofopt(4) = 4 bytes.
    // trailing total_len(4). Total = 16 + 8 + 4 + 4 = 32 bytes.
    let idb_len: u32 = 32;
    let mut idb = Vec::with_capacity(idb_len as usize);
    idb.extend_from_slice(&NG_BLOCK_IDB.to_le_bytes());
    idb.extend_from_slice(&idb_len.to_le_bytes());
    idb.extend_from_slice(&(dlt_for(link) as u16).to_le_bytes()); // linktype
    idb.extend_from_slice(&0u16.to_le_bytes()); // reserved
    idb.extend_from_slice(&SNAPLEN.to_le_bytes()); // snaplen
                                                   // Option if_tsresol (code 9), length 1, value 9 (10^-9 == nanoseconds), padded to 4.
    idb.extend_from_slice(&9u16.to_le_bytes()); // option code
    idb.extend_from_slice(&1u16.to_le_bytes()); // option length
    idb.push(9); // tsresol = 9 (nanoseconds)
    idb.extend_from_slice(&[0, 0, 0]); // pad to 32-bit boundary
    idb.extend_from_slice(&0u16.to_le_bytes()); // opt_endofopt code
    idb.extend_from_slice(&0u16.to_le_bytes()); // opt_endofopt length
    idb.extend_from_slice(&idb_len.to_le_bytes());
    write_all(w, &idb, "write pcapng IDB")?;

    Ok((shb_len + idb_len) as usize)
}

/// Write one pcapng Enhanced Packet Block. Returns bytes written.
pub fn write_epb<W: std::io::Write>(
    w: &mut W,
    iface_id: u32,
    ts_ns: i64,
    caplen: u32,
    origlen: u32,
    data: &[u8],
) -> Result<usize> {
    let cap = caplen as usize;
    // Defensive: only write up to `caplen` bytes of data, padded to a 32-bit boundary.
    let pad = (4 - (cap % 4)) % 4;
    // block_type(4) + total_len(4) + iface_id(4) + ts_high(4) + ts_low(4) + caplen(4)
    //   + origlen(4) + data(cap) + pad + total_len(4).
    let total_len = (28 + cap + pad + 4) as u32;
    let ticks = ns_ticks(ts_ns);
    let ts_high = (ticks >> 32) as u32;
    let ts_low = (ticks & 0xFFFF_FFFF) as u32;

    let mut blk = Vec::with_capacity(total_len as usize);
    blk.extend_from_slice(&NG_BLOCK_EPB.to_le_bytes());
    blk.extend_from_slice(&total_len.to_le_bytes());
    blk.extend_from_slice(&iface_id.to_le_bytes());
    blk.extend_from_slice(&ts_high.to_le_bytes());
    blk.extend_from_slice(&ts_low.to_le_bytes());
    blk.extend_from_slice(&caplen.to_le_bytes());
    blk.extend_from_slice(&origlen.to_le_bytes());
    let take = cap.min(data.len());
    blk.extend_from_slice(&data[..take]);
    // If caplen claimed more than data provided, zero-fill (should not happen in practice).
    blk.resize(blk.len() + (cap - take), 0);
    blk.resize(blk.len() + pad, 0);
    blk.extend_from_slice(&total_len.to_le_bytes());
    write_all(w, &blk, "write pcapng EPB")?;
    Ok(total_len as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_header_is_24_bytes_and_well_formed() {
        let mut buf = Vec::new();
        let n = write_pcap_header(&mut buf, LinkType::Ethernet).unwrap();
        assert_eq!(n, 24);
        assert_eq!(buf.len(), 24);
        assert_eq!(
            u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            PCAP_MAGIC_USEC_LE
        );
        assert_eq!(u16::from_le_bytes([buf[4], buf[5]]), 2); // major
        assert_eq!(u16::from_le_bytes([buf[6], buf[7]]), 4); // minor
        assert_eq!(
            u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
            SNAPLEN
        );
        assert_eq!(u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]), 1);
        // EN10MB
    }

    #[test]
    fn record_header_roundtrips() {
        let mut buf = Vec::new();
        // 1_700_000_000.123456789 s -> sec=1_700_000_000, usec=123_456.
        let ts = 1_700_000_000i64 * 1_000_000_000 + 123_456_789;
        let n = write_legacy_record(&mut buf, ts, 64, 80).unwrap();
        assert_eq!(n, 16);
        assert_eq!(
            u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            1_700_000_000
        );
        assert_eq!(
            u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            123_456
        );
        assert_eq!(u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]), 64);
        assert_eq!(u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]), 80);
    }

    #[test]
    fn split_secs_usec_handles_negative() {
        // -1 ns -> -1 s with 999_999 us (floored).
        let (s, u) = split_secs_usec(-1);
        // seconds clamp to 0 (defensive), but usec uses euclidean remainder.
        assert_eq!(s, 0);
        assert_eq!(u, 999_999);
    }

    #[test]
    fn dlt_mapping() {
        assert_eq!(dlt_for(LinkType::Ethernet), 1);
        assert_eq!(dlt_for(LinkType::Raw), 101);
        assert_eq!(dlt_for(LinkType::Unsupported(123)), 123);
    }

    #[test]
    fn ng_shb_idb_lengths_match_header_and_trailer() {
        let mut buf = Vec::new();
        let n = write_pcapng_shb_idb(&mut buf, LinkType::Ethernet).unwrap();
        assert_eq!(n, 60); // 28 + 32
        assert_eq!(buf.len(), 60);
        // SHB block type + leading/trailing length agree.
        assert_eq!(
            u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            NG_BLOCK_SHB
        );
        assert_eq!(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]), 28);
        assert_eq!(u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]), 28);
        // IDB starts at offset 28.
        assert_eq!(
            u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]),
            NG_BLOCK_IDB
        );
        assert_eq!(u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]), 32);
        assert_eq!(u32::from_le_bytes([buf[56], buf[57], buf[58], buf[59]]), 32);
    }

    #[test]
    fn epb_is_32bit_aligned_with_matching_lengths() {
        let mut buf = Vec::new();
        let data = [0xDEu8, 0xAD, 0xBE]; // 3 bytes -> 1 byte pad
        let n = write_epb(&mut buf, 0, 5, 3, 3, &data).unwrap();
        assert_eq!(n % 4, 0);
        assert_eq!(buf.len(), n);
        let total = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let trailer = u32::from_le_bytes([buf[n - 4], buf[n - 3], buf[n - 2], buf[n - 1]]);
        assert_eq!(total, trailer);
        assert_eq!(total as usize, n);
        assert_eq!(
            u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            NG_BLOCK_EPB
        );
    }
}
