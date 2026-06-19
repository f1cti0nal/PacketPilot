//! Generator container byte-exactness + cross-validation against `pcap-file`.

use ppcap_core::gen::{GenConfig, Scenario, SynthGen};

fn gen_config(packets: u64, seed: u64) -> GenConfig {
    GenConfig {
        scenario: Scenario::Mixed,
        packets,
        seed,
        host_count: 8,
        ..Default::default()
    }
}

#[test]
fn legacy_global_header_exact_bytes() {
    let mut buf = Vec::new();
    SynthGen::new(gen_config(2, 1)).write_to(&mut buf).unwrap();
    assert!(
        buf.len() > 24 + 16,
        "must hold header + at least one record"
    );

    // Global header (24 bytes, little-endian µs magic).
    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    assert_eq!(magic, 0xa1b2_c3d4);
    assert_eq!(u16::from_le_bytes([buf[4], buf[5]]), 2); // version major
    assert_eq!(u16::from_le_bytes([buf[6], buf[7]]), 4); // version minor
    assert_eq!(
        u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
        65535
    ); // snaplen
    assert_eq!(u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]), 1); // DLT EN10MB

    // First record header begins at offset 24.
    let caplen = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);
    let origlen = u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]);
    assert!(caplen > 0);
    assert_eq!(
        caplen, origlen,
        "generator does not truncate captured length"
    );
    let start_secs = 1_700_000_000u32; // default start ts
    assert_eq!(
        u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]),
        start_secs
    );
}

#[test]
fn cross_validate_with_pcap_file() {
    use pcap_file::pcap::PcapReader;

    let mut buf = Vec::new();
    let manifest = SynthGen::new(gen_config(50, 9)).write_to(&mut buf).unwrap();
    assert_eq!(manifest.packets_written, 50);

    let mut reader = PcapReader::new(std::io::Cursor::new(buf)).expect("open generated pcap");
    let mut count = 0u64;
    let mut last_ts_ns: i64 = 0;
    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt.expect("read packet");
        count += 1;
        // pcap-file exposes the timestamp as a Duration since the epoch.
        last_ts_ns = pkt.timestamp.as_nanos() as i64;
    }
    assert_eq!(
        count, 50,
        "pcap-file must read exactly the generated packet count"
    );

    // The generator wrote microsecond-resolution records, so compare at microsecond precision.
    assert_eq!(
        last_ts_ns / 1_000,
        manifest.last_ts_ns / 1_000,
        "last timestamp must agree at microsecond resolution"
    );
}
