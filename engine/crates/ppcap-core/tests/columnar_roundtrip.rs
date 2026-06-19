//! Parquet write -> read-back: column values, KV metadata, Snappy codec, row count.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use arrow_array::{Array, BooleanArray, StringArray, UInt16Array, UInt64Array};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use ppcap_core::columnar::schema::FLOW_PARQUET_VERSION;
use ppcap_core::columnar::{FlowParquetWriter, WriterConfig};
use ppcap_core::model::category::Category;
use ppcap_core::model::flow::{FlowKey, FlowRecord};
use ppcap_core::model::packet::Transport;
use ppcap_core::model::severity::Severity;

// Test helper: each arg maps to a distinct FlowKey/FlowRecord field; collapsing
// them into a struct would just mirror those types and add noise.
#[allow(clippy::too_many_arguments)]
fn rec(
    lo_ip: IpAddr,
    hi_ip: IpAddr,
    lo_port: u16,
    hi_port: u16,
    transport: Transport,
    app_proto: &str,
    cat: Category,
    bytes_fwd: u64,
    bytes_rev: u64,
    pkts_fwd: u64,
    pkts_rev: u64,
) -> FlowRecord {
    let key = FlowKey {
        lo_ip,
        hi_ip,
        lo_port,
        hi_port,
        transport,
    };
    let mut r = FlowRecord::new(key, 1_000);
    r.last_ts_ns = 2_000;
    r.bytes_fwd = bytes_fwd;
    r.bytes_rev = bytes_rev;
    r.pkts_fwd = pkts_fwd;
    r.pkts_rev = pkts_rev;
    r.tcp_flags_fwd = 0x02;
    r.tcp_flags_rev = 0x12;
    r.ttl_min_fwd = 64;
    r.category = cat;
    r.app_proto = app_proto.to_string();
    // Phase-2 verdict columns: distinct non-default values; per-row variation (incl. an
    // ioc=false row) is applied in the test body.
    r.severity = Severity::High;
    r.threat_score = 72;
    r.ioc = true;
    r
}

#[test]
fn write_then_read_flow_parquet() {
    let v4a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v4b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let v6a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let v6b = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));

    let mut flows = vec![
        rec(
            v4a,
            v4b,
            1234,
            443,
            Transport::Tcp,
            "https",
            Category::Web,
            300,
            500,
            3,
            5,
        ),
        rec(
            v4a,
            v4b,
            5000,
            53,
            Transport::Udp,
            "dns",
            Category::Dns,
            40,
            80,
            1,
            1,
        ),
        // Empty app_proto -> NULL in the column.
        rec(
            v6a,
            v6b,
            40000,
            9999,
            Transport::Tcp,
            "",
            Category::Unknown,
            10,
            0,
            1,
            0,
        ),
    ];
    // Row 0 carries a payload-derived app_proto_src and an SNI host; the others leave both
    // NULL so the read-back exercises both the value and the NULL path.
    flows[0].app_proto_src = Some("payload");
    flows[0].sni = Some("api.example".to_string());
    // Vary the Phase-2 verdict columns per row, including an ioc=false / Info row so both
    // boolean states and a distinct severity token round-trip.
    flows[0].severity = Severity::Critical;
    flows[0].threat_score = 95;
    flows[0].ioc = true;
    flows[1].severity = Severity::Medium;
    flows[1].threat_score = 40;
    flows[1].ioc = true;
    flows[2].severity = Severity::Info;
    flows[2].threat_score = 0;
    flows[2].ioc = false;
    let n = flows.len();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("flow.parquet");

    let mut w = FlowParquetWriter::create(&path, WriterConfig::default()).unwrap();
    for r in &flows {
        w.write(r).unwrap();
    }
    assert_eq!(w.rows_written(), n as u64);
    w.close().unwrap();

    // Read back the footer metadata + all rows.
    let file = std::fs::File::open(&path).unwrap();
    let builder = ParquetRecordBatchReaderBuilder::try_new(file).unwrap();

    // --- KV metadata ---
    let meta = builder.metadata().clone();
    let kv = meta
        .file_metadata()
        .key_value_metadata()
        .expect("KV metadata present");
    let get = |key: &str| -> Option<String> {
        kv.iter()
            .rfind(|e| e.key == key)
            .and_then(|e| e.value.clone())
    };
    // Assert against the constant so a future version bump cannot drift from this test.
    assert_eq!(
        get("ppcap.flow_schema_version").as_deref(),
        Some(FLOW_PARQUET_VERSION.to_string().as_str())
    );
    assert_eq!(get("ppcap.ts_precision").as_deref(), Some("ns"));
    assert_eq!(
        get("ppcap.row_count").as_deref(),
        Some(n.to_string().as_str())
    );

    // --- Snappy codec on every column chunk ---
    for rg in meta.row_groups() {
        for col in rg.columns() {
            assert_eq!(
                col.compression(),
                parquet::basic::Compression::SNAPPY,
                "column {} not Snappy",
                col.column_path()
            );
        }
    }

    // --- Row values ---
    let reader = builder.build().unwrap();
    let mut total_rows = 0usize;
    let mut src_ips: Vec<String> = Vec::new();
    let mut app_protos: Vec<Option<String>> = Vec::new();
    let mut pkts: Vec<u64> = Vec::new();
    let mut app_proto_srcs: Vec<Option<String>> = Vec::new();
    let mut snis: Vec<Option<String>> = Vec::new();
    let mut severities: Vec<String> = Vec::new();
    let mut threat_scores: Vec<u16> = Vec::new();
    let mut iocs: Vec<bool> = Vec::new();
    for batch in reader {
        let batch = batch.unwrap();
        total_rows += batch.num_rows();

        let src = batch
            .column(2)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let app = batch
            .column(7)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let pk = batch
            .column(10)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .unwrap();
        let aps = batch
            .column(17)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let sni = batch
            .column(18)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let sev = batch
            .column(19)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let ts = batch
            .column(20)
            .as_any()
            .downcast_ref::<UInt16Array>()
            .unwrap();
        let ioc = batch
            .column(21)
            .as_any()
            .downcast_ref::<BooleanArray>()
            .unwrap();
        for i in 0..batch.num_rows() {
            src_ips.push(src.value(i).to_string());
            app_protos.push(if app.is_null(i) {
                None
            } else {
                Some(app.value(i).to_string())
            });
            pkts.push(pk.value(i));
            app_proto_srcs.push(if aps.is_null(i) {
                None
            } else {
                Some(aps.value(i).to_string())
            });
            snis.push(if sni.is_null(i) {
                None
            } else {
                Some(sni.value(i).to_string())
            });
            severities.push(sev.value(i).to_string());
            threat_scores.push(ts.value(i));
            iocs.push(ioc.value(i));
        }
    }

    assert_eq!(total_rows, n);
    // src_ip column == lo_ip (canonical string), including lowercase RFC 5952 IPv6.
    assert_eq!(src_ips[0], "10.0.0.1");
    assert_eq!(src_ips[2], "2001:db8::1");
    // pkts == pkts_fwd + pkts_rev.
    assert_eq!(pkts[0], 8);
    assert_eq!(pkts[1], 2);
    assert_eq!(pkts[2], 1);
    // app_proto NULL where the record's app_proto was empty.
    assert_eq!(app_protos[0].as_deref(), Some("https"));
    assert_eq!(app_protos[1].as_deref(), Some("dns"));
    assert_eq!(app_protos[2], None);
    // app_proto_src and sni: present on row 0 (payload-derived), NULL elsewhere.
    assert_eq!(app_proto_srcs[0].as_deref(), Some("payload"));
    assert_eq!(app_proto_srcs[1], None);
    assert_eq!(app_proto_srcs[2], None);
    assert_eq!(snis[0].as_deref(), Some("api.example"));
    assert_eq!(snis[1], None);
    assert_eq!(snis[2], None);
    // Phase-2 verdict columns round-trip: lowercase severity token, u16 score, bool ioc
    // (both boolean states exercised).
    assert_eq!(severities[0], "critical");
    assert_eq!(severities[1], "medium");
    assert_eq!(severities[2], "info");
    assert_eq!(threat_scores[0], 95);
    assert_eq!(threat_scores[1], 40);
    assert_eq!(threat_scores[2], 0);
    assert!(iocs[0]);
    assert!(iocs[1]);
    assert!(!iocs[2]);
}
