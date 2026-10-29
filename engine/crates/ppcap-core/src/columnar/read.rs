//! Streaming reader for the flow Parquet table — the in-engine counterpart of the DuckDB view.
//!
//! [`scan_flows`] decodes one record batch at a time into [`FlowRow`]s and hands each to a
//! visitor, so memory stays bounded by the batch size however many flows the file holds. Columns
//! are looked up by name, so a file from an older schema version that lacks a later (nullable)
//! column still reads, with that field `None`.

use std::path::Path;

use arrow_array::{
    Array, BooleanArray, RecordBatch, StringArray, TimestampNanosecondArray, UInt16Array,
    UInt64Array, UInt8Array,
};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use serde::Serialize;

use crate::{PpError, Result};

/// Rows decoded per record batch.
const BATCH_ROWS: usize = 8192;

/// One flow as persisted (initiator-oriented `src`/`dst`, `c2s`/`s2c`), minus the columns an
/// investigator rarely reads (TTL, per-side TCP flags, entropy, capture id).
#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct FlowRow {
    pub flow_id: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    /// IANA L4 protocol number (6 TCP, 17 UDP, 1 ICMP, ...).
    pub proto: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_proto: Option<String>,
    pub bytes_c2s: u64,
    pub bytes_s2c: u64,
    pub pkts: u64,
    pub start_ns: i64,
    pub end_ns: i64,
    pub category: String,
    pub severity: String,
    pub threat_score: u16,
    pub ioc: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_ua: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja3s: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja4s: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hassh: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hassh_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_banner: Option<String>,
}

impl FlowRow {
    /// Total bytes in both directions.
    pub fn bytes(&self) -> u64 {
        self.bytes_c2s.saturating_add(self.bytes_s2c)
    }
}

fn col<'a, T: 'static>(batch: &'a RecordBatch, name: &str) -> Option<&'a T> {
    batch.column_by_name(name)?.as_any().downcast_ref::<T>()
}

fn need<'a, T: 'static>(batch: &'a RecordBatch, name: &str) -> Result<&'a T> {
    col(batch, name).ok_or_else(|| {
        PpError::Columnar(format!(
            "flow parquet: column {name} missing or of the wrong type"
        ))
    })
}

fn opt_str(a: Option<&StringArray>, i: usize) -> Option<String> {
    let a = a?;
    if a.is_null(i) {
        None
    } else {
        Some(a.value(i).to_string())
    }
}

/// Stream every flow in the Parquet file at `path` through `visit`, in file order. `visit`
/// returns `false` to stop early. Returns the number of rows visited.
pub fn scan_flows(path: &Path, mut visit: impl FnMut(FlowRow) -> bool) -> Result<u64> {
    let file = std::fs::File::open(path)
        .map_err(|e| PpError::io(format!("open flows parquet {}", path.display()), e))?;
    let reader = ParquetRecordBatchReaderBuilder::try_new(file)
        .map_err(|e| PpError::Columnar(e.to_string()))?
        .with_batch_size(BATCH_ROWS)
        .build()
        .map_err(|e| PpError::Columnar(e.to_string()))?;

    let mut seen: u64 = 0;
    for batch in reader {
        let batch = batch.map_err(|e| PpError::Columnar(e.to_string()))?;
        let flow_id = need::<UInt64Array>(&batch, "flow_id")?;
        let src_ip = need::<StringArray>(&batch, "src_ip")?;
        let dst_ip = need::<StringArray>(&batch, "dst_ip")?;
        let src_port = need::<UInt16Array>(&batch, "src_port")?;
        let dst_port = need::<UInt16Array>(&batch, "dst_port")?;
        let proto = need::<UInt8Array>(&batch, "proto")?;
        let bytes_c2s = need::<UInt64Array>(&batch, "bytes_c2s")?;
        let bytes_s2c = need::<UInt64Array>(&batch, "bytes_s2c")?;
        let pkts = need::<UInt64Array>(&batch, "pkts")?;
        let start_ts = need::<TimestampNanosecondArray>(&batch, "start_ts")?;
        let end_ts = need::<TimestampNanosecondArray>(&batch, "end_ts")?;
        let category = need::<StringArray>(&batch, "category")?;
        let severity = need::<StringArray>(&batch, "severity")?;
        let threat_score = need::<UInt16Array>(&batch, "threat_score")?;
        let ioc = need::<BooleanArray>(&batch, "ioc")?;
        let app_proto = col::<StringArray>(&batch, "app_proto");
        let sni = col::<StringArray>(&batch, "sni");
        let http_host = col::<StringArray>(&batch, "http_host");
        let http_ua = col::<StringArray>(&batch, "http_ua");
        let ja3 = col::<StringArray>(&batch, "ja3");
        let ja4 = col::<StringArray>(&batch, "ja4");
        let ja3s = col::<StringArray>(&batch, "ja3s");
        let ja4s = col::<StringArray>(&batch, "ja4s");
        let tls_version = col::<StringArray>(&batch, "tls_version");
        let hassh = col::<StringArray>(&batch, "hassh");
        let hassh_server = col::<StringArray>(&batch, "hassh_server");
        let ssh_banner = col::<StringArray>(&batch, "ssh_banner");

        for i in 0..batch.num_rows() {
            seen += 1;
            let row = FlowRow {
                flow_id: flow_id.value(i),
                src_ip: src_ip.value(i).to_string(),
                dst_ip: dst_ip.value(i).to_string(),
                src_port: src_port.value(i),
                dst_port: dst_port.value(i),
                proto: proto.value(i),
                app_proto: opt_str(app_proto, i),
                bytes_c2s: bytes_c2s.value(i),
                bytes_s2c: bytes_s2c.value(i),
                pkts: pkts.value(i),
                start_ns: start_ts.value(i),
                end_ns: end_ts.value(i),
                category: category.value(i).to_string(),
                severity: severity.value(i).to_string(),
                threat_score: threat_score.value(i),
                ioc: ioc.value(i),
                sni: opt_str(sni, i),
                http_host: opt_str(http_host, i),
                http_ua: opt_str(http_ua, i),
                ja3: opt_str(ja3, i),
                ja4: opt_str(ja4, i),
                ja3s: opt_str(ja3s, i),
                ja4s: opt_str(ja4s, i),
                tls_version: opt_str(tls_version, i),
                hassh: opt_str(hassh, i),
                hassh_server: opt_str(hassh_server, i),
                ssh_banner: opt_str(ssh_banner, i),
            };
            if !visit(row) {
                return Ok(seen);
            }
        }
    }
    Ok(seen)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::columnar::write_flows_parquet;
    use crate::model::category::Category;
    use crate::model::flow::{FlowKey, FlowRecord};
    use crate::model::packet::Transport;
    use std::net::{IpAddr, Ipv4Addr};

    fn rec(lo: u8, hi: u8, port: u16, app: &str, sni: Option<&str>) -> FlowRecord {
        let key = FlowKey {
            lo_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, lo)),
            hi_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, hi)),
            lo_port: 50000,
            hi_port: port,
            transport: Transport::Tcp,
        };
        let mut r = FlowRecord::new(key, 1_000);
        r.last_ts_ns = 2_000;
        r.pkts_fwd = 3;
        r.bytes_fwd = 300;
        r.bytes_rev = 700;
        r.category = Category::Web;
        r.app_proto = app.to_string();
        r.sni = sni.map(str::to_string);
        r.hassh_server = Some("0123456789abcdef0123456789abcdef".into());
        r
    }

    #[test]
    fn scan_round_trips_written_flows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.parquet");
        let flows = vec![
            rec(1, 2, 443, "https", Some("example.org")),
            rec(1, 3, 80, "", None),
        ];
        write_flows_parquet(&path, &flows).unwrap();

        let mut rows = Vec::new();
        let n = scan_flows(&path, |r| {
            rows.push(r);
            true
        })
        .unwrap();
        assert_eq!(n, 2);
        assert_eq!(rows[0].dst_port, 443);
        assert_eq!(rows[0].app_proto.as_deref(), Some("https"));
        assert_eq!(rows[0].sni.as_deref(), Some("example.org"));
        assert_eq!(rows[0].bytes(), 1_000);
        assert_eq!(rows[0].proto, 6);
        assert_eq!(
            rows[0].hassh_server.as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
        assert_eq!(rows[0].category, "web");
        assert_eq!(rows[1].app_proto, None);
        assert_eq!(rows[1].start_ns, 1_000);
        assert_eq!(rows[1].end_ns, 2_000);
    }

    #[test]
    fn scan_stops_when_visitor_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.parquet");
        let flows = vec![rec(1, 2, 443, "https", None), rec(1, 3, 80, "http", None)];
        write_flows_parquet(&path, &flows).unwrap();
        let n = scan_flows(&path, |_| false).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn scan_reports_a_missing_file() {
        let err = scan_flows(Path::new("/nonexistent/flows.parquet"), |_| true).unwrap_err();
        assert!(err.to_string().contains("flows parquet"));
    }
}
