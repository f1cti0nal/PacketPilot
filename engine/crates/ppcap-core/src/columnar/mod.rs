//! Columnar output: the Snappy-Parquet flow writer.
//!
//! Buffers [`FlowRecord`]s into Arrow array builders matching [`schema::flow_arrow_schema`]
//! and flushes them as row groups via `parquet`'s `ArrowWriter`. Snappy is the on-disk
//! codec (pure-Rust; the default). `lz4_flex` is the only opt-in escalation; zstd/gzip/
//! brotli are not exposed and are unreachable by construction (parquet built with
//! `default-features = false`, features `arrow,snap,base64,lz4`).
//!
//! Memory stays bounded: at most one row group (`row_group_size` rows) is held in builders
//! before being flushed and the builders reset.

pub mod schema;

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use arrow_array::builder::{
    BooleanBuilder, StringBuilder, TimestampNanosecondBuilder, UInt16Builder, UInt64Builder,
    UInt8Builder,
};
use arrow_array::{ArrayRef, RecordBatch};
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression as ParquetCompression;
use parquet::file::metadata::KeyValue;
use parquet::file::properties::{WriterProperties, WriterVersion};
use parquet::schema::types::ColumnPath;

use crate::model::flow::FlowRecord;
use crate::{PpError, Result};

use schema::{flow_arrow_schema, FLOW_PARQUET_VERSION};

/// KV-metadata keys written to the Parquet footer.
const KV_FLOW_SCHEMA_VERSION: &str = "ppcap.flow_schema_version";
const KV_CAPTURE_ID: &str = "ppcap.capture_id";
const KV_ENGINE_VERSION: &str = "ppcap.engine_version";
const KV_TS_PRECISION: &str = "ppcap.ts_precision";
const KV_ROW_COUNT: &str = "ppcap.row_count";

/// On-disk compression codec. Deliberately a closed set — NO Zstd/Gzip/Brotli variant.
#[derive(Debug, Clone, Copy)]
pub enum Compression {
    None,
    Snappy,
    Lz4,
}

impl Compression {
    /// Map to the underlying `parquet` codec. `Lz4` maps to `LZ4_RAW` (the modern,
    /// interoperable LZ4 framing), matching the `lz4` parquet feature.
    fn to_parquet(self) -> ParquetCompression {
        match self {
            Compression::None => ParquetCompression::UNCOMPRESSED,
            Compression::Snappy => ParquetCompression::SNAPPY,
            Compression::Lz4 => ParquetCompression::LZ4_RAW,
        }
    }
}

/// Writer tuning.
#[derive(Debug, Clone)]
pub struct WriterConfig {
    pub capture_id: u64,
    pub row_group_size: usize,
    pub compression: Compression,
    pub engine_version: String,
}

impl Default for WriterConfig {
    fn default() -> Self {
        WriterConfig {
            capture_id: 0,
            row_group_size: 32_768,
            compression: Compression::Snappy,
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Column builders for one in-flight row group. Field order mirrors
/// [`schema::flow_arrow_schema`] exactly so [`Builders::finish`] can assemble the
/// `RecordBatch` columns in canonical order.
struct Builders {
    flow_id: UInt64Builder,
    capture_id: UInt64Builder,
    src_ip: StringBuilder,
    dst_ip: StringBuilder,
    src_port: UInt16Builder,
    dst_port: UInt16Builder,
    proto: UInt8Builder,
    app_proto: StringBuilder,
    bytes_c2s: UInt64Builder,
    bytes_s2c: UInt64Builder,
    pkts: UInt64Builder,
    start_ts: TimestampNanosecondBuilder,
    end_ts: TimestampNanosecondBuilder,
    tcp_flags_c2s: UInt8Builder,
    tcp_flags_s2c: UInt8Builder,
    ttl_min_c2s: UInt8Builder,
    category: StringBuilder,
    app_proto_src: StringBuilder,
    sni: StringBuilder,
    severity: StringBuilder,
    threat_score: UInt16Builder,
    ioc: BooleanBuilder,
}

impl Builders {
    fn new() -> Builders {
        Builders {
            flow_id: UInt64Builder::new(),
            capture_id: UInt64Builder::new(),
            src_ip: StringBuilder::new(),
            dst_ip: StringBuilder::new(),
            src_port: UInt16Builder::new(),
            dst_port: UInt16Builder::new(),
            proto: UInt8Builder::new(),
            app_proto: StringBuilder::new(),
            bytes_c2s: UInt64Builder::new(),
            bytes_s2c: UInt64Builder::new(),
            pkts: UInt64Builder::new(),
            start_ts: TimestampNanosecondBuilder::new(),
            end_ts: TimestampNanosecondBuilder::new(),
            tcp_flags_c2s: UInt8Builder::new(),
            tcp_flags_s2c: UInt8Builder::new(),
            ttl_min_c2s: UInt8Builder::new(),
            category: StringBuilder::new(),
            app_proto_src: StringBuilder::new(),
            sni: StringBuilder::new(),
            severity: StringBuilder::new(),
            threat_score: UInt16Builder::new(),
            ioc: BooleanBuilder::new(),
        }
    }

    /// Consume the builders into a `RecordBatch` matching [`flow_arrow_schema`].
    ///
    /// The two timestamp arrays are stamped with the `"UTC"` timezone so their `DataType`
    /// equals the schema's `Timestamp(Nanosecond, Some("UTC"))`; otherwise
    /// `RecordBatch::try_new` would reject them on a datatype mismatch.
    fn finish(&mut self) -> Result<RecordBatch> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.flow_id.finish()),
            Arc::new(self.capture_id.finish()),
            Arc::new(self.src_ip.finish()),
            Arc::new(self.dst_ip.finish()),
            Arc::new(self.src_port.finish()),
            Arc::new(self.dst_port.finish()),
            Arc::new(self.proto.finish()),
            Arc::new(self.app_proto.finish()),
            Arc::new(self.bytes_c2s.finish()),
            Arc::new(self.bytes_s2c.finish()),
            Arc::new(self.pkts.finish()),
            Arc::new(self.start_ts.finish().with_timezone("UTC")),
            Arc::new(self.end_ts.finish().with_timezone("UTC")),
            Arc::new(self.tcp_flags_c2s.finish()),
            Arc::new(self.tcp_flags_s2c.finish()),
            Arc::new(self.ttl_min_c2s.finish()),
            Arc::new(self.category.finish()),
            Arc::new(self.app_proto_src.finish()),
            Arc::new(self.sni.finish()),
            Arc::new(self.severity.finish()),
            Arc::new(self.threat_score.finish()),
            Arc::new(self.ioc.finish()),
        ];
        // `?` converts arrow_schema::ArrowError -> PpError::Columnar via the From impl.
        Ok(RecordBatch::try_new(flow_arrow_schema(), columns)?)
    }
}

/// Render an [`IpAddr`] to its canonical string for the `src_ip`/`dst_ip` columns.
///
/// `IpAddr`'s `Display` is already canonical (IPv6 uses the lowercase, zero-compressed
/// RFC 5952 form), so this is a thin wrapper kept for intent and testability.
fn canonical_ip(ip: IpAddr) -> String {
    ip.to_string()
}

/// Streaming Parquet writer for the flow table.
pub struct FlowParquetWriter {
    writer: ArrowWriter<std::fs::File>,
    builders: Builders,
    cfg: WriterConfig,
    /// Monotonic flow id, assigned at write time.
    next_flow_id: u64,
    /// Rows currently buffered in `builders` (not yet flushed as a row group).
    buffered_rows: usize,
    /// Total rows handed to [`FlowParquetWriter::write`].
    rows_written: u64,
}

impl FlowParquetWriter {
    /// Create `path` and configure writer properties + KV metadata.
    pub fn create(path: &Path, cfg: WriterConfig) -> Result<FlowParquetWriter> {
        let dict_cols = [
            "src_ip",
            "dst_ip",
            "app_proto",
            "category",
            "app_proto_src",
            "sni",
            "severity",
        ];

        let mut props = WriterProperties::builder()
            .set_compression(cfg.compression.to_parquet())
            .set_writer_version(WriterVersion::PARQUET_2_0)
            // Dictionary off globally; switched on for the low-cardinality string columns.
            .set_dictionary_enabled(false)
            .set_data_page_size_limit(1 << 20)
            .set_max_row_group_row_count(Some(cfg.row_group_size))
            // No `sorting_columns` hint is advertised: while the EOF drain emits flows in a
            // deterministic (first_ts, last_ts, 5-tuple) order, periodic cap/idle eviction
            // flushes earlier batches in LRU/last_ts order, so the file is NOT globally
            // start-ts-sorted. Claiming a sort would mislead readers that trust the hint.
            .set_key_value_metadata(Some(vec![
                KeyValue::new(
                    KV_FLOW_SCHEMA_VERSION.to_string(),
                    FLOW_PARQUET_VERSION.to_string(),
                ),
                KeyValue::new(KV_CAPTURE_ID.to_string(), cfg.capture_id.to_string()),
                KeyValue::new(KV_ENGINE_VERSION.to_string(), cfg.engine_version.clone()),
                KeyValue::new(KV_TS_PRECISION.to_string(), "ns".to_string()),
                // row_count is provisional here and overwritten on close().
                KeyValue::new(KV_ROW_COUNT.to_string(), "0".to_string()),
            ]));

        for col in dict_cols {
            props = props.set_column_dictionary_enabled(ColumnPath::from(col), true);
        }
        let props = props.build();

        let file = std::fs::File::create(path)
            .map_err(|e| PpError::io(format!("create flow parquet {}", path.display()), e))?;

        let writer = ArrowWriter::try_new(file, flow_arrow_schema(), Some(props))?;

        Ok(FlowParquetWriter {
            writer,
            builders: Builders::new(),
            cfg,
            next_flow_id: 0,
            buffered_rows: 0,
            rows_written: 0,
        })
    }

    /// Append one flow row (may flush a full row group).
    pub fn write(&mut self, rec: &FlowRecord) -> Result<()> {
        // Snapshot scalar fields before borrowing `builders`, keeping the borrow checker
        // and the reader happy (no interleaved self-field access during the &mut borrow).
        let flow_id = self.next_flow_id;
        self.next_flow_id += 1;
        let capture_id = self.cfg.capture_id;

        let b = &mut self.builders;

        b.flow_id.append_value(flow_id);
        b.capture_id.append_value(capture_id);
        b.src_ip.append_value(canonical_ip(rec.key.lo_ip));
        b.dst_ip.append_value(canonical_ip(rec.key.hi_ip));
        b.src_port.append_value(rec.key.lo_port);
        b.dst_port.append_value(rec.key.hi_port);
        b.proto.append_value(rec.key.transport.ip_proto());

        // app_proto is nullable: empty string -> NULL.
        if rec.app_proto.is_empty() {
            b.app_proto.append_null();
        } else {
            b.app_proto.append_value(&rec.app_proto);
        }

        b.bytes_c2s.append_value(rec.bytes_fwd);
        b.bytes_s2c.append_value(rec.bytes_rev);
        b.pkts.append_value(rec.total_pkts());
        b.start_ts.append_value(rec.first_ts_ns);
        b.end_ts.append_value(rec.last_ts_ns);
        b.tcp_flags_c2s.append_value(rec.tcp_flags_fwd);
        b.tcp_flags_s2c.append_value(rec.tcp_flags_rev);
        b.ttl_min_c2s.append_value(rec.ttl_min_fwd);
        b.category.append_value(rec.category.as_str());
        // app_proto_src derivation: Some("payload"|"port") or NULL.
        match rec.app_proto_src {
            Some(s) => b.app_proto_src.append_value(s),
            None => b.app_proto_src.append_null(),
        }
        // sni: present only for observed TLS SNI; NULL otherwise.
        match &rec.sni {
            Some(h) if !h.is_empty() => b.sni.append_value(h),
            _ => b.sni.append_null(),
        }
        // Phase-2 verdict columns (never NULL).
        b.severity.append_value(rec.severity.as_str());
        b.threat_score.append_value(rec.threat_score);
        b.ioc.append_value(rec.ioc);

        self.buffered_rows += 1;
        self.rows_written += 1;

        if self.buffered_rows >= self.cfg.row_group_size {
            self.flush_batch()?;
        }
        Ok(())
    }

    /// Build the buffered rows into a `RecordBatch`, write it, and reset the builders.
    /// No-op when nothing is buffered.
    fn flush_batch(&mut self) -> Result<()> {
        if self.buffered_rows == 0 {
            return Ok(());
        }
        let batch = self.builders.finish();
        // Always reset builders, even on a finish() error, so a retry does not double-write.
        self.buffered_rows = 0;
        let batch = batch?;
        self.writer.write(&batch)?;
        Ok(())
    }

    /// Rows written so far.
    pub fn rows_written(&self) -> u64 {
        self.rows_written
    }

    /// Flush remaining rows, finalize KV metadata (row_count), and close the file.
    pub fn close(mut self) -> Result<()> {
        self.flush_batch()?;
        // Overwrite the provisional row_count with the final tally. `append_key_value_metadata`
        // appends; on read the last value for a key wins, so this reflects the true count.
        self.writer.append_key_value_metadata(KeyValue::new(
            KV_ROW_COUNT.to_string(),
            self.rows_written.to_string(),
        ));
        self.writer.close()?;
        Ok(())
    }
}

/// Write a complete slice of [`FlowRecord`]s to a Snappy-compressed Parquet file at `path`,
/// using [`WriterConfig::default`] (capture_id 0, 122 880-row groups, Snappy).
///
/// This is the one-shot convenience entry point; for streaming use [`FlowParquetWriter`]
/// directly. Records are written in slice order (no sort hint is written to the footer), so
/// callers wanting a `start_ts`-ascending file should pre-sort the slice themselves.
pub fn write_flows_parquet(path: &Path, flows: &[FlowRecord]) -> Result<u64> {
    let mut w = FlowParquetWriter::create(path, WriterConfig::default())?;
    for rec in flows {
        w.write(rec)?;
    }
    let n = w.rows_written();
    w.close()?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::category::Category;
    use crate::model::flow::{FlowKey, FlowRecord};
    use crate::model::packet::Transport;
    use std::net::Ipv4Addr;

    fn rec(app_proto: &str, cat: Category) -> FlowRecord {
        let key = FlowKey {
            lo_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            hi_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            lo_port: 1234,
            hi_port: 443,
            transport: Transport::Tcp,
        };
        let mut r = FlowRecord::new(key, 1_000);
        r.last_ts_ns = 2_000;
        r.pkts_fwd = 3;
        r.pkts_rev = 5;
        r.bytes_fwd = 300;
        r.bytes_rev = 500;
        r.tcp_flags_fwd = 0x02;
        r.tcp_flags_rev = 0x12;
        r.ttl_min_fwd = 64;
        r.category = cat;
        r.app_proto = app_proto.to_string();
        r
    }

    #[test]
    fn canonical_ip_is_rfc5952_lowercase() {
        let v6: IpAddr = "2001:DB8::1".parse().unwrap();
        // Canonical form is lowercase and zero-compressed.
        assert_eq!(canonical_ip(v6), "2001:db8::1");
        let v4: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(canonical_ip(v4), "192.168.1.1");
    }

    #[test]
    fn compression_maps_to_expected_codec() {
        assert!(matches!(
            Compression::Snappy.to_parquet(),
            ParquetCompression::SNAPPY
        ));
        assert!(matches!(
            Compression::None.to_parquet(),
            ParquetCompression::UNCOMPRESSED
        ));
        assert!(matches!(
            Compression::Lz4.to_parquet(),
            ParquetCompression::LZ4_RAW
        ));
    }

    #[test]
    fn default_config_values() {
        let c = WriterConfig::default();
        assert_eq!(c.capture_id, 0);
        assert_eq!(c.row_group_size, 32_768);
        assert!(matches!(c.compression, Compression::Snappy));
        assert_eq!(c.engine_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn finish_builds_batch_with_canonical_schema_and_values() {
        let mut b = Builders::new();
        // Append two rows directly to exercise the timestamp-timezone stamping and column
        // order without going through the file writer.
        for (i, app) in [("dns", true), ("", false)].into_iter().enumerate() {
            b.flow_id.append_value(i as u64);
            b.capture_id.append_value(7);
            b.src_ip.append_value("10.0.0.1");
            b.dst_ip.append_value("10.0.0.2");
            b.src_port.append_value(1234);
            b.dst_port.append_value(443);
            b.proto.append_value(6);
            if app.0.is_empty() {
                b.app_proto.append_null();
            } else {
                b.app_proto.append_value(app.0);
            }
            b.bytes_c2s.append_value(300);
            b.bytes_s2c.append_value(500);
            b.pkts.append_value(8);
            b.start_ts.append_value(1_000);
            b.end_ts.append_value(2_000);
            b.tcp_flags_c2s.append_value(0x02);
            b.tcp_flags_s2c.append_value(0x12);
            b.ttl_min_c2s.append_value(64);
            b.category.append_value("web");
            b.app_proto_src.append_null();
            b.sni.append_null();
            b.severity.append_value("info");
            b.threat_score.append_value(0);
            b.ioc.append_value(false);
            let _ = app.1;
        }
        let batch = b.finish().expect("finish");
        assert_eq!(batch.num_rows(), 2);
        assert_eq!(batch.num_columns(), 22);
        // Schema must equal the canonical schema (column names, types incl. tz).
        assert_eq!(batch.schema(), flow_arrow_schema());
    }

    #[test]
    fn write_close_counts_rows_and_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flow.parquet");
        let flows = vec![
            rec("https", Category::Web),
            rec("", Category::Unknown),
            rec("dns", Category::Dns),
        ];
        let n = write_flows_parquet(&path, &flows).expect("write");
        assert_eq!(n, 3);
        let meta = std::fs::metadata(&path).expect("file exists");
        assert!(meta.len() > 0);
    }

    #[test]
    fn small_row_group_size_flushes_multiple_groups() {
        // row_group_size of 2 with 5 rows -> 3 row groups (2 + 2 + 1). The writer must not
        // panic and rows_written must equal the input count.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flow_rg.parquet");
        let cfg = WriterConfig {
            row_group_size: 2,
            ..WriterConfig::default()
        };
        let mut w = FlowParquetWriter::create(&path, cfg).unwrap();
        for _ in 0..5 {
            w.write(&rec("ssh", Category::RemoteAccess)).unwrap();
        }
        assert_eq!(w.rows_written(), 5);
        w.close().unwrap();
        assert!(std::fs::metadata(&path).unwrap().len() > 0);
    }
}
