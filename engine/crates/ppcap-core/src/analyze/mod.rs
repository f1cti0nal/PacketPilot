//! The single-pass analysis orchestrator.
//!
//! Wires the stages together: reader -> decode -> stats(packet) + flow.observe, with
//! periodic flow eviction whose sink classifies (consulting the scanner spread) and feeds
//! stats(flow) + the optional Parquet writer; at EOF all remaining flows drain through the
//! same sink, then `stats.finish()` materializes the [`Summary`] into an [`AnalysisOutput`].
//! One streaming pass; bounded memory.

use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::classify::{Classifier, ClassifyConfig};
use crate::columnar::{FlowParquetWriter, WriterConfig};
use crate::detect::{
    contact_from_flow, detect_beacons, detect_exfil, detect_sweeps, BeaconParams, BehaviorTracker,
    DetectConfig, ExfilParams, SweepParams,
};
use crate::enrich::{Enricher, ThreatFeed};
use crate::flow::{FlowConfig, FlowTable};
use crate::model::flow::FlowRecord;
use crate::model::output::AnalysisOutput;
use crate::reader::PacketSource;
use crate::score::score_flow;
use crate::stats::{StatsAccumulator, StatsConfig};
use crate::{PpError, Result};

/// JSON/output schema version emitted in [`AnalysisOutput::schema_version`].
const SCHEMA_VERSION: u32 = 1;

/// End-to-end pipeline configuration (composes every stage's config).
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Where to write the flows Parquet, or `None` to skip persistence.
    pub flows_parquet: Option<PathBuf>,
    /// Local IOC threat-feed JSON for offline enrichment; `None` => no enrichment.
    pub threat_feed: Option<PathBuf>,
    /// Run flow eviction every N packets.
    pub evict_interval_pkts: u64,
    /// Compute the source SHA-256 (an extra read pass).
    pub hash_source: bool,
    /// Abort on the first malformed packet instead of counting & continuing.
    pub strict_decode: bool,
    pub flow: FlowConfig,
    pub classify: ClassifyConfig,
    pub stats: StatsConfig,
    pub writer: WriterConfig,
    /// Beaconing-detector tuning (cross-flow behavioral detection).
    pub beacon: BeaconParams,
    /// Data-exfiltration-detector tuning.
    pub exfil: ExfilParams,
    /// Host-sweep-detector tuning.
    pub sweep: SweepParams,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        PipelineConfig {
            flows_parquet: None,
            threat_feed: None,
            // Drain cadence for closed/cap-evicted flows. Kept small so the cap-eviction
            // victim buffer (`pending`) cannot accumulate up to a full interval of flows
            // between drains — that buffer, not the live map, was the residual peak-heap
            // growth on worst-case (~1 flow/packet) captures. Output is identical regardless
            // of cadence (each flow is processed exactly once); only peak working set changes.
            evict_interval_pkts: 16_384,
            hash_source: false,
            strict_decode: false,
            flow: FlowConfig::default(),
            classify: ClassifyConfig::default(),
            stats: StatsConfig::default(),
            writer: WriterConfig::default(),
            beacon: BeaconParams::default(),
            exfil: ExfilParams::default(),
            sweep: SweepParams::default(),
        }
    }
}

/// Run the full Phase-0 pipeline on a file. `progress(pkts_done, bytes_done, size_hint)`
/// is called periodically (route it to stderr or ignore).
pub fn run(
    path: &Path,
    cfg: &PipelineConfig,
    progress: impl FnMut(u64, u64, Option<u64>),
) -> Result<AnalysisOutput> {
    // 1. Provenance from the filesystem. `source_bytes` is the on-disk size; for a
    //    gzip-wrapped capture this is the compressed size, which is the correct on-disk
    //    figure to report (the decompressed byte count is not a file-level property).
    let source_bytes = std::fs::metadata(path)
        .map(|m| m.len())
        .map_err(|e| PpError::io(format!("stat {}", path.display()), e))?;

    // 2. Optionally hash the raw source in its own bounded streaming pass.
    let source_sha256 = if cfg.hash_source {
        Some(hash_file_sha256(path)?)
    } else {
        None
    };

    // 3. Open the (possibly gunzip-wrapped) source and run the single analysis pass.
    let source = crate::reader::open(path)?;
    let label = path.display().to_string();
    let mut out = run_source(source, &label, source_bytes, cfg, progress)?;

    // 4. Decorate with provenance the streaming pass cannot know.
    out.source_sha256 = source_sha256;
    Ok(out)
}

/// Run the pipeline over an already-opened source (used by tests and `run`).
pub fn run_source(
    source: Box<dyn PacketSource>,
    source_label: &str,
    source_bytes: u64,
    cfg: &PipelineConfig,
    mut progress: impl FnMut(u64, u64, Option<u64>),
) -> Result<AnalysisOutput> {
    if cfg.evict_interval_pkts == 0 {
        return Err(PpError::Config(
            "evict_interval_pkts must be non-zero".to_string(),
        ));
    }

    let start = Instant::now();
    let mut source = source;
    let link = source.link_type();
    let size_hint = source.size_hint();

    // Stage state. All bounded; nothing buffers the whole file or all packets.
    let mut flow = FlowTable::new(cfg.flow.clone());
    let classifier = Classifier::new(cfg.classify.clone());
    // Load the threat feed exactly once (fail fast on IO/parse/bad indicator).
    let enricher = Enricher::new(ThreatFeed::load_opt(cfg.threat_feed.as_deref())?);
    let mut stats = StatsAccumulator::new(cfg.stats.clone());
    // Cross-flow behavioral tracker: fed one "contact" per closed flow, queried at finish for
    // beaconing/sweep findings. Bounded like every other per-key map.
    let mut tracker = BehaviorTracker::new(DetectConfig::default());
    let mut writer: Option<FlowParquetWriter> = match &cfg.flows_parquet {
        Some(p) => Some(FlowParquetWriter::create(p, cfg.writer.clone())?),
        None => None,
    };

    // A fallible Parquet write inside an infallible `FnMut(FlowRecord)` eviction sink can't
    // propagate `?` directly, so the sink stashes the first write error here and the main
    // loop checks it after every eviction call. `detect_scans`/`scan_port_threshold` are
    // snapshotted so the sink doesn't need to borrow `cfg`.
    let detect_scans = cfg.classify.detect_scans;
    let scan_threshold = cfg.classify.scan_port_threshold;
    let mut sink_err: Option<PpError> = None;

    let mut pkts: u64 = 0;
    let mut bytes: u64 = 0;
    // Monotonic high-water packet clock used to drive idle/active flow expiry. A single
    // backward (clock-skewed / reordered) packet never lowers it, so flows are not evicted
    // prematurely. Seeded to `i64::MIN` so the first packet always sets it.
    let mut max_seen_ts: i64 = i64::MIN;

    // Single streaming pass.
    loop {
        // Bind the borrow of `source` only for the duration of decoding one frame so the
        // lending-iterator borrow is released before we touch other stages next iteration.
        let decoded = match source.next_frame() {
            Ok(None) => break, // clean EOF
            Ok(Some(frame)) => {
                let frame_bytes = frame.wire_len as u64;
                let decode_result = crate::decode::decode_frame(&frame);
                (frame_bytes, decode_result)
            }
            // Lenient mode: a torn/truncated final record (a non-fatal reader-level framing
            // error) means no more frames are recoverable. Count it like a malformed packet
            // and stop, reporting the frames already processed instead of failing the run.
            Err(e) if !cfg.strict_decode && !e.is_fatal() => {
                stats.record_decode_error();
                break;
            }
            // Strict mode, or a fatal reader error: propagate.
            Err(e) => return Err(e),
        };
        let (frame_bytes, decode_result) = decoded;

        match decode_result {
            Ok(meta) => {
                if meta.ts_ns > max_seen_ts {
                    max_seen_ts = meta.ts_ns;
                }
                stats.observe_packet(&meta);
                flow.observe(&meta);
            }
            Err(e) if !cfg.strict_decode && !e.is_fatal() => {
                // Lenient mode: a single malformed/truncated packet is counted, not fatal.
                stats.record_decode_error();
            }
            Err(e) => return Err(e), // strict mode, or a fatal error
        }

        pkts += 1;
        bytes += frame_bytes;

        if pkts % cfg.evict_interval_pkts == 0 {
            evict(
                &mut flow,
                max_seen_ts,
                &classifier,
                &enricher,
                detect_scans,
                scan_threshold,
                &mut stats,
                &mut tracker,
                &mut writer,
                &mut sink_err,
            );
            if let Some(e) = sink_err.take() {
                return Err(e);
            }
            progress(pkts, bytes, size_hint);
        }
    }

    // EOF: drain every remaining flow through the same classify/scan/stats/write sink.
    drain(
        &mut flow,
        &classifier,
        &enricher,
        detect_scans,
        scan_threshold,
        &mut stats,
        &mut tracker,
        &mut writer,
        &mut sink_err,
    );
    if let Some(e) = sink_err.take() {
        return Err(e);
    }

    // Final progress tick so callers see the terminal totals.
    progress(pkts, bytes, size_hint);

    // Cross-flow behavioral detection runs once, after every flow's contact has been folded in.
    // Its findings uplift the implicated hosts' per-IP threat cards *before* the summary sorts
    // and truncates them, so a beaconing host/C2 surfaces in the Top Threats panel.
    let mut findings = detect_beacons(&tracker, &cfg.beacon);
    findings.extend(detect_exfil(&tracker, &cfg.exfil));
    findings.extend(detect_sweeps(&tracker, &cfg.sweep));
    stats.apply_findings(&findings);

    // Materialize the summary (consumes stats) and finalize the Parquet file.
    let mut summary = stats.finish();
    summary.findings = findings;
    let flows_parquet_path = match writer {
        Some(w) => {
            w.close()?;
            cfg.flows_parquet.as_ref().map(|p| p.display().to_string())
        }
        None => None,
    };

    Ok(AnalysisOutput {
        schema_version: SCHEMA_VERSION,
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        source_path: source_label.to_string(),
        // `run_source` has no file handle to hash; `run` fills this in when requested.
        source_sha256: None,
        source_bytes,
        link_type: link.as_str().to_string(),
        summary,
        flows_parquet_path,
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

/// Classify, scan-uplift, count, and (optionally) persist one closed flow. Shared by both
/// the periodic-eviction and EOF-drain sinks so the two paths stay identical.
#[allow(clippy::too_many_arguments)]
fn process_flow(
    record: &mut FlowRecord,
    classifier: &Classifier,
    enricher: &Enricher,
    detect_scans: bool,
    scan_threshold: u32,
    stats: &mut StatsAccumulator,
    tracker: &mut BehaviorTracker,
    writer: &mut Option<FlowParquetWriter>,
    sink_err: &mut Option<PpError>,
) {
    classifier.classify(record);

    // Behavioral substrate: fold this connection's directed contact (client -> server:port at
    // the flow's start time, with directional bytes) into the cross-flow tracker for
    // beaconing / exfil detection.
    if let Some(c) = contact_from_flow(record) {
        tracker.observe_flow_contact(
            c.client,
            c.server,
            c.server_port,
            c.ts_ns,
            c.bytes_out,
            c.bytes_in,
        );
    }

    // Single-pass scan uplift: promote an UNNAMED flow to Scan when either endpoint is a
    // confirmed port-spraying scanner. Two guards prevent the over-firing that would
    // otherwise relabel every flow of a noisy host: (1) only uplift flows still `Unknown`
    // after port + shape classification, so a named service (Web/Dns/Tls/...) is never
    // clobbered; (2) check BOTH endpoints, since the scanner may sit on either side of the
    // byte-normalized key (`lo_ip` is the canonical-lower address, not necessarily the
    // flow initiator).
    if detect_scans
        && record.category == crate::model::category::Category::Unknown
        && (stats.is_scanner(record.key.lo_ip, scan_threshold)
            || stats.is_scanner(record.key.hi_ip, scan_threshold))
    {
        record.category = crate::model::category::Category::Scan;
    }

    // Enrich + score AFTER classify + scan uplift (so `record.category` is final) and BEFORE
    // the writer (so Parquet carries severity/score/ioc). Evidence is allocated only on match.
    let enr = enricher.enrich(record);
    let fm = enricher.feed_match(&enr);
    let scored = score_flow(record, &fm);
    record.severity = scored.severity;
    record.threat_score = scored.score;
    record.ioc = fm.any();

    stats.observe_flow(record);
    stats.observe_scored_flow(record, &scored);

    if let Some(w) = writer.as_mut() {
        if let Err(e) = w.write(record) {
            // Keep only the first error; later evictions are best-effort once we've failed.
            if sink_err.is_none() {
                *sink_err = Some(e);
            }
        }
    }
}

/// Drive periodic idle/active + cap eviction.
#[allow(clippy::too_many_arguments)]
fn evict(
    flow: &mut FlowTable,
    now_ns: i64,
    classifier: &Classifier,
    enricher: &Enricher,
    detect_scans: bool,
    scan_threshold: u32,
    stats: &mut StatsAccumulator,
    tracker: &mut BehaviorTracker,
    writer: &mut Option<FlowParquetWriter>,
    sink_err: &mut Option<PpError>,
) {
    flow.evict_expired(now_ns, |mut record| {
        process_flow(
            &mut record,
            classifier,
            enricher,
            detect_scans,
            scan_threshold,
            stats,
            tracker,
            writer,
            sink_err,
        );
    });
}

/// Drain all remaining flows at EOF.
#[allow(clippy::too_many_arguments)]
fn drain(
    flow: &mut FlowTable,
    classifier: &Classifier,
    enricher: &Enricher,
    detect_scans: bool,
    scan_threshold: u32,
    stats: &mut StatsAccumulator,
    tracker: &mut BehaviorTracker,
    writer: &mut Option<FlowParquetWriter>,
    sink_err: &mut Option<PpError>,
) {
    flow.drain_all(|mut record| {
        process_flow(
            &mut record,
            classifier,
            enricher,
            detect_scans,
            scan_threshold,
            stats,
            tracker,
            writer,
            sink_err,
        );
    });
}

/// Stream a file through a pure-Rust SHA-256 in bounded memory (64 KiB buffer), returning
/// the lowercase hex digest.
///
// NOTE TO INTEGRATOR: `Cargo.toml` intentionally pulls in NO hashing crate (the C-free /
// minimal-deps invariant in PROJECT-SPEC §7 forbids zstd/lz4-sys/duckdb/rand, and `sha2`
// would be an avoidable new dependency). Rather than fail when `--hash` is requested, this
// module ships a small, self-contained, FIPS-180-4 SHA-256 (unit-tested below against the
// published vectors). If you would rather depend on the `sha2` crate, delete `Sha256` and
// `hash_file_sha256` and call `sha2` here — no public signature changes.
fn hash_file_sha256(path: &Path) -> Result<String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)
        .map_err(|e| PpError::io(format!("open {}", path.display()), e))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| PpError::io(format!("read {}", path.display()), e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize_hex())
}

/// Minimal streaming SHA-256 (FIPS 180-4). No external dependencies; constant memory.
struct Sha256 {
    state: [u32; 8],
    /// Partial block buffer (0..64 bytes pending).
    block: [u8; 64],
    block_len: usize,
    /// Total message length in bytes (for the length padding).
    total_len: u64,
}

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    fn new() -> Self {
        Sha256 {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            block: [0u8; 64],
            block_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        // Top off any partial block first.
        if self.block_len > 0 {
            let need = 64 - self.block_len;
            let take = need.min(data.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&data[..take]);
            self.block_len += take;
            data = &data[take..];
            if self.block_len == 64 {
                let block = self.block;
                self.compress(&block);
                self.block_len = 0;
            }
        }

        // Consume full blocks directly from the input.
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }

        // Stash the remainder.
        if !data.is_empty() {
            self.block[..data.len()].copy_from_slice(data);
            self.block_len = data.len();
        }
    }

    fn finalize_hex(mut self) -> String {
        let bit_len = self.total_len.wrapping_mul(8);

        // Append 0x80 then zero-pad to a 56-byte boundary, then the 64-bit length.
        let mut pad = [0u8; 72];
        pad[0] = 0x80;
        let pad_len = if self.block_len < 56 {
            56 - self.block_len
        } else {
            120 - self.block_len
        };
        self.update_raw(&pad[..pad_len]);
        self.update_raw(&bit_len.to_be_bytes());
        debug_assert_eq!(self.block_len, 0);

        let mut hex = String::with_capacity(64);
        for word in self.state.iter() {
            for byte in word.to_be_bytes() {
                hex.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
                hex.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
            }
        }
        hex
    }

    /// Like `update` but does NOT advance `total_len` (used for padding).
    fn update_raw(&mut self, mut data: &[u8]) {
        if self.block_len > 0 {
            let need = 64 - self.block_len;
            let take = need.min(data.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&data[..take]);
            self.block_len += take;
            data = &data[take..];
            if self.block_len == 64 {
                let block = self.block;
                self.compress(&block);
                self.block_len = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.block[..data.len()].copy_from_slice(data);
            self.block_len = data.len();
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for (i, &wi) in w.iter().enumerate() {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(wi);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256_hex(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize_hex()
    }

    #[test]
    fn sha256_known_vectors() {
        // FIPS 180-4 / NIST published test vectors.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn sha256_chunked_matches_one_shot() {
        // Cross a block boundary in several pieces to exercise the partial-block buffer.
        let msg: Vec<u8> = (0u8..=200).cycle().take(1000).collect();
        let one_shot = sha256_hex(&msg);

        let mut h = Sha256::new();
        for chunk in msg.chunks(7) {
            h.update(chunk);
        }
        assert_eq!(h.finalize_hex(), one_shot);
    }

    #[test]
    fn sha256_exact_block_multiple() {
        // Exactly 64 and 128 bytes: padding pushes into a fresh block (block_len >= 56 path).
        let one = sha256_hex(&[0xABu8; 64]);
        let two = sha256_hex(&[0xABu8; 128]);
        assert_ne!(one, two);
        // Stable values computed with a reference implementation.
        assert_eq!(
            sha256_hex(&[0u8; 64]),
            "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
        );
    }

    #[test]
    fn hash_file_streams_in_bounded_memory() {
        use std::io::Write;
        let mut tf = tempfile::NamedTempFile::new().expect("temp file");
        // Larger than the 64 KiB streaming buffer to exercise multi-read accumulation.
        let payload = vec![0x5Au8; 200_000];
        tf.write_all(&payload).expect("write");
        tf.flush().expect("flush");

        let got = hash_file_sha256(tf.path()).expect("hash");
        assert_eq!(got, sha256_hex(&payload));
        assert_eq!(got.len(), 64);
        assert!(got.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn pipeline_config_default_is_lenient_no_parquet() {
        let cfg = PipelineConfig::default();
        assert!(cfg.flows_parquet.is_none());
        assert_eq!(cfg.evict_interval_pkts, 16_384);
        assert!(!cfg.hash_source);
        assert!(!cfg.strict_decode);
    }

    #[test]
    fn schema_version_is_one() {
        assert_eq!(SCHEMA_VERSION, 1);
    }

    /// One TLS-ClientHello frame (Ethernet+IPv4+TCP PSH/ACK) from `client:sport` to
    /// `server:443`, built from the same frame helpers the generator uses.
    fn tls_frame(client: std::net::Ipv4Addr, sport: u16, server: std::net::Ipv4Addr) -> Vec<u8> {
        use crate::gen::frames;
        let payload = frames::tls_client_hello_payload("c2.example");
        let tcp = frames::build_tcp(
            client,
            server,
            sport,
            443,
            frames::TCP_PSH | frames::TCP_ACK,
            &payload,
        );
        let ip = frames::build_ipv4(client, server, frames::IP_PROTO_TCP, 64, tcp.len());
        let mut frame = frames::build_ethernet(
            [0x02, 0, 0, 0, 0, 1],
            [0x02, 0, 0, 0, 0, 2],
            frames::ETHERTYPE_IPV4,
        );
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&tcp);
        frame
    }

    #[test]
    fn pipeline_surfaces_beacon_finding_without_threat_feed() {
        use crate::gen::container;
        use std::io::Write;
        use std::net::Ipv4Addr;

        let client = Ipv4Addr::new(10, 0, 0, 5);
        let c2 = Ipv4Addr::new(8, 8, 8, 8); // public => external => High severity
        let base: i64 = 1_700_000_000 * 1_000_000_000;
        let period: i64 = 60 * 1_000_000_000; // 60s callbacks

        // Build an in-memory pcap: 16 regular callbacks, each a distinct flow (new ephemeral
        // source port), so the tracker sees 16 contacts to (client -> c2:443).
        let mut buf: Vec<u8> = Vec::new();
        container::write_pcap_header(&mut buf, crate::reader::LinkType::Ethernet).unwrap();
        for i in 0..16i64 {
            let frame = tls_frame(client, 50_000 + i as u16, c2);
            let ts = base + i * period;
            let wire = frame.len() as u32;
            container::write_legacy_record(&mut buf, ts, wire, wire).unwrap();
            buf.write_all(&frame).unwrap();
        }

        let mut tf = tempfile::NamedTempFile::new().unwrap();
        tf.write_all(&buf).unwrap();
        tf.flush().unwrap();

        // Default config: NO threat feed loaded — any High verdict comes from behavior alone.
        let out = run(tf.path(), &PipelineConfig::default(), |_, _, _| {}).unwrap();

        let beacons: Vec<_> = out
            .summary
            .findings
            .iter()
            .filter(|f| f.kind == crate::model::finding::FindingKind::Beacon)
            .collect();
        assert_eq!(beacons.len(), 1, "findings: {:?}", out.summary.findings);
        let b = beacons[0];
        assert_eq!(b.src_ip, "10.0.0.5");
        assert_eq!(b.dst_ip.as_deref(), Some("8.8.8.8"));
        assert_eq!(b.dst_port, Some(443));
        assert_eq!(b.severity, crate::model::severity::Severity::High);
        assert!(b.contacts.unwrap() >= 6, "contacts: {:?}", b.contacts);

        // The finding must also UPLIFT the C2's per-IP threat card (Top Threats panel), again
        // with no threat feed — proving behavior alone drives the host's verdict to High.
        let c2_card = out
            .summary
            .ip_threats
            .iter()
            .find(|t| t.ip == "8.8.8.8")
            .expect("c2 threat card present");
        assert_eq!(c2_card.severity, crate::model::severity::Severity::High);
        assert!(c2_card.score >= 70, "c2 card score: {}", c2_card.score);
        assert!(c2_card.attack.iter().any(|a| a == "T1071"));
    }

    #[test]
    fn generated_beacon_scenario_is_detected_as_high() {
        use crate::gen::{GenConfig, Scenario, SynthGen};
        use crate::model::finding::FindingKind;
        use crate::model::severity::Severity;

        // A large capture (many cycles) is the case that previously let benign background form
        // a spurious low-jitter channel; keep it big enough to guard that regression.
        let cfg = GenConfig {
            scenario: Scenario::Beacon,
            packets: 40_000,
            seed: 1,
            // Many hosts => background channels stay sparse (few contacts each), so benign
            // traffic does not accumulate enough contacts to be mistaken for a beacon.
            host_count: 256,
            ..Default::default()
        };
        let tf = tempfile::NamedTempFile::new().unwrap();
        let mut g = SynthGen::new(cfg);
        g.write_pcap(tf.path()).unwrap();

        // No threat feed: the verdict must come from the beacon's periodicity alone.
        let out = run(tf.path(), &PipelineConfig::default(), |_, _, _| {}).unwrap();

        let beacons: Vec<_> = out
            .summary
            .findings
            .iter()
            .filter(|f| f.kind == FindingKind::Beacon)
            .collect();
        assert!(
            !beacons.is_empty(),
            "no beacon finding: {:?}",
            out.summary.findings
        );
        // The real C2 callback is an external High beacon...
        let real = beacons
            .iter()
            .find(|b| b.severity == Severity::High)
            .unwrap_or_else(|| panic!("no High beacon: {beacons:?}"));
        assert!(real.contacts.unwrap() >= 6, "contacts: {:?}", real.contacts);
        // ...and the benign background must NOT trip any spurious beacon.
        assert!(
            beacons.iter().all(|b| b.severity == Severity::High),
            "background produced a spurious beacon: {beacons:?}"
        );
        // The C2 it dials is surfaced as a High threat card (no threat feed involved).
        let c2 = real.dst_ip.clone().unwrap();
        assert!(
            out.summary
                .ip_threats
                .iter()
                .any(|t| t.ip == c2 && t.severity == Severity::High),
            "c2 {c2} not High in ip_threats"
        );
    }

    #[test]
    fn pipeline_surfaces_exfil_finding_without_threat_feed() {
        use crate::gen::{container, frames};
        use std::io::Write;
        use std::net::Ipv4Addr;

        let client = Ipv4Addr::new(10, 0, 0, 5);
        let ext = Ipv4Addr::new(8, 8, 8, 8); // external destination
        let base: i64 = 1_700_000_000 * 1_000_000_000;

        let mut buf: Vec<u8> = Vec::new();
        container::write_pcap_header(&mut buf, crate::reader::LinkType::Ethernet).unwrap();

        // One flow, heavily asymmetric: ~75 KB uploaded client -> ext:443 over 60 data packets...
        let payload = vec![0xABu8; 1200];
        let push = |buf: &mut Vec<u8>, frame: &[u8], ts: i64| {
            let wl = frame.len() as u32;
            container::write_legacy_record(buf, ts, wl, wl).unwrap();
            buf.write_all(frame).unwrap();
        };
        for i in 0..60i64 {
            let tcp = frames::build_tcp(
                client,
                ext,
                50000,
                443,
                frames::TCP_PSH | frames::TCP_ACK,
                &payload,
            );
            let ip = frames::build_ipv4(client, ext, frames::IP_PROTO_TCP, 64, tcp.len());
            let mut frame = frames::build_ethernet(
                [0x02, 0, 0, 0, 0, 1],
                [0x02, 0, 0, 0, 0, 2],
                frames::ETHERTYPE_IPV4,
            );
            frame.extend_from_slice(&ip);
            frame.extend_from_slice(&tcp);
            push(&mut buf, &frame, base + i * 1_000_000);
        }
        // ...with only a few tiny inbound acks.
        for i in 0..3i64 {
            let tcp = frames::build_tcp(ext, client, 443, 50000, frames::TCP_ACK, &[]);
            let ip = frames::build_ipv4(ext, client, frames::IP_PROTO_TCP, 64, tcp.len());
            let mut frame = frames::build_ethernet(
                [0x02, 0, 0, 0, 0, 2],
                [0x02, 0, 0, 0, 0, 1],
                frames::ETHERTYPE_IPV4,
            );
            frame.extend_from_slice(&ip);
            frame.extend_from_slice(&tcp);
            push(&mut buf, &frame, base + (60 + i) * 1_000_000);
        }

        let mut tf = tempfile::NamedTempFile::new().unwrap();
        tf.write_all(&buf).unwrap();
        tf.flush().unwrap();

        // Low exfil floor so the ~75 KB upload trips it; NO threat feed.
        let cfg = PipelineConfig {
            exfil: crate::detect::ExfilParams {
                enabled: true,
                min_bytes_out: 50_000,
                min_ratio: 4.0,
                critical_bytes_out: 100_000_000,
            },
            ..PipelineConfig::default()
        };
        let out = run(tf.path(), &cfg, |_, _, _| {}).unwrap();

        let exfil = out
            .summary
            .findings
            .iter()
            .find(|f| f.kind == crate::model::finding::FindingKind::DataExfil)
            .unwrap_or_else(|| panic!("no exfil finding: {:?}", out.summary.findings));
        assert_eq!(exfil.severity, crate::model::severity::Severity::High);
        assert_eq!(exfil.dst_ip.as_deref(), Some("8.8.8.8"));
        assert_eq!(exfil.src_ip, "10.0.0.5");
        assert!(exfil.attack.iter().any(|a| a == "T1048"));
        // The external peer is surfaced as a High threat card (behavior alone).
        assert!(
            out.summary
                .ip_threats
                .iter()
                .any(|t| t.ip == "8.8.8.8" && t.severity == crate::model::severity::Severity::High),
            "exfil peer not High in ip_threats"
        );
    }

    #[test]
    fn pipeline_surfaces_host_sweep_finding_without_threat_feed() {
        use crate::gen::{container, frames};
        use std::io::Write;
        use std::net::Ipv4Addr;

        let attacker = Ipv4Addr::new(10, 0, 0, 9);
        let base: i64 = 1_700_000_000 * 1_000_000_000;

        let mut buf: Vec<u8> = Vec::new();
        container::write_pcap_header(&mut buf, crate::reader::LinkType::Ethernet).unwrap();

        // One SYN to port 445 on each of 20 distinct hosts — a horizontal SMB sweep. Distinct
        // destination hosts make distinct flows even with a shared source port.
        for last in 1..=20i64 {
            let target = Ipv4Addr::new(10, 0, 1, last as u8);
            let tcp = frames::build_tcp(attacker, target, 40000, 445, frames::TCP_SYN, &[]);
            let ip = frames::build_ipv4(attacker, target, frames::IP_PROTO_TCP, 64, tcp.len());
            let mut frame = frames::build_ethernet(
                [0x02, 0, 0, 0, 0, 9],
                [0x02, 0, 0, 0, 0, last as u8],
                frames::ETHERTYPE_IPV4,
            );
            frame.extend_from_slice(&ip);
            frame.extend_from_slice(&tcp);
            let ts = base + last * 1_000_000;
            let wl = frame.len() as u32;
            container::write_legacy_record(&mut buf, ts, wl, wl).unwrap();
            buf.write_all(&frame).unwrap();
        }

        let mut tf = tempfile::NamedTempFile::new().unwrap();
        tf.write_all(&buf).unwrap();
        tf.flush().unwrap();

        // No threat feed: the sweep verdict comes from the fan-out alone.
        let out = run(tf.path(), &PipelineConfig::default(), |_, _, _| {}).unwrap();

        let sweep = out
            .summary
            .findings
            .iter()
            .find(|f| f.kind == crate::model::finding::FindingKind::HostSweep)
            .unwrap_or_else(|| panic!("no sweep finding: {:?}", out.summary.findings));
        assert_eq!(sweep.severity, crate::model::severity::Severity::High);
        assert_eq!(sweep.src_ip, "10.0.0.9");
        assert_eq!(sweep.dst_port, Some(445));
        assert!(sweep.attack.iter().any(|a| a == "T1046"));
        // The scanning host is surfaced as a High threat card.
        assert!(
            out.summary
                .ip_threats
                .iter()
                .any(|t| t.ip == "10.0.0.9" && t.severity == crate::model::severity::Severity::High),
            "sweeper not High in ip_threats"
        );
    }
}
