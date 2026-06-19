//! Criterion ingest benchmark (`harness = false`).
//!
//! Measures `analyze::run` only — captures are pre-generated to a tempfile so generation
//! cost is excluded. This is the ONLY place the `peak_alloc` global allocator is installed,
//! so the shipped binary keeps the system allocator. Budget assertions live in the golden
//! test (not here) so `cargo bench` never fails the build.

use std::time::Instant;

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};

// The single global-allocator declaration for the whole project (bench binary only).
#[global_allocator]
static PEAK: peak_alloc::PeakAlloc = peak_alloc::PeakAlloc;

use ppcap_core::analyze::{self, PipelineConfig};
use ppcap_core::gen::{GenConfig, Scenario, SynthGen};

/// Pre-generate a Mixed capture of `packets` frames to a tempfile and return
/// `(path, frame_bytes)` for throughput accounting.
fn make_capture(packets: u64) -> (tempfile::TempPath, u64) {
    let tf = tempfile::NamedTempFile::new().unwrap();
    let mut g = SynthGen::new(GenConfig {
        scenario: Scenario::Mixed,
        packets,
        ..Default::default()
    });
    let manifest = g.write_pcap(tf.path()).unwrap();
    (tf.into_temp_path(), manifest.frame_bytes)
}

fn bench_ingest(c: &mut Criterion) {
    let mut group = c.benchmark_group("ingest");
    let cfg = PipelineConfig::default();
    for &n in &[10_000u64, 100_000, 1_000_000] {
        let (path, frame_bytes) = make_capture(n);
        group.throughput(Throughput::Bytes(frame_bytes));
        group.bench_function(format!("mixed_{n}"), |b| {
            b.iter_batched(
                || PEAK.reset_peak_usage(),
                |_| {
                    let no_progress: fn(u64, u64, Option<u64>) = |_, _, _| {};
                    black_box(analyze::run(&path, &cfg, no_progress).unwrap())
                },
                BatchSize::PerIteration,
            );
        });

        // One out-of-band timed run to report headline pps / MiB-s / peak heap / wall. This
        // reads the instrumented `PEAK` static directly (the library's metrics helpers are
        // const-0 no-ops because the allocator is only installed here).
        PEAK.reset_peak_usage();
        let start = Instant::now();
        let no_progress: fn(u64, u64, Option<u64>) = |_, _, _| {};
        let _out = black_box(analyze::run(&path, &cfg, no_progress).unwrap());
        let wall = start.elapsed();
        let peak_bytes = PEAK.peak_usage() as u64;
        let secs = wall.as_secs_f64().max(f64::MIN_POSITIVE);
        let pps = n as f64 / secs;
        let mibps = (frame_bytes as f64 / (1024.0 * 1024.0)) / secs;
        let peak_mib = peak_bytes as f64 / (1024.0 * 1024.0);
        eprintln!(
            "[ingest mixed_{n}] {pps:.0} pps, {mibps:.1} MiB/s, peak {peak_mib:.2} MiB, wall {wall:?}"
        );
    }
    group.finish();
}

criterion_group!(benches, bench_ingest);
criterion_main!(benches);
