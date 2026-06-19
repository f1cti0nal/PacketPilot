//! Ingest metrics and the Phase-0 performance budget.
//!
//! [`IngestMetrics`] captures throughput + peak heap for one analyze run; [`Phase0Budget`]
//! checks them against the headline guarantees. The peak-heap reading comes from a
//! `peak_alloc` global allocator that is installed **only** in `benches/ingest.rs` — in the
//! shipped binary [`peak_heap_bytes`] returns 0 (system allocator, no instrumentation).

use std::time::Duration;

/// Measured metrics for one ingest.
#[derive(Debug, Clone, Copy)]
pub struct IngestMetrics {
    pub packets: u64,
    /// Σ wire_len processed.
    pub wire_bytes: u64,
    pub wall: Duration,
    /// From `peak_alloc`; 0 outside bench/test.
    pub peak_heap_bytes: u64,
}

impl IngestMetrics {
    /// Packets per second over the wall clock.
    pub fn packets_per_sec(&self) -> f64 {
        let s = self.wall.as_secs_f64();
        if s <= 0.0 {
            0.0
        } else {
            self.packets as f64 / s
        }
    }

    /// MiB/s of wire bytes over the wall clock.
    pub fn mb_per_sec(&self) -> f64 {
        let s = self.wall.as_secs_f64();
        if s <= 0.0 {
            0.0
        } else {
            (self.wire_bytes as f64 / (1024.0 * 1024.0)) / s
        }
    }

    /// Peak heap in MiB.
    pub fn peak_heap_mib(&self) -> f64 {
        self.peak_heap_bytes as f64 / (1024.0 * 1024.0)
    }
}

/// Read the global peak allocator. Returns 0 unless the `peak_alloc` global allocator is
/// installed (bench binary only).
pub fn peak_heap_bytes() -> u64 {
    // The `peak_alloc` dependency is dev-only and the global allocator is installed ONLY in
    // `benches/ingest.rs`. The library/binary build therefore has no `PEAK` to read and uses
    // the system allocator with no instrumentation, so this is a const 0 here. The bench
    // binary reads (and resets) its own `PEAK` static directly for the real measurement.
    0
}

/// Reset the global peak allocator's high-water mark (call before each measured iteration).
pub fn reset_peak_heap() {
    // No-op in the library/binary build (no instrumented allocator is installed). The bench
    // binary resets its own `PEAK` static directly before each measured iteration.
}

/// The Phase-0 perf budget.
#[derive(Debug, Clone, Copy)]
pub struct Phase0Budget {
    pub min_packets_per_sec: f64,
    pub min_mb_per_sec: f64,
    pub max_peak_heap_bytes: u64,
    pub max_wall: Duration,
}

impl Phase0Budget {
    /// Check metrics against the budget; `Ok(())` or a human-readable list of violations.
    pub fn check(&self, m: &IngestMetrics) -> Result<(), String> {
        let mut violations: Vec<String> = Vec::new();
        let pps = m.packets_per_sec();
        if pps < self.min_packets_per_sec {
            violations.push(format!(
                "packets/sec {pps:.0} < min {:.0}",
                self.min_packets_per_sec
            ));
        }
        let mbps = m.mb_per_sec();
        if mbps < self.min_mb_per_sec {
            violations.push(format!(
                "MiB/sec {mbps:.1} < min {:.1}",
                self.min_mb_per_sec
            ));
        }
        if m.peak_heap_bytes > self.max_peak_heap_bytes {
            violations.push(format!(
                "peak heap {} bytes > max {} bytes",
                m.peak_heap_bytes, self.max_peak_heap_bytes
            ));
        }
        if m.wall > self.max_wall {
            violations.push(format!("wall {:?} > max {:?}", m.wall, self.max_wall));
        }
        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations.join("; "))
        }
    }
}

/// The binding Phase-0 budget (see README perf table).
pub const PHASE0_BUDGET: Phase0Budget = Phase0Budget {
    min_packets_per_sec: 250_000.0, // >= 250k pps on the synthetic mix, 1 core
    min_mb_per_sec: 40.0,           // >= 40 MiB/s of wire bytes on the synthetic mix, which is
    // tiny-frame / packet-bound (~83 B avg); real MTU traffic
    // at the same packet rate is an order of magnitude higher
    max_peak_heap_bytes: 64 * 1024 * 1024, // <= 64 MiB peak heap -- INDEPENDENT of pcap size
    max_wall: Duration::from_secs(2),      // 100k pkts < 2s
};
