//! # ppcap-core
//!
//! The PacketPilot Phase-0 analysis engine library. A C-compiler-free, streaming,
//! bounded-memory pipeline that ingests pcap/pcapng (optionally gzip-wrapped) captures
//! in a single pass and produces:
//!
//! - a capture-wide [`Summary`] (top talkers, protocol hierarchy, port/time histograms,
//!   category breakdown), and
//! - per-flow [`FlowRecord`]s persisted as Snappy-compressed Parquet for an external
//!   DuckDB sidecar to query via a view.
//!
//! ## Module map
//!
//! - [`model`] — the shared data contract (`PacketMeta`, `FlowKey`/`FlowRecord`,
//!   `Category`, `Summary`, `AnalysisOutput`). Every other module imports from here.
//! - [`error`] — the typed [`PpError`] and crate [`Result`].
//! - [`reader`] — magic-sniffing source factory + lending-iterator `PacketSource` trait.
//! - [`decode`] — raw frame -> `PacketMeta` (etherparse-backed, never panics).
//! - [`flow`] — bidirectional flow table with bounded-memory eviction.
//! - [`classify`] — deterministic Phase-0 port/proto category heuristics.
//! - [`stats`] — streaming summary accumulator (heavy-hitter bounded).
//! - [`columnar`] — Arrow schema + Snappy Parquet flow writer.
//! - [`analyze`] — the single-pass orchestrator ([`run`] / [`run_source`]).
//! - [`gen`] — deterministic synthetic capture generator + ground-truth manifest.
//! - [`metrics`] — ingest metrics + the Phase-0 perf budget.
//!
//! ## Invariants (see PROJECT-SPEC §7)
//!
//! 1. No panics on bad input — release builds use `panic = "abort"`.
//! 2. Bounded memory independent of capture size (peak heap ≤ 64 MiB).
//! 3. Single source of truth for the flow schema (`columnar::schema`), CI-drift-guarded.
//! 4. C-compiler-free build (Snappy on disk; no zstd/lz4-sys/duckdb/rand).
//! 5. Time unit is `i64` nanoseconds since the Unix epoch, end to end.

pub mod analyze;
pub mod classify;
pub mod columnar;
pub mod decode;
pub mod detect;
pub mod enrich;
pub mod error;
pub mod export;
pub mod flow;
pub mod gen;
pub mod metrics;
pub mod model;
pub mod packets;
pub mod reader;
pub mod report;
pub mod score;
pub mod stats;

pub use analyze::{run, run_source, run_source_visiting, PipelineConfig};
pub use detect::{
    BeaconParams, BehaviorTracker, BruteForceParams, CleartextCredsParams, DetectConfig,
    DnsTunnelParams, ExfilParams, LateralMovementParams, PiiExposureParams, SweepParams,
};
pub use enrich::{
    apply_reputation, attack_for, classify_ip, AttackTechnique, Enricher, FeedMatch,
    FlowEnrichment, IpClass, RepStatus, ReputationVerdict, ThreatFeed,
};
pub use error::{PpError, Result};
pub use model::category::Category;
pub use model::finding::{Finding, FindingKind};
pub use model::flow::{Direction, FlowKey, FlowRecord};
pub use model::incident::Incident;
pub use model::output::AnalysisOutput;
pub use model::packet::{PacketMeta, Protocol, Transport};
pub use model::severity::Severity;
pub use model::summary::{
    CategoryCount, IpThreat, PortCount, ProtoCount, ProtoCounts, SeverityCounts, Summary,
    TimeBucket, TopTalker,
};
pub use packets::{extract_flow_packets, FlowPackets, PacketCaps, PacketQuery, PacketRecord};
pub use report::render_html;
pub use score::{score_flow, ScoredFlow};

#[cfg(feature = "online")]
pub use crate::enrich::online::{lookup_reputation_native, ReputationKeys};
