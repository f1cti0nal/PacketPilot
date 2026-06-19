//! The shared data contract. Every analysis stage imports these types; they are the
//! Phase-0 "wire model" and are fully implemented (not stubs).
//!
//! - [`packet`] — `PacketMeta`, `Transport`, `Protocol`
//! - [`flow`] — `FlowKey`, `FlowRecord`, `Direction`
//! - [`category`] — `Category` (12-value closed taxonomy)
//! - [`summary`] — `Summary` + sub-structs + `ProtoCounts`
//! - [`output`] — `AnalysisOutput` (the headline JSON object)

pub mod category;
pub mod finding;
pub mod flow;
pub mod incident;
pub mod output;
pub mod packet;
pub mod severity;
pub mod summary;

pub use category::Category;
pub use finding::{Finding, FindingKind};
pub use flow::{Direction, FlowKey, FlowRecord};
pub use incident::Incident;
pub use output::AnalysisOutput;
pub use packet::{AppProto, PacketMeta, Protocol, Transport};
pub use severity::Severity;
pub use summary::{
    CategoryCount, IpThreat, PortCount, ProtoCount, ProtoCounts, SeverityCounts, Summary,
    TimeBucket, TopTalker,
};
