//! Batch / Case triage — analyze a *folder* of captures into one case directory + a ranked index.
//!
//! [`run_case`] fans the existing single-capture pipeline ([`crate::analyze::run`]) over every
//! capture discovered under a directory, writing each capture's flows Parquet + summary JSON +
//! HTML report into the **case layout the DuckDB schema already expects**
//! (`<case>/parquet/flow/<id>.parquet`, queried by `sql/schema.sql`'s `{CASE_DIR}` view), and
//! returns a [`CaseSummary`]: a per-capture roll-up **ranked by worst severity**, plus a
//! cross-capture **correlation** block — indicators (IP / SNI domain / JA3) that appear in ≥2
//! captures, with the capture list per indicator.
//!
//! Design invariants mirror the single-capture engine:
//! - **Bounded memory** — captures are processed *sequentially* in sorted order, so peak heap
//!   stays one-capture-sized regardless of folder size.
//! - **Deterministic** — sorted discovery + a caller-supplied "generated at" timestamp make the
//!   output byte-identical across runs.
//! - **Robust** — a capture that fails to parse is recorded as [`CaptureStatus::Error`] and
//!   skipped; it never aborts the batch unless [`CaseConfig::strict`] is set.
//!
//! This module adds **no** decode/detect code — it is orchestration + aggregation over the
//! per-capture [`AnalysisOutput`]s the engine already produces.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::analyze::{run, PipelineConfig};
use crate::error::PpError;
use crate::model::alert::{AlertSource, PriorityBand};
use crate::model::output::AnalysisOutput;
use crate::model::severity::Severity;
use crate::model::summary::{ScoreTerm, SeverityCounts};
use crate::Result;

/// Recurrence uplift per extra capture a story appears in — cross-capture persistence is
/// corroboration (the `shared_indicators` ≥2-captures doctrine, applied to whole stories).
pub const PTS_CASE_RECURRENCE: i32 = 5;
/// Recurrence uplift ceiling (≤ one severity sub-band — the SAC uplift-cap discipline).
pub const CASE_RECURRENCE_CAP: i32 = 15;
/// Case-queue emission bound. Truncation is never silent: `total_case_alerts` keeps the
/// pre-truncation count, and every per-capture queue remains intact in `captures/<id>.json`.
const MAX_CASE_ALERTS: usize = 64;

/// Options for a batch/case run.
#[derive(Debug, Clone)]
pub struct CaseConfig {
    /// Case output root. `parquet/flow/`, `captures/` are created beneath it.
    pub case_out: PathBuf,
    /// Recurse into subdirectories when discovering captures (default: top-level only).
    pub recursive: bool,
    /// Abort the whole batch on the first capture that fails to parse (default: skip & continue).
    pub strict: bool,
    /// Write a per-capture self-contained HTML report next to each summary JSON.
    pub per_capture_html: bool,
}

impl Default for CaseConfig {
    fn default() -> Self {
        CaseConfig {
            case_out: PathBuf::from("case"),
            recursive: false,
            strict: false,
            per_capture_html: true,
        }
    }
}

/// Per-capture parse status in a case roll-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureStatus {
    /// Analyzed successfully.
    Ok,
    /// Failed to parse; skipped (or fatal under `--strict`).
    Error,
}

/// One capture's roll-up row in a [`CaseSummary`].
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CaptureEntry {
    /// Stable 16-hex id (FNV-1a of the capture's path relative to the case root). Names the
    /// per-capture artifacts (`captures/<id>.json|html`, `parquet/flow/<id>.parquet`) and is the
    /// join key referenced by [`SharedIndicator::captures`].
    pub capture_id: String,
    /// Basename of the capture file (display).
    pub filename: String,
    /// Path relative to the case root, forward-slashed (display; unique within the case).
    pub rel_path: String,
    /// Whether the capture analyzed cleanly.
    pub status: CaptureStatus,
    /// Human error message when `status == Error`; `None` otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Worst severity band observed across the capture's flows (`Info` for an errored/empty one).
    pub worst_severity: Severity,
    /// Per-band flow counts (all zero for an errored capture).
    pub severity_counts: SeverityCounts,
    pub total_packets: u64,
    pub total_flows: u64,
    /// Number of behavioral/rule findings in the capture.
    pub finding_count: u64,
    /// Case-relative path to this capture's flows Parquet (`None` when errored).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parquet_path: Option<String>,
    /// Case-relative path to this capture's summary JSON (`None` when errored).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary_path: Option<String>,
    /// Case-relative path to this capture's HTML report (`None` when errored or HTML disabled).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_path: Option<String>,
}

/// The kind of a cross-capture shared indicator.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum IndicatorKind {
    /// A threat-carded IP address (from `ip_threats`).
    Ip,
    /// A TLS SNI host (from `domain_threats`).
    Domain,
    /// A JA3 TLS client fingerprint (malware-matched, from `ip_threats[].fingerprints`).
    Ja3,
}

impl IndicatorKind {
    /// Stable lowercase token (matches the serde wire form).
    pub fn as_str(self) -> &'static str {
        match self {
            IndicatorKind::Ip => "ip",
            IndicatorKind::Domain => "domain",
            IndicatorKind::Ja3 => "ja3",
        }
    }
}

/// An indicator seen in ≥2 captures — the analytic edge of "correlate, don't merge".
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SharedIndicator {
    pub kind: IndicatorKind,
    pub value: String,
    /// [`CaptureEntry::capture_id`]s this indicator appears in (sorted, ≥2 entries).
    pub captures: Vec<String>,
    /// Worst severity associated with this indicator across the captures it appears in.
    pub worst_severity: Severity,
}

/// One row of the case-wide alert queue: the same adversary story — identified by its stable
/// per-capture `Alert.id` (`host:<ip>` / `chain:<host-set-hash>` / `rollup:<kind>` hash
/// identically in every capture) — merged across every capture it appeared in. Representative
/// fields (title/action/actor) come from the worst member; recurrence adds a bounded,
/// ledger-visible uplift. The full member alerts live in the per-capture summaries
/// (`captures/<id>.json`) — this row is the case-level rank, not a re-derivation.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CaseAlert {
    /// The shared per-capture `Alert.id`.
    pub id: String,
    pub source: AlertSource,
    /// Band of the fused `priority` (the `Severity::from_score` cutoffs, as everywhere).
    pub band: PriorityBand,
    /// `clamp(max member priority + min(PTS_CASE_RECURRENCE·(captures−1), CASE_RECURRENCE_CAP), 0, 100)`.
    pub priority: u16,
    /// Max member severity (the judgment axis, never rewritten from priority).
    pub severity: Severity,
    /// Max member confidence.
    pub confidence: u8,
    /// The worst member's headline.
    pub title: String,
    /// The worst member's recommended action.
    pub action: String,
    /// The worst member's primary actor host.
    pub actor: String,
    /// Sorted [`CaptureEntry::capture_id`]s this story appeared in (≥ 1).
    pub captures: Vec<String>,
    /// `== captures.len()`.
    pub capture_count: u32,
    /// Summed member `finding_count` across captures.
    pub finding_count: u64,
    /// The transparent rank ledger: base (worst member priority) + the recurrence term when
    /// ≥2 captures (+ a clamp term when binding). `Σ terms == priority`, test-enforced.
    pub priority_terms: Vec<ScoreTerm>,
    /// Earliest member activity (ns since epoch — comparable across captures).
    pub first_seen_ns: Option<i64>,
    /// Latest member activity (ns since epoch).
    pub last_seen_ns: Option<i64>,
}

/// The complete result of a batch/case run.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CaseSummary {
    /// JSON schema version; `1` in v1.
    pub schema_version: u32,
    /// Engine version that produced this case.
    pub engine_version: String,
    /// The input directory that was triaged (display).
    pub case_dir: String,
    /// Total captures discovered.
    pub total_captures: u64,
    /// Captures that failed to parse (skipped).
    pub error_captures: u64,
    /// Per-capture roll-ups, ranked worst-severity first (errored captures last).
    pub captures: Vec<CaptureEntry>,
    /// Indicators seen across ≥2 captures, ranked worst-severity first.
    pub shared_indicators: Vec<SharedIndicator>,
    /// The case-wide alert queue: per-capture Smart Alerting queues merged by stable alert
    /// id, recurrence-uplifted, ranked worst-first, capped at `MAX_CASE_ALERTS`.
    /// `#[serde(default)]` keeps older case files readable.
    #[serde(default)]
    pub case_alerts: Vec<CaseAlert>,
    /// Pre-truncation case-alert count (`>= case_alerts.len()`) — truncation is never silent.
    /// `#[serde(default)]` keeps older case files readable.
    #[serde(default)]
    pub total_case_alerts: u64,
}

impl CaseSummary {
    /// Serialize as pretty (multi-line) JSON.
    pub fn to_json_pretty(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

/// FNV-1a 64-bit hash — the stable per-capture id derivation (path-relative, so identical folders
/// yield identical ids across machines).
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

/// Worst (highest) severity band with a non-zero flow count; `Info` when all bands are empty.
fn worst_severity(sc: &SeverityCounts) -> Severity {
    if sc.critical > 0 {
        Severity::Critical
    } else if sc.high > 0 {
        Severity::High
    } else if sc.medium > 0 {
        Severity::Medium
    } else if sc.low > 0 {
        Severity::Low
    } else {
        Severity::Info
    }
}

/// True for a path whose name ends in a capture extension we ingest (`.pcap`, `.pcapng`, and their
/// `.gz` forms). Case-insensitive on the extension.
fn is_capture(path: &Path) -> bool {
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_ascii_lowercase(),
        None => return false,
    };
    name.ends_with(".pcap")
        || name.ends_with(".pcapng")
        || name.ends_with(".pcap.gz")
        || name.ends_with(".pcapng.gz")
}

/// Discover capture files under `dir`, sorted for determinism. Non-recursive unless `recursive`.
/// Directories are skipped (except as recursion targets); non-capture files are ignored.
fn discover(dir: &Path, recursive: bool) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let rd = std::fs::read_dir(&d)
            .map_err(|e| PpError::io(format!("read case dir {}", d.display()), e))?;
        // Collect this directory's entries, then sort, so traversal order is stable.
        let mut entries: Vec<PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        entries.sort();
        for p in entries {
            if p.is_dir() {
                if recursive {
                    stack.push(p);
                }
            } else if is_capture(&p) {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Per-capture indicator set (deduped within one capture, each carrying the worst severity seen
/// for that value in that capture). Used to build the cross-capture correlation.
struct CaptureIndicators {
    /// `(kind, value) -> worst severity within this capture`.
    items: BTreeMap<(IndicatorKind, String), Severity>,
}

impl CaptureIndicators {
    fn from_output(out: &AnalysisOutput) -> CaptureIndicators {
        let mut items: BTreeMap<(IndicatorKind, String), Severity> = BTreeMap::new();
        let mut bump = |kind: IndicatorKind, value: String, sev: Severity| {
            items
                .entry((kind, value))
                .and_modify(|s| *s = (*s).max(sev))
                .or_insert(sev);
        };
        for t in &out.summary.ip_threats {
            bump(IndicatorKind::Ip, t.ip.clone(), t.severity);
            for fp in &t.fingerprints {
                if let Some(ja3) = &fp.ja3 {
                    bump(IndicatorKind::Ja3, ja3.clone(), t.severity);
                }
            }
        }
        for d in &out.summary.domain_threats {
            // Domains are a context surface, not severity-scored — record as Info.
            bump(IndicatorKind::Domain, d.host.clone(), Severity::Info);
        }
        CaptureIndicators { items }
    }
}

/// Analyze every capture under `dir` into the case layout beneath `cfg.case_out`, returning the
/// ranked [`CaseSummary`].
///
/// `pipeline` is the per-capture base config (threat feed, detection params, …); its
/// `flows_parquet` and `writer.capture_id` are overridden per capture. `generated_unix_secs` is
/// threaded into each per-capture HTML report so this stays deterministic/testable. `on_capture`
/// is invoked once before each capture as `(index, total, path)` for progress reporting.
pub fn run_case(
    dir: &Path,
    cfg: &CaseConfig,
    pipeline: &PipelineConfig,
    generated_unix_secs: i64,
    mut on_capture: impl FnMut(usize, usize, &Path),
) -> Result<CaseSummary> {
    if !dir.is_dir() {
        return Err(PpError::Config(format!(
            "batch input is not a directory: {}",
            dir.display()
        )));
    }

    let paths = discover(dir, cfg.recursive)?;

    // Case layout the DuckDB `{CASE_DIR}` view expects, plus a captures/ dir for per-capture
    // summary JSON + HTML. `File::create` does not make parents, so create them up front.
    let flow_dir = cfg.case_out.join("parquet").join("flow");
    let captures_dir = cfg.case_out.join("captures");
    std::fs::create_dir_all(&flow_dir)
        .map_err(|e| PpError::io(format!("create {}", flow_dir.display()), e))?;
    std::fs::create_dir_all(&captures_dir)
        .map_err(|e| PpError::io(format!("create {}", captures_dir.display()), e))?;

    let total = paths.len();
    let mut entries: Vec<CaptureEntry> = Vec::with_capacity(total);
    let mut error_captures = 0u64;

    // (kind, value) -> { capture_id -> worst severity }. BTree keeps deterministic ordering.
    let mut corr: BTreeMap<(IndicatorKind, String), BTreeMap<String, Severity>> = BTreeMap::new();

    // Case-alert drafts: alert id -> merged story. Captures are processed in sorted order and
    // representative fields only change on a STRICTLY higher member priority, so the fold is
    // order-deterministic. Compact rows only — the per-capture summaries keep the full alerts.
    struct CaseAlertDraft {
        source: AlertSource,
        max_priority: u16,
        severity: Severity,
        confidence: u8,
        title: String,
        action: String,
        actor: String,
        finding_count: u64,
        first_seen_ns: Option<i64>,
        last_seen_ns: Option<i64>,
        captures: Vec<String>, // insertion order == sorted discovery order; deduped by caller
    }
    let mut alert_drafts: BTreeMap<String, CaseAlertDraft> = BTreeMap::new();

    for (idx, path) in paths.iter().enumerate() {
        on_capture(idx, total, path);

        let rel = path.strip_prefix(dir).unwrap_or(path);
        let rel_path = rel.to_string_lossy().replace('\\', "/");
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| rel_path.clone());
        let id = fnv1a64(rel_path.as_bytes());
        let id_hex = format!("{id:016x}");

        let parquet_rel = format!("parquet/flow/{id_hex}.parquet");
        let parquet_abs = cfg.case_out.join(&parquet_rel);

        // Per-capture pipeline: same detection/enrichment as a single-capture run, but write into
        // this capture's slot of the case layout with a distinct, stable capture id.
        let mut per = pipeline.clone();
        per.flows_parquet = Some(parquet_abs.clone());
        per.writer.capture_id = id;

        match run(path, &per, |_, _, _| {}) {
            Ok(out) => {
                let sc = out.summary.severity_counts;
                let worst = worst_severity(&sc);

                // Per-capture summary JSON.
                let summary_rel = format!("captures/{id_hex}.json");
                if let Ok(js) = out.to_json_pretty() {
                    let _ = std::fs::write(cfg.case_out.join(&summary_rel), js);
                }

                // Optional per-capture HTML report (self-contained; deep-linked from case.html).
                let report_rel = if cfg.per_capture_html {
                    let rel = format!("captures/{id_hex}.html");
                    let doc = crate::report::render_html(&out, generated_unix_secs, None);
                    let _ = std::fs::write(cfg.case_out.join(&rel), doc);
                    Some(rel)
                } else {
                    None
                };

                // Fold this capture's indicators into the cross-capture correlation.
                for ((kind, value), sev) in CaptureIndicators::from_output(&out).items {
                    corr.entry((kind, value))
                        .or_default()
                        .entry(id_hex.clone())
                        .and_modify(|s| *s = (*s).max(sev))
                        .or_insert(sev);
                }

                // Fold this capture's alert queue into the case-wide queue. The alert id is
                // the merge key: SAC ids are stable across captures by construction, so the
                // same story (same host / same chain host-set / same rollup kind) collapses
                // into one case row.
                for a in &out.summary.alerts {
                    match alert_drafts.get_mut(&a.id) {
                        Some(d) => {
                            if a.priority > d.max_priority {
                                d.max_priority = a.priority;
                                d.source = a.source;
                                d.title = a.title.clone();
                                d.action = a.action.clone();
                                d.actor = a.actor.clone();
                            }
                            d.severity = d.severity.max(a.severity);
                            d.confidence = d.confidence.max(a.confidence);
                            d.finding_count += a.finding_count as u64;
                            d.first_seen_ns = match (d.first_seen_ns, a.first_seen_ns) {
                                (Some(x), Some(y)) => Some(x.min(y)),
                                (x, y) => x.or(y),
                            };
                            d.last_seen_ns = match (d.last_seen_ns, a.last_seen_ns) {
                                (Some(x), Some(y)) => Some(x.max(y)),
                                (x, y) => x.or(y),
                            };
                            if d.captures.last() != Some(&id_hex) {
                                d.captures.push(id_hex.clone());
                            }
                        }
                        None => {
                            alert_drafts.insert(
                                a.id.clone(),
                                CaseAlertDraft {
                                    source: a.source,
                                    max_priority: a.priority,
                                    severity: a.severity,
                                    confidence: a.confidence,
                                    title: a.title.clone(),
                                    action: a.action.clone(),
                                    actor: a.actor.clone(),
                                    finding_count: a.finding_count as u64,
                                    first_seen_ns: a.first_seen_ns,
                                    last_seen_ns: a.last_seen_ns,
                                    captures: vec![id_hex.clone()],
                                },
                            );
                        }
                    }
                }

                entries.push(CaptureEntry {
                    capture_id: id_hex,
                    filename,
                    rel_path,
                    status: CaptureStatus::Ok,
                    error: None,
                    worst_severity: worst,
                    severity_counts: sc,
                    total_packets: out.summary.total_packets,
                    total_flows: out.summary.total_flows,
                    finding_count: out.summary.findings.len() as u64,
                    parquet_path: Some(parquet_rel),
                    summary_path: Some(summary_rel),
                    report_path: report_rel,
                });
            }
            Err(e) => {
                if cfg.strict {
                    return Err(e);
                }
                // A failed run may have created a partial Parquet before erroring; drop it so it
                // cannot pollute the DuckDB union view.
                let _ = std::fs::remove_file(&parquet_abs);
                error_captures += 1;
                entries.push(CaptureEntry {
                    capture_id: id_hex,
                    filename,
                    rel_path,
                    status: CaptureStatus::Error,
                    error: Some(e.to_string()),
                    worst_severity: Severity::Info,
                    severity_counts: SeverityCounts::default(),
                    total_packets: 0,
                    total_flows: 0,
                    finding_count: 0,
                    parquet_path: None,
                    summary_path: None,
                    report_path: None,
                });
            }
        }
    }

    // Rank: successful captures first (worst severity desc, then finding count desc), errored
    // captures last; ties broken by rel_path for a total, stable order.
    entries.sort_by(|a, b| {
        let ok = |s: CaptureStatus| matches!(s, CaptureStatus::Ok);
        ok(b.status)
            .cmp(&ok(a.status))
            .then(b.worst_severity.cmp(&a.worst_severity))
            .then(b.finding_count.cmp(&a.finding_count))
            .then(a.rel_path.cmp(&b.rel_path))
    });

    // Shared indicators: keep those present in ≥2 distinct captures.
    let mut shared_indicators: Vec<SharedIndicator> = corr
        .into_iter()
        .filter(|(_, caps)| caps.len() >= 2)
        .map(|((kind, value), caps)| {
            let worst = caps.values().copied().max().unwrap_or(Severity::Info);
            let mut captures: Vec<String> = caps.into_keys().collect();
            captures.sort();
            SharedIndicator {
                kind,
                value,
                captures,
                worst_severity: worst,
            }
        })
        .collect();
    // Rank worst-severity first, then by count, then kind/value for a stable order.
    shared_indicators.sort_by(|a, b| {
        b.worst_severity
            .cmp(&a.worst_severity)
            .then(b.captures.len().cmp(&a.captures.len()))
            .then(a.kind.as_str().cmp(b.kind.as_str()))
            .then(a.value.cmp(&b.value))
    });

    // The case-wide alert queue: finish each merged draft with its recurrence-uplifted,
    // ledger-reconciled priority (Σ terms == priority — the SAC discipline).
    let total_case_alerts = alert_drafts.len() as u64;
    let mut case_alerts: Vec<CaseAlert> = alert_drafts
        .into_iter()
        .map(|(id, d)| {
            let mut terms = vec![ScoreTerm {
                label: "base: worst per-capture alert priority".to_string(),
                points: d.max_priority as i32,
            }];
            let mut p: i32 = d.max_priority as i32;
            let n = d.captures.len();
            if n >= 2 {
                let uplift = (PTS_CASE_RECURRENCE * (n as i32 - 1)).min(CASE_RECURRENCE_CAP);
                terms.push(ScoreTerm {
                    label: format!("recurring: seen in {n} captures"),
                    points: uplift,
                });
                p += uplift;
            }
            if p > 100 {
                terms.push(ScoreTerm {
                    label: format!("clamp: raw {p} -> 100"),
                    points: 100 - p,
                });
                p = 100;
            }
            let priority = p as u16;
            let mut captures = d.captures;
            captures.sort();
            CaseAlert {
                id,
                source: d.source,
                band: PriorityBand::from_priority(priority),
                priority,
                severity: d.severity,
                confidence: d.confidence,
                title: d.title,
                action: d.action,
                actor: d.actor,
                capture_count: captures.len() as u32,
                captures,
                finding_count: d.finding_count,
                priority_terms: terms,
                first_seen_ns: d.first_seen_ns,
                last_seen_ns: d.last_seen_ns,
            }
        })
        .collect();
    // Strict total order (ids are unique — the map key), worst-first; visible truncation.
    case_alerts.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then(b.severity.rank().cmp(&a.severity.rank()))
            .then(b.capture_count.cmp(&a.capture_count))
            .then_with(|| a.id.cmp(&b.id))
    });
    case_alerts.truncate(MAX_CASE_ALERTS);

    Ok(CaseSummary {
        schema_version: 1,
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        case_dir: dir.to_string_lossy().into_owned(),
        total_captures: total as u64,
        error_captures,
        captures: entries,
        shared_indicators,
        case_alerts,
        total_case_alerts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worst_severity_picks_highest_nonzero_band() {
        let mut sc = SeverityCounts::default();
        assert_eq!(worst_severity(&sc), Severity::Info);
        sc.low = 3;
        assert_eq!(worst_severity(&sc), Severity::Low);
        sc.high = 1;
        assert_eq!(worst_severity(&sc), Severity::High);
        sc.critical = 1;
        assert_eq!(worst_severity(&sc), Severity::Critical);
    }

    #[test]
    fn is_capture_matches_known_extensions() {
        for ok in ["a.pcap", "a.pcapng", "a.PCAP", "a.pcap.gz", "a.pcapng.gz"] {
            assert!(is_capture(Path::new(ok)), "{ok} should match");
        }
        for no in ["a.txt", "a.json", "a.pcapx", "pcap", "a.gz"] {
            assert!(!is_capture(Path::new(no)), "{no} should not match");
        }
    }

    #[test]
    fn fnv1a64_is_stable_and_path_sensitive() {
        assert_eq!(fnv1a64(b"a/b.pcap"), fnv1a64(b"a/b.pcap"));
        assert_ne!(fnv1a64(b"a/b.pcap"), fnv1a64(b"a/c.pcap"));
    }
}
