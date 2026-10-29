//! Batch / case triage integration: generate a folder of synthetic captures, run `run_case`,
//! and assert the case layout, per-capture equivalence with a standalone `analyze::run`, the
//! severity ranking, cross-capture indicator correlation, and robustness (skip vs. `--strict`).

use std::path::{Path, PathBuf};

use ppcap_core::analyze::{self, PipelineConfig};
use ppcap_core::case::{run_case, CaptureStatus, CaseConfig};
use ppcap_core::gen::{GenConfig, Scenario, SynthGen};

/// Write one synthetic capture of `scenario` into `dir/<name>`; return its path.
fn gen_capture(dir: &Path, name: &str, scenario: Scenario, packets: u64, seed: u64) -> PathBuf {
    let path = dir.join(name);
    let cfg = GenConfig {
        scenario,
        packets,
        seed,
        include_edge_cases: false,
        host_count: 12,
        ..Default::default()
    };
    SynthGen::new(cfg).write_pcap(&path).expect("write capture");
    path
}

/// A folder with a beacon (findings), a benign web-only, a port-scan, plus a non-parseable file
/// and a non-capture file that must be ignored. Returns (input_dir, case_out) temp dirs.
fn build_case_dir() -> (tempfile::TempDir, tempfile::TempDir) {
    let input = tempfile::tempdir().expect("input dir");
    let case_out = tempfile::tempdir().expect("case dir");
    gen_capture(input.path(), "beacon.pcap", Scenario::Beacon, 12_000, 1);
    gen_capture(input.path(), "webonly.pcap", Scenario::WebOnly, 12_000, 2);
    gen_capture(input.path(), "portscan.pcap", Scenario::PortScan, 12_000, 3);
    std::fs::write(input.path().join("broken.pcap"), b"not a pcap at all").unwrap();
    std::fs::write(input.path().join("notes.txt"), b"ignore me").unwrap();
    (input, case_out)
}

fn cfg_for(case_out: &Path) -> CaseConfig {
    CaseConfig {
        case_out: case_out.to_path_buf(),
        recursive: false,
        strict: false,
        per_capture_html: true,
    }
}

#[test]
fn batch_produces_case_layout_and_skips_bad_capture() {
    let (input, case_out) = build_case_dir();
    let case = run_case(
        input.path(),
        &cfg_for(case_out.path()),
        &PipelineConfig::default(),
        0,
        |_, _, _| {},
    )
    .expect("run_case");

    // notes.txt ignored; 3 good captures + 1 broken discovered.
    assert_eq!(case.total_captures, 4, "should discover 4 captures");
    assert_eq!(
        case.error_captures, 1,
        "broken.pcap should be the one error"
    );

    // Exactly one entry is an error, and it wrote no per-capture artifacts.
    let errors: Vec<_> = case
        .captures
        .iter()
        .filter(|e| e.status == CaptureStatus::Error)
        .collect();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].filename, "broken.pcap");
    assert!(errors[0].error.is_some());
    assert!(errors[0].parquet_path.is_none());

    // Good captures wrote parquet + json + html into the case layout, and the files exist.
    for e in case
        .captures
        .iter()
        .filter(|e| e.status == CaptureStatus::Ok)
    {
        let pq = case_out.path().join(e.parquet_path.as_ref().unwrap());
        let js = case_out.path().join(e.summary_path.as_ref().unwrap());
        let ht = case_out.path().join(e.report_path.as_ref().unwrap());
        assert!(pq.exists(), "missing parquet {}", pq.display());
        assert!(js.exists(), "missing summary {}", js.display());
        assert!(ht.exists(), "missing report {}", ht.display());
    }
    // A broken capture must not leave a partial parquet behind (DuckDB union stays clean).
    let flow_dir = case_out.path().join("parquet").join("flow");
    let n_parquet = std::fs::read_dir(&flow_dir).unwrap().count();
    assert_eq!(n_parquet, 3, "exactly the 3 good captures produce parquet");
}

#[test]
fn per_capture_output_equals_standalone_analyze() {
    let (input, case_out) = build_case_dir();
    let case = run_case(
        input.path(),
        &cfg_for(case_out.path()),
        &PipelineConfig::default(),
        0,
        |_, _, _| {},
    )
    .expect("run_case");

    let beacon = case
        .captures
        .iter()
        .find(|e| e.filename == "beacon.pcap")
        .expect("beacon entry");

    // The batch's per-capture summary must match a standalone single-capture run byte-for-byte on
    // the load-bearing counters (batch is a loop over the *same* pipeline, nothing else).
    let standalone = analyze::run(
        &input.path().join("beacon.pcap"),
        &PipelineConfig::default(),
        |_, _, _| {},
    )
    .expect("standalone run");

    let batch_json =
        std::fs::read_to_string(case_out.path().join(beacon.summary_path.as_ref().unwrap()))
            .unwrap();
    let batch: ppcap_core::model::output::AnalysisOutput =
        serde_json::from_str(&batch_json).unwrap();

    assert_eq!(
        batch.summary.total_packets,
        standalone.summary.total_packets
    );
    assert_eq!(batch.summary.total_flows, standalone.summary.total_flows);
    assert_eq!(batch.summary.total_bytes, standalone.summary.total_bytes);
    assert_eq!(
        batch.summary.findings.len(),
        standalone.summary.findings.len()
    );
    assert_eq!(
        batch.summary.severity_counts,
        standalone.summary.severity_counts
    );
    // The batch entry's rolled-up counts mirror the summary it wrote.
    assert_eq!(beacon.total_packets, standalone.summary.total_packets);
    assert_eq!(
        beacon.finding_count,
        standalone.summary.findings.len() as u64
    );
}

#[test]
fn captures_rank_worst_first_and_errors_last() {
    let (input, case_out) = build_case_dir();
    let case = run_case(
        input.path(),
        &cfg_for(case_out.path()),
        &PipelineConfig::default(),
        0,
        |_, _, _| {},
    )
    .expect("run_case");

    // Ranking is non-increasing by (worst_severity, finding_count) among the OK captures, and the
    // errored capture sorts last.
    assert_eq!(
        case.captures.last().unwrap().status,
        CaptureStatus::Error,
        "errored capture must rank last"
    );

    let oks: Vec<_> = case
        .captures
        .iter()
        .filter(|e| e.status == CaptureStatus::Ok)
        .collect();
    for w in oks.windows(2) {
        let a = (w[0].worst_severity, w[0].finding_count);
        let b = (w[1].worst_severity, w[1].finding_count);
        assert!(a >= b, "captures out of rank order: {a:?} before {b:?}");
    }

    // The beacon (with behavioral findings) must outrank the benign web-only capture.
    let pos = |name: &str| oks.iter().position(|e| e.filename == name).unwrap();
    assert!(
        pos("beacon.pcap") < pos("webonly.pcap"),
        "beacon should rank above benign web-only"
    );
}

#[test]
fn shared_indicators_require_two_captures() {
    let (input, case_out) = build_case_dir();
    let case = run_case(
        input.path(),
        &cfg_for(case_out.path()),
        &PipelineConfig::default(),
        0,
        |_, _, _| {},
    )
    .expect("run_case");

    // Every shared indicator appears in ≥2 distinct captures, and each referenced capture_id is a
    // real, successfully-analyzed capture in the case (never the errored one).
    let ok_ids: std::collections::HashSet<&str> = case
        .captures
        .iter()
        .filter(|e| e.status == CaptureStatus::Ok)
        .map(|e| e.capture_id.as_str())
        .collect();
    assert!(
        !case.shared_indicators.is_empty(),
        "synthetic captures share a host pool → expect correlations"
    );
    for ind in &case.shared_indicators {
        assert!(ind.captures.len() >= 2, "indicator seen in <2 captures");
        // capture_ids are sorted + deduped.
        let mut sorted = ind.captures.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted, ind.captures, "capture list not sorted/deduped");
        for id in &ind.captures {
            assert!(
                ok_ids.contains(id.as_str()),
                "indicator references unknown/errored capture"
            );
        }
    }
}

#[test]
fn strict_makes_a_bad_capture_fatal() {
    let (input, case_out) = build_case_dir();
    let mut cfg = cfg_for(case_out.path());
    cfg.strict = true;
    let res = run_case(
        input.path(),
        &cfg,
        &PipelineConfig::default(),
        0,
        |_, _, _| {},
    );
    assert!(res.is_err(), "--strict must abort on the broken capture");
}

#[test]
fn case_html_links_each_capture_report() {
    let (input, case_out) = build_case_dir();
    let case = run_case(
        input.path(),
        &cfg_for(case_out.path()),
        &PipelineConfig::default(),
        0,
        |_, _, _| {},
    )
    .expect("run_case");

    let html = ppcap_core::case_html(&case, 0);
    assert!(html.contains("Case Triage"));
    assert!(html.contains("Shared indicators"));
    // Each OK capture's report is deep-linked.
    for e in case
        .captures
        .iter()
        .filter(|e| e.status == CaptureStatus::Ok)
    {
        let href = format!("href=\"{}\"", e.report_path.as_ref().unwrap());
        assert!(html.contains(&href), "case.html missing link {href}");
    }
}

#[test]
fn recursive_discovers_nested_captures() {
    let input = tempfile::tempdir().expect("input dir");
    let case_out = tempfile::tempdir().expect("case dir");
    gen_capture(input.path(), "top.pcap", Scenario::WebOnly, 4_000, 1);
    let sub = input.path().join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    gen_capture(&sub, "nested.pcap", Scenario::WebOnly, 4_000, 2);

    // Non-recursive: only the top-level capture.
    let flat = run_case(
        input.path(),
        &cfg_for(case_out.path()),
        &PipelineConfig::default(),
        0,
        |_, _, _| {},
    )
    .expect("flat run");
    assert_eq!(flat.total_captures, 1);

    // Recursive: both, and the nested one's rel_path is forward-slashed.
    let case_out2 = tempfile::tempdir().expect("case dir 2");
    let mut cfg = cfg_for(case_out2.path());
    cfg.recursive = true;
    let deep = run_case(
        input.path(),
        &cfg,
        &PipelineConfig::default(),
        0,
        |_, _, _| {},
    )
    .expect("recursive run");
    assert_eq!(deep.total_captures, 2);
    assert!(
        deep.captures
            .iter()
            .any(|e| e.rel_path == "sub/nested.pcap"),
        "recursive run should include sub/nested.pcap"
    );
}

/// Two captures with the SAME beacon story (same seed => same hosts => same stable alert ids)
/// must merge into one recurrence-uplifted case alert.
#[test]
fn case_alerts_merge_recurring_story_across_captures() {
    let input = tempfile::tempdir().expect("input dir");
    let case_out = tempfile::tempdir().expect("case dir");
    gen_capture(input.path(), "day1.pcap", Scenario::Beacon, 12_000, 1);
    gen_capture(input.path(), "day2.pcap", Scenario::Beacon, 12_000, 1);
    gen_capture(input.path(), "web.pcap", Scenario::WebOnly, 12_000, 2);

    let case = run_case(
        input.path(),
        &cfg_for(case_out.path()),
        &PipelineConfig::default(),
        0,
        |_, _, _| {},
    )
    .expect("run_case");

    assert!(
        !case.case_alerts.is_empty(),
        "the beaconing captures must produce case alerts"
    );
    assert!(case.total_case_alerts >= case.case_alerts.len() as u64);

    let recurring = case
        .case_alerts
        .iter()
        .find(|a| a.capture_count == 2)
        .expect("the same story in day1+day2 merges into one row");
    assert_eq!(recurring.captures.len(), 2);
    assert!(
        recurring
            .priority_terms
            .iter()
            .any(|t| t.label.starts_with("recurring: seen in 2 captures")),
        "recurrence must be a visible ledger term: {:?}",
        recurring.priority_terms
    );
    // The uplift raises the fused priority above the base term (unless already clamped at 100).
    let base = recurring.priority_terms[0].points;
    assert!(
        recurring.priority as i32 > base || recurring.priority == 100,
        "recurrence uplifts the rank (priority {} vs base {})",
        recurring.priority,
        base
    );
}

/// Every case-alert ledger reconciles exactly, and the queue is worst-first + deterministic.
#[test]
fn case_alert_ledgers_reconcile_and_queue_is_deterministic() {
    let (input, case_out) = build_case_dir();
    let run_once = |out: &Path| {
        run_case(
            input.path(),
            &cfg_for(out),
            &PipelineConfig::default(),
            0,
            |_, _, _| {},
        )
        .expect("run_case")
    };
    let case = run_once(case_out.path());
    for a in &case.case_alerts {
        let sum: i32 = a.priority_terms.iter().map(|t| t.points).sum();
        assert_eq!(sum, a.priority as i32, "ledger must reconcile for {}", a.id);
        assert_eq!(a.capture_count as usize, a.captures.len());
    }
    for w in case.case_alerts.windows(2) {
        assert!(w[0].priority >= w[1].priority, "queue must be worst-first");
    }
    // Deterministic: a second run over the same inputs yields the identical queue.
    let case_out2 = tempfile::tempdir().expect("case dir 2");
    let again = run_once(case_out2.path());
    assert_eq!(case.case_alerts, again.case_alerts);
    assert_eq!(case.total_case_alerts, again.total_case_alerts);
}

/// Older case.json files (written before the queue existed) still parse, and the case report
/// renders the queue section only when there is one.
#[test]
fn case_json_back_compat_and_html_queue_section() {
    let (input, case_out) = build_case_dir();
    let case = run_case(
        input.path(),
        &cfg_for(case_out.path()),
        &PipelineConfig::default(),
        0,
        |_, _, _| {},
    )
    .expect("run_case");

    // Back-compat: strip the new keys and re-parse.
    let mut v: serde_json::Value = serde_json::from_str(&case.to_json_pretty().unwrap()).unwrap();
    let obj = v.as_object_mut().unwrap();
    obj.remove("case_alerts");
    obj.remove("total_case_alerts");
    let old: ppcap_core::CaseSummary = serde_json::from_value(v).unwrap();
    assert!(old.case_alerts.is_empty());
    assert_eq!(old.total_case_alerts, 0);

    // The case report renders the queue when present, omits it when absent.
    let html = ppcap_core::case_html(&case, 0);
    if case.case_alerts.is_empty() {
        assert!(!html.contains("Case alert queue"));
    } else {
        assert!(html.contains("<h2>Case alert queue</h2>"));
        assert!(html.contains(&case.case_alerts[0].priority.to_string()));
    }
    let html_old = ppcap_core::case_html(&old, 0);
    assert!(!html_old.contains("Case alert queue"));
}
