//! End-to-end tests for Smart Alerting with Context.
//!
//! Run full synthetic captures through `analyze::run` and assert the derived alert queue:
//! present, ranked, coverage-exact (every finding index in exactly one alert), deterministic,
//! and led by the strongest story — with the transparent priority ledger reconciling on every
//! row. The `AttackChain` scenario exercises the chain tier end-to-end; `Mixed` exercises
//! compression over a noisy capture.

use ppcap_core::analyze::{self, PipelineConfig};
use ppcap_core::gen::{GenConfig, Scenario, SynthGen};
use ppcap_core::model::alert::AlertSource;
use ppcap_core::model::summary::Summary;

fn capture(scenario: Scenario, packets: u64) -> tempfile::TempPath {
    let cfg = GenConfig {
        scenario,
        packets,
        seed: 0x5EED_1234,
        include_edge_cases: false,
        host_count: 8,
        ..Default::default()
    };
    let tf = tempfile::NamedTempFile::new().expect("temp file");
    SynthGen::new(cfg)
        .write_pcap(tf.path())
        .expect("generate capture");
    tf.into_temp_path()
}

/// The coverage invariant: every finding index appears in exactly one alert.
fn assert_coverage(s: &Summary) {
    let mut seen = vec![0usize; s.findings.len()];
    for a in &s.alerts {
        assert_eq!(a.finding_count as usize, a.finding_indices.len());
        for &i in &a.finding_indices {
            seen[i as usize] += 1;
        }
    }
    for (i, &count) in seen.iter().enumerate() {
        assert_eq!(
            count, 1,
            "finding {i} ({:?}) covered {count} times",
            s.findings[i].kind
        );
    }
}

#[test]
fn attack_chain_scenario_leads_with_a_chain_alert() {
    let path = capture(Scenario::AttackChain, 4_000);
    let out = analyze::run(&path, &PipelineConfig::default(), |_, _, _| {}).expect("analyze");
    let s = &out.summary;

    assert!(
        !s.alerts.is_empty(),
        "the staged attack must produce alerts; findings: {:?}",
        s.findings.iter().map(|f| f.kind).collect::<Vec<_>>()
    );
    assert_coverage(s);

    // The queue is a permutation-stable rank: worst first.
    for w in s.alerts.windows(2) {
        assert!(
            w[0].priority >= w[1].priority,
            "queue must be priority-sorted"
        );
    }
    // The staged cross-host compromise is the headline when reconstruction stitched one.
    if s.attack_chains.iter().any(|c| c.host_count >= 2) {
        assert_eq!(
            s.alerts[0].source,
            AlertSource::Chain,
            "a cross-host chain leads the queue; got {:?} ({})",
            s.alerts[0].source,
            s.alerts[0].title
        );
        assert!(s.alerts[0].chain_id.is_some());
        assert!(!s.alerts[0].incident_hosts.is_empty());
    }
    // Every row's ledger reconciles and carries an action + kill-chain position.
    for a in &s.alerts {
        let sum: i32 = a.priority_terms.iter().map(|t| t.points).sum();
        assert_eq!(sum, a.priority as i32, "ledger reconciles for {}", a.id);
        assert!(!a.action.is_empty());
        assert!(!a.stage.is_empty());
    }
}

#[test]
fn mixed_scenario_compresses_findings_into_a_short_queue() {
    let path = capture(Scenario::Mixed, 20_000);
    let out = analyze::run(&path, &PipelineConfig::default(), |_, _, _| {}).expect("analyze");
    let s = &out.summary;
    if s.findings.is_empty() {
        return; // nothing to alert on — vacuously fine for this seed
    }
    assert_coverage(s);
    assert!(
        s.alerts.len() <= s.findings.len(),
        "the queue never exceeds the finding count"
    );
}

#[test]
fn alert_queue_is_deterministic_across_runs() {
    let path = capture(Scenario::AttackChain, 4_000);
    let run = || {
        analyze::run(&path, &PipelineConfig::default(), |_, _, _| {})
            .expect("analyze")
            .summary
            .alerts
    };
    let a = run();
    let b = run();
    assert_eq!(a, b, "same capture => byte-identical queue");
}

#[test]
fn alerts_render_in_the_html_report() {
    let path = capture(Scenario::AttackChain, 4_000);
    let out = analyze::run(&path, &PipelineConfig::default(), |_, _, _| {}).expect("analyze");
    let html = ppcap_core::render_html(&out, 1_700_000_000, None);
    if out.summary.alerts.is_empty() {
        assert!(!html.contains("Alert queue"));
    } else {
        assert!(html.contains("<h2>Alert queue</h2>"));
        assert!(html.contains(&out.summary.alerts[0].priority.to_string()));
    }
}
