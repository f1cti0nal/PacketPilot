//! Unit tests for the HTML triage report renderer (`ppcap_core::render_html`).
//!
//! These build an `AnalysisOutput` by hand (no capture needed) so the renderer is exercised
//! in isolation, with a focus on the escaping discipline (the security-critical invariant)
//! and the presence of every section.

use ppcap_core::{
    render_html, AnalysisOutput, Finding, FindingKind, Incident, IpClass, IpThreat, Severity,
    SeverityCounts, Summary,
};

fn sample() -> AnalysisOutput {
    let mut sum = Summary::empty();
    sum.total_packets = 123_456;
    sum.total_flows = 42;
    sum.total_bytes = 9_876_543;
    sum.unique_hosts = 7;
    sum.severity_counts = SeverityCounts {
        critical: 2,
        high: 3,
        medium: 1,
        low: 0,
        info: 5,
    };
    sum.ip_threats = vec![IpThreat {
        ip: "203.0.113.7".into(),
        ip_class: IpClass::Public,
        severity: Severity::Critical,
        score: 92,
        flows: 4,
        bytes: 8888,
        ioc: true,
        tags: vec!["public".into(), "ioc".into()],
        attack: vec!["T1071".into()],
        evidence: vec!["beacon <script>alert(1)</script> & co".into()],
    }];

    AnalysisOutput {
        schema_version: 1,
        engine_version: "9.9.9".into(),
        source_path: "/tmp/evil<&>name.pcap".into(),
        source_sha256: Some("deadbeefcafef00d0011".into()),
        source_bytes: 1_572_864,
        link_type: "EN10MB".into(),
        summary: sum,
        flows_parquet_path: None,
        elapsed_ms: 42,
    }
}

#[test]
fn renders_well_formed_document_with_all_sections() {
    let html = render_html(&sample(), 1_700_000_000);

    assert!(html.starts_with("<!doctype"), "must start with doctype");
    assert!(html.contains("</html>"), "must close html");

    for heading in [
        "Executive summary",
        "Active incidents",
        "Severity distribution",
        "Top threats",
        "Traffic categories",
        "Top talkers",
        "Protocol mix",
        "Activity timeline",
    ] {
        assert!(html.contains(heading), "missing section heading: {heading}");
    }

    // Severity labels in the distribution chart.
    for label in ["critical", "high", "medium", "low", "info"] {
        assert!(html.contains(label), "missing severity label: {label}");
    }

    // The known threat IP is present.
    assert!(html.contains("203.0.113.7"), "threat IP missing");

    // Thousands-grouped total_packets.
    assert!(html.contains("123,456"), "grouped packet count missing");

    // Generated-at timestamp: 1_700_000_000 == 2023-11-14 UTC.
    assert!(html.contains("2023-11-14"), "generated-at date missing");
}

#[test]
fn escapes_all_dynamic_strings() {
    let html = render_html(&sample(), 1_700_000_000);

    // Capture basename is escaped; raw form must NOT appear.
    assert!(
        html.contains("evil&lt;&amp;&gt;name.pcap"),
        "basename not escaped"
    );
    assert!(
        !html.contains("evil<&>name"),
        "raw unescaped basename leaked"
    );

    // Evidence escaping: the script tag is neutralized, the ampersand is entity-encoded.
    assert!(html.contains("&lt;script&gt;"), "script tag not escaped");
    assert!(
        !html.contains("<script>alert(1)"),
        "raw <script> leaked into output"
    );
    assert!(
        html.contains("alert(1)&lt;/script&gt; &amp; co"),
        "evidence ampersand/closing-tag not escaped"
    );
}

#[test]
fn empty_summary_still_renders_valid_document() {
    let mut out = sample();
    out.summary = Summary::empty();
    let html = render_html(&out, 0);
    assert!(html.starts_with("<!doctype"));
    assert!(html.contains("</html>"));
    assert!(html.contains("No scored IP threats."));
    assert!(html.contains("No categorized flows."));
    assert!(html.contains("Insufficient timeline data."));
    assert!(html.contains("No active incidents"));
}

/// An output carrying one correlated, multi-stage incident.
fn incident_sample() -> AnalysisOutput {
    let mut out = sample();
    let finding = Finding {
        kind: FindingKind::Beacon,
        severity: Severity::High,
        score: 70,
        title: "Periodic beacon: 10.0.0.5 -> 8.8.8.8:443 every ~60s".into(),
        src_ip: "10.0.0.5".into(),
        dst_ip: Some("8.8.8.8".into()),
        dst_port: Some(443),
        attack: vec!["T1071".into()],
        evidence: vec!["periodic beaconing".into()],
        interval_ns: Some(60_000_000_000),
        jitter_cv: Some(0.013),
        contacts: Some(16),
    };
    out.summary.incidents = vec![Incident {
        host: "10.0.0.5".into(),
        severity: Severity::Critical,
        score: 89,
        title: "Multi-stage incident on 10.0.0.5".into(),
        // Includes a raw '<' to exercise escaping in the narrative.
        narrative: "10.0.0.5 swept the network, then beaconed to a C2 <b>".into(),
        stages: vec!["Discovery".into(), "Command & Control".into()],
        attack: vec!["T1046".into(), "T1071".into()],
        findings: vec![finding],
    }];
    out
}

#[test]
fn renders_active_incidents_with_kill_chain() {
    let html = render_html(&incident_sample(), 1_700_000_000);

    // The incident card surfaces host, score, kill-chain stages, ATT&CK, the finding kind label,
    // and its metric pills.
    assert!(html.contains("Active incidents"));
    assert!(html.contains("10.0.0.5"), "incident host missing");
    assert!(html.contains("89/100"), "incident score missing");
    assert!(
        html.contains("Command &amp; Control"),
        "kill-chain stage missing/escaped wrong"
    );
    assert!(html.contains("C2 Beacon"), "finding kind label missing");
    assert!(html.contains("16 contacts"), "finding metric missing");
    assert!(html.contains("T1046"), "ATT&CK technique missing");

    // The executive-summary callout leads with the correlated-incident count + worst severity.
    assert!(
        html.contains("correlated incident"),
        "exec summary omits incident count"
    );
    assert!(
        html.contains("worst critical"),
        "exec summary omits worst severity"
    );

    // Narrative is escaped: the raw '<b>' must be neutralized.
    assert!(
        html.contains("a C2 &lt;b&gt;"),
        "incident narrative not escaped"
    );
    assert!(
        !html.contains("a C2 <b>"),
        "raw '<b>' leaked from narrative"
    );
}
