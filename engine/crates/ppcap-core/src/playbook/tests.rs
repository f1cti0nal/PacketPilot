use super::*;
use crate::detect::alerts::refresh_alerts;
use crate::detect::{correlate_incidents, reconstruct_attack_chains};
use crate::model::alert::ContextEntry;
use crate::model::finding::Finding;
use crate::model::severity::Severity;
use crate::model::summary::{CarvedFile, ResolvedDomain};

const S: i64 = 1_000_000_000;

fn f(kind: FindingKind, src: &str, dst: Option<&str>, port: Option<u16>) -> Finding {
    Finding {
        kind,
        severity: Severity::High,
        score: 70,
        title: format!("{}: {src}", kind.as_str()),
        src_ip: src.to_string(),
        dst_ip: dst.map(str::to_string),
        dst_port: port,
        attack: vec!["T1071".to_string()],
        evidence: vec![format!("{} evidence", kind.as_str())],
        interval_ns: None,
        jitter_cv: None,
        contacts: None,
        first_seen_ns: Some(1_700_000_000 * S),
        last_seen_ns: Some(1_700_000_060 * S),
        victims: Vec::new(),
    }
}

fn summary(findings: Vec<Finding>) -> Summary {
    let mut s = Summary::empty();
    s.first_ts_ns = Some(1_700_000_000 * S);
    s.last_ts_ns = Some(1_700_000_600 * S);
    s.incidents = correlate_incidents(&findings);
    s.attack_chains = reconstruct_attack_chains(&findings);
    s.findings = findings;
    s.resolved_ips = vec![ResolvedDomain {
        ip: "45.77.13.37".into(),
        domain: "c2.example".into(),
        resolutions: 3,
    }];
    s.carved_files = vec![CarvedFile {
        client: "10.0.0.7".into(),
        server: "45.77.13.37".into(),
        sha256: "ab".repeat(32),
        size: 68,
        known_bad: true,
        ..Default::default()
    }];
    refresh_alerts(&mut s);
    s
}

fn beacon_summary() -> Summary {
    summary(vec![f(
        FindingKind::Beacon,
        "10.0.0.7",
        Some("45.77.13.37"),
        Some(443),
    )])
}

#[test]
fn builtin_parses_lints_clean_and_covers_every_kind() {
    let (file, warnings) = parse_file(builtin_json()).expect("built-in lints clean");
    assert!(warnings.is_empty(), "{warnings:?}");
    let set = builtin();
    assert_eq!(set.playbooks.len(), file.playbooks.len());
    for k in FindingKind::ALL {
        assert!(
            set.for_kind(k).is_some(),
            "no built-in playbook for {}",
            k.as_str()
        );
    }
    assert!(set.get(GENERIC_ID).is_some());
    assert!(set
        .playbooks
        .iter()
        .all(|p| p.origin.as_deref() == Some("built-in")));
}

#[test]
fn beacon_alert_gets_filled_pivots() {
    let s = beacon_summary();
    let alert = &s.alerts[0];
    let runs = runs_for_alert(&s, alert, &builtin());
    assert_eq!(runs.len(), 1);
    let run = &runs[0];
    assert_eq!(run.playbook_id, "c2-channel");
    assert_eq!(run.kinds, vec![FindingKind::Beacon]);
    let all: Vec<&RenderedPivot> = run.steps.iter().flat_map(|s| &s.pivots).collect();
    // No template survives rendering.
    for p in &all {
        assert!(
            !p.value.contains('{') && !p.label.contains("{actor}"),
            "{p:?}"
        );
    }
    let conv = all
        .iter()
        .find(|p| p.target == PivotTarget::Sql && p.value.contains("dst_ip = '45.77.13.37'"))
        .expect("conversation SQL");
    assert!(conv.value.contains("src_ip = '10.0.0.7'"));
    // The domain came from the DNS answers.
    assert!(all
        .iter()
        .any(|p| p.target == PivotTarget::Flows && p.value == "c2.example"));
    // Packets carry a carve scope over the padded alert window.
    let pk = all
        .iter()
        .find(|p| p.target == PivotTarget::Packets)
        .unwrap();
    let scope = pk.scope.as_ref().unwrap();
    assert_eq!(scope.host, "10.0.0.7");
    assert_eq!(scope.peer.as_deref(), Some("45.77.13.37"));
    assert_eq!(scope.start_ns, 1_700_000_000 * S - WINDOW_PAD_NS);
    assert_eq!(scope.end_ns, 1_700_000_060 * S + WINDOW_PAD_NS);
    // The alert window as SQL timestamps (2023-11-14 22:13:20 UTC minus 15 minutes).
    assert!(all
        .iter()
        .any(|p| p.value.contains("TIMESTAMP '2023-11-14 21:58:20'")));
    // Prose names the hosts.
    assert!(run.steps.iter().any(|s| s.question.contains("45.77.13.37")));
}

#[test]
fn missing_values_drop_the_pivot_and_read_naturally_in_prose() {
    // A sweep has no single peer and no domain.
    let mut sweep = f(FindingKind::HostSweep, "10.0.0.5", None, None);
    sweep.victims = vec!["10.0.0.8".into(), "10.0.0.9".into()];
    let s = summary(vec![sweep]);
    let alert = s.alerts.iter().find(|a| a.actor == "10.0.0.5").unwrap();
    let runs = runs_for_alert(&s, alert, &builtin());
    assert_eq!(runs[0].playbook_id, "recon-scan");
    let pivots: Vec<_> = runs[0].steps.iter().flat_map(|s| &s.pivots).collect();
    assert!(pivots.iter().all(|p| !p.value.contains("{peer}")));
    let victims = pivots
        .iter()
        .find(|p| p.value.contains("IN ("))
        .expect("victims pivot");
    assert!(victims.value.contains("'10.0.0.8', '10.0.0.9'"));
    // Prose with no peer falls back to plain words.
    assert_eq!(fill_prose("Ask {peer}", &Vars::default()), "Ask the peer");
}

#[test]
fn auto_answers_come_from_alert_context() {
    let mut s = beacon_summary();
    let alert = &mut s.alerts[0];
    alert.context.entries.push(ContextEntry {
        kind: ContextKind::NewToNetwork,
        text: "45.77.13.37 was never reached in 5 earlier captures".into(),
        finding_index: None,
        ip: Some("45.77.13.37".into()),
    });
    let alert = s.alerts[0].clone();
    let runs = runs_for_alert(&s, &alert, &builtin());
    let new = runs[0].steps.iter().find(|s| s.id == "new").unwrap();
    let a = new.auto.as_ref().unwrap();
    assert!(a.found);
    assert_eq!(
        a.evidence,
        vec!["45.77.13.37 was never reached in 5 earlier captures"]
    );
    // A step with nothing in context says so instead of guessing.
    let rep = runs[0].steps.iter().find(|s| s.id == "reputation").unwrap();
    assert!(!rep.auto.as_ref().unwrap().found);
    // A step with no answer source has no auto answer.
    let cad = runs[0].steps.iter().find(|s| s.id == "cadence").unwrap();
    assert!(cad.auto.is_none());
}

#[test]
fn chain_alert_gets_one_playbook_per_kind_family() {
    let s = summary(vec![
        f(
            FindingKind::Beacon,
            "10.0.0.7",
            Some("45.77.13.37"),
            Some(443),
        ),
        f(
            FindingKind::MissingSni,
            "10.0.0.7",
            Some("45.77.13.37"),
            Some(443),
        ),
        f(
            FindingKind::DataExfil,
            "10.0.0.7",
            Some("45.77.13.37"),
            Some(443),
        ),
    ]);
    let alert = s.alerts.iter().max_by_key(|a| a.finding_count).unwrap();
    let runs = runs_for_alert(&s, alert, &builtin());
    let ids: Vec<&str> = runs.iter().map(|r| r.playbook_id.as_str()).collect();
    assert!(
        ids.contains(&"c2-channel") && ids.contains(&"data-exfil"),
        "{ids:?}"
    );
    let c2 = runs.iter().find(|r| r.playbook_id == "c2-channel").unwrap();
    if alert.finding_count == 3 {
        assert_eq!(c2.kinds, vec![FindingKind::Beacon, FindingKind::MissingSni]);
    }
    // The malware file on the actor fills {sha256} for anyone who uses it.
    let vars = alert_vars(&s, alert, None);
    assert_eq!(
        vars.map.get("sha256").map(String::as_str),
        Some("ab".repeat(32).as_str())
    );
}

#[test]
fn chain_playbooks_pivot_on_the_host_that_did_each_step() {
    // A sweeps B; B then beacons out. The C2 playbook must pivot on B, not the chain root A.
    let mut sweep = f(FindingKind::HostSweep, "10.0.0.5", Some("10.0.0.7"), None);
    sweep.victims = vec!["10.0.0.7".into()];
    sweep.first_seen_ns = Some(1_699_999_000 * S);
    sweep.last_seen_ns = Some(1_699_999_100 * S);
    let s = summary(vec![
        sweep,
        f(
            FindingKind::Beacon,
            "10.0.0.7",
            Some("45.77.13.37"),
            Some(443),
        ),
    ]);
    let alert = s
        .alerts
        .iter()
        .find(|a| a.chain_id.is_some())
        .expect("chain alert");
    let runs = runs_for_alert(&s, alert, &builtin());
    let c2 = runs.iter().find(|r| r.playbook_id == "c2-channel").unwrap();
    let pk = c2
        .steps
        .iter()
        .flat_map(|s| &s.pivots)
        .find(|p| p.target == PivotTarget::Packets)
        .unwrap();
    assert_eq!(pk.value, "host 10.0.0.7 and host 45.77.13.37");
    assert_eq!(
        pk.scope.as_ref().unwrap().start_ns,
        1_700_000_000 * S - WINDOW_PAD_NS
    );
    let scan = runs.iter().find(|r| r.playbook_id == "recon-scan").unwrap();
    assert!(
        scan.steps[0].question.contains("10.0.0.5"),
        "{:?}",
        scan.steps[0].question
    );
}

#[test]
fn team_file_overrides_by_id_and_by_kind() {
    let team = r#"{
      "version": 1,
      "playbooks": [
        { "id": "c2-channel", "title": "Our C2 checklist", "kinds": ["beacon"],
          "steps": [ { "id": "ticket", "question": "Open a ticket for {actor}", "why": "Policy." } ] },
        { "id": "exfil-team", "title": "Exfil, our way", "kinds": ["data_exfil"],
          "steps": [ { "id": "dlp", "question": "Check DLP for {actor}", "why": "DLP sees content.",
            "pivots": [ { "label": "Uploads", "target": "sql",
              "value": "SELECT * FROM flow WHERE src_ip = '{actor}'" } ] } ] }
      ]
    }"#;
    let (file, _) = parse_file(team).unwrap();
    let mut set = builtin();
    let before = set.playbooks.len();
    set.add_file(file, "team.json");
    assert_eq!(set.playbooks.len(), before + 1, "same id replaces in place");
    assert_eq!(
        set.for_kind(FindingKind::Beacon).unwrap().title,
        "Our C2 checklist"
    );
    assert_eq!(
        set.for_kind(FindingKind::DataExfil).unwrap().id,
        "exfil-team"
    );
    let s = beacon_summary();
    let runs = runs_for_alert(&s, &s.alerts[0], &set);
    assert_eq!(runs[0].origin, "team.json");
    assert_eq!(runs[0].steps[0].question, "Open a ticket for 10.0.0.7");
}

#[test]
fn lint_reports_every_problem() {
    let bad = r#"{
      "version": 2,
      "playbooks": [
        { "id": "x", "title": "", "kinds": ["beacon"], "steps": [
          { "id": "a", "question": "Who is {attacker}?", "why": "" },
          { "id": "a", "question": "", "why": "",
            "pivots": [ { "label": "drop", "target": "sql", "value": "DELETE FROM flow" },
                        { "label": "empty", "target": "flows", "value": "" } ] } ] },
        { "id": "x", "title": "Dup", "kinds": ["beacon"], "steps": [] }
      ]
    }"#;
    let problems = parse_file(bad).unwrap_err();
    let joined = problems.join("\n");
    for needle in [
        "version 2",
        "empty title",
        "unknown placeholder {attacker}",
        "duplicate step id",
        "empty question",
        "SELECT or WITH",
        "empty value",
        "duplicate id",
        "has no steps",
    ] {
        assert!(joined.contains(needle), "missing {needle:?} in:\n{joined}");
    }
    // An unknown kind is a parse error with serde's message.
    let err = parse_file(
        r#"{"version":1,"playbooks":[{"id":"a","title":"A","kinds":["nope"],"steps":[]}]}"#,
    )
    .unwrap_err();
    assert!(err[0].contains("nope"), "{err:?}");
}

#[test]
fn sql_values_are_quoted_safely() {
    let mut v = Vars::default();
    v.map.insert("domain", "o'brien.example".into());
    assert_eq!(
        fill_pivot("SELECT 1 WHERE sni = '{domain}'", &v, true).unwrap(),
        "SELECT 1 WHERE sni = 'o''brien.example'"
    );
    assert_eq!(
        fill_pivot("{domain}", &v, false).unwrap(),
        "o'brien.example"
    );
    assert!(fill_pivot("{peer}", &v, false).is_none());
}

#[test]
fn literal_port_reads_one_port_only() {
    assert_eq!(literal_port("host 10.0.0.7 and port 88"), Some(88));
    assert_eq!(literal_port("host a and (port 389 or port 445)"), None);
    assert_eq!(literal_port("host a and icmp"), None);
}

#[test]
fn generic_playbook_when_nothing_matches() {
    let s = beacon_summary();
    let mut set = builtin();
    set.playbooks
        .retain(|p| !p.kinds.contains(&FindingKind::Beacon));
    let runs = runs_for_alert(&s, &s.alerts[0], &set);
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].playbook_id, GENERIC_ID);
    assert!(runs[0].kinds.is_empty());
}

#[test]
fn markdown_ticks_progress_and_includes_notes() {
    let s = beacon_summary();
    let runs = runs_for_alert(&s, &s.alerts[0], &builtin());
    let mut progress = PlaybookProgress::default();
    progress.done.insert("c2-channel/cadence".into());
    progress.notes.insert(
        "c2-channel/cadence".into(),
        "60s interval, 2% jitter\nall night".into(),
    );
    let md = render_markdown(&runs, Some(&progress));
    assert!(md.starts_with("# Hunt: "), "{md}");
    assert!(md.contains(&format!("Alert `{}`", s.alerts[0].id)));
    let total = runs[0].steps.len();
    assert!(md.contains(&format!("## Command and control channel (1/{total})")));
    assert!(md.contains("- [x] **Is the timing machine-regular"));
    assert!(md.contains("- [ ] **Is the peer already known bad?"));
    assert!(md.contains("  - Note: 60s interval, 2% jitter all night"));
    assert!(md.contains("```sql"));
    assert!(md.contains("Engine found: nothing in this capture"));
    // Without progress nothing is ticked.
    assert!(!render_markdown(&runs, None).contains("- [x]"));
}

#[test]
fn runs_for_unknown_alert_is_none() {
    let s = beacon_summary();
    assert!(runs_for_alert_id(&s, "alert:nope", &builtin()).is_none());
    assert!(runs_for_alert_id(&s, &s.alerts[0].id, &builtin()).is_some());
}
