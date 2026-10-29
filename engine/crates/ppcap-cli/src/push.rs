//! `ppcap push`: deliver an analysis's alert queue to the destinations in a `destinations.json`.
//!
//! The payloads, URL/credential resolution and the sent ledger are pure in
//! [`ppcap_core::export::push`]; this module only orders the work, talks HTTP through a
//! [`Sender`] (real `ureq` in the binary, a recorder in tests) and prints progress to stderr.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use ppcap_core::export::push::{
    build_payloads, bulk_item_errors, delivery_key, escalation_payload, resolve_target,
    response_ok, response_reference, select_alerts, Destination, DestinationFile, DestinationKind,
    PushLedger, PushPayload, SendDecision,
};
use ppcap_core::{AnalysisOutput, PriorityBand};

/// How one request leaves the machine.
pub(crate) trait Sender {
    fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        content_type: &str,
        body: &str,
    ) -> Result<(u16, String), String>;
}

/// The real network sender.
pub(crate) struct HttpSender;

impl Sender for HttpSender {
    fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        content_type: &str,
        body: &str,
    ) -> Result<(u16, String), String> {
        ppcap_core::export::push::http_send(method, url, headers, content_type, body)
    }
}

/// What to do with the rendered requests.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Mode {
    /// Send, and record deliveries in the ledger.
    Send,
    /// Print each request (secrets hidden); send nothing, record nothing.
    DryRun,
    /// Write each request body into this directory; send nothing, record nothing.
    OutDir(PathBuf),
}

/// Options shared by every destination in one run.
pub(crate) struct PushOptions {
    pub to: Vec<String>,
    pub min_band: Option<PriorityBand>,
    pub alerts: Vec<String>,
    pub resend: bool,
    pub mode: Mode,
    pub quiet: bool,
}

/// Per-destination outcome, also the `--json` report row.
#[derive(Debug, Default, Clone, PartialEq, serde::Serialize)]
pub(crate) struct DestinationReport {
    pub name: String,
    pub kind: String,
    /// Alerts that passed the band / id filters.
    pub selected: usize,
    /// Alerts delivered (or, in dry-run / out-dir mode, rendered).
    pub sent: usize,
    /// Of `sent`, re-sent because their band rose since the last delivery.
    pub escalated: usize,
    /// Skipped because the ledger already has them at this band.
    pub already_sent: usize,
    /// Alerts whose request failed.
    pub failed: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    /// Ticket references returned per alert (Jira key, TheHive id).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub references: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq, serde::Serialize)]
pub(crate) struct PushReport {
    pub destinations: Vec<DestinationReport>,
}

impl PushReport {
    pub fn failed(&self) -> usize {
        self.destinations.iter().map(|d| d.failed).sum()
    }
}

/// The destinations this run addresses: every enabled one, or exactly those named by `--to`
/// (which may name a disabled one), each once, in the order first named.
fn chosen<'a>(file: &'a DestinationFile, to: &[String]) -> anyhow::Result<Vec<&'a Destination>> {
    if to.is_empty() {
        return Ok(file.destinations.iter().filter(|d| !d.disabled).collect());
    }
    let mut seen = std::collections::BTreeSet::new();
    to.iter()
        .filter(|name| seen.insert(name.as_str()))
        .map(|name| {
            file.destinations
                .iter()
                .find(|d| &d.name == name)
                .ok_or_else(|| {
                    let known: Vec<&str> =
                        file.destinations.iter().map(|d| d.name.as_str()).collect();
                    anyhow!(
                        "no destination named {name:?} (known: {})",
                        known.join(", ")
                    )
                })
        })
        .collect()
}

/// File-name-safe form of a destination name.
fn slug(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Push `out`'s alert queue to the chosen destinations. `ledger` is updated in `Mode::Send` and
/// `save_ledger` called after each destination, so a later failure keeps earlier deliveries.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_push(
    out: &AnalysisOutput,
    file: &DestinationFile,
    opts: &PushOptions,
    ledger: &mut PushLedger,
    sender: &dyn Sender,
    env: &dyn Fn(&str) -> Option<String>,
    now_secs: i64,
    save_ledger: &mut dyn FnMut(&PushLedger) -> anyhow::Result<()>,
) -> anyhow::Result<PushReport> {
    let dests = chosen(file, &opts.to)?;
    if dests.is_empty() && !opts.quiet {
        eprintln!("push: no enabled destinations (name one with --to, or set \"disabled\": false)");
    }
    let mut report = PushReport::default();
    for (index, dest) in dests.into_iter().enumerate() {
        let mut row = DestinationReport {
            name: dest.name.clone(),
            kind: dest.kind.as_str().to_string(),
            ..DestinationReport::default()
        };
        let selected = select_alerts(out, dest, opts.min_band, &opts.alerts);
        row.selected = selected.len();
        // The ledger decides what is new; an out-dir export renders the whole selection.
        let exporting = matches!(opts.mode, Mode::OutDir(_));
        let keys: BTreeMap<&str, String> = selected
            .iter()
            .map(|a| (a.id.as_str(), delivery_key(out, a)))
            .collect();
        let mut todo = Vec::new();
        let mut escalated = std::collections::BTreeSet::new();
        for a in selected {
            let decision = ledger.decide(&dest.name, &keys[a.id.as_str()], a);
            match decision {
                SendDecision::AlreadySent if !opts.resend && !exporting => {
                    row.already_sent += 1;
                }
                SendDecision::Escalated => {
                    escalated.insert(a.id.clone());
                    todo.push(a);
                }
                _ => todo.push(a),
            }
        }
        // An escalated alert that already has a ticket updates it (a Jira comment, a TheHive
        // severity bump) instead of opening a second one; everything else is created.
        let mut payloads: Vec<PushPayload> = Vec::new();
        let mut create = Vec::new();
        for a in &todo {
            let update = (escalated.contains(&a.id) && !exporting)
                .then(|| ledger.entry(&dest.name, &keys[a.id.as_str()]))
                .flatten()
                .and_then(|e| e.reference.as_deref())
                .and_then(|r| escalation_payload(out, dest, a, r));
            match update {
                Some(p) => payloads.push(p),
                None => create.push(*a),
            }
        }
        let updates = payloads.len();
        payloads.extend(build_payloads(out, dest, &create, now_secs));
        let by_id: BTreeMap<&str, &ppcap_core::Alert> =
            todo.iter().map(|a| (a.id.as_str(), *a)).collect();

        match &opts.mode {
            Mode::OutDir(dir) => {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("create {}", dir.display()))?;
                for (i, p) in payloads.iter().enumerate() {
                    // The destination's position keeps two names that slug alike apart.
                    let path = dir.join(format!(
                        "{:02}-{}-{:03}.{}",
                        index + 1,
                        slug(&dest.name),
                        i + 1,
                        p.extension()
                    ));
                    std::fs::write(&path, &p.body)
                        .with_context(|| format!("write {}", path.display()))?;
                    row.sent += p.alert_ids.len();
                    row.files.push(path.display().to_string());
                }
            }
            Mode::DryRun => {
                let shown = resolve_target(dest, env)
                    .map(|t| t.display_url)
                    .unwrap_or_else(|e| {
                        row.errors.push(e);
                        dest.url
                            .clone()
                            .or_else(|| dest.url_env.as_ref().map(|v| format!("${v}")))
                            .unwrap_or_default()
                    });
                for p in &payloads {
                    println!(
                        "### {} ({}) {} {}{} [{}] {} alert(s)",
                        dest.name,
                        dest.kind.as_str(),
                        p.method,
                        shown,
                        p.path,
                        p.content_type,
                        p.alert_ids.len()
                    );
                    println!("{}", p.body.trim_end());
                    row.sent += p.alert_ids.len();
                }
                row.escalated = escalated.len();
            }
            Mode::Send => {
                if payloads.is_empty() {
                    report.destinations.push(row);
                    continue;
                }
                let target = match resolve_target(dest, env) {
                    Ok(t) => t,
                    Err(e) => {
                        row.failed += todo.len();
                        row.errors.push(e);
                        report.destinations.push(row);
                        continue;
                    }
                };
                for (i, p) in payloads.iter().enumerate() {
                    let url = format!("{}{}", target.base_url, p.path);
                    let result = sender
                        .send(&p.method, &url, &target.headers, &p.content_type, &p.body)
                        .and_then(|(status, body)| {
                            response_ok(dest.kind, status, &body).map(|()| body)
                        })
                        // Errors can echo the secret URL or token back; never print or save it.
                        .map_err(|e| target.redact(&e));
                    let body = match result {
                        Ok(body) => body,
                        Err(e) => {
                            row.failed += p.alert_ids.len();
                            row.errors.push(e);
                            continue;
                        }
                    };
                    // A bulk request succeeds or fails item by item.
                    let item_errors = if dest.kind == DestinationKind::Elastic {
                        bulk_item_errors(&body, p.alert_ids.len())
                    } else {
                        vec![None; p.alert_ids.len()]
                    };
                    // Only a create returns a new ticket; an update keeps the recorded one.
                    let reference = (dest.kind.per_alert() && i >= updates)
                        .then(|| response_reference(dest.kind, &body))
                        .flatten();
                    for (id, err) in p.alert_ids.iter().zip(item_errors) {
                        if let Some(e) = err {
                            row.failed += 1;
                            row.errors.push(target.redact(&format!("{id}: {e}")));
                            continue;
                        }
                        if let Some(a) = by_id.get(id.as_str()) {
                            ledger.record(
                                &dest.name,
                                &keys[id.as_str()],
                                a,
                                now_secs,
                                reference.clone(),
                            );
                        }
                        if escalated.contains(id) {
                            row.escalated += 1;
                        }
                        if let Some(r) = ledger
                            .entry(&dest.name, &keys[id.as_str()])
                            .and_then(|e| e.reference.clone())
                        {
                            row.references.insert(id.clone(), r);
                        }
                        row.sent += 1;
                    }
                    // Checkpoint after every request, so an interrupted run never re-sends
                    // what already went out.
                    save_ledger(ledger)?;
                }
            }
        }
        if !opts.quiet {
            eprintln!("{}", report_line(&row, &opts.mode));
        }
        report.destinations.push(row);
    }
    Ok(report)
}

fn report_line(r: &DestinationReport, mode: &Mode) -> String {
    let verb = match mode {
        Mode::Send => "sent",
        Mode::DryRun => "would send",
        Mode::OutDir(_) => "wrote",
    };
    let mut s = format!("push: {} ({}): {verb} {}", r.name, r.kind, r.sent);
    if r.escalated > 0 {
        s.push_str(&format!(" ({} escalated)", r.escalated));
    }
    if r.already_sent > 0 {
        s.push_str(&format!(", {} already sent", r.already_sent));
    }
    if r.failed > 0 {
        s.push_str(&format!(", {} failed", r.failed));
    }
    if !r.references.is_empty() {
        let refs: Vec<&str> = r.references.values().map(String::as_str).collect();
        s.push_str(&format!(" → {}", refs.join(", ")));
    }
    for e in &r.errors {
        s.push_str(&format!("\n  error: {e}"));
    }
    s
}

/// Default ledger: `push-ledger.json` beside the destinations file, so a team that shares the
/// destinations also shares what was sent.
pub(crate) fn default_ledger_path(destinations: &Path) -> PathBuf {
    destinations
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("push-ledger.json")
}

pub(crate) fn load_ledger(path: &Path) -> anyhow::Result<PushLedger> {
    match std::fs::read_to_string(path) {
        Ok(text) => PushLedger::parse(&text)
            .map_err(|e| anyhow!(e))
            .with_context(|| format!("parse push ledger {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PushLedger::default()),
        Err(e) => Err(e).with_context(|| format!("read push ledger {}", path.display())),
    }
}

pub(crate) fn save_ledger(path: &Path, ledger: &PushLedger) -> anyhow::Result<()> {
    let text = serde_json::to_string_pretty(ledger)?;
    // Write-then-rename so an interrupted run never leaves a truncated ledger.
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text + "\n").with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("write {}", path.display()))
}

/// clap value parser for `--min-band`.
pub(crate) fn parse_band(s: &str) -> Result<PriorityBand, String> {
    serde_json::from_value(serde_json::Value::String(s.replace('-', "_")))
        .map_err(|_| format!("{s:?} is not a band (act_now, investigate, review, log, info)"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// One recorded request: "METHOD url", headers, body.
    type Call = (String, Vec<(String, String)>, String);
    type Answer = Box<dyn Fn(&str) -> Result<(u16, String), String>>;

    struct Recorder {
        calls: RefCell<Vec<Call>>,
        answer: Answer,
    }

    impl Sender for Recorder {
        fn send(
            &self,
            method: &str,
            url: &str,
            headers: &[(String, String)],
            _ct: &str,
            body: &str,
        ) -> Result<(u16, String), String> {
            self.calls.borrow_mut().push((
                format!("{method} {url}"),
                headers.to_vec(),
                body.to_string(),
            ));
            (self.answer)(url)
        }
    }

    fn analysis() -> AnalysisOutput {
        let mut out = AnalysisOutput::default();
        let mk = |id: &str, band: PriorityBand, prio: u16| {
            let mut a: ppcap_core::Alert = serde_json::from_value(serde_json::json!({
                "id": id, "source": "host", "band": "info", "priority": 0, "confidence": 70,
                "severity": "high", "title": format!("Alert {id}"), "narrative": "n",
                "action": "a", "actor": "10.0.0.5", "hosts": ["10.0.0.5"], "host_count": 1,
                "attack": ["T1071"], "stage": "Command and Control", "stage_ordinal": 5,
                "priority_terms": [],
                "context": {"actor": {"ip": "10.0.0.5", "internal": true}, "peers": [],
                            "entries": []},
                "finding_indices": [], "finding_count": 0,
                "first_seen_ns": null, "last_seen_ns": null
            }))
            .unwrap();
            a.band = band;
            a.priority = prio;
            a
        };
        out.summary.alerts = vec![
            mk("alert:a", PriorityBand::ActNow, 90),
            mk("alert:b", PriorityBand::Review, 40),
        ];
        out
    }

    fn file() -> DestinationFile {
        DestinationFile::parse(
            r#"{"destinations":[
              {"name":"jira","kind":"jira","url":"https://jira.example","project":"SEC",
               "token_env":"PPCAP_JT"},
              {"name":"hec","kind":"splunk_hec","url":"https://hec.example","token_env":"PPCAP_HT",
               "min_band":"investigate"},
              {"name":"off","kind":"webhook","url":"https://w.example","disabled":true}
            ]}"#,
        )
        .unwrap()
    }

    fn env(k: &str) -> Option<String> {
        match k {
            "PPCAP_JT" => Some("jt".into()),
            "PPCAP_HT" => Some("ht".into()),
            _ => None,
        }
    }

    fn opts(mode: Mode) -> PushOptions {
        PushOptions {
            to: Vec::new(),
            min_band: None,
            alerts: Vec::new(),
            resend: false,
            mode,
            quiet: true,
        }
    }

    fn ok_sender() -> Recorder {
        Recorder {
            calls: RefCell::new(Vec::new()),
            answer: Box::new(|url| {
                if url.contains("/rest/api/2/issue") {
                    Ok((201, r#"{"id":"1","key":"SEC-1"}"#.into()))
                } else {
                    Ok((200, r#"{"text":"Success","code":0}"#.into()))
                }
            }),
        }
    }

    #[test]
    fn sends_records_and_skips_on_rerun() {
        let out = analysis();
        let f = file();
        let sender = ok_sender();
        let mut ledger = PushLedger::default();
        let saves = std::cell::Cell::new(0);
        let mut save = |_: &PushLedger| {
            saves.set(saves.get() + 1);
            Ok(())
        };
        let r = run_push(
            &out,
            &f,
            &opts(Mode::Send),
            &mut ledger,
            &sender,
            &env,
            100,
            &mut save,
        )
        .unwrap();
        assert_eq!(
            saves.get(),
            3,
            "the ledger is checkpointed after every request"
        );
        let names: Vec<_> = r.destinations.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["jira", "hec"], "disabled destinations are skipped");
        assert_eq!(r.destinations[0].sent, 2);
        assert_eq!(r.destinations[1].sent, 1, "hec floor is investigate");
        let calls = sender.calls.borrow();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].0, "POST https://jira.example/rest/api/2/issue");
        assert_eq!(
            calls[0].1,
            vec![("Authorization".into(), "Bearer jt".into())]
        );
        assert_eq!(
            calls[2].0,
            "POST https://hec.example/services/collector/event"
        );
        assert_eq!(calls[2].1[0].1, "Splunk ht");
        assert_eq!(
            ledger
                .entry("jira", &delivery_key(&out, &out.summary.alerts[0]))
                .unwrap()
                .reference
                .as_deref(),
            Some("SEC-1")
        );
        drop(calls);

        // Same alerts again: nothing goes out.
        let r2 = run_push(
            &out,
            &f,
            &opts(Mode::Send),
            &mut ledger,
            &sender,
            &env,
            200,
            &mut save,
        )
        .unwrap();
        assert_eq!(sender.calls.borrow().len(), 3);
        assert_eq!(r2.destinations[0].already_sent, 2);
        assert_eq!(r2.destinations[0].sent, 0);

        // An escalated alert goes again; --resend sends everything.
        let mut worse = out.clone();
        worse.summary.alerts[1].band = PriorityBand::Investigate;
        let r3 = run_push(
            &worse,
            &f,
            &opts(Mode::Send),
            &mut ledger,
            &sender,
            &env,
            300,
            &mut save,
        )
        .unwrap();
        assert_eq!(r3.destinations[0].sent, 1);
        assert_eq!(r3.destinations[0].escalated, 1);
        // The escalation comments on the existing issue instead of opening a second one.
        let jira_calls: Vec<String> = sender
            .calls
            .borrow()
            .iter()
            .map(|c| c.0.clone())
            .filter(|u| u.contains("jira"))
            .collect();
        assert_eq!(
            jira_calls.last().unwrap(),
            "POST https://jira.example/rest/api/2/issue/SEC-1/comment"
        );
        let key = delivery_key(&worse, &worse.summary.alerts[1]);
        let e = ledger.entry("jira", &key).unwrap();
        assert_eq!(
            (e.band, e.reference.as_deref()),
            (PriorityBand::Investigate, Some("SEC-1"))
        );
        assert_eq!(
            r3.destinations[1].sent, 1,
            "now above the hec floor, new there"
        );
        let mut again = opts(Mode::Send);
        again.resend = true;
        again.to = vec!["jira".into()];
        let r4 = run_push(
            &worse,
            &f,
            &again,
            &mut ledger,
            &sender,
            &env,
            400,
            &mut save,
        )
        .unwrap();
        assert_eq!(r4.destinations.len(), 1);
        assert_eq!(r4.destinations[0].sent, 2);
    }

    #[test]
    fn failures_are_reported_and_not_recorded() {
        let out = analysis();
        let f = file();
        let sender = Recorder {
            calls: RefCell::new(Vec::new()),
            answer: Box::new(|_| Ok((401, "unauthorized".into()))),
        };
        let mut ledger = PushLedger::default();
        let r = run_push(
            &out,
            &f,
            &opts(Mode::Send),
            &mut ledger,
            &sender,
            &env,
            1,
            &mut |_| Ok(()),
        )
        .unwrap();
        assert_eq!(r.destinations[0].failed, 2);
        assert!(r.destinations[0].errors[0].contains("HTTP 401"));
        assert!(r.failed() > 0);
        assert!(ledger.sent.values().all(|m| m.is_empty()));

        // A missing secret fails the destination without any request.
        let none = |_: &str| None;
        let sender = ok_sender();
        let r = run_push(
            &out,
            &f,
            &opts(Mode::Send),
            &mut ledger,
            &sender,
            &none,
            1,
            &mut |_| Ok(()),
        )
        .unwrap();
        assert!(sender.calls.borrow().is_empty());
        assert!(r.destinations[0].errors[0].contains("JT"));
        assert_eq!(r.failed(), 3);
    }

    #[test]
    fn dry_run_and_out_dir_never_send_or_record() {
        let out = analysis();
        let f = file();
        let sender = ok_sender();
        let mut ledger = PushLedger::default();
        let r = run_push(
            &out,
            &f,
            &opts(Mode::DryRun),
            &mut ledger,
            &sender,
            &env,
            1,
            &mut |_| panic!("dry run must not save"),
        )
        .unwrap();
        assert_eq!(r.destinations[0].sent, 2);
        assert!(sender.calls.borrow().is_empty());

        let dir = tempfile::tempdir().unwrap();
        let mode = Mode::OutDir(dir.path().join("out"));
        // Out-dir needs no secrets and ignores the ledger.
        let a = &out.summary.alerts[0];
        ledger.record("jira", &delivery_key(&out, a), a, 1, None);
        let none = |_: &str| None;
        let r = run_push(
            &out,
            &f,
            &opts(mode),
            &mut ledger,
            &sender,
            &none,
            1,
            &mut |_| panic!("export must not save"),
        )
        .unwrap();
        assert!(sender.calls.borrow().is_empty());
        assert_eq!(r.destinations[0].files.len(), 2);
        assert_eq!(r.destinations[1].files.len(), 1);
        assert!(dir.path().join("out/01-jira-001.json").exists());
        assert!(dir.path().join("out/02-hec-001.json").exists());
    }

    #[test]
    fn repeated_to_names_send_once() {
        let out = analysis();
        let sender = ok_sender();
        let mut o = opts(Mode::Send);
        o.to = vec!["jira".into(), "jira".into()];
        o.resend = true;
        let r = run_push(
            &out,
            &file(),
            &o,
            &mut PushLedger::default(),
            &sender,
            &env,
            1,
            &mut |_| Ok(()),
        )
        .unwrap();
        assert_eq!(r.destinations.len(), 1);
        assert_eq!(sender.calls.borrow().len(), 2);
    }

    #[test]
    fn elastic_partial_bulk_records_only_accepted_items() {
        let out = analysis();
        let f = DestinationFile::parse(
            r#"{"destinations":[{"name":"es","kind":"elastic","url":"https://es.example",
                "token_env":"PPCAP_JT"}]}"#,
        )
        .unwrap();
        let sender = Recorder {
            calls: RefCell::new(Vec::new()),
            answer: Box::new(|_| {
                Ok((
                    200,
                    r#"{"errors":true,"items":[{"create":{"status":201}},
                        {"create":{"status":400,"error":{"reason":"mapper_parsing_exception"}}}]}"#
                        .into(),
                ))
            }),
        };
        let mut ledger = PushLedger::default();
        let r = run_push(
            &out,
            &f,
            &opts(Mode::Send),
            &mut ledger,
            &sender,
            &env,
            1,
            &mut |_| Ok(()),
        )
        .unwrap();
        assert_eq!((r.destinations[0].sent, r.destinations[0].failed), (1, 1));
        assert!(r.destinations[0].errors[0].starts_with("alert:b: HTTP 400"));
        let a = &out.summary.alerts;
        assert!(ledger.entry("es", &delivery_key(&out, &a[0])).is_some());
        assert!(ledger.entry("es", &delivery_key(&out, &a[1])).is_none());
    }

    #[test]
    fn errors_never_carry_secret_urls_or_tokens() {
        let out = analysis();
        let f = DestinationFile::parse(
            r#"{"destinations":[{"name":"s","kind":"slack","url_env":"PPCAP_SLACK"}]}"#,
        )
        .unwrap();
        let env = |k: &str| {
            (k == "PPCAP_SLACK").then(|| "https://hooks.slack.com/services/T0/B0/s3cr3t".into())
        };
        let sender = Recorder {
            calls: RefCell::new(Vec::new()),
            answer: Box::new(|url| Err(format!("{url}: Connection refused"))),
        };
        let r = run_push(
            &out,
            &f,
            &opts(Mode::Send),
            &mut PushLedger::default(),
            &sender,
            &env,
            1,
            &mut |_| Ok(()),
        )
        .unwrap();
        let err = &r.destinations[0].errors[0];
        assert!(!err.contains("s3cr3t"), "{err}");
        assert!(err.contains("$PPCAP_SLACK"), "{err}");
    }

    #[test]
    fn unknown_destination_names_are_an_error() {
        let out = analysis();
        let mut o = opts(Mode::DryRun);
        o.to = vec!["nope".into()];
        let e = run_push(
            &out,
            &file(),
            &o,
            &mut PushLedger::default(),
            &ok_sender(),
            &env,
            1,
            &mut |_| Ok(()),
        )
        .unwrap_err();
        assert!(e.to_string().contains("jira, hec, off"), "{e}");
    }

    #[test]
    fn band_parser_accepts_both_spellings() {
        assert_eq!(parse_band("act-now"), Ok(PriorityBand::ActNow));
        assert_eq!(parse_band("review"), Ok(PriorityBand::Review));
        assert!(parse_band("urgent").is_err());
    }

    #[test]
    fn ledger_file_round_trips_beside_destinations() {
        let dir = tempfile::tempdir().unwrap();
        let p = default_ledger_path(&dir.path().join("destinations.json"));
        assert_eq!(p, dir.path().join("push-ledger.json"));
        assert_eq!(load_ledger(&p).unwrap(), PushLedger::default());
        let mut l = PushLedger::default();
        l.record(
            "x",
            "alert:a@0",
            &analysis().summary.alerts[0],
            5,
            Some("T-1".into()),
        );
        save_ledger(&p, &l).unwrap();
        assert_eq!(load_ledger(&p).unwrap(), l);
        assert_eq!(
            default_ledger_path(Path::new("destinations.json")),
            PathBuf::from("./push-ledger.json")
        );
    }
}
