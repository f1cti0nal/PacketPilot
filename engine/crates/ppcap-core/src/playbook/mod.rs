//! Guided hunt playbooks — a senior analyst's checklist per alert type, with the pivots filled in.
//!
//! A [`Playbook`] is an ordered list of [`Step`]s: a question, why it matters, what normal and bad
//! look like, the context kinds that can answer it, and [`Pivot`]s written as templates over the
//! alert (`{actor}`, `{peer}`, `{port}`, `{domain}`, `{sha256}`, `{start}`, `{end}`, `{hosts}`,
//! `{victims}`). [`runs_for_alert`] picks the playbook for each finding kind in an alert and renders
//! it: placeholders become this alert's values, a pivot whose value is unknown is dropped rather
//! than shown half-filled, and a step whose answer the engine already holds (IOC, reputation,
//! first-seen, baseline, kill chain…) carries that evidence as an [`AutoAnswer`].
//!
//! The built-in set ships embedded ([`builtin`]). Teams override or extend it with plain JSON
//! files in the same format ([`PlaybookFile`], version 1), so the checklist travels with the rule
//! files and needs no server. Pure and offline: no clock, no network, deterministic order.

use std::collections::{BTreeMap, BTreeSet};

use crate::model::alert::{Alert, ContextKind};
use crate::model::finding::{Finding, FindingKind};
use crate::model::summary::{CarvedFile, Summary};
use crate::model::timeline::PacketScope;

/// The only playbook file version this build reads.
pub const PLAYBOOK_FILE_VERSION: u32 = 1;
/// Playbooks rendered per alert (one per distinct member kind, in member order).
pub const MAX_RUNS_PER_ALERT: usize = 3;
/// Steps a playbook may hold.
pub const MAX_STEPS: usize = 20;
/// Pivots a step may hold.
pub const MAX_PIVOTS: usize = 8;
/// Evidence lines carried by one auto-answer.
pub const MAX_AUTO_EVIDENCE: usize = 5;
/// Padding around the alert's activity for `{start}` / `{end}` and packet windows.
const WINDOW_PAD_NS: i64 = 15 * 60 * 1_000_000_000;
/// The id of the fallback playbook used when no playbook names an alert's kinds.
pub const GENERIC_ID: &str = "generic";

const BUILTIN_JSON: &str = include_str!("builtin.json");

/// Placeholders a template may use.
pub const PLACEHOLDERS: [&str; 9] = [
    "actor", "peer", "port", "domain", "sha256", "start", "end", "hosts", "victims",
];

/// Where a pivot lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PivotTarget {
    /// The Flows table, filtered by free text (an address, a name, a fingerprint).
    Flows,
    /// A read-only SQL statement over the `flow` table (the Query console / DuckDB).
    Sql,
    /// The packets themselves: a capture filter, plus a carve scope over the alert window.
    Packets,
    /// The alert's incident timeline.
    Timeline,
}

impl PivotTarget {
    pub fn label(self) -> &'static str {
        match self {
            PivotTarget::Flows => "Flows",
            PivotTarget::Sql => "SQL",
            PivotTarget::Packets => "Packets",
            PivotTarget::Timeline => "Timeline",
        }
    }
}

/// One pivot template.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Pivot {
    pub label: String,
    pub target: PivotTarget,
    /// Template: free text for `flows`, SQL for `sql`, a capture filter for `packets`; unused for
    /// `timeline`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub value: String,
}

/// One checklist step.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Step {
    /// Unique within its playbook; the key analyst progress is stored under.
    pub id: String,
    pub question: String,
    pub why: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bad: Option<String>,
    /// Alert context kinds that answer this step when present.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub answers_from: Vec<ContextKind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pivots: Vec<Pivot>,
}

/// One playbook.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Playbook {
    pub id: String,
    pub title: String,
    /// The finding kinds this playbook covers. Empty only for the generic fallback.
    #[serde(default)]
    pub kinds: Vec<FindingKind>,
    #[serde(default)]
    pub summary: String,
    pub steps: Vec<Step>,
    /// Where it was loaded from ("built-in" or a file name). Set by the loader.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

/// A playbook file: plain, versioned JSON, safe to commit and share.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PlaybookFile {
    pub version: u32,
    #[serde(default)]
    pub playbooks: Vec<Playbook>,
}

/// The active playbooks: the built-ins, then team files in load order. A later playbook with the
/// same id replaces the earlier one; for each kind the last loaded playbook naming it wins.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PlaybookSet {
    pub playbooks: Vec<Playbook>,
}

/// The built-in playbook file, verbatim (a team's starting point for its own copy).
pub fn builtin_json() -> &'static str {
    BUILTIN_JSON
}

/// The built-in set.
pub fn builtin() -> PlaybookSet {
    let file: PlaybookFile =
        serde_json::from_str(BUILTIN_JSON).expect("built-in playbooks are valid JSON");
    let mut set = PlaybookSet::default();
    set.add_file(file, "built-in");
    set
}

impl PlaybookSet {
    /// Add every playbook of `file`, tagging each with `origin`.
    pub fn add_file(&mut self, file: PlaybookFile, origin: &str) {
        for mut p in file.playbooks {
            p.origin = Some(origin.to_string());
            // A replacement moves to the end, so it outranks everything loaded before it.
            self.playbooks.retain(|q| q.id != p.id);
            self.playbooks.push(p);
        }
    }

    /// The playbook for `kind`: the last one naming it.
    pub fn for_kind(&self, kind: FindingKind) -> Option<&Playbook> {
        self.playbooks
            .iter()
            .rev()
            .find(|p| p.kinds.contains(&kind))
    }

    pub fn get(&self, id: &str) -> Option<&Playbook> {
        self.playbooks.iter().find(|p| p.id == id)
    }
}

/// Parse and check a playbook file. `Ok` carries the file and any non-fatal warnings; `Err`
/// carries every problem found (a file with problems is never half-loaded).
pub fn parse_file(text: &str) -> Result<(PlaybookFile, Vec<String>), Vec<String>> {
    let file: PlaybookFile = serde_json::from_str(text).map_err(|e| vec![e.to_string()])?;
    let (problems, warnings) = lint(&file);
    if problems.is_empty() {
        Ok((file, warnings))
    } else {
        Err(problems)
    }
}

/// `(problems, warnings)` for a parsed file.
pub fn lint(file: &PlaybookFile) -> (Vec<String>, Vec<String>) {
    let mut problems = Vec::new();
    let mut warnings = Vec::new();
    if file.version != PLAYBOOK_FILE_VERSION {
        problems.push(format!(
            "version {} is not supported (expected {PLAYBOOK_FILE_VERSION})",
            file.version
        ));
    }
    let mut ids = BTreeSet::new();
    let mut kind_owner: BTreeMap<FindingKind, &str> = BTreeMap::new();
    for p in &file.playbooks {
        let at = format!("playbook \"{}\"", p.id);
        if p.id.trim().is_empty() {
            problems.push("a playbook has an empty id".to_string());
        }
        if !ids.insert(p.id.as_str()) {
            problems.push(format!("{at}: duplicate id"));
        }
        if p.title.trim().is_empty() {
            problems.push(format!("{at}: empty title"));
        }
        if p.kinds.is_empty() && p.id != GENERIC_ID {
            warnings.push(format!(
                "{at}: names no kinds, so only replaces a built-in by id"
            ));
        }
        for &k in &p.kinds {
            if let Some(prev) = kind_owner.insert(k, &p.id) {
                warnings.push(format!(
                    "{at}: kind {} is also named by \"{prev}\"; the later one wins",
                    k.as_str()
                ));
            }
        }
        if p.steps.is_empty() {
            problems.push(format!("{at}: has no steps"));
        }
        if p.steps.len() > MAX_STEPS {
            problems.push(format!("{at}: more than {MAX_STEPS} steps"));
        }
        let mut step_ids = BTreeSet::new();
        for s in &p.steps {
            let at = format!("{at} step \"{}\"", s.id);
            if s.id.trim().is_empty() {
                problems.push(format!("{at}: empty step id"));
            }
            if !step_ids.insert(s.id.as_str()) {
                problems.push(format!("{at}: duplicate step id"));
            }
            if s.question.trim().is_empty() {
                problems.push(format!("{at}: empty question"));
            }
            if s.pivots.len() > MAX_PIVOTS {
                problems.push(format!("{at}: more than {MAX_PIVOTS} pivots"));
            }
            let mut texts: Vec<&str> = vec![&s.question, &s.why];
            texts.extend(s.normal.as_deref());
            texts.extend(s.bad.as_deref());
            for t in texts {
                for name in unknown_placeholders(t) {
                    problems.push(format!("{at}: unknown placeholder {{{name}}}"));
                }
            }
            for pv in &s.pivots {
                for name in unknown_placeholders(&pv.value) {
                    problems.push(format!(
                        "{at} pivot \"{}\": unknown placeholder {{{name}}}",
                        pv.label
                    ));
                }
                if pv.target == PivotTarget::Sql {
                    let head = pv.value.trim_start().to_ascii_lowercase();
                    if !(head.starts_with("select") || head.starts_with("with")) {
                        problems.push(format!(
                            "{at} pivot \"{}\": SQL must start with SELECT or WITH",
                            pv.label
                        ));
                    }
                }
                if pv.target != PivotTarget::Timeline && pv.value.trim().is_empty() {
                    problems.push(format!("{at} pivot \"{}\": empty value", pv.label));
                }
            }
        }
    }
    (problems, warnings)
}

/// Placeholder names in `t` (text inside `{…}` made of `[a-z0-9_]`).
fn placeholders(t: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = t;
    while let Some(i) = rest.find('{') {
        let after = &rest[i + 1..];
        match after.find('}') {
            Some(j)
                if j > 0
                    && after[..j]
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') =>
            {
                out.push(&after[..j]);
                rest = &after[j + 1..];
            }
            _ => rest = after,
        }
    }
    out
}

fn unknown_placeholders(t: &str) -> Vec<&str> {
    placeholders(t)
        .into_iter()
        .filter(|n| !PLACEHOLDERS.contains(n))
        .collect()
}

/// A pivot with this alert's values filled in.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RenderedPivot {
    pub label: String,
    pub target: PivotTarget,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub value: String,
    /// For `packets`: the carve scope (host, peer, port, alert window).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<PacketScope>,
}

/// What the engine already knows for a step, from the alert's context.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AutoAnswer {
    /// Whether any matching context was found. `false` means "nothing in this capture says so",
    /// not "proven clean".
    pub found: bool,
    pub evidence: Vec<String>,
}

/// One rendered step.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RunStep {
    pub id: String,
    pub question: String,
    pub why: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bad: Option<String>,
    #[serde(default)]
    pub pivots: Vec<RenderedPivot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto: Option<AutoAnswer>,
}

/// One playbook rendered for one alert.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PlaybookRun {
    pub alert_id: String,
    pub alert_title: String,
    pub playbook_id: String,
    pub title: String,
    pub summary: String,
    pub origin: String,
    /// The alert's member kinds this playbook was picked for.
    pub kinds: Vec<FindingKind>,
    pub steps: Vec<RunStep>,
}

/// Analyst progress on an alert's playbooks, keyed `"{playbook_id}/{step_id}"`.
#[derive(Debug, Clone, PartialEq, Default, serde::Serialize, serde::Deserialize)]
pub struct PlaybookProgress {
    #[serde(default)]
    pub done: BTreeSet<String>,
    #[serde(default)]
    pub notes: BTreeMap<String, String>,
}

/// The alert's values for each placeholder (absent when unknown).
#[derive(Debug, Clone, Default)]
struct Vars {
    map: BTreeMap<&'static str, String>,
    window: Option<(i64, i64)>,
    /// The member findings this playbook was picked for; `None` = the whole alert (no anchor).
    members: Option<BTreeSet<u32>>,
}

fn sql_list(items: &BTreeSet<String>) -> Option<String> {
    if items.is_empty() {
        return None;
    }
    Some(
        items
            .iter()
            .map(|s| format!("'{}'", s.replace('\'', "''")))
            .collect::<Vec<_>>()
            .join(", "),
    )
}

/// `YYYY-MM-DD HH:MM:SS` (UTC) for a ns timestamp — the SQL `TIMESTAMP` literal form.
fn utc_timestamp(ns: i64) -> String {
    let secs = ns.div_euclid(1_000_000_000);
    let tod = secs.rem_euclid(86_400);
    format!(
        "{} {:02}:{:02}:{:02}",
        crate::detect::suppress::ymd_from_unix_secs(secs),
        tod / 3600,
        (tod / 60) % 60,
        tod % 60
    )
}

/// The alert's values, anchored on `anchor` — the first member finding of the kinds a playbook was
/// picked for — so on a multi-host chain each playbook pivots on the host that did that step, not
/// the chain root.
fn alert_vars(
    summary: &Summary,
    alert: &Alert,
    anchor: Option<&Finding>,
    kinds: &[FindingKind],
) -> Vars {
    let mut v = Vars::default();
    if anchor.is_some() {
        v.members = Some(
            alert
                .finding_indices
                .iter()
                .copied()
                .filter(|&i| {
                    summary
                        .findings
                        .get(i as usize)
                        .is_some_and(|f| kinds.contains(&f.kind))
                })
                .collect(),
        );
    }
    let members: Vec<&Finding> = alert
        .finding_indices
        .iter()
        .filter_map(|&i| summary.findings.get(i as usize))
        .collect();
    let actor = anchor.map_or_else(|| alert.actor.clone(), |f| f.src_ip.clone());
    v.map.insert("actor", actor.clone());
    let peer = anchor
        .and_then(|f| f.dst_ip.clone())
        .or_else(|| alert.peer.clone())
        .or_else(|| alert.context.peers.first().map(|p| p.ip.clone()))
        .or_else(|| {
            members
                .iter()
                .find_map(|f| f.dst_ip.clone().filter(|d| *d != actor))
        })
        .filter(|p| *p != actor);
    if let Some(peer) = &peer {
        v.map.insert("peer", peer.clone());
    }
    let pc = peer
        .as_ref()
        .and_then(|p| alert.context.peers.iter().find(|c| &c.ip == p));
    let port = anchor
        .and_then(|f| f.dst_port)
        .or_else(|| {
            members
                .iter()
                .find(|f| peer.is_some() && f.dst_ip.as_ref() == peer.as_ref())
                .and_then(|f| f.dst_port)
        })
        .or_else(|| pc.and_then(|c| c.dst_port));
    if let Some(port) = port {
        v.map.insert("port", port.to_string());
    }
    let domain = pc.and_then(|c| c.domain.clone()).or_else(|| {
        peer.as_ref().and_then(|p| {
            summary
                .resolved_ips
                .iter()
                .find(|r| &r.ip == p)
                .map(|r| r.domain.clone())
        })
    });
    if let Some(d) = domain {
        v.map.insert("domain", d);
    }
    // A carved file on the actor: known-bad first, then one from the peer, then any.
    let touches = |c: &&CarvedFile| c.client == actor || c.server == actor;
    let from_peer = |c: &&CarvedFile| {
        peer.as_ref()
            .is_some_and(|p| &c.server == p || &c.client == p)
    };
    let file = summary
        .carved_files
        .iter()
        .filter(touches)
        .find(|c| c.known_bad || !c.signatures.is_empty())
        .or_else(|| summary.carved_files.iter().filter(touches).find(from_peer))
        .or_else(|| summary.carved_files.iter().find(touches));
    if let Some(f) = file {
        v.map.insert("sha256", f.sha256.clone());
    }
    let first = anchor
        .and_then(|f| f.first_seen_ns)
        .or(alert.first_seen_ns)
        .or(summary.first_ts_ns);
    let last = anchor
        .and_then(|f| f.last_seen_ns)
        .or(alert.last_seen_ns)
        .or(summary.last_ts_ns)
        .or(first);
    if let (Some(a), Some(b)) = (first, last) {
        let (a, b) = (
            a.min(b).saturating_sub(WINDOW_PAD_NS),
            a.max(b).saturating_add(WINDOW_PAD_NS),
        );
        v.map.insert("start", utc_timestamp(a));
        v.map.insert("end", utc_timestamp(b));
        v.window = Some((a, b));
    }
    let mut hosts: BTreeSet<String> = alert.hosts.iter().cloned().collect();
    hosts.insert(actor.clone());
    if let Some(h) = sql_list(&hosts) {
        v.map.insert("hosts", h);
    }
    let victims: BTreeSet<String> = members
        .iter()
        .filter(|f| f.src_ip == actor)
        .flat_map(|f| f.victims.iter().cloned().chain(f.dst_ip.clone()))
        .filter(|h| *h != actor)
        .collect();
    if let Some(l) = sql_list(&victims) {
        v.map.insert("victims", l);
    }
    v
}

/// Human fallback for an unknown placeholder in prose.
fn prose_fallback(name: &str) -> &'static str {
    match name {
        "actor" => "the host",
        "peer" => "the peer",
        "port" => "the port",
        "domain" => "the domain",
        "sha256" => "the file",
        "start" => "the start of the alert",
        "end" => "the end of the alert",
        "hosts" => "the hosts",
        "victims" => "the targets",
        _ => "…",
    }
}

/// Fill a prose template; unknown values read as a plain phrase.
fn fill_prose(t: &str, v: &Vars) -> String {
    let mut out = t.to_string();
    for name in PLACEHOLDERS {
        let key = format!("{{{name}}}");
        if out.contains(&key) {
            let val = v
                .map
                .get(name)
                .cloned()
                .unwrap_or_else(|| prose_fallback(name).to_string());
            out = out.replace(&key, &val);
        }
    }
    out
}

/// Fill a pivot template; `None` when it needs a value the alert does not have. SQL values get
/// single quotes doubled (list placeholders are pre-quoted).
fn fill_pivot(t: &str, v: &Vars, sql: bool) -> Option<String> {
    let mut out = t.to_string();
    for name in placeholders(t) {
        let val = v.map.get(name)?;
        let val = if sql && name != "hosts" && name != "victims" {
            val.replace('\'', "''")
        } else {
            val.clone()
        };
        out = out.replace(&format!("{{{name}}}"), &val);
    }
    Some(out)
}

/// The carve scope terms of `filter` when it is exactly `host <actor> [and host <ip>] [and port
/// N]`, the shape a [`PacketScope`] carves: the second host and the port, read from the rendered
/// filter itself so a literal peer is carved as written.
fn scope_terms(filter: &str, v: &Vars) -> Option<(Option<String>, Option<u16>)> {
    let t: Vec<&str> = filter.split_whitespace().collect();
    if t.len() % 3 != 2 || t.iter().skip(2).step_by(3).any(|w| *w != "and") {
        return None;
    }
    let terms: Vec<(&str, &str)> = t
        .iter()
        .enumerate()
        .filter(|(i, _)| i % 3 == 0)
        .map(|(i, w)| (*w, t[i + 1]))
        .collect();
    let actor = v.map.get("actor").map(String::as_str);
    let [("host", a), rest @ ..] = terms.as_slice() else {
        return None;
    };
    if Some(*a) != actor {
        return None;
    }
    let (peer, rest) = match rest {
        [("host", p), rest @ ..] if p.parse::<std::net::IpAddr>().is_ok() => {
            (Some((*p).to_string()), rest)
        }
        r => (None, r),
    };
    match rest {
        [] => Some((peer, None)),
        [("port", n)] => n.parse::<u16>().ok().map(|n| (peer, Some(n))),
        _ => None,
    }
}

fn render_pivot(p: &Pivot, v: &Vars) -> Option<RenderedPivot> {
    let label = fill_pivot(&p.label, v, false).unwrap_or_else(|| fill_prose(&p.label, v));
    match p.target {
        PivotTarget::Timeline => Some(RenderedPivot {
            label,
            target: p.target,
            value: String::new(),
            scope: None,
        }),
        PivotTarget::Flows | PivotTarget::Sql => Some(RenderedPivot {
            label,
            target: p.target,
            value: fill_pivot(&p.value, v, p.target == PivotTarget::Sql)?,
            scope: None,
        }),
        PivotTarget::Packets => {
            let value = fill_pivot(&p.value, v, false)?;
            // A carve scope is host, optional peer, one port and a window. A filter it cannot
            // express (a protocol, alternative ports) or an untimed capture leaves just the
            // capture filter, so a carve never returns packets the filter would not.
            let scope = v.window.and_then(|(start_ns, end_ns)| {
                let (peer, port) = scope_terms(&value, v)?;
                Some(PacketScope {
                    host: v.map.get("actor").cloned().unwrap_or_default(),
                    peer,
                    port,
                    start_ns,
                    end_ns,
                })
            });
            Some(RenderedPivot {
                label,
                target: p.target,
                value,
                scope,
            })
        }
    }
}

fn auto_answer(step: &Step, alert: &Alert, v: &Vars) -> Option<AutoAnswer> {
    if step.answers_from.is_empty() {
        return None;
    }
    // On a multi-host alert a playbook is about its own host and peer: keep the context facts
    // about them or about this playbook's member findings, plus alert-wide ones.
    let actor = v.map.get("actor");
    let peer = v.map.get("peer");
    let anchored = v.members.is_some();
    let about_us = |ip: &String| Some(ip) == actor || Some(ip) == peer;
    let mut evidence: Vec<String> = Vec::new();
    for e in &alert.context.entries {
        let relevant = !anchored
            || match (&e.ip, e.finding_index) {
                (Some(ip), _) => about_us(ip),
                (None, Some(i)) => v.members.as_ref().is_some_and(|m| m.contains(&i)),
                (None, None) => true,
            };
        if relevant && step.answers_from.contains(&e.kind) && !evidence.contains(&e.text) {
            evidence.push(e.text.clone());
        }
    }
    // The actor's identity lives on the host context, not in the entries, and describes the
    // alert's primary actor only.
    if step.answers_from.contains(&ContextKind::Identity)
        && (!anchored || Some(&alert.context.actor.ip) == actor)
    {
        let a = &alert.context.actor;
        let mut parts = Vec::new();
        if let Some(h) = &a.hostname {
            parts.push(format!("hostname {h}"));
        }
        if let Some(m) = &a.mac {
            parts.push(format!("MAC {m}"));
        }
        if let Some(vd) = &a.vendor {
            parts.push(vd.clone());
        }
        if !parts.is_empty() {
            let line = format!("{} is {}", a.ip, parts.join(", "));
            if !evidence.contains(&line) {
                evidence.insert(0, line);
            }
        }
    }
    if step.answers_from.contains(&ContextKind::ThreatIntel) {
        for p in alert
            .context
            .peers
            .iter()
            .filter(|p| p.ioc && (!anchored || Some(&p.ip) == peer))
        {
            let line = format!("{} is on the offline IOC feed", p.ip);
            if !evidence.contains(&line) {
                evidence.push(line);
            }
        }
    }
    evidence.truncate(MAX_AUTO_EVIDENCE);
    Some(AutoAnswer {
        found: !evidence.is_empty(),
        evidence,
    })
}

fn render(p: &Playbook, kinds: Vec<FindingKind>, alert: &Alert, v: &Vars) -> PlaybookRun {
    PlaybookRun {
        alert_id: alert.id.clone(),
        alert_title: alert.title.clone(),
        playbook_id: p.id.clone(),
        title: p.title.clone(),
        summary: fill_prose(&p.summary, v),
        origin: p.origin.clone().unwrap_or_else(|| "built-in".to_string()),
        kinds,
        steps: p
            .steps
            .iter()
            .map(|s| RunStep {
                id: s.id.clone(),
                question: fill_prose(&s.question, v),
                why: fill_prose(&s.why, v),
                normal: s.normal.as_deref().map(|t| fill_prose(t, v)),
                bad: s.bad.as_deref().map(|t| fill_prose(t, v)),
                pivots: s
                    .pivots
                    .iter()
                    .filter_map(|pv| render_pivot(pv, v))
                    .collect(),
                auto: auto_answer(s, alert, v),
            })
            .collect(),
    }
}

/// The playbooks for one alert, rendered: one per distinct member kind (member order, merged
/// when two kinds share a playbook), capped at [`MAX_RUNS_PER_ALERT`]; the generic playbook when
/// none matches.
pub fn runs_for_alert(summary: &Summary, alert: &Alert, set: &PlaybookSet) -> Vec<PlaybookRun> {
    let mut picked: Vec<(&Playbook, Vec<FindingKind>, Option<&Finding>)> = Vec::new();
    for &i in &alert.finding_indices {
        let Some(f) = summary.findings.get(i as usize) else {
            continue;
        };
        let Some(p) = set.for_kind(f.kind) else {
            continue;
        };
        if let Some((_, kinds, _)) = picked.iter_mut().find(|(q, _, _)| q.id == p.id) {
            if !kinds.contains(&f.kind) {
                kinds.push(f.kind);
            }
        } else if picked.len() < MAX_RUNS_PER_ALERT {
            picked.push((p, vec![f.kind], Some(f)));
        }
    }
    if picked.is_empty() {
        if let Some(g) = set.get(GENERIC_ID) {
            picked.push((g, Vec::new(), None));
        }
    }
    picked
        .into_iter()
        .map(|(p, kinds, anchor)| {
            let vars = alert_vars(summary, alert, anchor, &kinds);
            render(p, kinds, alert, &vars)
        })
        .collect()
}

/// The runs for an alert id, or `None` when the summary has no such alert.
pub fn runs_for_alert_id(
    summary: &Summary,
    alert_id: &str,
    set: &PlaybookSet,
) -> Option<Vec<PlaybookRun>> {
    let alert = summary.alerts.iter().find(|a| a.id == alert_id)?;
    Some(runs_for_alert(summary, alert, set))
}

/// The runs as a Markdown checklist for case notes or a ticket. With `progress`, finished steps
/// are ticked and notes are included.
pub fn render_markdown(runs: &[PlaybookRun], progress: Option<&PlaybookProgress>) -> String {
    let mut out = String::new();
    let mut last_alert: Option<&str> = None;
    for run in runs {
        if last_alert != Some(run.alert_id.as_str()) {
            if last_alert.is_some() {
                out.push('\n');
            }
            out.push_str(&format!(
                "# Hunt: {}\n\nAlert `{}`\n",
                run.alert_title, run.alert_id
            ));
            last_alert = Some(&run.alert_id);
        }
        let total = run.steps.len();
        let done = run
            .steps
            .iter()
            .filter(|s| progress.is_some_and(|p| p.done.contains(&step_key(run, s))))
            .count();
        out.push_str(&format!("\n## {} ({done}/{total})\n\n", run.title));
        if !run.summary.is_empty() {
            out.push_str(&format!("{}\n\n", run.summary));
        }
        if run.origin != "built-in" {
            out.push_str(&format!("_Playbook from {}_\n\n", run.origin));
        }
        for s in &run.steps {
            let key = step_key(run, s);
            let tick = if progress.is_some_and(|p| p.done.contains(&key)) {
                "x"
            } else {
                " "
            };
            out.push_str(&format!("- [{tick}] **{}** {}\n", s.question, s.why));
            if let Some(n) = &s.normal {
                out.push_str(&format!("  - Normal: {n}\n"));
            }
            if let Some(b) = &s.bad {
                out.push_str(&format!("  - Bad: {b}\n"));
            }
            if let Some(a) = &s.auto {
                if a.found {
                    out.push_str("  - Engine found:\n");
                    for e in &a.evidence {
                        out.push_str(&format!("    - {e}\n"));
                    }
                } else {
                    out.push_str("  - Engine found: nothing in this capture\n");
                }
            }
            for p in &s.pivots {
                match p.target {
                    PivotTarget::Timeline => {
                        out.push_str(&format!("  - {}: {}\n", p.target.label(), p.label));
                    }
                    PivotTarget::Sql => {
                        out.push_str(&format!(
                            "  - {}: {}\n\n    ```sql\n    {}\n    ```\n\n",
                            p.target.label(),
                            p.label,
                            p.value
                        ));
                    }
                    _ => out.push_str(&format!(
                        "  - {}: {} `{}`\n",
                        p.target.label(),
                        p.label,
                        p.value
                    )),
                }
            }
            if let Some(note) = progress.and_then(|p| p.notes.get(&key)) {
                if !note.trim().is_empty() {
                    out.push_str(&format!("  - Note: {}\n", note.trim().replace('\n', " ")));
                }
            }
        }
    }
    out
}

/// The progress key for a step.
pub fn step_key(run: &PlaybookRun, step: &RunStep) -> String {
    format!("{}/{}", run.playbook_id, step.id)
}

#[cfg(test)]
mod tests;
