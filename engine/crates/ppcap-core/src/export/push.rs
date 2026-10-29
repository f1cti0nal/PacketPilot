//! Push integrations: send the alert queue to where a SOC already works — a generic webhook,
//! Slack, Microsoft Teams, Jira, TheHive, Splunk HEC, Elastic (ECS) or any OCSF consumer.
//!
//! Destinations live in a plain, shareable `destinations.json` ([`DestinationFile`]). Secrets are
//! never written in it: a destination names the *environment variables* that hold its URL or token
//! (`url_env`, `token_env`, `user_env`), and unknown keys are rejected, so a stray `"token"` cannot
//! slip into a committed file. One analyst keeps the file next to their cases; a team commits it.
//!
//! Everything here is pure, like the rest of `export`: [`build_payloads`] renders the exact HTTP
//! bodies, [`resolve_target`] turns a destination plus an env lookup into a URL and headers, and
//! the [`PushLedger`] remembers which alert went where so a re-run never opens a duplicate ticket.
//! The caller supplies the clock and does the I/O; only [`http_post`] (behind the `online`
//! feature) touches the network.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use crate::model::alert::{Alert, PriorityBand};
use crate::model::output::AnalysisOutput;
use crate::model::severity::Severity;
use crate::model::timeline::AlertTimeline;

/// Alerts per Slack / Teams message: one readable digest, well under both block limits.
pub const CHAT_ALERTS_PER_MESSAGE: usize = 10;
/// Events per Splunk HEC / Elastic bulk / OCSF batch request.
pub const BATCH_EVENTS_PER_REQUEST: usize = 100;
/// Timeline rows carried into a ticket description (the full story is one `ppcap timeline` away).
pub const TICKET_TIMELINE_ROWS: usize = 15;
/// Member findings listed in a webhook / HEC / ECS document.
pub const DOC_FINDINGS: usize = 20;

/// Every environment variable a destination names must start with this, so a shared or
/// untrusted destinations file cannot read an unrelated secret from the analyst's shell.
pub const SECRET_ENV_PREFIX: &str = "PPCAP_";

/// The OCSF schema version the Detection Finding payloads follow.
pub const OCSF_VERSION: &str = "1.3.0";
/// The ECS version the Elastic documents follow.
pub const ECS_VERSION: &str = "8.11.0";

// ─── Destination file ────────────────────────────────────────────────────────

/// What a destination speaks.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DestinationKind {
    /// One JSON document per alert, POSTed to `url`.
    Webhook,
    /// Slack incoming webhook (Block Kit digest, up to 10 alerts per message).
    Slack,
    /// Microsoft Teams Workflows webhook (Adaptive Card digest).
    Teams,
    /// Jira REST API v2: one issue per alert.
    Jira,
    /// TheHive 5 API: one alert per alert, `sourceRef` = its delivery key.
    Thehive,
    /// Splunk HTTP Event Collector: batched events.
    SplunkHec,
    /// Elasticsearch `_bulk`: Elastic Common Schema documents.
    Elastic,
    /// OCSF Detection Finding (class 2004) JSON array, POSTed to `url`.
    Ocsf,
}

impl DestinationKind {
    /// Stable snake_case token (matches the serde wire form).
    pub fn as_str(self) -> &'static str {
        match self {
            DestinationKind::Webhook => "webhook",
            DestinationKind::Slack => "slack",
            DestinationKind::Teams => "teams",
            DestinationKind::Jira => "jira",
            DestinationKind::Thehive => "thehive",
            DestinationKind::SplunkHec => "splunk_hec",
            DestinationKind::Elastic => "elastic",
            DestinationKind::Ocsf => "ocsf",
        }
    }

    /// Whether one request carries one alert (and so can return a ticket reference).
    pub fn per_alert(self) -> bool {
        matches!(
            self,
            DestinationKind::Webhook | DestinationKind::Jira | DestinationKind::Thehive
        )
    }
}

/// One place alerts go. Secrets are referenced by environment-variable name only.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    /// Unique name, used by `--to` and as the sent-ledger key.
    pub name: String,
    pub kind: DestinationKind,
    /// Base URL (not secret): the Jira / TheHive / Splunk / Elastic server, or a webhook URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Environment variable holding the URL, for URLs that are themselves secrets (Slack and
    /// Teams webhooks). Wins over `url` when both are set and the variable is non-empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_env: Option<String>,
    /// Environment variable holding the API token / key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_env: Option<String>,
    /// Environment variable holding the user name (Jira Cloud e-mail, Elastic basic auth); with
    /// it the token is sent as HTTP Basic credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_env: Option<String>,
    /// Only alerts at or above this band go here (default: every alert in the queue).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_band: Option<PriorityBand>,
    /// Jira project key (required for `jira`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Jira issue type (default `Task`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue_type: Option<String>,
    /// Splunk index / Elastic index or data stream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<String>,
    /// Splunk sourcetype (default `packetpilot:alert`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sourcetype: Option<String>,
    /// Extra labels / tags added to tickets and documents.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Permit a plain `http://` URL to a non-loopback host (tokens would cross the wire in clear).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_http: bool,
    /// Keep the entry but skip it unless named with `--to`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
}

/// The `destinations.json` file.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationFile {
    #[serde(default = "one")]
    pub version: u32,
    pub destinations: Vec<Destination>,
}

fn one() -> u32 {
    1
}

impl DestinationFile {
    /// Parse and validate a destination file. Errors name the offending destination.
    pub fn parse(text: &str) -> Result<DestinationFile, String> {
        let file: DestinationFile = serde_json::from_str(text).map_err(|e| {
            let msg = e.to_string();
            if msg.contains("unknown field") {
                format!(
                    "{msg} (secrets never go in this file: name the environment variable that \
                     holds them with url_env / token_env / user_env)"
                )
            } else {
                msg
            }
        })?;
        if file.version != 1 {
            return Err(format!("unsupported destinations version {}", file.version));
        }
        let mut seen = BTreeSet::new();
        for d in &file.destinations {
            d.validate()?;
            if !seen.insert(d.name.as_str()) {
                return Err(format!("duplicate destination name {:?}", d.name));
            }
        }
        Ok(file)
    }

    /// A commented-by-example starter file covering every kind.
    pub fn example() -> DestinationFile {
        let base = |name: &str, kind| Destination {
            name: name.to_string(),
            kind,
            url: None,
            url_env: None,
            token_env: None,
            user_env: None,
            min_band: None,
            project: None,
            issue_type: None,
            index: None,
            sourcetype: None,
            tags: Vec::new(),
            allow_http: false,
            disabled: true,
        };
        DestinationFile {
            version: 1,
            destinations: vec![
                Destination {
                    url_env: Some("PPCAP_SLACK_WEBHOOK_URL".into()),
                    min_band: Some(PriorityBand::Investigate),
                    ..base("soc-slack", DestinationKind::Slack)
                },
                Destination {
                    url_env: Some("PPCAP_TEAMS_WEBHOOK_URL".into()),
                    min_band: Some(PriorityBand::Investigate),
                    ..base("soc-teams", DestinationKind::Teams)
                },
                Destination {
                    url: Some("https://example.atlassian.net".into()),
                    user_env: Some("PPCAP_JIRA_USER".into()),
                    token_env: Some("PPCAP_JIRA_TOKEN".into()),
                    project: Some("SEC".into()),
                    issue_type: Some("Task".into()),
                    min_band: Some(PriorityBand::Investigate),
                    ..base("jira", DestinationKind::Jira)
                },
                Destination {
                    url: Some("https://thehive.example.org".into()),
                    token_env: Some("PPCAP_THEHIVE_API_KEY".into()),
                    min_band: Some(PriorityBand::Review),
                    ..base("thehive", DestinationKind::Thehive)
                },
                Destination {
                    url: Some("https://splunk.example.org:8088".into()),
                    token_env: Some("PPCAP_SPLUNK_HEC_TOKEN".into()),
                    index: Some("network".into()),
                    ..base("splunk", DestinationKind::SplunkHec)
                },
                Destination {
                    url: Some("https://elastic.example.org:9200".into()),
                    token_env: Some("PPCAP_ELASTIC_API_KEY".into()),
                    index: Some("logs-packetpilot.alert-default".into()),
                    ..base("elastic", DestinationKind::Elastic)
                },
                Destination {
                    url: Some("https://collector.example.org/ocsf".into()),
                    token_env: Some("PPCAP_OCSF_TOKEN".into()),
                    ..base("ocsf", DestinationKind::Ocsf)
                },
                Destination {
                    url: Some("https://automation.example.org/hooks/packetpilot".into()),
                    token_env: Some("PPCAP_WEBHOOK_TOKEN".into()),
                    ..base("webhook", DestinationKind::Webhook)
                },
            ],
        }
    }
}

impl Destination {
    fn validate(&self) -> Result<(), String> {
        let who = format!("destination {:?}", self.name);
        if self.name.trim().is_empty() {
            return Err("a destination has an empty name".into());
        }
        if self.url.is_none() && self.url_env.is_none() {
            return Err(format!("{who}: set url or url_env"));
        }
        if let Some(u) = &self.url {
            check_url(u, self.allow_http).map_err(|e| format!("{who}: {e}"))?;
        }
        for (field, v) in [
            ("url_env", &self.url_env),
            ("token_env", &self.token_env),
            ("user_env", &self.user_env),
        ] {
            if let Some(v) = v {
                if v.is_empty() || !v.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    return Err(format!(
                        "{who}: {field} must be an environment variable name, not {v:?}"
                    ));
                }
                // A shared file can only reach secrets set up for PacketPilot, never an
                // unrelated credential (a cloud key, a CI token) that happens to be exported.
                if !v.starts_with(SECRET_ENV_PREFIX) {
                    return Err(format!(
                        "{who}: {field} {v:?} must start with {SECRET_ENV_PREFIX} \
                         (only PacketPilot-scoped variables can be read)"
                    ));
                }
            }
        }
        let needs_token = matches!(
            self.kind,
            DestinationKind::Jira
                | DestinationKind::Thehive
                | DestinationKind::SplunkHec
                | DestinationKind::Elastic
        );
        if needs_token && self.token_env.is_none() {
            return Err(format!("{who}: {} needs token_env", self.kind.as_str()));
        }
        if self.kind == DestinationKind::Jira
            && self.project.as_deref().is_none_or(|p| p.trim().is_empty())
        {
            return Err(format!("{who}: jira needs project (the project key)"));
        }
        Ok(())
    }
}

/// `https://` always; `http://` only to loopback or with `allow_http`.
fn check_url(url: &str, allow_http: bool) -> Result<(), String> {
    let lower = url.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("http://") {
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        let host = host.rsplit('@').next().unwrap_or(host);
        let host = if let Some(h) = host.strip_prefix('[') {
            h.split(']').next().unwrap_or("")
        } else {
            host.split(':').next().unwrap_or("")
        };
        let loopback = host == "localhost" || host == "::1" || host.starts_with("127.");
        if loopback || allow_http {
            return Ok(());
        }
        return Err(format!(
            "{url} is plain http; use https or set allow_http: true"
        ));
    }
    if lower.starts_with("https://") {
        return Ok(());
    }
    Err(format!("{url} is not an http(s) URL"))
}

// ─── Selection ───────────────────────────────────────────────────────────────

/// The alerts that go to `dest`: the queue (already suppression-filtered) in queue order, at or
/// above the stricter of `min_band` and the destination's own, restricted to `only` when given.
pub fn select_alerts<'a>(
    out: &'a AnalysisOutput,
    dest: &Destination,
    min_band: Option<PriorityBand>,
    only: &[String],
) -> Vec<&'a Alert> {
    let floor = match (min_band, dest.min_band) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    out.summary
        .alerts
        .iter()
        .filter(|a| floor.is_none_or(|f| a.band >= f))
        .filter(|a| only.is_empty() || only.iter().any(|id| id == &a.id))
        .collect()
}

// ─── Payloads ────────────────────────────────────────────────────────────────

/// One HTTP request to make: `method` `path` (appended to the destination's base URL).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct PushPayload {
    /// `POST`, or `PATCH` for an escalation that updates an existing TheHive alert.
    pub method: String,
    /// The alerts this request delivers (ledger bookkeeping), in body order.
    pub alert_ids: Vec<String>,
    /// Appended to the base URL (`""` for webhooks).
    pub path: String,
    pub content_type: String,
    pub body: String,
}

impl PushPayload {
    /// File extension for `--out-dir`.
    pub fn extension(&self) -> &'static str {
        if self.content_type == "application/x-ndjson" {
            "ndjson"
        } else {
            "json"
        }
    }
}

/// A stable identity for the analysed capture: the source SHA-256 when the run hashed it, else a
/// digest of its path, size and packet time span. Re-running push on the same analysis keeps
/// it; a different capture gets a different one.
pub fn capture_id(out: &AnalysisOutput) -> String {
    if let Some(h) = out.source_sha256.as_deref().filter(|h| h.len() >= 16) {
        return h[..16].to_ascii_lowercase();
    }
    let seed = format!(
        "{}|{}|{:?}|{:?}",
        out.source_path, out.source_bytes, out.summary.first_ts_ns, out.summary.last_ts_ns
    );
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in seed.as_bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    format!("{h:016x}")
}

/// The delivery key of one alert from one capture: `alert:…@<capture id>`. Alert ids are stable
/// per story (a host alert is keyed by its host), so the capture is part of the key: the same
/// host flagged again in a new capture is a new delivery, a re-run of the same analysis is not.
/// Also the TheHive `sourceRef` and the Elastic document `_id`.
pub fn delivery_key(out: &AnalysisOutput, a: &Alert) -> String {
    format!("{}@{}", a.id, capture_id(out))
}

/// Render the requests that deliver `alerts` to `dest`. `now_secs` stamps untimed alerts.
pub fn build_payloads(
    out: &AnalysisOutput,
    dest: &Destination,
    alerts: &[&Alert],
    now_secs: i64,
) -> Vec<PushPayload> {
    if alerts.is_empty() {
        return Vec::new();
    }
    let timeline = |a: &Alert| out.summary.timelines.iter().find(|t| t.alert_id == a.id);
    let ids = |chunk: &[&Alert]| chunk.iter().map(|a| a.id.clone()).collect::<Vec<_>>();
    let json_body = |v: &Value| serde_json::to_string(v).unwrap_or_else(|_| "{}".into());
    match dest.kind {
        DestinationKind::Webhook => alerts
            .iter()
            .map(|a| PushPayload {
                method: "POST".into(),
                alert_ids: vec![a.id.clone()],
                path: String::new(),
                content_type: "application/json".into(),
                body: json_body(&alert_document(out, a, timeline(a), dest, now_secs)),
            })
            .collect(),
        DestinationKind::Slack => alerts
            .chunks(CHAT_ALERTS_PER_MESSAGE)
            .map(|c| PushPayload {
                method: "POST".into(),
                alert_ids: ids(c),
                path: String::new(),
                content_type: "application/json".into(),
                body: json_body(&slack_message(out, c, alerts.len())),
            })
            .collect(),
        DestinationKind::Teams => alerts
            .chunks(CHAT_ALERTS_PER_MESSAGE)
            .map(|c| PushPayload {
                method: "POST".into(),
                alert_ids: ids(c),
                path: String::new(),
                content_type: "application/json".into(),
                body: json_body(&teams_message(out, c, alerts.len())),
            })
            .collect(),
        DestinationKind::Jira => alerts
            .iter()
            .map(|a| PushPayload {
                method: "POST".into(),
                alert_ids: vec![a.id.clone()],
                path: "/rest/api/2/issue".into(),
                content_type: "application/json".into(),
                body: json_body(&jira_issue(out, a, timeline(a), dest)),
            })
            .collect(),
        DestinationKind::Thehive => alerts
            .iter()
            .map(|a| PushPayload {
                method: "POST".into(),
                alert_ids: vec![a.id.clone()],
                path: "/api/v1/alert".into(),
                content_type: "application/json".into(),
                body: json_body(&thehive_alert(out, a, timeline(a), dest)),
            })
            .collect(),
        DestinationKind::SplunkHec => alerts
            .chunks(BATCH_EVENTS_PER_REQUEST)
            .map(|c| PushPayload {
                method: "POST".into(),
                alert_ids: ids(c),
                path: "/services/collector/event".into(),
                content_type: "application/json".into(),
                // HEC takes concatenated event objects in one body.
                body: c
                    .iter()
                    .map(|a| json_body(&hec_event(out, a, timeline(a), dest, now_secs)))
                    .collect::<Vec<_>>()
                    .join("\n"),
            })
            .collect(),
        DestinationKind::Elastic => {
            let index = dest
                .index
                .clone()
                .unwrap_or_else(|| "logs-packetpilot.alert-default".into());
            alerts
                .chunks(BATCH_EVENTS_PER_REQUEST)
                .map(|c| {
                    let mut body = String::new();
                    for a in c {
                        // `create` works for both plain indices and data streams.
                        // A stable `_id` makes a retried item a 409 conflict, not a duplicate.
                        body.push_str(&json_body(
                            &json!({"create": {"_index": index, "_id": delivery_key(out, a)}}),
                        ));
                        body.push('\n');
                        body.push_str(&json_body(&ecs_document(
                            out,
                            a,
                            timeline(a),
                            dest,
                            now_secs,
                        )));
                        body.push('\n');
                    }
                    PushPayload {
                        method: "POST".into(),
                        alert_ids: ids(c),
                        path: "/_bulk".into(),
                        content_type: "application/x-ndjson".into(),
                        body,
                    }
                })
                .collect()
        }
        DestinationKind::Ocsf => alerts
            .chunks(BATCH_EVENTS_PER_REQUEST)
            .map(|c| PushPayload {
                method: "POST".into(),
                alert_ids: ids(c),
                path: String::new(),
                content_type: "application/json".into(),
                body: json_body(&Value::Array(
                    c.iter()
                        .map(|a| ocsf_finding(out, a, timeline(a), now_secs))
                        .collect(),
                )),
            })
            .collect(),
    }
}

fn severity_word(s: Severity) -> &'static str {
    s.as_str()
}

fn band_label(b: PriorityBand) -> &'static str {
    match b {
        PriorityBand::ActNow => "ACT NOW",
        PriorityBand::Investigate => "INVESTIGATE",
        PriorityBand::Review => "REVIEW",
        PriorityBand::Log => "LOG",
        PriorityBand::Info => "INFO",
    }
}

fn iso_opt(ns: Option<i64>) -> Value {
    ns.map(|n| Value::String(super::iso_ns(n)))
        .unwrap_or(Value::Null)
}

/// Every tag a ticket or document carries: `packetpilot`, the band, the ATT&CK ids and the
/// destination's own tags.
fn tags_for(a: &Alert, dest: &Destination) -> Vec<String> {
    let mut tags = vec![
        "packetpilot".to_string(),
        format!("band:{}", a.band.as_str()),
    ];
    tags.extend(a.attack.iter().map(|t| format!("attack:{t}")));
    for t in &dest.tags {
        if !tags.contains(t) {
            tags.push(t.clone());
        }
    }
    tags
}

fn capture_name(out: &AnalysisOutput) -> String {
    std::path::Path::new(&out.source_path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| out.source_path.clone())
}

/// The vendor-neutral alert document: the webhook body, the HEC event and the `packetpilot.*`
/// block of an ECS document. Schema tag `packetpilot.alert/1`.
pub fn alert_document(
    out: &AnalysisOutput,
    a: &Alert,
    timeline: Option<&AlertTimeline>,
    dest: &Destination,
    now_secs: i64,
) -> Value {
    let findings: Vec<Value> = a
        .finding_indices
        .iter()
        .filter_map(|&i| out.summary.findings.get(i as usize))
        .take(DOC_FINDINGS)
        .map(|f| {
            json!({
                "kind": f.kind.as_str(),
                "severity": f.severity.as_str(),
                "title": f.title,
                "src_ip": f.src_ip,
                "dst_ip": f.dst_ip,
                "dst_port": f.dst_port,
                "attack": f.attack,
                "first_seen": iso_opt(f.first_seen_ns),
            })
        })
        .collect();
    let timeline: Vec<Value> = timeline
        .map(|t| {
            t.events
                .iter()
                .take(TICKET_TIMELINE_ROWS)
                .map(|e| {
                    json!({
                        "time": iso_opt(e.ts_ns),
                        "kind": e.kind.as_str(),
                        "host": e.host,
                        "peer": e.peer,
                        "title": e.title,
                        "bpf": e.packets.as_ref().map(|p| p.bpf()),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    json!({
        "schema": "packetpilot.alert/1",
        "alert_id": a.id,
        "title": a.title,
        "band": a.band.as_str(),
        "priority": a.priority,
        "confidence": a.confidence,
        "severity": severity_word(a.severity),
        "source": a.source.as_str(),
        "actor": a.actor,
        "hosts": a.hosts,
        "host_count": a.host_count,
        "peer": a.peer,
        "attack": a.attack,
        "stage": a.stage,
        "next_stage": a.next_stage,
        "narrative": a.narrative,
        "action": a.action,
        "first_seen": iso_opt(a.first_seen_ns),
        "last_seen": iso_opt(a.last_seen_ns),
        "finding_count": a.finding_count,
        "findings": findings,
        "timeline": timeline,
        "tags": tags_for(a, dest),
        "capture": {
            "name": capture_name(out),
            "path": out.source_path,
            "sha256": out.source_sha256,
            "engine_version": out.engine_version,
        },
        "sent_at": super::iso(now_secs),
    })
}

// ─── Chat (Slack / Teams) ────────────────────────────────────────────────────

/// Slack mrkdwn: `&`, `<`, `>` are the only control characters (and stop `<!channel>` pings).
fn slack_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn alert_line_parts(a: &Alert) -> (String, String) {
    let head = format!("[{} {}] {}", band_label(a.band), a.priority, a.title);
    let mut meta = format!("{} · {}", a.actor, a.stage);
    if let Some(p) = &a.peer {
        meta = format!("{} → {} · {}", a.actor, p, a.stage);
    }
    if !a.attack.is_empty() {
        meta.push_str(&format!(" · {}", a.attack.join(", ")));
    }
    (head, meta)
}

fn digest_heading(out: &AnalysisOutput, shown: usize, total: usize) -> String {
    let n = if shown == total {
        format!("{total} alert{}", if total == 1 { "" } else { "s" })
    } else {
        format!("{shown} of {total} alerts")
    };
    format!("PacketPilot: {n} from {}", capture_name(out))
}

fn slack_message(out: &AnalysisOutput, chunk: &[&Alert], total: usize) -> Value {
    let heading = digest_heading(out, chunk.len(), total);
    let mut blocks = vec![json!({
        "type": "header",
        "text": {"type": "plain_text", "text": truncate(&heading, 150)},
    })];
    for a in chunk {
        let (head, meta) = alert_line_parts(a);
        blocks.push(json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": truncate(
                    &format!(
                        "*{}*\n{}\n_Next:_ {}\n`{}`",
                        slack_escape(&head),
                        slack_escape(&meta),
                        slack_escape(&a.action),
                        slack_escape(&a.id)
                    ),
                    3000,
                ),
            },
        }));
    }
    json!({ "text": heading, "blocks": blocks })
}

/// Teams TextBlock markdown subset: neutralize link / emphasis syntax in capture text.
fn teams_escape(s: &str) -> String {
    md_escape(s)
}

fn teams_message(out: &AnalysisOutput, chunk: &[&Alert], total: usize) -> Value {
    let heading = digest_heading(out, chunk.len(), total);
    let mut body = vec![json!({
        "type": "TextBlock",
        "text": teams_escape(&heading),
        "weight": "Bolder",
        "size": "Medium",
        "wrap": true,
    })];
    for a in chunk {
        let (head, meta) = alert_line_parts(a);
        let color = match a.band {
            PriorityBand::ActNow => "Attention",
            PriorityBand::Investigate => "Warning",
            _ => "Default",
        };
        body.push(json!({
            "type": "Container",
            "separator": true,
            "items": [
                {"type": "TextBlock", "text": teams_escape(&head), "weight": "Bolder",
                 "color": color, "wrap": true},
                {"type": "TextBlock", "text": teams_escape(&meta), "isSubtle": true,
                 "wrap": true, "spacing": "None"},
                {"type": "TextBlock", "text": format!("Next: {}", teams_escape(&a.action)),
                 "wrap": true, "spacing": "Small"},
                {"type": "TextBlock", "text": teams_escape(&a.id), "isSubtle": true,
                 "size": "Small", "spacing": "None"},
            ],
        }));
    }
    json!({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "msteams": {"width": "Full"},
                "body": body,
            },
        }],
    })
}

// ─── Tickets (Jira / TheHive) ────────────────────────────────────────────────

/// Markdown: backslash-escape every character that could start a link, emphasis or HTML.
fn md_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(
            c,
            '\\' | '`' | '*' | '_' | '[' | ']' | '(' | ')' | '<' | '>' | '#' | '|' | '!' | '~'
        ) {
            o.push('\\');
        }
        o.push(c);
    }
    o
}

/// Jira wiki markup: escape the characters that open macros, links, tables and emphasis.
fn jira_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(
            c,
            '\\' | '{'
                | '}'
                | '['
                | ']'
                | '|'
                | '*'
                | '_'
                | '^'
                | '~'
                | '+'
                | '-'
                | '?'
                | '!'
                | '#'
        ) {
            o.push('\\');
        }
        o.push(c);
    }
    o
}

#[derive(Clone, Copy)]
enum Markup {
    Markdown,
    JiraWiki,
}

impl Markup {
    fn esc(self, s: &str) -> String {
        match self {
            Markup::Markdown => md_escape(s),
            Markup::JiraWiki => jira_escape(s),
        }
    }
    fn heading(self, s: &str) -> String {
        match self {
            Markup::Markdown => format!("### {s}"),
            Markup::JiraWiki => format!("h3. {s}"),
        }
    }
    fn bold(self, s: &str) -> String {
        match self {
            Markup::Markdown => format!("**{s}**"),
            Markup::JiraWiki => format!("*{s}*"),
        }
    }
    fn code(self, s: &str) -> String {
        match self {
            // The id / filter text is ours, but keep backticks out of a code span anyway.
            Markup::Markdown => format!("`{}`", s.replace('`', "'")),
            Markup::JiraWiki => format!("{{{{{}}}}}", s.replace('}', ")")),
        }
    }
}

/// The ticket body: verdict line, narrative, next step, the first timeline rows, provenance.
fn ticket_description(
    out: &AnalysisOutput,
    a: &Alert,
    timeline: Option<&AlertTimeline>,
    m: Markup,
) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{} priority {} · severity {} · confidence {}%",
        m.bold(band_label(a.band)),
        a.priority,
        severity_word(a.severity),
        a.confidence
    );
    let _ = writeln!(s);
    let _ = writeln!(s, "{}", m.esc(&a.narrative));
    let _ = writeln!(s);
    let _ = writeln!(s, "{} {}", m.bold("Next step:"), m.esc(&a.action));
    let _ = writeln!(s);
    let _ = writeln!(s, "{}", m.heading("Scope"));
    let _ = writeln!(s, "* Actor: {}", m.esc(&a.actor));
    if a.host_count as usize > 1 {
        let _ = writeln!(
            s,
            "* Hosts ({}): {}",
            a.host_count,
            m.esc(&a.hosts.join(", "))
        );
    }
    if let Some(p) = &a.peer {
        let _ = writeln!(s, "* Peer: {}", m.esc(p));
    }
    let next = a
        .next_stage
        .as_deref()
        .map(|n| format!(" (watch for: {})", m.esc(n)))
        .unwrap_or_default();
    let _ = writeln!(s, "* Stage: {}{next}", m.esc(&a.stage));
    if !a.attack.is_empty() {
        let _ = writeln!(s, "* ATT&CK: {}", m.esc(&a.attack.join(", ")));
    }
    if let (Some(f), Some(l)) = (a.first_seen_ns, a.last_seen_ns) {
        let _ = writeln!(s, "* Seen: {} to {}", super::iso_ns(f), super::iso_ns(l));
    }
    if let Some(t) = timeline.filter(|t| !t.events.is_empty()) {
        let _ = writeln!(s);
        let _ = writeln!(s, "{}", m.heading("Timeline"));
        for e in t.events.iter().take(TICKET_TIMELINE_ROWS) {
            let when = e
                .ts_ns
                .map(super::iso_ns)
                .unwrap_or_else(|| "untimed".to_string());
            let bpf = e
                .packets
                .as_ref()
                .map(|p| format!(" {}", m.code(&p.bpf())))
                .unwrap_or_default();
            // Event titles already name their hosts.
            let _ = writeln!(s, "* {} {}: {}{bpf}", when, e.kind.label(), m.esc(&e.title));
        }
        if t.event_count as usize > TICKET_TIMELINE_ROWS {
            let _ = writeln!(
                s,
                "* … {} more rows: run {}",
                t.event_count as usize - TICKET_TIMELINE_ROWS,
                m.code(&format!("ppcap timeline <summary.json> --alert {}", a.id))
            );
        }
    }
    let _ = writeln!(s);
    let sha = out
        .source_sha256
        .as_deref()
        .map(|h| format!(", sha256 {}", m.code(h)))
        .unwrap_or_default();
    let _ = writeln!(
        s,
        "Capture {}{sha} · PacketPilot {} · alert {}",
        m.esc(&capture_name(out)),
        m.esc(&out.engine_version),
        m.code(&a.id)
    );
    s
}

/// Jira labels cannot contain spaces.
fn jira_label(t: &str) -> String {
    t.chars()
        .map(|c| if c.is_whitespace() { '-' } else { c })
        .collect()
}

fn jira_issue(
    out: &AnalysisOutput,
    a: &Alert,
    timeline: Option<&AlertTimeline>,
    dest: &Destination,
) -> Value {
    json!({
        "fields": {
            "project": {"key": dest.project.as_deref().unwrap_or("")},
            "issuetype": {"name": dest.issue_type.as_deref().unwrap_or("Task")},
            "summary": truncate(
                &format!("[PacketPilot {}] {}", band_label(a.band), a.title),
                250,
            ),
            "description": ticket_description(out, a, timeline, Markup::JiraWiki),
            "labels": tags_for(a, dest).iter().map(|t| jira_label(t)).collect::<Vec<_>>(),
        }
    })
}

/// Whether a ticket reference is safe to put in a URL path (Jira `SEC-12`, TheHive `~4096`).
fn path_safe(r: &str) -> bool {
    !r.is_empty()
        && r.len() <= 128
        && r.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '~' | '.'))
}

/// The request that escalates an alert already ticketed as `reference`: a comment on the Jira
/// issue, or an update of the TheHive alert's severity, tags and description. `None` for other
/// kinds, or a reference that cannot be addressed (the caller then creates a new ticket).
pub fn escalation_payload(
    out: &AnalysisOutput,
    dest: &Destination,
    a: &Alert,
    reference: &str,
) -> Option<PushPayload> {
    if !path_safe(reference) {
        return None;
    }
    let timeline = out.summary.timelines.iter().find(|t| t.alert_id == a.id);
    let (method, path, body) = match dest.kind {
        DestinationKind::Jira => {
            let body = format!(
                "*Escalated by PacketPilot to {}* (priority {}).\n\n{}",
                band_label(a.band),
                a.priority,
                ticket_description(out, a, timeline, Markup::JiraWiki)
            );
            (
                "POST",
                format!("/rest/api/2/issue/{reference}/comment"),
                json!({ "body": body }),
            )
        }
        DestinationKind::Thehive => (
            "PATCH",
            format!("/api/v1/alert/{reference}"),
            json!({
                "severity": thehive_severity(a.severity),
                "tags": tags_for(a, dest),
                "description": ticket_description(out, a, timeline, Markup::Markdown),
            }),
        ),
        _ => return None,
    };
    Some(PushPayload {
        method: method.into(),
        alert_ids: vec![a.id.clone()],
        path,
        content_type: "application/json".into(),
        body: serde_json::to_string(&body).unwrap_or_else(|_| "{}".into()),
    })
}

fn thehive_severity(s: Severity) -> u8 {
    match s {
        Severity::Info | Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn is_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

fn thehive_alert(
    out: &AnalysisOutput,
    a: &Alert,
    timeline: Option<&AlertTimeline>,
    dest: &Destination,
) -> Value {
    let mut seen = BTreeSet::new();
    let mut observables = Vec::new();
    for h in std::iter::once(&a.actor)
        .chain(a.hosts.iter())
        .chain(a.peer.iter())
    {
        if seen.insert(h.clone()) {
            let data_type = if is_ip(h) { "ip" } else { "domain" };
            observables.push(json!({"dataType": data_type, "data": h}));
        }
    }
    for p in &a.context.peers {
        if let Some(d) = &p.domain {
            if seen.insert(d.clone()) {
                observables.push(json!({"dataType": "domain", "data": d, "ioc": p.ioc}));
            }
        }
    }
    let mut v = json!({
        "type": "packetpilot",
        "source": "PacketPilot",
        "sourceRef": delivery_key(out, a),
        "title": truncate(&a.title, 250),
        "description": ticket_description(out, a, timeline, Markup::Markdown),
        "severity": thehive_severity(a.severity),
        "tags": tags_for(a, dest),
        "observables": observables,
    });
    if let Some(ns) = a.first_seen_ns {
        v["date"] = json!(ns.div_euclid(1_000_000));
    }
    v
}

// ─── SIEM (Splunk HEC / Elastic ECS / OCSF) ─────────────────────────────────

fn hec_event(
    out: &AnalysisOutput,
    a: &Alert,
    timeline: Option<&AlertTimeline>,
    dest: &Destination,
    now_secs: i64,
) -> Value {
    let time = a
        .first_seen_ns
        .map(|ns| ns as f64 / 1e9)
        .unwrap_or(now_secs as f64);
    let mut v = json!({
        "time": time,
        "host": a.actor,
        "source": "packetpilot",
        "sourcetype": dest.sourcetype.as_deref().unwrap_or("packetpilot:alert"),
        "event": alert_document(out, a, timeline, dest, now_secs),
    });
    if let Some(i) = &dest.index {
        v["index"] = json!(i);
    }
    v
}

fn ecs_severity(s: Severity) -> u8 {
    // ECS leaves the scale to the source; use the common 21/47/73/99 SIEM quartiles.
    match s {
        Severity::Info => 1,
        Severity::Low => 21,
        Severity::Medium => 47,
        Severity::High => 73,
        Severity::Critical => 99,
    }
}

/// An Elastic Common Schema document for one alert.
pub fn ecs_document(
    out: &AnalysisOutput,
    a: &Alert,
    timeline: Option<&AlertTimeline>,
    dest: &Destination,
    now_secs: i64,
) -> Value {
    let mut related: BTreeSet<String> = BTreeSet::new();
    let mut related_hosts: BTreeSet<String> = BTreeSet::new();
    for h in std::iter::once(&a.actor)
        .chain(a.hosts.iter())
        .chain(a.peer.iter())
    {
        if is_ip(h) {
            related.insert(h.clone());
        } else {
            related_hosts.insert(h.clone());
        }
    }
    let timestamp = a
        .first_seen_ns
        .map(super::iso_ns)
        .unwrap_or_else(|| super::iso(now_secs));
    let mut v = json!({
        "@timestamp": timestamp,
        "ecs": {"version": ECS_VERSION},
        "message": a.title,
        "event": {
            "kind": "alert",
            "category": ["network", "intrusion_detection"],
            "type": ["info"],
            "module": "packetpilot",
            "dataset": "packetpilot.alert",
            "id": a.id,
            "severity": ecs_severity(a.severity),
            "risk_score": a.priority,
            "start": iso_opt(a.first_seen_ns),
            "end": iso_opt(a.last_seen_ns),
            "reason": a.narrative,
        },
        "rule": {"name": a.title, "category": a.stage},
        "observer": {"vendor": "PacketPilot", "product": "PacketPilot", "type": "ids",
                     "version": out.engine_version},
        "related": {"ip": related, "hosts": related_hosts},
        "tags": tags_for(a, dest),
        "packetpilot": alert_document(out, a, timeline, dest, now_secs),
    });
    if is_ip(&a.actor) {
        v["source"] = json!({"ip": a.actor});
    }
    if let Some(p) = &a.peer {
        v["destination"] = if is_ip(p) {
            json!({"ip": p})
        } else {
            json!({"domain": p})
        };
    }
    if !a.attack.is_empty() {
        v["threat"] = json!({
            "framework": "MITRE ATT&CK",
            "technique": {"id": a.attack},
        });
    }
    v
}

fn ocsf_severity_id(s: Severity) -> u8 {
    match s {
        Severity::Info => 1,
        Severity::Low => 2,
        Severity::Medium => 3,
        Severity::High => 4,
        Severity::Critical => 5,
    }
}

fn ms(ns: Option<i64>) -> Value {
    ns.map(|n| json!(n.div_euclid(1_000_000)))
        .unwrap_or(Value::Null)
}

/// An OCSF 1.3 Detection Finding (class 2004, activity Create) for one alert.
pub fn ocsf_finding(
    out: &AnalysisOutput,
    a: &Alert,
    timeline: Option<&AlertTimeline>,
    now_secs: i64,
) -> Value {
    let observables: Vec<Value> = std::iter::once(("actor", &a.actor))
        .chain(a.peer.iter().map(|p| ("peer", p)))
        .map(|(name, v)| {
            // type_id 2 = IP Address, 1 = Hostname.
            let type_id = if is_ip(v) { 2 } else { 1 };
            json!({"name": name, "type_id": type_id, "value": v})
        })
        .collect();
    let attacks: Vec<Value> = a
        .attack
        .iter()
        .map(|t| json!({"technique": {"uid": t}, "version": "v15"}))
        .collect();
    let time_ms = a
        .first_seen_ns
        .map(|n| n.div_euclid(1_000_000))
        .unwrap_or(now_secs * 1000);
    let sev_id = ocsf_severity_id(a.severity);
    let mut types = vec![a.stage.clone()];
    if let Some(t) = timeline {
        for e in &t.events {
            if let Some(tac) = &e.tactic {
                if !types.contains(tac) {
                    types.push(tac.clone());
                }
            }
        }
    }
    json!({
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": 1,
        "activity_name": "Create",
        "type_uid": 200401,
        "type_name": "Detection Finding: Create",
        "time": time_ms,
        "severity_id": sev_id,
        "severity": match sev_id { 1 => "Informational", 2 => "Low", 3 => "Medium",
                                   4 => "High", _ => "Critical" },
        "status_id": 1,
        "status": "New",
        "confidence_score": a.confidence,
        "risk_score": a.priority,
        "message": a.title,
        "metadata": {
            "version": OCSF_VERSION,
            "uid": a.id,
            "product": {"name": "PacketPilot", "vendor_name": "PacketPilot",
                        "version": out.engine_version},
        },
        "finding_info": {
            "uid": a.id,
            "title": a.title,
            "desc": a.narrative,
            "types": types,
            "first_seen_time": ms(a.first_seen_ns),
            "last_seen_time": ms(a.last_seen_ns),
            "analytic": {"name": a.source.as_str(), "type_id": 1, "type": "Rule",
                         "uid": a.id},
            "attacks": attacks,
            "src_url": Value::Null,
        },
        "remediation": {"desc": a.action},
        "observables": observables,
        "unmapped": {
            "band": a.band.as_str(),
            "capture": capture_name(out),
            "capture_sha256": out.source_sha256,
            "finding_count": a.finding_count,
        },
    })
}

fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let mut o: String = s.chars().take(max_chars.saturating_sub(1)).collect();
    o.push('…');
    o
}

// ─── Target resolution ───────────────────────────────────────────────────────

/// A destination ready to send to: the full base URL and the auth header, both resolved from the
/// environment. `display_url` is safe to print (a secret URL shows as `$VAR`).
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedTarget {
    pub base_url: String,
    pub display_url: String,
    pub headers: Vec<(String, String)>,
    /// Every secret value resolved from the environment, longest first, for [`Self::redact`].
    secrets: Vec<String>,
}

impl ResolvedTarget {
    /// `text` with every resolved secret (a secret URL, token, user, auth header) replaced, so an
    /// error message or a server's echo can be printed or saved safely.
    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_string();
        if self.display_url != self.base_url {
            out = out.replace(&self.base_url, &self.display_url);
        }
        for s in &self.secrets {
            out = out.replace(s.as_str(), "***");
        }
        out
    }
}

/// Resolve `dest`'s URL and credentials through `env` (normally `std::env::var`). Errors name
/// the variable that is missing.
pub fn resolve_target(
    dest: &Destination,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<ResolvedTarget, String> {
    let who = format!("destination {:?}", dest.name);
    let get = |var: &str| env(var).filter(|v| !v.trim().is_empty());
    let (base_url, display_url) = match (&dest.url_env, &dest.url) {
        (Some(var), fallback) => match (get(var), fallback) {
            (Some(u), _) => (u.trim().to_string(), format!("${var}")),
            (None, Some(u)) => (u.clone(), u.clone()),
            (None, None) => return Err(format!("{who}: environment variable {var} is not set")),
        },
        (None, Some(u)) => (u.clone(), u.clone()),
        (None, None) => return Err(format!("{who}: no url")),
    };
    check_url(&base_url, dest.allow_http).map_err(|e| {
        // Never echo a secret URL into an error.
        if dest.url_env.is_some() {
            format!(
                "{who}: the URL in ${} is not a valid https URL",
                dest.url_env.as_deref().unwrap_or("")
            )
        } else {
            format!("{who}: {e}")
        }
    })?;
    let base_url = base_url.trim_end_matches('/').to_string();
    let token = match &dest.token_env {
        Some(var) => {
            Some(get(var).ok_or_else(|| format!("{who}: environment variable {var} is not set"))?)
        }
        None => None,
    };
    let user = match &dest.user_env {
        Some(var) => {
            Some(get(var).ok_or_else(|| format!("{who}: environment variable {var} is not set"))?)
        }
        None => None,
    };
    let mut secrets: Vec<String> = Vec::new();
    if display_url != base_url {
        // The secret webhook URL's path (its token part) may be echoed without the host.
        if let Some(path) = base_url.splitn(4, '/').nth(3) {
            secrets.push(path.to_string());
        }
    }
    secrets.extend(token.iter().cloned());
    secrets.extend(user.iter().cloned());
    let mut headers = Vec::new();
    if let Some(tok) = token {
        let value = match (dest.kind, user) {
            (_, Some(u)) => {
                use base64::Engine as _;
                let pair = format!("{u}:{tok}");
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(pair.as_bytes())
                )
            }
            (DestinationKind::SplunkHec, None) => format!("Splunk {tok}"),
            (DestinationKind::Elastic, None) => format!("ApiKey {tok}"),
            (_, None) => format!("Bearer {tok}"),
        };
        secrets.push(value.clone());
        headers.push(("Authorization".to_string(), value));
    }
    secrets.retain(|s| s.len() >= 4);
    secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
    Ok(ResolvedTarget {
        base_url,
        display_url,
        headers,
        secrets,
    })
}

// ─── Sent ledger ─────────────────────────────────────────────────────────────

/// One delivery the ledger remembers.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LedgerEntry {
    /// Unix seconds of the delivery.
    pub sent_at: i64,
    pub band: PriorityBand,
    pub priority: u16,
    /// The ticket the destination created (Jira key, TheHive id), when it returned one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

/// Which alert went to which destination: `destination name → delivery key → entry`. A plain JSON
/// file a team can share alongside its destinations, so two analysts never double-ticket.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PushLedger {
    #[serde(default = "one")]
    pub version: u32,
    #[serde(default)]
    pub sent: BTreeMap<String, BTreeMap<String, LedgerEntry>>,
}

/// Why an alert is (or is not) sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendDecision {
    /// Never sent to this destination.
    New,
    /// Sent before at a lower band; it got worse, so it goes again.
    Escalated,
    /// Already delivered at this band or higher.
    AlreadySent,
}

impl PushLedger {
    pub fn parse(text: &str) -> Result<PushLedger, String> {
        serde_json::from_str(text).map_err(|e| e.to_string())
    }

    /// `key` is the alert's [`delivery_key`].
    pub fn decide(&self, dest: &str, key: &str, a: &Alert) -> SendDecision {
        match self.sent.get(dest).and_then(|m| m.get(key)) {
            None => SendDecision::New,
            Some(e) if a.band > e.band => SendDecision::Escalated,
            Some(_) => SendDecision::AlreadySent,
        }
    }

    pub fn entry(&self, dest: &str, key: &str) -> Option<&LedgerEntry> {
        self.sent.get(dest).and_then(|m| m.get(key))
    }

    pub fn record(
        &mut self,
        dest: &str,
        key: &str,
        a: &Alert,
        now_secs: i64,
        reference: Option<String>,
    ) {
        let slot = self
            .sent
            .entry(dest.to_string())
            .or_default()
            .entry(key.to_string());
        // Keep the first ticket reference across escalations: the ticket is the same story.
        let reference = reference.or_else(|| match &slot {
            std::collections::btree_map::Entry::Occupied(o) => o.get().reference.clone(),
            std::collections::btree_map::Entry::Vacant(_) => None,
        });
        let entry = LedgerEntry {
            sent_at: now_secs,
            band: a.band,
            priority: a.priority,
            reference,
        };
        match slot {
            std::collections::btree_map::Entry::Occupied(mut o) => {
                o.insert(entry);
            }
            std::collections::btree_map::Entry::Vacant(v) => {
                v.insert(entry);
            }
        }
    }
}

/// The ticket a per-alert destination created, from its response body (Jira `key`, TheHive
/// `_id`, or a webhook's `id`).
pub fn response_reference(kind: DestinationKind, body: &str) -> Option<String> {
    let v: Value = serde_json::from_str(body).ok()?;
    let field = match kind {
        DestinationKind::Jira => "key",
        DestinationKind::Thehive => "_id",
        DestinationKind::Webhook => "id",
        _ => return None,
    };
    match v.get(field)? {
        Value::String(s) if !s.is_empty() => Some(truncate(s, 128)),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Per-item outcome of an Elastic `_bulk` response for a request of `n` items, in order: `None`
/// when the item was stored, or was already there (a 409 on `create` with our stable `_id` means
/// an earlier, interrupted run delivered it), else the error reason.
pub fn bulk_item_errors(body: &str, n: usize) -> Vec<Option<String>> {
    let v: Option<Value> = serde_json::from_str(body).ok();
    if v.as_ref()
        .and_then(|v| v.get("errors"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return vec![None; n];
    }
    let items = v
        .as_ref()
        .and_then(|v| v.get("items"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    (0..n)
        .map(|i| {
            let Some(item) = items
                .get(i)
                .and_then(|it| it.as_object()?.values().next().cloned())
            else {
                return Some("no result for this item".to_string());
            };
            let status = item.get("status").and_then(Value::as_u64).unwrap_or(0);
            if (200..300).contains(&status) || status == 409 {
                return None;
            }
            let reason = item
                .get("error")
                .and_then(|e| e.get("reason").or_else(|| e.get("type")))
                .and_then(Value::as_str)
                .unwrap_or("rejected");
            Some(format!("HTTP {status}: {}", truncate(reason, 300)))
        })
        .collect()
}

/// Whether a response means the request was accepted. Splunk HEC answers 200 with an error
/// code in some setups, so its body is checked too; Elastic `_bulk` items are checked one by
/// one with [`bulk_item_errors`].
pub fn response_ok(kind: DestinationKind, status: u16, body: &str) -> Result<(), String> {
    if !(200..300).contains(&status) {
        let snippet = truncate(body.trim(), 300);
        return Err(format!("HTTP {status}: {snippet}"));
    }
    if kind == DestinationKind::SplunkHec {
        let v: Option<Value> = serde_json::from_str(body).ok();
        let code = v
            .as_ref()
            .and_then(|v| v.get("code"))
            .and_then(Value::as_i64);
        if let Some(code) = code.filter(|&c| c != 0) {
            let text = v
                .as_ref()
                .and_then(|v| v.get("text"))
                .and_then(Value::as_str)
                .unwrap_or("rejected");
            return Err(format!("HEC code {code}: {text}"));
        }
    }
    Ok(())
}

// ─── HTTP ────────────────────────────────────────────────────────────────────

/// Send `body` to `url` with `method` (pure-Rust `ureq` + rustls). Returns the status and body
/// for any HTTP answer, including 4xx/5xx; `Err` only when no answer came back. Redirects are
/// not followed, so credentials never reach a host the destination did not name.
#[cfg(feature = "online")]
pub fn http_send(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    content_type: &str,
    body: &str,
) -> Result<(u16, String), String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent(concat!("PacketPilot/", env!("CARGO_PKG_VERSION"), " push"))
        .redirects(0)
        .build();
    let mut req = agent.request(method, url).set("Content-Type", content_type);
    for (k, v) in headers {
        req = req.set(k, v);
    }
    match req.send_string(body) {
        Ok(resp) => {
            let status = resp.status();
            Ok((status, resp.into_string().unwrap_or_default()))
        }
        Err(ureq::Error::Status(code, resp)) => Ok((code, resp.into_string().unwrap_or_default())),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::alert::{AlertContext, AlertSource, HostContext, PeerContext};
    use crate::model::finding::{Finding, FindingKind};
    use crate::model::timeline::{PacketScope, TimelineEvent, TimelineEventKind};

    fn alert(id: &str, band: PriorityBand, priority: u16, title: &str) -> Alert {
        Alert {
            id: id.into(),
            source: AlertSource::Host,
            band,
            priority,
            confidence: 80,
            severity: Severity::High,
            title: title.into(),
            narrative: "10.0.0.5 beaconed to 203.0.113.9 every 60 s.".into(),
            action: "Isolate 10.0.0.5 and pull its EDR timeline.".into(),
            actor: "10.0.0.5".into(),
            hosts: vec!["10.0.0.5".into()],
            host_count: 1,
            peer: Some("203.0.113.9".into()),
            attack: vec!["T1071".into(), "T1105".into()],
            stage: "Command and Control".into(),
            stage_ordinal: 5,
            next_stage: Some("Exfiltration".into()),
            priority_terms: Vec::new(),
            context: AlertContext {
                actor: HostContext {
                    ip: "10.0.0.5".into(),
                    hostname: None,
                    mac: None,
                    vendor: None,
                    internal: true,
                    cloud: None,
                    new_to_baseline: false,
                },
                peers: vec![PeerContext {
                    ip: "203.0.113.9".into(),
                    domain: Some("evil.example".into()),
                    cloud: None,
                    ioc: true,
                    reputation_malicious: 0,
                    dst_port: Some(443),
                }],
                entries: Vec::new(),
            },
            finding_indices: vec![0],
            finding_count: 1,
            chain_id: None,
            incident_hosts: Vec::new(),
            first_seen_ns: Some(1_700_000_000_000_000_000),
            last_seen_ns: Some(1_700_000_600_000_000_000),
        }
    }

    fn output() -> AnalysisOutput {
        let mut out = AnalysisOutput {
            source_path: "/cases/acme/host5.pcap".into(),
            source_sha256: Some("ab".repeat(32)),
            ..AnalysisOutput::default()
        };
        out.summary.findings.push(Finding {
            kind: FindingKind::Beacon,
            severity: Severity::High,
            score: 80,
            title: "Beacon to 203.0.113.9".into(),
            src_ip: "10.0.0.5".into(),
            dst_ip: Some("203.0.113.9".into()),
            dst_port: Some(443),
            attack: vec!["T1071".into()],
            evidence: vec![],
            interval_ns: None,
            jitter_cv: None,
            contacts: Some(10),
            first_seen_ns: Some(1_700_000_000_000_000_000),
            last_seen_ns: None,
            victims: Vec::new(),
        });
        out.summary.alerts = vec![
            alert(
                "alert:1",
                PriorityBand::ActNow,
                90,
                "C2 beacon from 10.0.0.5",
            ),
            alert(
                "alert:2",
                PriorityBand::Review,
                40,
                "Odd DNS <!channel> [x](http://e)",
            ),
            alert("alert:3", PriorityBand::Info, 5, "Hygiene rollup"),
        ];
        out.summary.timelines = vec![AlertTimeline {
            alert_id: "alert:1".into(),
            title: "C2 beacon from 10.0.0.5".into(),
            hosts: vec!["10.0.0.5".into()],
            first_ts_ns: Some(1_700_000_000_000_000_000),
            last_ts_ns: Some(1_700_000_600_000_000_000),
            events: vec![TimelineEvent {
                ts_ns: Some(1_700_000_000_000_000_000),
                end_ns: None,
                kind: TimelineEventKind::FirstContact,
                host: "10.0.0.5".into(),
                peer: Some("203.0.113.9".into()),
                dst_port: Some(443),
                title: "First contact".into(),
                detail: None,
                severity: Severity::Info,
                tactic: Some("Command and Control".into()),
                attack: vec![],
                finding_index: None,
                packets: Some(PacketScope {
                    host: "10.0.0.5".into(),
                    peer: Some("203.0.113.9".into()),
                    port: Some(443),
                    start_ns: 0,
                    end_ns: 1,
                }),
            }],
            event_count: 1,
        }];
        out
    }

    fn dest(kind: DestinationKind) -> Destination {
        let mut d = DestinationFile::example()
            .destinations
            .into_iter()
            .find(|d| d.kind == kind)
            .unwrap();
        d.disabled = false;
        d.min_band = None;
        d
    }

    #[test]
    fn example_file_round_trips_and_validates() {
        let text = serde_json::to_string_pretty(&DestinationFile::example()).unwrap();
        let back = DestinationFile::parse(&text).unwrap();
        assert_eq!(back, DestinationFile::example());
        assert_eq!(back.destinations.len(), 8);
    }

    #[test]
    fn parse_rejects_inline_secrets_and_bad_shapes() {
        let inline =
            r#"{"destinations":[{"name":"s","kind":"slack","url":"https://x","token":"abc"}]}"#;
        let e = DestinationFile::parse(inline).unwrap_err();
        assert!(e.contains("token_env"), "{e}");
        let no_url = r#"{"destinations":[{"name":"s","kind":"slack"}]}"#;
        assert!(DestinationFile::parse(no_url).unwrap_err().contains("url"));
        let dup = r#"{"destinations":[{"name":"a","kind":"webhook","url":"https://x"},
                                       {"name":"a","kind":"webhook","url":"https://y"}]}"#;
        assert!(DestinationFile::parse(dup)
            .unwrap_err()
            .contains("duplicate"));
        let jira = r#"{"destinations":[{"name":"j","kind":"jira","url":"https://x","token_env":"PPCAP_T"}]}"#;
        assert!(DestinationFile::parse(jira)
            .unwrap_err()
            .contains("project"));
        let hec = r#"{"destinations":[{"name":"h","kind":"splunk_hec","url":"https://x"}]}"#;
        assert!(DestinationFile::parse(hec)
            .unwrap_err()
            .contains("token_env"));
        let env = r#"{"destinations":[{"name":"w","kind":"webhook","url":"https://x","token_env":"sk-123 abc"}]}"#;
        assert!(DestinationFile::parse(env)
            .unwrap_err()
            .contains("environment variable name"));
        let foreign = r#"{"destinations":[{"name":"w","kind":"webhook","url":"https://x","token_env":"AWS_SECRET_ACCESS_KEY"}]}"#;
        assert!(DestinationFile::parse(foreign)
            .unwrap_err()
            .contains("PPCAP_"));
        let http = r#"{"destinations":[{"name":"w","kind":"webhook","url":"http://siem.corp/x"}]}"#;
        assert!(DestinationFile::parse(http)
            .unwrap_err()
            .contains("plain http"));
        let ok_http = r#"{"destinations":[{"name":"w","kind":"webhook","url":"http://127.0.0.1:8080/x"},
                                          {"name":"v","kind":"webhook","url":"http://siem.corp/x","allow_http":true}]}"#;
        assert!(DestinationFile::parse(ok_http).is_ok());
    }

    #[test]
    fn select_alerts_applies_the_stricter_band_and_ids() {
        let out = output();
        let mut d = dest(DestinationKind::Webhook);
        let ids = |v: Vec<&Alert>| v.iter().map(|a| a.id.clone()).collect::<Vec<_>>();
        assert_eq!(ids(select_alerts(&out, &d, None, &[])).len(), 3);
        d.min_band = Some(PriorityBand::Review);
        assert_eq!(
            ids(select_alerts(&out, &d, None, &[])),
            ["alert:1", "alert:2"]
        );
        assert_eq!(
            ids(select_alerts(&out, &d, Some(PriorityBand::ActNow), &[])),
            ["alert:1"]
        );
        // The destination's floor still holds when the CLI asks for less.
        assert_eq!(
            ids(select_alerts(&out, &d, Some(PriorityBand::Info), &[])),
            ["alert:1", "alert:2"]
        );
        assert_eq!(
            ids(select_alerts(&out, &d, None, &["alert:2".into()])),
            ["alert:2"]
        );
    }

    #[test]
    fn webhook_sends_one_document_per_alert() {
        let out = output();
        let d = dest(DestinationKind::Webhook);
        let alerts: Vec<&Alert> = out.summary.alerts.iter().collect();
        let p = build_payloads(&out, &d, &alerts, 1_800_000_000);
        assert_eq!(p.len(), 3);
        let doc: Value = serde_json::from_str(&p[0].body).unwrap();
        assert_eq!(doc["schema"], "packetpilot.alert/1");
        assert_eq!(doc["alert_id"], "alert:1");
        assert_eq!(doc["band"], "act_now");
        assert_eq!(doc["findings"][0]["kind"], "beacon");
        assert_eq!(
            doc["timeline"][0]["bpf"],
            "host 10.0.0.5 and host 203.0.113.9 and port 443"
        );
        assert_eq!(doc["capture"]["name"], "host5.pcap");
        assert_eq!(doc["first_seen"], "2023-11-14T22:13:20.000Z");
        assert!(doc["tags"]
            .as_array()
            .unwrap()
            .contains(&json!("attack:T1071")));
    }

    #[test]
    fn slack_digest_escapes_capture_text_and_chunks() {
        let mut out = output();
        let template = out.summary.alerts[1].clone();
        for i in 0..12 {
            let mut a = template.clone();
            a.id = format!("alert:x{i}");
            out.summary.alerts.push(a);
        }
        let d = dest(DestinationKind::Slack);
        let alerts: Vec<&Alert> = out.summary.alerts.iter().collect();
        let p = build_payloads(&out, &d, &alerts, 0);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].alert_ids.len(), 10);
        assert_eq!(p[1].alert_ids.len(), 5);
        let msg: Value = serde_json::from_str(&p[0].body).unwrap();
        assert_eq!(msg["text"], "PacketPilot: 10 of 15 alerts from host5.pcap");
        let body = &p[0].body;
        assert!(
            !body.contains("<!channel>"),
            "a capture title must not ping a channel"
        );
        assert!(body.contains("&lt;!channel&gt;"));
    }

    #[test]
    fn teams_message_is_an_adaptive_card() {
        let out = output();
        let d = dest(DestinationKind::Teams);
        let alerts: Vec<&Alert> = out.summary.alerts.iter().take(2).collect();
        let p = build_payloads(&out, &d, &alerts, 0);
        let v: Value = serde_json::from_str(&p[0].body).unwrap();
        let card = &v["attachments"][0];
        assert_eq!(
            card["contentType"],
            "application/vnd.microsoft.card.adaptive"
        );
        assert_eq!(card["content"]["type"], "AdaptiveCard");
        assert_eq!(card["content"]["body"][1]["items"][0]["color"], "Attention");
        let title = card["content"]["body"][2]["items"][0]["text"]
            .as_str()
            .unwrap();
        assert!(
            title.contains(r"\[x\]\(http://e\)"),
            "link syntax neutralized: {title}"
        );
    }

    #[test]
    fn jira_issue_carries_project_wiki_description_and_labels() {
        let out = output();
        let d = dest(DestinationKind::Jira);
        let p = build_payloads(&out, &d, &[&out.summary.alerts[0]], 0);
        assert_eq!(p[0].path, "/rest/api/2/issue");
        let v: Value = serde_json::from_str(&p[0].body).unwrap();
        let f = &v["fields"];
        assert_eq!(f["project"]["key"], "SEC");
        assert_eq!(f["issuetype"]["name"], "Task");
        assert_eq!(
            f["summary"],
            "[PacketPilot ACT NOW] C2 beacon from 10.0.0.5"
        );
        let desc = f["description"].as_str().unwrap();
        assert!(desc.contains("h3. Timeline"), "{desc}");
        assert!(desc.contains("{{host 10.0.0.5 and host 203.0.113.9 and port 443}}"));
        assert!(desc.contains("{{alert:1}}"));
        assert!(f["labels"]
            .as_array()
            .unwrap()
            .iter()
            .all(|l| !l.as_str().unwrap().contains(' ')));
    }

    #[test]
    fn jira_escape_defuses_wiki_macros() {
        assert_eq!(jira_escape("{html}[x|y]"), r"\{html\}\[x\|y\]");
    }

    #[test]
    fn thehive_alert_uses_source_ref_and_observables() {
        let out = output();
        let d = dest(DestinationKind::Thehive);
        let p = build_payloads(&out, &d, &[&out.summary.alerts[0]], 0);
        assert_eq!(p[0].path, "/api/v1/alert");
        let v: Value = serde_json::from_str(&p[0].body).unwrap();
        assert_eq!(v["sourceRef"], format!("alert:1@{}", "ab".repeat(8)));
        assert_eq!(v["severity"], 3);
        assert_eq!(v["date"], 1_700_000_000_000i64);
        let obs = v["observables"].as_array().unwrap();
        assert!(obs.contains(&json!({"dataType": "ip", "data": "203.0.113.9"})));
        assert!(obs.contains(&json!({"dataType": "domain", "data": "evil.example", "ioc": true})));
        assert!(v["description"].as_str().unwrap().contains("### Timeline"));
    }

    #[test]
    fn hec_batches_concatenated_events() {
        let out = output();
        let d = dest(DestinationKind::SplunkHec);
        let alerts: Vec<&Alert> = out.summary.alerts.iter().collect();
        let p = build_payloads(&out, &d, &alerts, 0);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].path, "/services/collector/event");
        let events: Vec<Value> = p[0]
            .body
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0]["index"], "network");
        assert_eq!(events[0]["sourcetype"], "packetpilot:alert");
        assert_eq!(events[0]["time"], 1_700_000_000.0);
        assert_eq!(events[0]["event"]["alert_id"], "alert:1");
    }

    #[test]
    fn elastic_bulk_is_ndjson_ecs() {
        let out = output();
        let d = dest(DestinationKind::Elastic);
        let p = build_payloads(&out, &d, &[&out.summary.alerts[0]], 0);
        assert_eq!(p[0].content_type, "application/x-ndjson");
        assert_eq!(p[0].extension(), "ndjson");
        let lines: Vec<Value> = p[0]
            .body
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(
            lines[0]["create"]["_id"],
            format!("alert:1@{}", "ab".repeat(8))
        );
        assert_eq!(
            lines[0]["create"]["_index"],
            "logs-packetpilot.alert-default"
        );
        let doc = &lines[1];
        assert_eq!(doc["event"]["kind"], "alert");
        assert_eq!(doc["event"]["risk_score"], 90);
        assert_eq!(doc["source"]["ip"], "10.0.0.5");
        assert_eq!(doc["destination"]["ip"], "203.0.113.9");
        assert_eq!(doc["threat"]["technique"]["id"], json!(["T1071", "T1105"]));
        assert_eq!(doc["@timestamp"], "2023-11-14T22:13:20.000Z");
        assert!(p[0].body.ends_with('\n'), "bulk bodies end with a newline");
    }

    #[test]
    fn ocsf_detection_finding_shape() {
        let out = output();
        let d = dest(DestinationKind::Ocsf);
        let p = build_payloads(&out, &d, &[&out.summary.alerts[0]], 0);
        let arr: Vec<Value> = serde_json::from_str(&p[0].body).unwrap();
        let f = &arr[0];
        assert_eq!(f["class_uid"], 2004);
        assert_eq!(f["type_uid"], 200401);
        assert_eq!(f["severity_id"], 4);
        assert_eq!(f["time"], 1_700_000_000_000i64);
        assert_eq!(f["finding_info"]["uid"], "alert:1");
        assert_eq!(f["finding_info"]["attacks"][0]["technique"]["uid"], "T1071");
        assert_eq!(f["metadata"]["version"], OCSF_VERSION);
        assert_eq!(f["observables"][0]["type_id"], 2);
    }

    #[test]
    fn untimed_alerts_use_the_supplied_clock() {
        let mut out = output();
        out.summary.alerts[0].first_seen_ns = None;
        let d = dest(DestinationKind::Ocsf);
        let p = build_payloads(&out, &d, &[&out.summary.alerts[0]], 1_800_000_000);
        let arr: Vec<Value> = serde_json::from_str(&p[0].body).unwrap();
        assert_eq!(arr[0]["time"], 1_800_000_000_000i64);
    }

    #[test]
    fn resolve_target_reads_env_and_builds_auth() {
        let env = |k: &str| match k {
            "PPCAP_SLACK_WEBHOOK_URL" => Some("https://hooks.slack.com/services/T/B/secret".into()),
            "PPCAP_JIRA_USER" => Some("me@example.org".into()),
            "PPCAP_JIRA_TOKEN" => Some("tok".into()),
            "PPCAP_SPLUNK_HEC_TOKEN" => Some("hec".into()),
            "PPCAP_ELASTIC_API_KEY" => Some("ek".into()),
            "PPCAP_THEHIVE_API_KEY" => Some("hk".into()),
            _ => None,
        };
        let s = resolve_target(&dest(DestinationKind::Slack), &env).unwrap();
        assert_eq!(s.base_url, "https://hooks.slack.com/services/T/B/secret");
        assert_eq!(s.display_url, "$PPCAP_SLACK_WEBHOOK_URL");
        assert!(s.headers.is_empty());
        let j = resolve_target(&dest(DestinationKind::Jira), &env).unwrap();
        assert_eq!(j.headers[0].1, "Basic bWVAZXhhbXBsZS5vcmc6dG9r");
        let h = resolve_target(&dest(DestinationKind::SplunkHec), &env).unwrap();
        assert_eq!(h.headers[0].1, "Splunk hec");
        let e = resolve_target(&dest(DestinationKind::Elastic), &env).unwrap();
        assert_eq!(e.headers[0].1, "ApiKey ek");
        let t = resolve_target(&dest(DestinationKind::Thehive), &env).unwrap();
        assert_eq!(t.headers[0].1, "Bearer hk");
        let missing = resolve_target(&dest(DestinationKind::Teams), &env).unwrap_err();
        assert!(missing.contains("PPCAP_TEAMS_WEBHOOK_URL"), "{missing}");
        // A secret URL that is not https is refused without echoing it.
        let bad = |k: &str| (k == "PPCAP_SLACK_WEBHOOK_URL").then(|| "http://evil/secret".into());
        let err = resolve_target(&dest(DestinationKind::Slack), &bad).unwrap_err();
        assert!(!err.contains("secret"), "{err}");
    }

    #[test]
    fn ledger_skips_repeats_and_resends_escalations() {
        let out = output();
        let mut a = out.summary.alerts[1].clone();
        let k = delivery_key(&out, &a);
        let mut l = PushLedger::default();
        assert_eq!(l.decide("jira", &k, &a), SendDecision::New);
        l.record("jira", &k, &a, 100, Some("SEC-7".into()));
        assert_eq!(l.decide("jira", &k, &a), SendDecision::AlreadySent);
        assert_eq!(l.decide("slack", &k, &a), SendDecision::New);
        a.band = PriorityBand::ActNow;
        assert_eq!(l.decide("jira", &k, &a), SendDecision::Escalated);
        l.record("jira", &k, &a, 200, None);
        let e = l.entry("jira", &k).unwrap();
        assert_eq!((e.sent_at, e.band), (200, PriorityBand::ActNow));
        assert_eq!(
            e.reference.as_deref(),
            Some("SEC-7"),
            "ticket kept across escalation"
        );
        let text = serde_json::to_string(&l).unwrap();
        assert_eq!(PushLedger::parse(&text).unwrap(), l);
    }

    #[test]
    fn delivery_keys_separate_captures_and_survive_reruns() {
        let out = output();
        let a = &out.summary.alerts[0];
        assert_eq!(capture_id(&out), "ab".repeat(8));
        assert_eq!(delivery_key(&out, a), format!("alert:1@{}", "ab".repeat(8)));
        // Without a hash the identity comes from path, size and time span: stable per analysis,
        // different for another capture of the same host.
        let mut unhashed = out.clone();
        unhashed.source_sha256 = None;
        let k1 = delivery_key(&unhashed, a);
        assert_eq!(k1, delivery_key(&unhashed.clone(), a));
        let mut other = unhashed.clone();
        other.source_path = "/cases/acme/host5-day2.pcap".into();
        assert_ne!(k1, delivery_key(&other, a));
        assert!(k1.starts_with("alert:1@") && k1.len() == "alert:1@".len() + 16);
    }

    #[test]
    fn escalations_update_the_existing_ticket() {
        let out = output();
        let a = &out.summary.alerts[0];
        let j = escalation_payload(&out, &dest(DestinationKind::Jira), a, "SEC-7").unwrap();
        assert_eq!(
            (j.method.as_str(), j.path.as_str()),
            ("POST", "/rest/api/2/issue/SEC-7/comment")
        );
        let body: Value = serde_json::from_str(&j.body).unwrap();
        assert!(body["body"]
            .as_str()
            .unwrap()
            .starts_with("*Escalated by PacketPilot to ACT NOW*"));
        let t = escalation_payload(&out, &dest(DestinationKind::Thehive), a, "~4096").unwrap();
        assert_eq!(
            (t.method.as_str(), t.path.as_str()),
            ("PATCH", "/api/v1/alert/~4096")
        );
        let body: Value = serde_json::from_str(&t.body).unwrap();
        assert_eq!(body["severity"], 3);
        // Kinds without tickets, and references that cannot go in a path, fall back to create.
        assert!(escalation_payload(&out, &dest(DestinationKind::Slack), a, "x").is_none());
        assert!(escalation_payload(&out, &dest(DestinationKind::Jira), a, "../admin").is_none());
        assert!(escalation_payload(&out, &dest(DestinationKind::Jira), a, "").is_none());
    }

    #[test]
    fn redact_hides_secret_urls_and_tokens() {
        let env = |k: &str| match k {
            "PPCAP_SLACK_WEBHOOK_URL" => {
                Some("https://hooks.slack.com/services/T0/B0/s3cr3t".into())
            }
            "PPCAP_SPLUNK_HEC_TOKEN" => Some("hec-token-123".into()),
            _ => None,
        };
        let s = resolve_target(&dest(DestinationKind::Slack), &env).unwrap();
        let e = "https://hooks.slack.com/services/T0/B0/s3cr3t: Connection refused";
        assert_eq!(s.redact(e), "$PPCAP_SLACK_WEBHOOK_URL: Connection refused");
        assert_eq!(
            s.redact("no_service for services/T0/B0/s3cr3t"),
            "no_service for ***"
        );
        let h = resolve_target(&dest(DestinationKind::SplunkHec), &env).unwrap();
        assert_eq!(h.redact("bad token hec-token-123"), "bad token ***");
        assert_eq!(
            h.redact("https://splunk.example.org:8088 down"),
            "https://splunk.example.org:8088 down"
        );
    }

    #[test]
    fn bulk_items_are_judged_one_by_one() {
        let body = r#"{"errors":true,"items":[
            {"create":{"status":201}},
            {"create":{"status":409,"error":{"type":"version_conflict_engine_exception"}}},
            {"create":{"status":400,"error":{"reason":"mapper_parsing_exception"}}}]}"#;
        let r = bulk_item_errors(body, 3);
        assert_eq!(r[0], None);
        assert_eq!(r[1], None, "already stored by an earlier run");
        assert!(r[2]
            .as_deref()
            .unwrap()
            .contains("mapper_parsing_exception"));
        assert_eq!(
            bulk_item_errors(r#"{"errors":false,"items":[]}"#, 2),
            vec![None, None]
        );
        assert!(bulk_item_errors(r#"{"errors":true,"items":[]}"#, 1)[0].is_some());
    }

    #[test]
    fn responses_are_checked_per_kind() {
        assert_eq!(
            response_reference(DestinationKind::Jira, r#"{"id":"1","key":"SEC-12"}"#).as_deref(),
            Some("SEC-12")
        );
        assert_eq!(
            response_reference(DestinationKind::Thehive, r#"{"_id":"~4096"}"#).as_deref(),
            Some("~4096")
        );
        assert_eq!(response_reference(DestinationKind::Slack, "ok"), None);
        assert!(response_ok(DestinationKind::Slack, 200, "ok").is_ok());
        assert!(response_ok(DestinationKind::Jira, 400, r#"{"errors":{}}"#)
            .unwrap_err()
            .starts_with("HTTP 400"));
        assert!(response_ok(DestinationKind::Elastic, 200, r#"{"errors":false}"#).is_ok());
        assert!(response_ok(
            DestinationKind::SplunkHec,
            200,
            r#"{"text":"Success","code":0}"#
        )
        .is_ok());
        assert!(response_ok(
            DestinationKind::SplunkHec,
            200,
            r#"{"text":"Invalid index","code":7}"#
        )
        .is_err());
    }

    #[test]
    fn empty_selection_builds_nothing() {
        let out = output();
        assert!(build_payloads(&out, &dest(DestinationKind::Slack), &[], 0).is_empty());
    }
}
