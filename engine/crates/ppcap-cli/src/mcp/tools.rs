//! The MCP tool catalogue and handlers, plus the `triage` promptbook.
//!
//! Handlers return `Ok(json)` for the agent or `Err(message)`, which the protocol layer turns
//! into an `isError` result so the agent can read the message and correct its call. Every list
//! a handler returns is capped, and every timestamp leaves as ISO-8601 UTC.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::PathBuf;

use base64::Engine as _;
use ppcap_core::{Alert, Finding, Summary, Transport};
use serde_json::{json, Map, Value};

use super::capture::Capture;
use super::flows::{self, ip_arg, port_arg, proto_arg, time_arg, u64_arg};
use super::time::{fmt_ns, fmt_opt};
use super::Server;

const MAX_FINDINGS_PER_ALERT: usize = 50;
const MAX_TIMELINE_EVENTS: usize = 200;
const MAX_EVIDENCE_LINES: usize = 10;
const DEFAULT_PACKETS: usize = 50;
const MAX_PACKETS: usize = 500;
const DEFAULT_PAYLOAD_BYTES: usize = 128;
const MAX_CARVE_PACKETS: usize = 100_000;

/// Object keys holding nanosecond instants. [`iso_times`] rewrites them to ISO strings and
/// drops the `_ns` suffix; durations such as `interval_ns` are left alone.
const INSTANT_KEYS: &[&str] = &[
    "ts_ns",
    "start_ns",
    "end_ns",
    "first_seen_ns",
    "last_seen_ns",
    "first_ts_ns",
    "last_ts_ns",
];

fn iso_times(v: &mut Value) {
    match v {
        Value::Object(m) => {
            let keys: Vec<String> = m.keys().cloned().collect();
            for k in keys {
                if INSTANT_KEYS.contains(&k.as_str()) {
                    if let Some(val) = m.remove(&k) {
                        let iso = val
                            .as_i64()
                            .map(|n| Value::String(fmt_ns(n)))
                            .unwrap_or(Value::Null);
                        m.insert(k.trim_end_matches("_ns").to_string(), iso);
                    }
                } else if let Some(child) = m.get_mut(&k) {
                    iso_times(child);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(iso_times),
        _ => {}
    }
}

fn to_json<T: serde::Serialize>(t: &T) -> Value {
    let mut v = serde_json::to_value(t).unwrap_or(Value::Null);
    iso_times(&mut v);
    v
}

fn ro(title: &str) -> Value {
    json!({ "title": title, "readOnlyHint": true, "openWorldHint": false })
}

fn capture_prop() -> Value {
    json!({
        "type": "string",
        "description": "Capture id from list_captures. Optional when only one capture is loaded."
    })
}

/// The tools this server offers, given its launch options.
pub fn definitions(s: &Server) -> Vec<Value> {
    let cap = capture_prop();
    let flow_filter_props = json!({
        "capture": cap,
        "flow_id": { "type": "integer", "description": "One flow by id." },
        "ip": { "type": "string", "description": "Either endpoint is this IP." },
        "peer": { "type": "string", "description": "With ip: the other endpoint is this IP." },
        "src_ip": { "type": "string", "description": "Initiator (SYN sender / first packet)." },
        "dst_ip": { "type": "string", "description": "Responder." },
        "port": { "type": "integer", "description": "Either port." },
        "dst_port": { "type": "integer", "description": "Responder port." },
        "proto": { "type": ["string", "integer"], "description": "tcp, udp, icmp, icmpv6, sctp or an IANA number." },
        "app_proto": { "type": "string", "description": "Application protocol label, e.g. dns, https, http, ssh, smb, kerberos." },
        "category": { "type": "string", "description": "Flow category token, e.g. web, dns, remote_access, file_transfer." },
        "min_severity": { "type": "string", "enum": ["info", "low", "medium", "high", "critical"] },
        "ioc": { "type": "boolean", "description": "Only flows that matched (true) or did not match (false) the threat feed." },
        "text": { "type": "string", "description": "Case-insensitive substring of TLS SNI, HTTP Host or User-Agent." },
        "since": { "type": "string", "description": "ISO-8601 UTC; flows still active at or after this time." },
        "until": { "type": "string", "description": "ISO-8601 UTC; flows that started at or before this time." },
        "min_bytes": { "type": "integer", "description": "Total bytes, both directions." },
        "group_by": { "type": "string", "enum": flows::GROUP_BY_NAMES },
        "sort": { "type": "string", "enum": flows::SORT_NAMES, "description": "Descending, except start (earliest first). Default bytes; flows needs group_by." },
        "limit": { "type": "integer", "minimum": 1, "maximum": flows::MAX_LIMIT, "description": "Default 25." }
    });

    let mut tools = vec![
        json!({
            "name": "list_captures",
            "title": "List loaded captures",
            "description": "The captures this server has loaded: ids, time span, size, alert counts, and whether packets and flows are available. The flows Parquet path and columns are listed for agents that have their own SQL engine (DuckDB: SELECT ... FROM read_parquet('<path>')).",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": ro("List loaded captures"),
        }),
        json!({
            "name": "capture_overview",
            "title": "Capture overview",
            "description": "Headline numbers for one capture: packets, bytes, duration, hosts, protocol mix, severity counts, top talkers and ports, alert queue by band, the top five alerts, and analyst suppressions in effect.",
            "inputSchema": { "type": "object", "properties": { "capture": cap } },
            "annotations": ro("Capture overview"),
        }),
        json!({
            "name": "list_alerts",
            "title": "List alerts",
            "description": "The ranked triage queue (highest priority first). Each alert is one deduplicated story (attack chain, host incident or finding) with its priority 0-100, band, severity, actor and peer hosts, ATT&CK techniques and kill-chain stage. Use get_alert for the narrative, evidence and timeline.",
            "inputSchema": { "type": "object", "properties": {
                "capture": cap,
                "min_band": { "type": "string", "enum": ["info", "log", "review", "investigate", "act_now"], "description": "Only alerts at or above this band." },
                "host": { "type": "string", "description": "Only alerts that implicate this IP (actor, host list or peer)." },
                "limit": { "type": "integer", "minimum": 1, "maximum": 200, "description": "Default 20." },
                "offset": { "type": "integer", "minimum": 0 }
            } },
            "annotations": ro("List alerts"),
        }),
        json!({
            "name": "get_alert",
            "title": "Get alert",
            "description": "One alert in full: narrative, recommended action, the priority ledger, host and peer context, its member findings with evidence, and its cross-host incident timeline (first contact, DNS answers, downloads, detections, lateral hops), each timeline row with the packet scope that reproduces it.",
            "inputSchema": { "type": "object", "properties": {
                "capture": cap,
                "alert_id": { "type": "string", "description": "alert:... id from list_alerts." },
                "include_findings": { "type": "boolean", "description": "Default true." },
                "include_timeline": { "type": "boolean", "description": "Default true." }
            }, "required": ["alert_id"] },
            "annotations": ro("Get alert"),
        }),
        json!({
            "name": "get_playbook",
            "title": "Get hunt playbook",
            "description": "The guided hunt checklist for one alert: per alert type, the questions a senior analyst would answer in order, why each matters, what normal and bad look like, what the engine already found for it, and ready pivots filled in with this alert's hosts, ports, names and time window (SQL over the flow table, a flow filter, a capture filter with its packet scope). Work the steps with query_flows and get_packets.",
            "inputSchema": { "type": "object", "properties": {
                "capture": cap,
                "alert_id": { "type": "string", "description": "alert:... id from list_alerts." }
            }, "required": ["alert_id"] },
            "annotations": ro("Get hunt playbook"),
        }),
        json!({
            "name": "host_profile",
            "title": "Host profile",
            "description": "Everything known about one IP in a capture: threat score and its reasons, identity (MAC, DHCP hostname, DNS names), the alerts and findings that implicate it, TLS server posture, files it downloaded or served, and (when the flows Parquet is available) its traffic: flows, bytes, top peers and top destination ports.",
            "inputSchema": { "type": "object", "properties": {
                "capture": cap,
                "ip": { "type": "string" }
            }, "required": ["ip"] },
            "annotations": ro("Host profile"),
        }),
        json!({
            "name": "query_flows",
            "title": "Query flows",
            "description": "Filter, group, sort and limit the capture's flow table (one row per connection, initiator-oriented). Without group_by it returns flow rows with their flow_id (pass it to get_packets); with group_by it returns per-key aggregates (flows, bytes, packets, time span). Filters combine with AND.",
            "inputSchema": { "type": "object", "properties": flow_filter_props },
            "annotations": ro("Query flows"),
        }),
        json!({
            "name": "get_packets",
            "title": "Get packets",
            "description": "The packets of one flow, both directions, read from the original capture: timestamp, direction (c2s = initiator to responder), length, TCP flags, seq/ack and a payload preview (printable text with dots for other bytes, or hex). Use it to verify a claim against the bytes. Give flow_id (from query_flows) or the full 5-tuple.",
            "inputSchema": { "type": "object", "properties": {
                "capture": cap,
                "flow_id": { "type": "integer" },
                "src_ip": { "type": "string" },
                "dst_ip": { "type": "string" },
                "src_port": { "type": "integer" },
                "dst_port": { "type": "integer" },
                "proto": { "type": ["string", "integer"], "description": "tcp, udp, ... (with the 5-tuple)." },
                "since": { "type": "string", "description": "ISO-8601 UTC window start (default: the flow's start)." },
                "until": { "type": "string", "description": "ISO-8601 UTC window end (default: the flow's end)." },
                "limit": { "type": "integer", "minimum": 1, "maximum": MAX_PACKETS, "description": "Default 50." },
                "payload_bytes": { "type": "integer", "minimum": 0, "maximum": ppcap_core::packets::PAYLOAD_CAP_BYTES, "description": "Payload bytes shown per packet, default 128." },
                "payload_format": { "type": "string", "enum": ["text", "hex"], "description": "Default text." }
            } },
            "annotations": ro("Get packets"),
        }),
        json!({
            "name": "lookup_indicator",
            "title": "Look up indicator",
            "description": if s.opts.online {
                "Where an indicator (IP, domain, SHA-256, JA3/JA3S/HASSH MD5 or JA4/JA4S) appears across the loaded captures, whether the local threat feed lists it, and online reputation (AbuseIPDB, GreyNoise, VirusTotal) for public IPs and domains."
            } else {
                "Where an indicator (IP, domain, SHA-256, JA3/JA3S/HASSH MD5 or JA4/JA4S) appears across the loaded captures and whether the local threat feed lists it. Offline: nothing is sent anywhere."
            },
            "inputSchema": { "type": "object", "properties": {
                "value": { "type": "string" },
                "capture": { "type": "string", "description": "Only this capture (default: every loaded capture)." }
            }, "required": ["value"] },
            "annotations": { "title": "Look up indicator", "readOnlyHint": true, "openWorldHint": s.opts.online },
        }),
    ];

    if s.opts.allow_write.is_some() {
        tools.push(json!({
            "name": "carve_pcap",
            "title": "Carve pcap",
            "description": "Write the packets of one flow (flow_id), or of one host optionally narrowed to a peer and/or port, to a new classic pcap in the server's export directory, for Wireshark or a ticket. Returns the file path and packet count. Never overwrites a file.",
            "inputSchema": { "type": "object", "properties": {
                "capture": cap,
                "flow_id": { "type": "integer" },
                "host": { "type": "string" },
                "peer": { "type": "string" },
                "port": { "type": "integer" },
                "since": { "type": "string", "description": "ISO-8601 UTC (default: whole capture, or the flow's span)." },
                "until": { "type": "string" },
                "name": { "type": "string", "description": "File name stem (letters, digits, - and _). Default derived from the target." }
            } },
            "annotations": { "title": "Carve pcap", "readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": false },
        }));
    }
    tools
}

/// Dispatch one tool call.
pub fn call(s: &Server, name: &str, args: &Value) -> Result<Value, String> {
    match name {
        "list_captures" => Ok(list_captures(s)),
        "capture_overview" => capture_overview(pick(s, args)?),
        "list_alerts" => list_alerts(pick(s, args)?, args),
        "get_alert" => get_alert(pick(s, args)?, args),
        "get_playbook" => get_playbook(s, pick(s, args)?, args),
        "host_profile" => host_profile(pick(s, args)?, args),
        "query_flows" => {
            let c = pick(s, args)?;
            flows::query(need_flows(c)?, args)
        }
        "get_packets" => get_packets(pick(s, args)?, args),
        "lookup_indicator" => lookup_indicator(s, args),
        "carve_pcap" => carve(s, args),
        _ => Err(format!("unknown tool: {name}")),
    }
}

fn pick<'a>(s: &'a Server, args: &Value) -> Result<&'a Capture, String> {
    match args.get("capture").and_then(Value::as_str) {
        Some(id) if !id.is_empty() => s.captures.iter().find(|c| c.id == id).ok_or_else(|| {
            format!(
                "no capture {id:?}; loaded: {}",
                s.captures
                    .iter()
                    .map(|c| c.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }),
        _ => match s.captures.as_slice() {
            [only] => Ok(only),
            [] => Err("no captures are loaded".into()),
            many => Err(format!(
                "{} captures are loaded; pass capture (one of {})",
                many.len(),
                many.iter()
                    .map(|c| c.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        },
    }
}

fn need_flows(c: &Capture) -> Result<&std::path::Path, String> {
    c.flows.as_deref().ok_or_else(|| {
        format!(
            "capture {} has no flows Parquet on disk; re-run `ppcap analyze --parquet <file> \
             --json <summary>` or load the pcap itself",
            c.id
        )
    })
}

fn need_pcap(c: &Capture) -> Result<&std::path::Path, String> {
    c.pcap.as_deref().ok_or_else(|| {
        format!(
            "capture {}'s original pcap ({}) is not on disk here, so packets cannot be read",
            c.id, c.out.source_path
        )
    })
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn list_captures(s: &Server) -> Value {
    let rows: Vec<Value> = s
        .captures
        .iter()
        .map(|c| {
            let sm = &c.out.summary;
            json!({
                "id": c.id,
                "source_path": c.out.source_path,
                "source_sha256": c.out.source_sha256,
                "link_type": c.out.link_type,
                "first_packet": fmt_opt(sm.first_ts_ns),
                "last_packet": fmt_opt(sm.last_ts_ns),
                "packets": sm.total_packets,
                "bytes": sm.total_bytes,
                "flows": sm.total_flows,
                "hosts": sm.unique_hosts,
                "alerts": sm.alerts.len(),
                "findings": sm.findings.len(),
                "packets_available": c.pcap.is_some(),
                "flows_parquet": c.flows.as_ref().map(|p| p.display().to_string()),
            })
        })
        .collect();
    json!({
        "captures": rows,
        "flow_columns": ppcap_core::columnar::schema::flow_columns_in_order().to_vec(),
        "threat_feed": s.feed.as_ref().map(feed_label),
        "carve_dir": s.opts.allow_write.as_ref().map(|p| p.display().to_string()),
        "online_reputation": s.opts.online,
    })
}

/// The feed's own label, or what an unlabelled feed holds (without `--threat-feed`, only the
/// built-in malware fingerprints).
fn feed_label(f: &ppcap_core::ThreatFeed) -> String {
    if f.label().is_empty() {
        "built-in fingerprints".into()
    } else {
        f.label().to_string()
    }
}

fn alert_row(a: &Alert) -> Value {
    json!({
        "id": a.id,
        "band": a.band,
        "priority": a.priority,
        "severity": a.severity,
        "confidence": a.confidence,
        "title": a.title,
        "actor": a.actor,
        "peer": a.peer,
        "hosts": a.hosts,
        "host_count": a.host_count,
        "attack": a.attack,
        "stage": a.stage,
        "findings": a.finding_count,
        "first_seen": fmt_opt(a.first_seen_ns),
        "last_seen": fmt_opt(a.last_seen_ns),
    })
}

fn alert_touches(a: &Alert, ip: &str) -> bool {
    a.actor == ip
        || a.peer.as_deref() == Some(ip)
        || a.hosts.iter().any(|h| h == ip)
        || a.incident_hosts.iter().any(|h| h == ip)
}

fn finding_touches(f: &Finding, ip: &str) -> bool {
    f.src_ip == ip || f.dst_ip.as_deref() == Some(ip) || f.victims.iter().any(|v| v == ip)
}

fn finding_row(i: usize, f: &Finding) -> Value {
    json!({
        "index": i,
        "kind": f.kind,
        "severity": f.severity,
        "score": f.score,
        "title": f.title,
        "src_ip": f.src_ip,
        "dst_ip": f.dst_ip,
        "dst_port": f.dst_port,
        "attack": f.attack,
        "evidence": f.evidence.iter().take(MAX_EVIDENCE_LINES).collect::<Vec<_>>(),
        "victims": f.victims.iter().take(20).collect::<Vec<_>>(),
        "first_seen": fmt_opt(f.first_seen_ns),
        "last_seen": fmt_opt(f.last_seen_ns),
    })
}

fn capture_overview(c: &Capture) -> Result<Value, String> {
    let sm = &c.out.summary;
    let mut bands: BTreeMap<String, usize> = BTreeMap::new();
    for a in &sm.alerts {
        *bands.entry(a.band.as_str().to_string()).or_default() += 1;
    }
    let hidden = sm
        .suppressions
        .iter()
        .filter(|h| h.outcome == ppcap_core::SuppressionOutcome::Suppressed)
        .count();
    Ok(json!({
        "capture": c.id,
        "source_path": c.out.source_path,
        "first_packet": fmt_opt(sm.first_ts_ns),
        "last_packet": fmt_opt(sm.last_ts_ns),
        "duration_seconds": sm.duration_ns as f64 / 1e9,
        "packets": sm.total_packets,
        "bytes": sm.total_bytes,
        "flows": sm.total_flows,
        "hosts": sm.unique_hosts,
        "decode_errors": sm.decode_errors,
        "protocols": sm.proto,
        "protocol_hierarchy": sm.protocol_hierarchy.iter().take(10).collect::<Vec<_>>(),
        "flow_severity": sm.severity_counts,
        "top_talkers": sm.top_talkers.iter().take(10).collect::<Vec<_>>(),
        "top_ports": sm.port_histogram.iter().take(10).collect::<Vec<_>>(),
        "alerts_by_band": bands,
        "alerts": sm.alerts.len(),
        "top_alerts": sm.alerts.iter().take(5).map(alert_row).collect::<Vec<_>>(),
        "findings": sm.findings.len(),
        "carved_files": sm.carved_files.len(),
        "suppression_rules": sm.suppression_rules.len(),
        "findings_suppressed": hidden,
    }))
}

fn band_rank(s: &str) -> Option<u8> {
    ["info", "log", "review", "investigate", "act_now"]
        .iter()
        .position(|b| *b == s)
        .map(|p| p as u8)
}

fn list_alerts(c: &Capture, args: &Value) -> Result<Value, String> {
    let min = match str_arg(args, "min_band") {
        None => 0,
        Some(b) => band_rank(b).ok_or_else(|| {
            format!("min_band must be info, log, review, investigate or act_now, not {b:?}")
        })?,
    };
    let host = ip_arg(args, "host")?;
    let limit = u64_arg(args, "limit")?.unwrap_or(20).clamp(1, 200) as usize;
    let offset = u64_arg(args, "offset")?.unwrap_or(0) as usize;
    let keep: Vec<&Alert> = c
        .out
        .summary
        .alerts
        .iter()
        .filter(|a| band_rank(a.band.as_str()).unwrap_or(0) >= min)
        .filter(|a| host.as_deref().is_none_or(|h| alert_touches(a, h)))
        .collect();
    let page: Vec<Value> = keep
        .iter()
        .skip(offset)
        .take(limit)
        .map(|a| alert_row(a))
        .collect();
    Ok(json!({
        "capture": c.id,
        "total": keep.len(),
        "offset": offset,
        "returned": page.len(),
        "alerts": page,
    }))
}

fn get_alert(c: &Capture, args: &Value) -> Result<Value, String> {
    let id = str_arg(args, "alert_id").ok_or("alert_id is required")?;
    let sm = &c.out.summary;
    let alert = sm
        .alerts
        .iter()
        .find(|a| a.id == id || a.id.strip_prefix("alert:") == Some(id))
        .ok_or_else(|| format!("no alert {id} in capture {}; see list_alerts", c.id))?;
    let mut out = Map::new();
    out.insert("capture".into(), json!(c.id));
    out.insert("alert".into(), to_json(alert));
    if args.get("include_findings").and_then(Value::as_bool) != Some(false) {
        let rows: Vec<Value> = alert
            .finding_indices
            .iter()
            .take(MAX_FINDINGS_PER_ALERT)
            .filter_map(|&i| {
                sm.findings
                    .get(i as usize)
                    .map(|f| finding_row(i as usize, f))
            })
            .collect();
        out.insert("findings_total".into(), json!(alert.finding_indices.len()));
        out.insert("findings".into(), Value::Array(rows));
    }
    if args.get("include_timeline").and_then(Value::as_bool) != Some(false) {
        if let Some(t) = sm.timelines.iter().find(|t| t.alert_id == alert.id) {
            let mut t = t.clone();
            t.events.truncate(MAX_TIMELINE_EVENTS);
            out.insert("timeline".into(), to_json(&t));
        }
    }
    Ok(Value::Object(out))
}

fn get_playbook(s: &Server, c: &Capture, args: &Value) -> Result<Value, String> {
    let id = str_arg(args, "alert_id").ok_or("alert_id is required")?;
    let sm = &c.out.summary;
    let alert = sm
        .alerts
        .iter()
        .find(|a| a.id == id || a.id.strip_prefix("alert:") == Some(id))
        .ok_or_else(|| format!("no alert {id} in capture {}; see list_alerts", c.id))?;
    let builtin;
    let set = match &s.opts.playbooks {
        Some(set) => set,
        None => {
            builtin = ppcap_core::builtin_playbooks();
            &builtin
        }
    };
    let runs = ppcap_core::runs_for_alert(sm, alert, set);
    Ok(json!({
        "capture": c.id,
        "alert_id": alert.id,
        "playbooks": to_json(&runs),
    }))
}

fn host_profile(c: &Capture, args: &Value) -> Result<Value, String> {
    let ip = ip_arg(args, "ip")?.ok_or("ip is required")?;
    let sm: &Summary = &c.out.summary;
    let mut out = Map::new();
    out.insert("capture".into(), json!(c.id));
    out.insert("ip".into(), json!(ip));
    if let Ok(addr) = ip.parse::<IpAddr>() {
        out.insert(
            "ip_class".into(),
            json!(ppcap_core::classify_ip(addr).as_str()),
        );
    }
    out.insert(
        "threat".into(),
        sm.ip_threats
            .iter()
            .find(|t| t.ip == ip)
            .map(to_json)
            .unwrap_or(Value::Null),
    );
    out.insert("ioc_match".into(), json!(sm.ioc_ips.contains(&ip)));
    out.insert(
        "talker".into(),
        sm.top_talkers
            .iter()
            .find(|t| t.ip == ip)
            .map(to_json)
            .unwrap_or(Value::Null),
    );
    let macs: Vec<&str> = sm
        .arp_hosts
        .iter()
        .filter(|a| a.ip == ip)
        .map(|a| a.mac.as_str())
        .collect();
    let dhcp: Vec<Value> = sm
        .dhcp_hosts
        .iter()
        .filter(|d| macs.contains(&d.mac.as_str()))
        .map(to_json)
        .collect();
    out.insert("macs".into(), json!(macs));
    out.insert("dhcp".into(), json!(dhcp));
    let names: Vec<Value> = sm
        .resolved_ips
        .iter()
        .filter(|r| r.ip == ip)
        .take(25)
        .map(to_json)
        .collect();
    out.insert("dns_names".into(), json!(names));
    let looked_up: BTreeSet<&str> = sm
        .timeline_context
        .dns_answers
        .iter()
        .filter(|a| a.client.as_deref() == Some(ip.as_str()))
        .map(|a| a.domain.as_str())
        .take(50)
        .collect();
    out.insert("domains_resolved_by_host".into(), json!(looked_up));
    let alerts: Vec<Value> = sm
        .alerts
        .iter()
        .filter(|a| alert_touches(a, &ip))
        .take(25)
        .map(alert_row)
        .collect();
    out.insert("alerts".into(), json!(alerts));
    let findings: Vec<Value> = sm
        .findings
        .iter()
        .enumerate()
        .filter(|(_, f)| finding_touches(f, &ip))
        .take(25)
        .map(|(i, f)| finding_row(i, f))
        .collect();
    out.insert("findings".into(), json!(findings));
    let files: Vec<Value> = sm
        .carved_files
        .iter()
        .filter(|f| f.client == ip || f.server == ip)
        .take(25)
        .map(to_json)
        .collect();
    out.insert("carved_files".into(), json!(files));
    out.insert(
        "tls_server".into(),
        sm.tls_servers
            .iter()
            .find(|t| t.server == ip)
            .map(to_json)
            .unwrap_or(Value::Null),
    );
    out.insert(
        "encrypted_dns".into(),
        json!(sm.encrypted_dns.iter().any(|e| e.host == ip)),
    );

    match c.flows.as_deref() {
        None => {
            out.insert("traffic".into(), json!("flows Parquet not available"));
        }
        Some(path) => {
            let mut initiated = 0u64;
            let mut received = 0u64;
            let mut bytes_out = 0u64;
            let mut bytes_in = 0u64;
            let mut peers: HashMap<String, (u64, u64)> = HashMap::new();
            let mut ports: HashMap<(u16, u8), (u64, u64)> = HashMap::new();
            let (mut first, mut last) = (i64::MAX, i64::MIN);
            ppcap_core::columnar::scan_flows(path, |r| {
                let (peer, outb, inb) = if r.src_ip == ip {
                    initiated += 1;
                    let p = ports.entry((r.dst_port, r.proto)).or_default();
                    p.0 += 1;
                    p.1 = p.1.saturating_add(r.bytes());
                    (r.dst_ip.clone(), r.bytes_c2s, r.bytes_s2c)
                } else if r.dst_ip == ip {
                    received += 1;
                    (r.src_ip.clone(), r.bytes_s2c, r.bytes_c2s)
                } else {
                    return true;
                };
                bytes_out = bytes_out.saturating_add(outb);
                bytes_in = bytes_in.saturating_add(inb);
                first = first.min(r.start_ns);
                last = last.max(r.end_ns);
                if peers.len() < 100_000 || peers.contains_key(&peer) {
                    let e = peers.entry(peer).or_default();
                    e.0 += 1;
                    e.1 = e.1.saturating_add(outb).saturating_add(inb);
                }
                true
            })
            .map_err(|e| format!("reading flows: {e}"))?;
            let mut peers: Vec<_> = peers.into_iter().collect();
            peers.sort_by(|a, b| b.1 .1.cmp(&a.1 .1).then_with(|| a.0.cmp(&b.0)));
            let mut ports: Vec<_> = ports.into_iter().collect();
            ports.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then_with(|| a.0.cmp(&b.0)));
            out.insert(
                "traffic".into(),
                json!({
                    "flows_initiated": initiated,
                    "flows_received": received,
                    "bytes_sent": bytes_out,
                    "bytes_received": bytes_in,
                    "first_seen": if initiated + received > 0 { json!(fmt_ns(first)) } else { Value::Null },
                    "last_seen": if initiated + received > 0 { json!(fmt_ns(last)) } else { Value::Null },
                    "distinct_peers": peers.len(),
                    "top_peers": peers.iter().take(10).map(|(p, (n, b))| json!({ "ip": p, "flows": n, "bytes": b })).collect::<Vec<_>>(),
                    "top_dst_ports": ports.iter().take(10).map(|((port, proto), (n, b))| json!({ "port": port, "proto": flows::proto_name(*proto), "flows": n, "bytes": b })).collect::<Vec<_>>(),
                }),
            );
        }
    }
    Ok(Value::Object(out))
}

fn flag_names(f: u8) -> String {
    const NAMES: [(u8, &str); 8] = [
        (0x02, "SYN"),
        (0x10, "ACK"),
        (0x01, "FIN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x20, "URG"),
        (0x40, "ECE"),
        (0x80, "CWR"),
    ];
    NAMES
        .iter()
        .filter(|(bit, _)| f & bit != 0)
        .map(|(_, n)| *n)
        .collect::<Vec<_>>()
        .join(",")
}

fn printable(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| match b {
            b'\n' => '\n',
            b'\r' => '\r',
            b'\t' => '\t',
            0x20..=0x7e => b as char,
            _ => '.',
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The 5-tuple and window a packet tool targets, from `flow_id` or explicit fields.
struct FlowTarget {
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
    proto: u8,
    start_ns: i64,
    end_ns: i64,
}

fn parse_ip(s: &str, what: &str) -> Result<IpAddr, String> {
    s.parse()
        .map_err(|_| format!("{what} {s:?} is not an IP address"))
}

fn flow_target(c: &Capture, args: &Value) -> Result<FlowTarget, String> {
    let since = time_arg(args, "since")?;
    let until = time_arg(args, "until")?;
    if let Some(id) = u64_arg(args, "flow_id")? {
        let r = flows::find_flow(need_flows(c)?, id)?
            .ok_or_else(|| format!("no flow {id} in capture {}", c.id))?;
        return Ok(FlowTarget {
            src: parse_ip(&r.src_ip, "src_ip")?,
            dst: parse_ip(&r.dst_ip, "dst_ip")?,
            sport: r.src_port,
            dport: r.dst_port,
            proto: r.proto,
            start_ns: since.unwrap_or(r.start_ns),
            end_ns: until.unwrap_or(r.end_ns),
        });
    }
    let missing = || "give flow_id, or all of src_ip, dst_ip, src_port, dst_port and proto";
    let src = ip_arg(args, "src_ip")?.ok_or_else(missing)?;
    let dst = ip_arg(args, "dst_ip")?.ok_or_else(missing)?;
    let sm = &c.out.summary;
    Ok(FlowTarget {
        src: parse_ip(&src, "src_ip")?,
        dst: parse_ip(&dst, "dst_ip")?,
        sport: port_arg(args, "src_port")?.ok_or_else(missing)?,
        dport: port_arg(args, "dst_port")?.ok_or_else(missing)?,
        proto: proto_arg(args, "proto")?.ok_or_else(missing)?,
        start_ns: since.or(sm.first_ts_ns).unwrap_or(i64::MIN),
        end_ns: until.or(sm.last_ts_ns).unwrap_or(i64::MAX),
    })
}

fn get_packets(c: &Capture, args: &Value) -> Result<Value, String> {
    let pcap = need_pcap(c)?;
    let t = flow_target(c, args)?;
    let limit = u64_arg(args, "limit")?
        .map(|n| (n as usize).clamp(1, MAX_PACKETS))
        .unwrap_or(DEFAULT_PACKETS);
    let shown = u64_arg(args, "payload_bytes")?
        .map(|n| (n as usize).min(ppcap_core::packets::PAYLOAD_CAP_BYTES))
        .unwrap_or(DEFAULT_PAYLOAD_BYTES);
    let as_hex = match str_arg(args, "payload_format") {
        None | Some("text") => false,
        Some("hex") => true,
        Some(other) => return Err(format!("payload_format must be text or hex, not {other:?}")),
    };
    let q = ppcap_core::PacketQuery {
        src_ip: t.src,
        dst_ip: t.dst,
        src_port: t.sport,
        dst_port: t.dport,
        transport: Transport::from_ip_proto(t.proto),
        start_ns: t.start_ns,
        end_ns: t.end_ns,
    };
    let caps = ppcap_core::PacketCaps {
        max_packets: limit,
        payload_cap: shown.max(1),
    };
    let source = ppcap_core::reader::open(pcap).map_err(|e| e.to_string())?;
    let fp = ppcap_core::extract_flow_packets(source, &q, &caps).map_err(|e| e.to_string())?;
    let packets: Vec<Value> = fp
        .packets
        .iter()
        .map(|p| {
            let payload = base64::engine::general_purpose::STANDARD
                .decode(&p.payload_b64)
                .unwrap_or_default();
            let payload = &payload[..payload.len().min(shown)];
            let mut row = json!({
                "index": p.index,
                "ts": fmt_ns(p.ts_ns),
                "dir": p.direction,
                "len": p.wire_len,
                "payload_len": p.payload_len,
            });
            if t.proto == 6 {
                row["flags"] = json!(flag_names(p.tcp_flags));
                row["seq"] = json!(p.seq);
                row["ack"] = json!(p.ack);
            }
            if shown > 0 && !payload.is_empty() {
                row["payload"] = json!(if as_hex {
                    hex(payload)
                } else {
                    printable(payload)
                });
                if (p.payload_len as usize) > payload.len() {
                    row["payload_truncated"] = json!(true);
                }
            }
            row
        })
        .collect();
    Ok(json!({
        "capture": c.id,
        "flow": {
            "src_ip": t.src.to_string(),
            "dst_ip": t.dst.to_string(),
            "src_port": t.sport,
            "dst_port": t.dport,
            "proto": flows::proto_name(t.proto),
        },
        "window": { "start": fmt_ns(t.start_ns.max(0)), "end": fmt_ns(t.end_ns.min(i64::MAX / 2)) },
        "total_packets": fp.total,
        "returned": packets.len(),
        "truncated": fp.truncated,
        "packets": packets,
    }))
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum IndicatorKind {
    Ip,
    Sha256,
    Md5,
    Ja4,
    Domain,
}

fn classify_indicator(v: &str) -> Result<IndicatorKind, String> {
    if v.parse::<IpAddr>().is_ok() {
        return Ok(IndicatorKind::Ip);
    }
    let is_hex = |s: &str| s.bytes().all(|b| b.is_ascii_hexdigit());
    if v.len() == 64 && is_hex(v) {
        return Ok(IndicatorKind::Sha256);
    }
    if v.len() == 32 && is_hex(v) {
        return Ok(IndicatorKind::Md5);
    }
    // JA4 / JA4S: `t13d1516h2_8daaf6152771_e5627efa2ab1` / `t130200_1301_234ea6891581`.
    let parts: Vec<&str> = v.split('_').collect();
    if parts.len() == 3
        && matches!(v.as_bytes().first(), Some(b't' | b'q' | b'd'))
        && parts[1..].iter().all(|p| !p.is_empty() && is_hex(p))
    {
        return Ok(IndicatorKind::Ja4);
    }
    if v.contains('.') && !v.contains(char::is_whitespace) && !v.contains('/') {
        return Ok(IndicatorKind::Domain);
    }
    Err(format!(
        "cannot tell what {v:?} is; give an IP, a domain, a SHA-256, a JA3/JA3S/HASSH MD5 or a JA4/JA4S"
    ))
}

fn lookup_indicator(s: &Server, args: &Value) -> Result<Value, String> {
    let raw = str_arg(args, "value").ok_or("value is required")?;
    let kind = classify_indicator(raw)?;
    let value = match kind {
        IndicatorKind::Ip => raw
            .parse::<IpAddr>()
            .map(|ip| ip.to_canonical().to_string())
            .unwrap_or_else(|_| raw.to_string()),
        _ => raw.trim_end_matches('.').to_ascii_lowercase(),
    };
    let scope: Vec<&Capture> = match str_arg(args, "capture") {
        Some(_) => vec![pick(s, args)?],
        None => s.captures.iter().collect(),
    };

    let mut per_capture = Vec::new();
    for c in scope {
        let sm = &c.out.summary;
        let mut hit = Map::new();
        match kind {
            IndicatorKind::Ip => {
                if let Some(t) = sm.ip_threats.iter().find(|t| t.ip == value) {
                    hit.insert("threat".into(), to_json(t));
                }
                let names: Vec<&str> = sm
                    .resolved_ips
                    .iter()
                    .filter(|r| r.ip == value)
                    .map(|r| r.domain.as_str())
                    .collect();
                if !names.is_empty() {
                    hit.insert("dns_names".into(), json!(names));
                }
                let alerts: Vec<&str> = sm
                    .alerts
                    .iter()
                    .filter(|a| alert_touches(a, &value))
                    .map(|a| a.id.as_str())
                    .collect();
                if !alerts.is_empty() {
                    hit.insert("alerts".into(), json!(alerts));
                }
                let n = sm
                    .findings
                    .iter()
                    .filter(|f| finding_touches(f, &value))
                    .count();
                if n > 0 {
                    hit.insert("findings".into(), json!(n));
                }
            }
            IndicatorKind::Domain => {
                let ips: BTreeSet<&str> = sm
                    .resolved_ips
                    .iter()
                    .filter(|r| r.domain.trim_end_matches('.').eq_ignore_ascii_case(&value))
                    .map(|r| r.ip.as_str())
                    .collect();
                if !ips.is_empty() {
                    hit.insert("resolved_to".into(), json!(ips));
                }
                if let Some(d) = sm
                    .domain_threats
                    .iter()
                    .find(|d| d.host.eq_ignore_ascii_case(&value))
                {
                    hit.insert("tls_sni".into(), to_json(d));
                }
                if let Some(h) = sm
                    .http_hosts
                    .iter()
                    .find(|h| h.host.eq_ignore_ascii_case(&value))
                {
                    hit.insert("http_host".into(), to_json(h));
                }
            }
            IndicatorKind::Sha256 => {
                let files: Vec<Value> = sm
                    .carved_files
                    .iter()
                    .filter(|f| f.sha256.eq_ignore_ascii_case(&value))
                    .map(to_json)
                    .collect();
                if !files.is_empty() {
                    hit.insert("carved_files".into(), json!(files));
                }
            }
            IndicatorKind::Md5 | IndicatorKind::Ja4 => {}
        }
        // Flow-level presence: every kind but a file hash can be matched on the flow table.
        if kind != IndicatorKind::Sha256 {
            if let Some(path) = c.flows.as_deref() {
                let (mut n, mut bytes) = (0u64, 0u64);
                let mut hosts: BTreeSet<String> = BTreeSet::new();
                ppcap_core::columnar::scan_flows(path, |r| {
                    let lc = |o: &Option<String>| {
                        o.as_deref()
                            .is_some_and(|x| x.trim_end_matches('.').eq_ignore_ascii_case(&value))
                    };
                    let m = match kind {
                        IndicatorKind::Ip => r.src_ip == value || r.dst_ip == value,
                        IndicatorKind::Domain => lc(&r.sni) || lc(&r.http_host),
                        IndicatorKind::Md5 => {
                            lc(&r.ja3) || lc(&r.ja3s) || lc(&r.hassh) || lc(&r.hassh_server)
                        }
                        IndicatorKind::Ja4 => lc(&r.ja4) || lc(&r.ja4s),
                        IndicatorKind::Sha256 => false,
                    };
                    if m {
                        n += 1;
                        bytes = bytes.saturating_add(r.bytes());
                        if hosts.len() < 25 {
                            hosts.insert(r.src_ip.clone());
                        }
                    }
                    true
                })
                .map_err(|e| format!("reading flows: {e}"))?;
                if n > 0 {
                    hit.insert(
                        "flows".into(),
                        json!({ "count": n, "bytes": bytes, "initiators": hosts }),
                    );
                }
            }
        }
        per_capture.push(json!({ "capture": c.id, "seen": !hit.is_empty(), "matches": hit }));
    }

    let feed = s.feed.as_ref().map(|f| {
        let listed = match kind {
            IndicatorKind::Ip => value.parse().map(|ip| f.matches_ip(ip)).unwrap_or(false),
            IndicatorKind::Domain => f.matches_domain(&value),
            IndicatorKind::Md5 => {
                f.matches_ja3(&value) || f.matches_hassh(&value) || f.matches_hassh_server(&value)
            }
            IndicatorKind::Ja4 => f.matches_ja4(&value) || f.matches_ja4s(&value),
            IndicatorKind::Sha256 => false,
        };
        let family = match kind {
            IndicatorKind::Md5 => f
                .fingerprint_label(Some(&value), None)
                .or_else(|| f.hassh_label(&value)),
            IndicatorKind::Ja4 => f
                .fingerprint_label(None, Some(&value))
                .or_else(|| f.ja4s_label(&value)),
            _ => None,
        };
        json!({ "feed": feed_label(f), "listed": listed, "family": family })
    });

    let mut out = json!({
        "value": value,
        "kind": format!("{kind:?}").to_lowercase(),
        "captures": per_capture,
        "threat_feed": feed,
    });
    if s.opts.online {
        out["reputation"] = online_reputation(kind, &value);
    }
    Ok(out)
}

#[cfg(not(test))]
fn online_reputation(kind: IndicatorKind, value: &str) -> Value {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let keys = ppcap_core::ReputationKeys {
        abuseipdb: env("ABUSEIPDB_API_KEY"),
        greynoise: env("GREYNOISE_API_KEY"),
        virustotal: env("VIRUSTOTAL_API_KEY"),
    };
    if keys.is_empty() {
        return json!(
            "no provider key set (ABUSEIPDB_API_KEY / GREYNOISE_API_KEY / VIRUSTOTAL_API_KEY)"
        );
    }
    let cache_dir = dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("packetpilot");
    let now = crate::cli::unix_now();
    match kind {
        IndicatorKind::Ip => {
            let Ok(ip) = value.parse::<IpAddr>() else {
                return Value::Null;
            };
            if !ppcap_core::classify_ip(ip).is_external() {
                return json!("not a public IP; nothing to look up");
            }
            let v = ppcap_core::lookup_reputation_native(&[ip], &keys, &cache_dir, now);
            json!(v.get(value).cloned().unwrap_or_default())
        }
        IndicatorKind::Domain => {
            let v = ppcap_core::lookup_domain_reputation_native(
                &[value.to_string()],
                &keys,
                &cache_dir,
                now,
            );
            json!(v.get(value).cloned().unwrap_or_default())
        }
        _ => json!("online reputation covers IPs and domains only"),
    }
}

// Tests never touch the network.
#[cfg(test)]
fn online_reputation(_kind: IndicatorKind, _value: &str) -> Value {
    json!("online lookups are disabled in tests")
}

fn safe_stem(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(80)
        .collect()
}

fn carve(s: &Server, args: &Value) -> Result<Value, String> {
    let dir: PathBuf = s
        .opts
        .allow_write
        .clone()
        .ok_or("carving is disabled; start the server with --allow-write <DIR>")?;
    let c = pick(s, args)?;
    let pcap = need_pcap(c)?;
    let since = time_arg(args, "since")?;
    let until = time_arg(args, "until")?;
    let sm = &c.out.summary;
    let (target, start_ns, end_ns, label) = if u64_arg(args, "flow_id")?.is_some() {
        let t = flow_target(c, args)?;
        (
            ppcap_core::CarveTarget::Flow {
                src_ip: t.src,
                dst_ip: t.dst,
                src_port: t.sport,
                dst_port: t.dport,
                transport: Transport::from_ip_proto(t.proto),
            },
            t.start_ns,
            t.end_ns,
            format!("flow{}", u64_arg(args, "flow_id")?.unwrap_or(0)),
        )
    } else {
        let host =
            ip_arg(args, "host")?.ok_or("give flow_id, or host (optionally with peer and port)")?;
        let peer = ip_arg(args, "peer")?;
        let port = port_arg(args, "port")?;
        let host_ip = parse_ip(&host, "host")?;
        let peer_ip = peer.as_deref().map(|p| parse_ip(p, "peer")).transpose()?;
        let mut label = host.clone();
        if let Some(p) = &peer {
            label.push_str(&format!("-{p}"));
        }
        if let Some(p) = port {
            label.push_str(&format!("-{p}"));
        }
        let target = if peer_ip.is_none() && port.is_none() {
            ppcap_core::CarveTarget::Host { ip: host_ip }
        } else {
            ppcap_core::CarveTarget::Scope {
                host: host_ip,
                peer: peer_ip,
                port,
            }
        };
        (
            target,
            since.or(sm.first_ts_ns).unwrap_or(i64::MIN),
            until.or(sm.last_ts_ns).unwrap_or(i64::MAX),
            label,
        )
    };
    let stem = safe_stem(str_arg(args, "name").unwrap_or(&format!("{}-{label}", c.id)));
    if stem.is_empty() {
        return Err("name must contain letters or digits".into());
    }
    let mut path = dir.join(format!("{stem}.pcap"));
    let mut n = 2;
    while path.exists() {
        path = dir.join(format!("{stem}-{n}.pcap"));
        n += 1;
    }
    let q = ppcap_core::CarveQuery {
        target,
        start_ns,
        end_ns,
    };
    let caps = ppcap_core::PacketCaps {
        max_packets: MAX_CARVE_PACKETS,
        ..Default::default()
    };
    let source = ppcap_core::reader::open(pcap).map_err(|e| e.to_string())?;
    let res = ppcap_core::carve_pcap(source, &q, &caps).map_err(|e| e.to_string())?;
    // create_new: never clobber a file that appeared between the check above and now.
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    f.write_all(&res.pcap)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(json!({
        "path": path.display().to_string(),
        "packets": res.packets,
        "bytes": res.pcap.len(),
        "truncated": res.truncated,
        "sha256": ppcap_core::sha256_hex(&res.pcap),
    }))
}

/// MCP prompts: one guided investigation, so agents follow the same order an analyst would.
pub fn prompt_definitions() -> Vec<Value> {
    vec![json!({
        "name": "triage",
        "title": "Triage a capture",
        "description": "Step-by-step investigation of a loaded capture: queue, top alerts, evidence checks against flows and packets, and a hand-off summary.",
        "arguments": [
            { "name": "capture", "description": "Capture id (optional when one is loaded).", "required": false },
            { "name": "focus", "description": "A host, alert id or question to centre the investigation on.", "required": false }
        ]
    })]
}

pub fn get_prompt(s: &Server, params: &Value) -> Result<Value, String> {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    if name != "triage" {
        return Err(format!("unknown prompt: {name}"));
    }
    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    let capture = str_arg(&args, "capture")
        .map(str::to_string)
        .or_else(|| (s.captures.len() == 1).then(|| s.captures[0].id.clone()))
        .unwrap_or_else(|| "<pick one from list_captures>".into());
    let focus = str_arg(&args, "focus")
        .map(|f| format!("\n\nCentre the investigation on: {f}."))
        .unwrap_or_default();
    let text = format!(
        "You are triaging network capture `{capture}` with PacketPilot's tools. Work in this order:\n\
         1. capture_overview: note the time span, protocol mix and how many alerts are in each band.\n\
         2. list_alerts with min_band \"review\": the queue is already ranked and deduplicated, so \
            work top-down rather than re-ranking.\n\
         3. For each of the top alerts (at most five): get_alert, then host_profile for its actor \
            and peer, then get_playbook and answer its steps in order.\n\
         4. Verify before you claim. For each key claim (beacon interval, data volume, a file \
            download, a credential or command), find the flows with query_flows and read the bytes \
            with get_packets. Say which flow_id backs each claim; if the packets do not support the \
            alert, say it looks like a false positive and why.\n\
         5. lookup_indicator for each external IP, domain or file hash you will report.\n\
         6. Finish with a hand-off: per alert, a verdict (true positive / benign / needs more data), \
            the evidence (flow ids, times in UTC), affected hosts, and the next action. Do not \
            invent indicators that no tool returned.{focus}"
    );
    Ok(json!({
        "description": "Triage a capture with PacketPilot",
        "messages": [{ "role": "user", "content": { "type": "text", "text": text } }]
    }))
}
