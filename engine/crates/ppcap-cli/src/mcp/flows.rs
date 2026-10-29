//! `query_flows`: filter / group / sort / limit over the flows Parquet, streamed batch by batch.
//!
//! The engine is DuckDB-free by design, so instead of SQL the agent gets a structured query that
//! covers what triage asks of the flow table: "every flow from this host", "top destinations by
//! bytes", "what talked on 4444". Memory stays bounded: ungrouped results keep only a pruned
//! top-N, and grouping stops opening new groups past [`MAX_GROUPS`].

use std::collections::HashMap;
use std::path::Path;

use ppcap_core::columnar::FlowRow;
use ppcap_core::{Severity, Transport};
use serde_json::{json, Map, Value};

use super::time::{fmt_ns, parse_time};

/// Hard ceiling on rows (or groups) one query returns.
pub const MAX_LIMIT: usize = 500;
const DEFAULT_LIMIT: usize = 25;
/// Distinct groups tracked before new keys are dropped (the result then says so).
const MAX_GROUPS: usize = 200_000;

/// Which flows a query (or a host profile) keeps.
#[derive(Default, Debug, Clone)]
pub struct FlowFilter {
    pub flow_id: Option<u64>,
    /// Either endpoint.
    pub ip: Option<String>,
    /// The other endpoint, with `ip`.
    pub peer: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    /// Either port.
    pub port: Option<u16>,
    pub dst_port: Option<u16>,
    pub proto: Option<u8>,
    pub app_proto: Option<String>,
    pub category: Option<String>,
    pub min_severity: Option<Severity>,
    pub ioc: Option<bool>,
    /// Case-insensitive substring of SNI, HTTP host or user agent.
    pub text: Option<String>,
    pub since_ns: Option<i64>,
    pub until_ns: Option<i64>,
    pub min_bytes: Option<u64>,
}

fn str_arg(args: &Value, key: &str) -> Result<Option<String>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.trim().to_string())),
        Some(_) => Err(format!("{key} must be a string")),
    }
}

/// An IP argument, canonicalised the way the Parquet stores it (so `::ffff:10.0.0.1` or
/// leading zeros cannot silently miss).
pub fn ip_arg(args: &Value, key: &str) -> Result<Option<String>, String> {
    match str_arg(args, key)? {
        None => Ok(None),
        Some(s) => s
            .parse::<std::net::IpAddr>()
            .map(|ip| Some(ip.to_canonical().to_string()))
            .map_err(|_| format!("{key} is not an IP address: {s:?}")),
    }
}

pub fn u64_arg(args: &Value, key: &str) -> Result<Option<u64>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("{key} must be a non-negative integer")),
    }
}

pub fn port_arg(args: &Value, key: &str) -> Result<Option<u16>, String> {
    match u64_arg(args, key)? {
        None => Ok(None),
        Some(n) => u16::try_from(n)
            .map(Some)
            .map_err(|_| format!("{key} must be 0..=65535")),
    }
}

fn bool_arg(args: &Value, key: &str) -> Result<Option<bool>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(format!("{key} must be true or false")),
    }
}

pub fn time_arg(args: &Value, key: &str) -> Result<Option<i64>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => parse_time(v).map(Some).map_err(|e| format!("{key}: {e}")),
    }
}

/// `tcp` / `udp` / `icmp` / `icmpv6` / `sctp` or an IANA protocol number.
pub fn proto_arg(args: &Value, key: &str) -> Result<Option<u8>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|n| u8::try_from(n).ok())
            .map(Some)
            .ok_or_else(|| format!("{key} must be 0..=255")),
        Some(Value::String(s)) => match s.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Some(6)),
            "udp" => Ok(Some(17)),
            "icmp" => Ok(Some(1)),
            "icmpv6" => Ok(Some(58)),
            "sctp" => Ok(Some(132)),
            other => other.parse().map(Some).map_err(|_| {
                format!("unknown {key} {s:?}; use tcp, udp, icmp, icmpv6, sctp or a number")
            }),
        },
        Some(_) => Err(format!("{key} must be a protocol name or number")),
    }
}

pub fn limit_arg(args: &Value) -> Result<usize, String> {
    Ok(u64_arg(args, "limit")?
        .map(|n| (n as usize).clamp(1, MAX_LIMIT))
        .unwrap_or(DEFAULT_LIMIT))
}

impl FlowFilter {
    pub fn from_args(args: &Value) -> Result<FlowFilter, String> {
        let min_severity = match str_arg(args, "min_severity")? {
            None => None,
            Some(s) => Some(
                Severity::from_str_opt(&s.to_ascii_lowercase()).ok_or_else(|| {
                    format!("min_severity must be info, low, medium, high or critical, not {s:?}")
                })?,
            ),
        };
        let f = FlowFilter {
            flow_id: u64_arg(args, "flow_id")?,
            ip: ip_arg(args, "ip")?,
            peer: ip_arg(args, "peer")?,
            src_ip: ip_arg(args, "src_ip")?,
            dst_ip: ip_arg(args, "dst_ip")?,
            port: port_arg(args, "port")?,
            dst_port: port_arg(args, "dst_port")?,
            proto: proto_arg(args, "proto")?,
            app_proto: str_arg(args, "app_proto")?.map(|s| s.to_ascii_lowercase()),
            category: str_arg(args, "category")?.map(|s| s.to_ascii_lowercase()),
            min_severity,
            ioc: bool_arg(args, "ioc")?,
            text: str_arg(args, "text")?.map(|s| s.to_ascii_lowercase()),
            since_ns: time_arg(args, "since")?,
            until_ns: time_arg(args, "until")?,
            min_bytes: u64_arg(args, "min_bytes")?,
        };
        if f.peer.is_some() && f.ip.is_none() {
            return Err("peer narrows ip; pass ip too".into());
        }
        Ok(f)
    }

    pub fn matches(&self, r: &FlowRow) -> bool {
        if self.flow_id.is_some_and(|id| id != r.flow_id) {
            return false;
        }
        if let Some(ip) = &self.ip {
            let other = if &r.src_ip == ip {
                &r.dst_ip
            } else if &r.dst_ip == ip {
                &r.src_ip
            } else {
                return false;
            };
            if self.peer.as_ref().is_some_and(|p| p != other) {
                return false;
            }
        }
        if self.src_ip.as_ref().is_some_and(|s| s != &r.src_ip)
            || self.dst_ip.as_ref().is_some_and(|d| d != &r.dst_ip)
            || self
                .port
                .is_some_and(|p| p != r.src_port && p != r.dst_port)
            || self.dst_port.is_some_and(|p| p != r.dst_port)
            || self.proto.is_some_and(|p| p != r.proto)
            || self.ioc.is_some_and(|b| b != r.ioc)
            || self.min_bytes.is_some_and(|b| r.bytes() < b)
            || self.since_ns.is_some_and(|t| r.end_ns < t)
            || self.until_ns.is_some_and(|t| r.start_ns > t)
        {
            return false;
        }
        if let Some(a) = &self.app_proto {
            if r.app_proto.as_deref() != Some(a.as_str()) {
                return false;
            }
        }
        if self.category.as_ref().is_some_and(|c| c != &r.category) {
            return false;
        }
        if let Some(min) = self.min_severity {
            if Severity::from_str_opt(&r.severity).unwrap_or_default() < min {
                return false;
            }
        }
        if let Some(t) = &self.text {
            let hit = [&r.sni, &r.http_host, &r.http_ua].iter().any(|f| {
                f.as_ref()
                    .is_some_and(|s| s.to_ascii_lowercase().contains(t))
            });
            if !hit {
                return false;
            }
        }
        true
    }
}

pub fn proto_name(p: u8) -> &'static str {
    Transport::from_ip_proto(p).as_str()
}

/// One flow row as an agent reads it: ISO times, a protocol name, total bytes.
pub fn row_json(r: &FlowRow) -> Value {
    let mut v = serde_json::to_value(r).unwrap_or(Value::Null);
    if let Value::Object(m) = &mut v {
        m.remove("start_ns");
        m.remove("end_ns");
        m.insert("proto".into(), json!(proto_name(r.proto)));
        m.insert("start".into(), json!(fmt_ns(r.start_ns)));
        m.insert("end".into(), json!(fmt_ns(r.end_ns)));
        m.insert("bytes".into(), json!(r.bytes()));
    }
    v
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum GroupBy {
    SrcIp,
    DstIp,
    DstPort,
    Pair,
    AppProto,
    Category,
    Severity,
    Sni,
    HttpHost,
    HttpUa,
    Ja3,
    Ja4,
}

impl GroupBy {
    const ALL: &'static [(&'static str, GroupBy)] = &[
        ("src_ip", GroupBy::SrcIp),
        ("dst_ip", GroupBy::DstIp),
        ("dst_port", GroupBy::DstPort),
        ("pair", GroupBy::Pair),
        ("app_proto", GroupBy::AppProto),
        ("category", GroupBy::Category),
        ("severity", GroupBy::Severity),
        ("sni", GroupBy::Sni),
        ("http_host", GroupBy::HttpHost),
        ("http_ua", GroupBy::HttpUa),
        ("ja3", GroupBy::Ja3),
        ("ja4", GroupBy::Ja4),
    ];

    fn key(self, r: &FlowRow) -> Option<String> {
        Some(match self {
            GroupBy::SrcIp => r.src_ip.clone(),
            GroupBy::DstIp => r.dst_ip.clone(),
            GroupBy::DstPort => format!("{}/{}", r.dst_port, proto_name(r.proto).to_lowercase()),
            GroupBy::Pair => format!("{} -> {}", r.src_ip, r.dst_ip),
            GroupBy::AppProto => r.app_proto.clone().unwrap_or_else(|| "unknown".into()),
            GroupBy::Category => r.category.clone(),
            GroupBy::Severity => r.severity.clone(),
            GroupBy::Sni => r.sni.clone()?,
            GroupBy::HttpHost => r.http_host.clone()?,
            GroupBy::HttpUa => r.http_ua.clone()?,
            GroupBy::Ja3 => r.ja3.clone()?,
            GroupBy::Ja4 => r.ja4.clone()?,
        })
    }
}

pub const GROUP_BY_NAMES: &[&str] = &[
    "src_ip",
    "dst_ip",
    "dst_port",
    "pair",
    "app_proto",
    "category",
    "severity",
    "sni",
    "http_host",
    "http_ua",
    "ja3",
    "ja4",
];
pub const SORT_NAMES: &[&str] = &[
    "bytes",
    "pkts",
    "flows",
    "start",
    "threat_score",
    "duration",
];

#[derive(Default)]
struct Agg {
    flows: u64,
    bytes: u64,
    pkts: u64,
    first: i64,
    last: i64,
    max_score: u16,
    ioc: bool,
}

fn row_sort_key(sort: &str, r: &FlowRow) -> i128 {
    match sort {
        "pkts" => r.pkts as i128,
        // Earliest first reads naturally for "start"; negate so one descending sort serves all.
        "start" => -(r.start_ns as i128),
        "threat_score" => r.threat_score as i128,
        "duration" => (r.end_ns as i128) - (r.start_ns as i128),
        _ => r.bytes() as i128,
    }
}

fn agg_sort_key(sort: &str, a: &Agg) -> i128 {
    match sort {
        "pkts" => a.pkts as i128,
        "flows" => a.flows as i128,
        "start" => -(a.first as i128),
        "threat_score" => a.max_score as i128,
        "duration" => (a.last as i128) - (a.first as i128),
        _ => a.bytes as i128,
    }
}

/// Run a `query_flows` call against the Parquet at `path`.
pub fn query(path: &Path, args: &Value) -> Result<Value, String> {
    let filter = FlowFilter::from_args(args)?;
    let limit = limit_arg(args)?;
    let sort = str_arg(args, "sort")?.unwrap_or_else(|| "bytes".into());
    if !SORT_NAMES.contains(&sort.as_str()) {
        return Err(format!("sort must be one of {}", SORT_NAMES.join(", ")));
    }
    let group = match str_arg(args, "group_by")? {
        None => None,
        Some(g) => Some(
            GroupBy::ALL
                .iter()
                .find(|(n, _)| *n == g)
                .map(|(_, v)| *v)
                .ok_or_else(|| format!("group_by must be one of {}", GROUP_BY_NAMES.join(", ")))?,
        ),
    };
    if group.is_none() && sort == "flows" {
        return Err("sort by flows needs group_by".into());
    }

    let mut matched: u64 = 0;
    let mut matched_bytes: u64 = 0;
    let mut rows: Vec<FlowRow> = Vec::new();
    let mut groups: HashMap<String, Agg> = HashMap::new();
    let mut groups_truncated = false;
    let scanned = ppcap_core::columnar::scan_flows(path, |r| {
        if !filter.matches(&r) {
            return true;
        }
        matched += 1;
        matched_bytes = matched_bytes.saturating_add(r.bytes());
        match group {
            None => {
                rows.push(r);
                // Prune to the running top-N so a million-flow file stays small in memory.
                if rows.len() >= limit * 4 + 1024 {
                    rows.sort_by_key(|r| std::cmp::Reverse(row_sort_key(&sort, r)));
                    rows.truncate(limit);
                }
            }
            Some(g) => {
                let Some(k) = g.key(&r) else { return true };
                if !groups.contains_key(&k) && groups.len() >= MAX_GROUPS {
                    groups_truncated = true;
                    return true;
                }
                let a = groups.entry(k).or_insert_with(|| Agg {
                    first: i64::MAX,
                    last: i64::MIN,
                    ..Default::default()
                });
                a.flows += 1;
                a.bytes = a.bytes.saturating_add(r.bytes());
                a.pkts = a.pkts.saturating_add(r.pkts);
                a.first = a.first.min(r.start_ns);
                a.last = a.last.max(r.end_ns);
                a.max_score = a.max_score.max(r.threat_score);
                a.ioc |= r.ioc;
            }
        }
        true
    })
    .map_err(|e| format!("reading flows: {e}"))?;

    let mut out = Map::new();
    out.insert("flows_scanned".into(), json!(scanned));
    out.insert("flows_matched".into(), json!(matched));
    out.insert("bytes_matched".into(), json!(matched_bytes));
    out.insert("sort".into(), json!(sort));
    match group {
        None => {
            rows.sort_by_key(|r| std::cmp::Reverse(row_sort_key(&sort, r)));
            rows.truncate(limit);
            out.insert("returned".into(), json!(rows.len()));
            out.insert("flows".into(), rows.iter().map(row_json).collect());
        }
        Some(g) => {
            let name = GroupBy::ALL.iter().find(|(_, v)| *v == g).map(|(n, _)| *n);
            let mut list: Vec<(String, Agg)> = groups.into_iter().collect();
            out.insert("groups_total".into(), json!(list.len()));
            list.sort_by(|a, b| {
                agg_sort_key(&sort, &b.1)
                    .cmp(&agg_sort_key(&sort, &a.1))
                    .then_with(|| a.0.cmp(&b.0))
            });
            list.truncate(limit);
            out.insert("group_by".into(), json!(name));
            out.insert("returned".into(), json!(list.len()));
            if groups_truncated {
                out.insert(
                    "groups_truncated".into(),
                    json!(format!("more than {MAX_GROUPS} groups; filter to narrow")),
                );
            }
            out.insert(
                "groups".into(),
                list.into_iter()
                    .map(|(k, a)| {
                        json!({
                            "key": k,
                            "flows": a.flows,
                            "bytes": a.bytes,
                            "pkts": a.pkts,
                            "first": fmt_ns(a.first),
                            "last": fmt_ns(a.last),
                            "max_threat_score": a.max_score,
                            "ioc": a.ioc,
                        })
                    })
                    .collect(),
            );
        }
    }
    Ok(Value::Object(out))
}

/// The first flow matching `id` (for tools that take a `flow_id`).
pub fn find_flow(path: &Path, id: u64) -> Result<Option<FlowRow>, String> {
    let mut found = None;
    ppcap_core::columnar::scan_flows(path, |r| {
        if r.flow_id == id {
            found = Some(r);
            false
        } else {
            true
        }
    })
    .map_err(|e| format!("reading flows: {e}"))?;
    Ok(found)
}
