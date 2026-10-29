//! Zeek-compatible logs from one analysis pass: `conn`, `dns`, `http`, `ssl`, `ssh`, `files` and a
//! `notice` log carrying PacketPilot's findings.
//!
//! [`ZeekLogger`] is a [`CaptureVisitor`]: it rides the normal analysis pass
//! ([`crate::run_source_observing`]), parses DNS messages and HTTP request/status lines from the
//! packets it is shown, and writes one `conn` row per finalized flow. Every row about the same
//! connection carries the same `uid`, derived deterministically from the flow's 5-tuple and opening
//! time, so the same capture always yields the same uids and SIEM pivots work as with real Zeek.
//!
//! Output is Zeek's tab-separated format with its `#fields`/`#types` header, or Zeek's JSON
//! format (one object per line, unset fields omitted). The `#open`/`#close` times come from the
//! caller: the engine has no clock.
//!
//! What is approximated, by design (no TCP reassembly beyond one segment):
//! - `history` is not tracked; `conn_state` comes from the sticky TCP flags of each direction.
//! - HTTP is parsed from the segment holding the request or status line, so body lengths are
//!   the declared `Content-Length`.
//! - A DNS-over-TCP message must fit its segment.
//!
//! Memory stays bounded: per-flow state lives only while the flow is open, with capped queues.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use crate::analyze::{CaptureVisitor, PacketView};
use crate::model::flow::{Direction, FlowKey, FlowRecord};
use crate::model::output::AnalysisOutput;
use crate::model::packet::Transport;

/// Pending DNS queries kept per flow while waiting for their answers.
const MAX_DNS_PENDING_PER_FLOW: usize = 256;
/// Pending HTTP requests kept per flow while waiting for their responses.
const MAX_HTTP_PENDING_PER_FLOW: usize = 64;
/// HTTP responses remembered to give carved files their connection uid.
const MAX_HTTP_RESPONSES: usize = 65_536;
/// Longest captured string field (URI, header, banner), in bytes; longer values are cut.
const MAX_FIELD: usize = 1024;

/// Log text format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeekFormat {
    /// Zeek's default tab-separated format with `#`-prefixed header lines.
    Tsv,
    /// Zeek's JSON format (`LogAscii::use_json`): one object per line, epoch-seconds `ts`.
    Json,
}

/// Where the logs go: one stream per log path (`conn`, `dns`, ...). The CLI writes files.
pub trait LogSink {
    fn write(&mut self, log: &str, bytes: &[u8]) -> std::io::Result<()>;
}

/// In-memory sink, used by tests and by callers that want the text.
#[derive(Debug, Default)]
pub struct MemorySink {
    pub logs: std::collections::BTreeMap<String, Vec<u8>>,
}

impl MemorySink {
    /// The text of one log, `""` when it was never written.
    pub fn text(&self, log: &str) -> String {
        self.logs
            .get(log)
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default()
    }
}

impl LogSink for MemorySink {
    fn write(&mut self, log: &str, bytes: &[u8]) -> std::io::Result<()> {
        self.logs
            .entry(log.to_string())
            .or_default()
            .extend_from_slice(bytes);
        Ok(())
    }
}

/// How many rows each log got.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct ZeekReport {
    /// `(log path, rows)` for every log that got at least one row, in write order.
    pub logs: Vec<(String, u64)>,
}

/// One field value. `Unset` is Zeek's `-`.
#[derive(Debug, Clone)]
enum Val {
    Time(i64),
    Interval(i64),
    Str(String),
    Addr(IpAddr),
    Port(u16),
    Count(u64),
    Bool(bool),
    /// `set[...]` or `vector[...]` of strings (rendered the same way).
    List(Vec<String>),
    Unset,
}

type Schema = &'static [(&'static str, &'static str)];

const ID: [(&str, &str); 4] = [
    ("id.orig_h", "addr"),
    ("id.orig_p", "port"),
    ("id.resp_h", "addr"),
    ("id.resp_p", "port"),
];

macro_rules! schema {
    ($($name:literal : $ty:literal),* $(,)?) => { &[$(($name, $ty)),*] };
}

const CONN: Schema = schema![
    "ts": "time", "uid": "string",
    "id.orig_h": "addr", "id.orig_p": "port", "id.resp_h": "addr", "id.resp_p": "port",
    "proto": "enum", "service": "string", "duration": "interval",
    "orig_bytes": "count", "resp_bytes": "count", "conn_state": "string",
    "local_orig": "bool", "local_resp": "bool", "missed_bytes": "count", "history": "string",
    "orig_pkts": "count", "orig_ip_bytes": "count", "resp_pkts": "count", "resp_ip_bytes": "count",
    "tunnel_parents": "set[string]",
];

const DNS: Schema = schema![
    "ts": "time", "uid": "string",
    "id.orig_h": "addr", "id.orig_p": "port", "id.resp_h": "addr", "id.resp_p": "port",
    "proto": "enum", "trans_id": "count", "rtt": "interval", "query": "string",
    "qclass": "count", "qclass_name": "string", "qtype": "count", "qtype_name": "string",
    "rcode": "count", "rcode_name": "string",
    "AA": "bool", "TC": "bool", "RD": "bool", "RA": "bool", "Z": "count",
    "answers": "vector[string]", "TTLs": "vector[interval]", "rejected": "bool",
];

const HTTP: Schema = schema![
    "ts": "time", "uid": "string",
    "id.orig_h": "addr", "id.orig_p": "port", "id.resp_h": "addr", "id.resp_p": "port",
    "trans_depth": "count", "method": "string", "host": "string", "uri": "string",
    "referrer": "string", "version": "string", "user_agent": "string", "origin": "string",
    "request_body_len": "count", "response_body_len": "count",
    "status_code": "count", "status_msg": "string", "tags": "set[enum]",
    "resp_mime_types": "vector[string]",
];

const SSL: Schema = schema![
    "ts": "time", "uid": "string",
    "id.orig_h": "addr", "id.orig_p": "port", "id.resp_h": "addr", "id.resp_p": "port",
    "version": "string", "cipher": "string", "server_name": "string",
    "ja3": "string", "ja3s": "string", "ja4": "string", "ja4s": "string",
];

const SSH: Schema = schema![
    "ts": "time", "uid": "string",
    "id.orig_h": "addr", "id.orig_p": "port", "id.resp_h": "addr", "id.resp_p": "port",
    "version": "count", "client": "string", "server": "string",
    "hassh": "string", "hasshServer": "string",
];

const FILES: Schema = schema![
    "ts": "time", "fuid": "string", "uid": "string",
    "id.orig_h": "addr", "id.orig_p": "port", "id.resp_h": "addr", "id.resp_p": "port",
    "source": "string", "analyzers": "set[string]", "mime_type": "string",
    "seen_bytes": "count", "total_bytes": "count", "sha256": "string", "extracted": "string",
    "signatures": "set[string]", "known_bad": "bool",
];

const NOTICE: Schema = schema![
    "ts": "time", "uid": "string",
    "id.orig_h": "addr", "id.orig_p": "port", "id.resp_h": "addr", "id.resp_p": "port",
    "proto": "enum", "note": "enum", "msg": "string", "sub": "string",
    "src": "addr", "dst": "addr", "p": "port", "n": "count",
    "actions": "set[enum]", "severity": "string", "score": "count", "mitre_attack": "set[string]",
];

/// One open log: header written lazily with its first row.
struct LogState {
    path: &'static str,
    schema: Schema,
    rows: u64,
}

/// A DNS query waiting for its answer.
struct DnsQuery {
    ts: i64,
    orig: (IpAddr, u16),
    resp: (IpAddr, u16),
    msg: DnsMessage,
}

/// An HTTP request waiting for its response.
struct HttpRequest {
    ts: i64,
    orig: (IpAddr, u16),
    resp: (IpAddr, u16),
    depth: u64,
    req: HttpReq,
}

/// Per-open-flow state, joined to the finalized record by `(key, opened_ts_ns)`.
#[derive(Default)]
struct FlowState {
    /// L4 payload bytes and IP bytes by physical direction ([`Direction::Forward`] = lo->hi).
    payload: [u64; 2],
    ip_bytes: [u64; 2],
    /// SSH identification line by physical direction.
    ssh_banner: [Option<String>; 2],
    dns: Vec<DnsQuery>,
    http: VecDeque<HttpRequest>,
    http_depth: u64,
    /// The service this pass's own parsers confirmed (`dns`, `http`), if any.
    parsed_service: Option<&'static str>,
}

fn dir_index(d: Direction) -> usize {
    match d {
        Direction::Forward => 0,
        Direction::Reverse => 1,
    }
}

/// Writes Zeek logs from an analysis pass. Feed it to [`crate::run_source_observing`], then call
/// [`ZeekLogger::finish`] with the resulting [`AnalysisOutput`].
pub struct ZeekLogger<S: LogSink> {
    sink: S,
    format: ZeekFormat,
    open_time: String,
    logs: Vec<LogState>,
    flows: HashMap<(FlowKey, i64), FlowState>,
    /// `(client, server, response ts)` -> uid, so carved files can name their connection.
    http_responses: HashMap<(IpAddr, IpAddr, i64), String>,
    error: Option<std::io::Error>,
}

impl<S: LogSink> ZeekLogger<S> {
    /// `open_time` is the `#open` header value, Zeek-style `YYYY-MM-DD-HH-MM-SS`.
    pub fn new(sink: S, format: ZeekFormat, open_time: &str) -> Self {
        ZeekLogger {
            sink,
            format,
            open_time: open_time.to_string(),
            logs: Vec::new(),
            flows: HashMap::new(),
            http_responses: HashMap::new(),
            error: None,
        }
    }

    /// Write the logs that need the whole analysis (`files`, `notice`), flush every pending DNS
    /// query and HTTP request, and close the logs. `close_time` is the `#close` header value.
    pub fn finish(
        mut self,
        out: &AnalysisOutput,
        close_time: &str,
    ) -> std::io::Result<(S, ZeekReport)> {
        // Flows the pass never finalized (none, normally) still flush their pending rows.
        let pending: Vec<((FlowKey, i64), FlowState)> = self.flows.drain().collect();
        for ((key, opened), state) in pending {
            let uid = conn_uid(&key, opened);
            self.flush_flow_state(&uid, state);
        }
        self.write_files(out);
        self.write_notices(out);
        if let Some(e) = self.error.take() {
            return Err(e);
        }
        if self.format == ZeekFormat::Tsv {
            for i in 0..self.logs.len() {
                let path = self.logs[i].path;
                let line = format!("#close\t{close_time}\n");
                self.sink
                    .write(&log_file(path, self.format), line.as_bytes())?;
            }
        }
        let report = ZeekReport {
            logs: self
                .logs
                .iter()
                .map(|l| (l.path.to_string(), l.rows))
                .collect(),
        };
        Ok((self.sink, report))
    }

    fn row(&mut self, path: &'static str, schema: Schema, vals: Vec<Val>) {
        debug_assert_eq!(schema.len(), vals.len(), "{path}");
        if self.error.is_some() {
            return;
        }
        let idx = match self.logs.iter().position(|l| l.path == path) {
            Some(i) => i,
            None => {
                self.logs.push(LogState {
                    path,
                    schema,
                    rows: 0,
                });
                if self.format == ZeekFormat::Tsv {
                    let header = tsv_header(path, schema, &self.open_time);
                    if let Err(e) = self
                        .sink
                        .write(&log_file(path, self.format), header.as_bytes())
                    {
                        self.error = Some(e);
                        return;
                    }
                }
                self.logs.len() - 1
            }
        };
        let line = match self.format {
            ZeekFormat::Tsv => tsv_row(&vals),
            ZeekFormat::Json => json_row(self.logs[idx].schema, &vals),
        };
        match self
            .sink
            .write(&log_file(path, self.format), line.as_bytes())
        {
            Ok(()) => self.logs[idx].rows += 1,
            Err(e) => self.error = Some(e),
        }
    }

    fn dns_row(&mut self, uid: &str, query: Option<&DnsQuery>, answer: Option<(&DnsQuery, i64)>) {
        // `query` is the request; `answer` is the response and its timestamp.
        let first = query.or(answer.map(|a| a.0));
        let Some(first) = first else { return };
        let q = &first.msg;
        let a = answer.map(|(m, _)| &m.msg);
        let rtt = match (query, answer) {
            (Some(q), Some((_, ts))) => Val::Interval(ts.saturating_sub(q.ts).max(0)),
            _ => Val::Unset,
        };
        let proto = if first.msg.tcp { "tcp" } else { "udp" };
        let mut vals = vec![Val::Time(first.ts), Val::Str(uid.to_string())];
        vals.extend(id_vals(first.orig, first.resp));
        vals.push(Val::Str(proto.into()));
        vals.push(Val::Count(u64::from(q.id)));
        vals.push(rtt);
        match &q.question {
            Some((name, qtype, qclass)) => {
                vals.push(Val::Str(name.clone()));
                vals.push(Val::Count(u64::from(*qclass)));
                vals.push(Val::Str(qclass_name(*qclass)));
                vals.push(Val::Count(u64::from(*qtype)));
                vals.push(Val::Str(qtype_name(*qtype)));
            }
            None => vals.extend([Val::Unset, Val::Unset, Val::Unset, Val::Unset, Val::Unset]),
        }
        match a {
            Some(a) => {
                vals.push(Val::Count(u64::from(a.rcode)));
                vals.push(Val::Str(rcode_name(a.rcode)));
                vals.push(Val::Bool(a.aa));
                vals.push(Val::Bool(a.tc));
                vals.push(Val::Bool(q.rd));
                vals.push(Val::Bool(a.ra));
                vals.push(Val::Count(u64::from(a.z)));
                if a.answers.is_empty() {
                    vals.push(Val::Unset);
                    vals.push(Val::Unset);
                } else {
                    vals.push(Val::List(
                        a.answers.iter().map(|(text, _)| text.clone()).collect(),
                    ));
                    vals.push(Val::List(
                        a.answers
                            .iter()
                            .map(|(_, ttl)| format!("{ttl}.000000"))
                            .collect(),
                    ));
                }
                vals.push(Val::Bool(a.rcode == 5));
            }
            None => {
                vals.extend([Val::Unset, Val::Unset, Val::Bool(false), Val::Bool(false)]);
                vals.push(Val::Bool(q.rd));
                vals.extend([Val::Bool(false), Val::Count(u64::from(q.z))]);
                vals.extend([Val::Unset, Val::Unset, Val::Bool(false)]);
            }
        }
        self.row("dns", DNS, vals);
    }

    fn http_row(&mut self, uid: &str, req: Option<&HttpRequest>, resp: Option<&HttpResp>) {
        let mut vals = Vec::with_capacity(HTTP.len());
        match req {
            Some(r) => {
                vals.push(Val::Time(r.ts));
                vals.push(Val::Str(uid.to_string()));
                vals.extend(id_vals(r.orig, r.resp));
                vals.push(Val::Count(r.depth));
                vals.push(Val::Str(r.req.method.clone()));
                vals.push(opt_str(&r.req.host));
                vals.push(Val::Str(r.req.uri.clone()));
                vals.push(opt_str(&r.req.referrer));
                vals.push(Val::Str(r.req.version.clone()));
                vals.push(opt_str(&r.req.user_agent));
                vals.push(opt_str(&r.req.origin));
                vals.push(Val::Count(r.req.content_length.unwrap_or(0)));
            }
            None => return,
        }
        match resp {
            Some(s) => {
                vals.push(s.content_length.map_or(Val::Unset, Val::Count));
                vals.push(Val::Count(u64::from(s.status)));
                vals.push(Val::Str(s.reason.clone()));
            }
            None => vals.extend([Val::Count(0), Val::Unset, Val::Unset]),
        }
        vals.push(Val::List(Vec::new()));
        vals.push(match resp.and_then(|s| s.content_type.clone()) {
            Some(ct) => Val::List(vec![ct]),
            None => Val::Unset,
        });
        self.row("http", HTTP, vals);
    }

    /// Emit every request/query still waiting on this flow (they never got an answer).
    fn flush_flow_state(&mut self, uid: &str, state: FlowState) {
        for q in &state.dns {
            self.dns_row(uid, Some(q), None);
        }
        for r in &state.http {
            self.http_row(uid, Some(r), None);
        }
    }

    fn write_files(&mut self, out: &AnalysisOutput) {
        let mut files = out.summary.carved_files.clone();
        files.sort_by_key(|f| (f.first_seen_ns.unwrap_or(0), f.sha256.clone()));
        for f in files {
            let (Ok(client), Ok(server)) = (f.client.parse::<IpAddr>(), f.server.parse::<IpAddr>())
            else {
                continue;
            };
            let ts = f
                .first_seen_ns
                .or(out.summary.first_ts_ns)
                .unwrap_or_default();
            let uid = f
                .first_seen_ns
                .and_then(|t| self.http_responses.get(&(client, server, t)).cloned());
            let fuid = file_uid(&f.sha256, &f.client, &f.server, ts);
            let vals = vec![
                Val::Time(ts),
                Val::Str(fuid),
                uid.map_or(Val::Unset, Val::Str),
                // The connection's orig is the downloading client, as in Zeek's `files.log`.
                Val::Addr(client),
                Val::Unset,
                Val::Addr(server),
                Val::Unset,
                Val::Str("HTTP".into()),
                Val::List(vec!["SHA256".into()]),
                mime_for(&f.signatures).map_or(Val::Unset, |m| Val::Str(m.into())),
                Val::Count(f.size),
                Val::Count(f.size),
                Val::Str(f.sha256.clone()),
                f.extracted_path.clone().map_or(Val::Unset, Val::Str),
                Val::List(f.signatures.clone()),
                Val::Bool(f.known_bad),
            ];
            self.row("files", FILES, vals);
        }
    }

    fn write_notices(&mut self, out: &AnalysisOutput) {
        let mut findings: Vec<_> = out.summary.findings.iter().collect();
        findings.sort_by_key(|f| f.first_seen_ns.or(out.summary.first_ts_ns).unwrap_or(0));
        for f in findings {
            let ts = f
                .first_seen_ns
                .or(out.summary.first_ts_ns)
                .unwrap_or_default();
            let src = f.src_ip.parse::<IpAddr>().ok();
            let dst = f.dst_ip.as_deref().and_then(|d| d.parse::<IpAddr>().ok());
            let vals = vec![
                Val::Time(ts),
                Val::Unset,
                src.map_or(Val::Unset, Val::Addr),
                Val::Unset,
                dst.map_or(Val::Unset, Val::Addr),
                f.dst_port.map_or(Val::Unset, Val::Port),
                Val::Unset,
                Val::Str(format!("PacketPilot::{}", f.kind.as_str())),
                Val::Str(clip(&f.title)),
                if f.evidence.is_empty() {
                    Val::Unset
                } else {
                    Val::Str(clip(&f.evidence.join("; ")))
                },
                src.map_or(Val::Unset, Val::Addr),
                dst.map_or(Val::Unset, Val::Addr),
                f.dst_port.map_or(Val::Unset, Val::Port),
                f.contacts.map_or(Val::Unset, Val::Count),
                Val::List(vec!["Notice::ACTION_LOG".into()]),
                Val::Str(f.severity.as_str().into()),
                Val::Count(u64::from(f.score)),
                Val::List(f.attack.clone()),
            ];
            self.row("notice", NOTICE, vals);
        }
    }

    fn on_dns(&mut self, view: &PacketView<'_>, flow: (FlowKey, Direction, i64)) {
        let meta = view.meta;
        let (Some(src), Some(dst)) = (meta.src_ip, meta.dst_ip) else {
            return;
        };
        let tcp = meta.transport == Transport::Tcp;
        let body = if tcp {
            // DNS over TCP: a 2-byte length prefix, then one message (if it fits the segment).
            match view.payload {
                [hi, lo, rest @ ..]
                    if usize::from(u16::from_be_bytes([*hi, *lo])) <= rest.len() =>
                {
                    &rest[..usize::from(u16::from_be_bytes([*hi, *lo]))]
                }
                _ => return,
            }
        } else {
            view.payload
        };
        let Some(mut msg) = parse_dns(body) else {
            return;
        };
        msg.tcp = tcp;
        let (key, _, opened) = flow;
        let uid = conn_uid(&key, opened);
        let state = self.flows.entry((key, opened)).or_default();
        state.parsed_service = Some("dns");
        if !msg.response {
            let q = DnsQuery {
                ts: meta.ts_ns,
                orig: (src, meta.src_port),
                resp: (dst, meta.dst_port),
                msg,
            };
            let evicted =
                (state.dns.len() >= MAX_DNS_PENDING_PER_FLOW).then(|| state.dns.remove(0));
            state.dns.push(q);
            if let Some(oldest) = evicted {
                self.dns_row(&uid, Some(&oldest), None);
            }
            return;
        }
        // A response: pair it with its query by id and question.
        let pos = state
            .dns
            .iter()
            .position(|q| q.msg.id == msg.id && q.msg.question == msg.question);
        let query = pos.map(|i| state.dns.remove(i));
        let answer = DnsQuery {
            ts: meta.ts_ns,
            // The responder answers the querier: orig is the response's destination.
            orig: (dst, meta.dst_port),
            resp: (src, meta.src_port),
            msg,
        };
        let ts = answer.ts;
        self.dns_row(&uid, query.as_ref(), Some((&answer, ts)));
    }

    fn on_http(&mut self, view: &PacketView<'_>, flow: (FlowKey, Direction, i64)) {
        let meta = view.meta;
        let (Some(src), Some(dst)) = (meta.src_ip, meta.dst_ip) else {
            return;
        };
        let (key, _, opened) = flow;
        if let Some(req) = parse_http_request(view.payload) {
            let state = self.flows.entry((key, opened)).or_default();
            state.parsed_service = Some("http");
            state.http_depth += 1;
            let r = HttpRequest {
                ts: meta.ts_ns,
                orig: (src, meta.src_port),
                resp: (dst, meta.dst_port),
                depth: state.http_depth,
                req,
            };
            if state.http.len() >= MAX_HTTP_PENDING_PER_FLOW {
                let oldest = state.http.pop_front();
                state.http.push_back(r);
                if let Some(o) = oldest {
                    let uid = conn_uid(&key, opened);
                    self.http_row(&uid, Some(&o), None);
                }
            } else {
                state.http.push_back(r);
            }
        } else if let Some(resp) = parse_http_response(view.payload) {
            let uid = conn_uid(&key, opened);
            // 1xx interim responses don't complete a request.
            if (100..200).contains(&resp.status) {
                return;
            }
            let state = self.flows.entry((key, opened)).or_default();
            state.parsed_service = Some("http");
            let req = state.http.pop_front();
            if self.http_responses.len() < MAX_HTTP_RESPONSES {
                // Client is the response's destination; keyed like a carved file.
                self.http_responses
                    .insert((dst, src, meta.ts_ns), uid.clone());
            }
            self.http_row(&uid, req.as_ref(), Some(&resp));
        }
    }

    fn conn_row(&mut self, rec: &FlowRecord, state: &FlowState, uid: &str) {
        let o = rec.oriented();
        // Physical index of the initiator's direction.
        let (oi, ri) = match rec.initiator {
            Direction::Forward => (0, 1),
            Direction::Reverse => (1, 0),
        };
        let (orig_pkts, resp_pkts) = match rec.initiator {
            Direction::Forward => (rec.pkts_fwd, rec.pkts_rev),
            Direction::Reverse => (rec.pkts_rev, rec.pkts_fwd),
        };
        let proto = proto_name(rec.key.transport);
        let tcp = rec.key.transport == Transport::Tcp;
        let mut vals = vec![Val::Time(rec.first_ts_ns), Val::Str(uid.to_string())];
        vals.extend(id_vals((o.src_ip, o.src_port), (o.dst_ip, o.dst_port)));
        vals.push(Val::Str(proto.into()));
        vals.push(
            service(rec)
                .or(state.parsed_service)
                .map_or(Val::Unset, |s| Val::Str(s.into())),
        );
        vals.push(Val::Interval(
            rec.last_ts_ns.saturating_sub(rec.first_ts_ns).max(0),
        ));
        vals.push(Val::Count(state.payload[oi]));
        vals.push(Val::Count(state.payload[ri]));
        vals.push(Val::Str(
            conn_state(tcp, o.tcp_flags_c2s, o.tcp_flags_s2c, resp_pkts).into(),
        ));
        vals.extend([Val::Unset, Val::Unset, Val::Count(0), Val::Unset]);
        vals.push(Val::Count(orig_pkts));
        vals.push(Val::Count(state.ip_bytes[oi]));
        vals.push(Val::Count(resp_pkts));
        vals.push(Val::Count(state.ip_bytes[ri]));
        vals.push(Val::List(Vec::new()));
        self.row("conn", CONN, vals);

        let id = id_vals((o.src_ip, o.src_port), (o.dst_ip, o.dst_port));
        let tls = rec.sni.is_some()
            || rec.ja3.is_some()
            || rec.ja4.is_some()
            || rec.ja3s.is_some()
            || rec.tls_version.is_some();
        if tls {
            let mut vals = vec![Val::Time(rec.first_ts_ns), Val::Str(uid.to_string())];
            vals.extend(id.clone());
            vals.push(
                rec.tls_version
                    .as_deref()
                    .map_or(Val::Unset, |v| Val::Str(tls_version(v))),
            );
            vals.push(opt_str(&rec.tls_cipher));
            vals.push(opt_str(&rec.sni));
            vals.push(opt_str(&rec.ja3));
            vals.push(opt_str(&rec.ja3s));
            vals.push(opt_str(&rec.ja4));
            vals.push(opt_str(&rec.ja4s));
            self.row("ssl", SSL, vals);
        }
        let banners = [&state.ssh_banner[oi], &state.ssh_banner[ri]];
        let ssh = rec.hassh.is_some()
            || rec.hassh_server.is_some()
            || banners.iter().any(|b| b.is_some())
            || rec.ssh_banner.is_some();
        if ssh {
            let (client, server) = (banners[0].clone(), banners[1].clone());
            let any = client
                .as_deref()
                .or(server.as_deref())
                .or(rec.ssh_banner.as_deref());
            let version = any.and_then(|b| {
                if b.starts_with("SSH-2.0") || b.starts_with("SSH-1.99") {
                    Some(2)
                } else if b.starts_with("SSH-1.") {
                    Some(1)
                } else {
                    None
                }
            });
            let mut vals = vec![Val::Time(rec.first_ts_ns), Val::Str(uid.to_string())];
            vals.extend(id);
            vals.push(version.map_or(Val::Unset, Val::Count));
            vals.push(opt_str(&client));
            vals.push(opt_str(&server));
            vals.push(opt_str(&rec.hassh));
            vals.push(opt_str(&rec.hassh_server));
            self.row("ssh", SSH, vals);
        }
    }
}

impl<S: LogSink> CaptureVisitor for ZeekLogger<S> {
    fn wants_packets(&self) -> bool {
        true
    }

    fn packet(&mut self, view: &PacketView<'_>) {
        let Some(flow) = view.flow else { return };
        let (key, dir, opened) = flow;
        let meta = view.meta;
        {
            let state = self.flows.entry((key, opened)).or_default();
            let d = dir_index(dir);
            state.payload[d] += u64::from(meta.payload_len);
            state.ip_bytes[d] += u64::from(view.ip_len.unwrap_or(meta.wire_len));
            if let Some(b) = &meta.ssh_banner {
                if state.ssh_banner[d].is_none() {
                    state.ssh_banner[d] = Some(clip(b));
                }
            }
        }
        if view.payload.is_empty() {
            return;
        }
        let dns_port = |p: u16| matches!(p, 53 | 5353 | 5355);
        let is_dns = matches!(meta.transport, Transport::Udp | Transport::Tcp)
            && (dns_port(meta.src_port) || dns_port(meta.dst_port));
        if is_dns {
            self.on_dns(view, flow);
        } else if meta.transport == Transport::Tcp {
            self.on_http(view, flow);
        }
    }

    fn flow(&mut self, record: &FlowRecord) {
        let uid = conn_uid(&record.key, record.opened_ts_ns);
        let state = self
            .flows
            .remove(&(record.key, record.opened_ts_ns))
            .unwrap_or_default();
        self.conn_row(record, &state, &uid);
        self.flush_flow_state(&uid, state);
    }
}

/// Zeek names its logs `<path>.log` in both formats.
fn log_file(path: &str, _format: ZeekFormat) -> String {
    format!("{path}.log")
}

fn id_vals(orig: (IpAddr, u16), resp: (IpAddr, u16)) -> Vec<Val> {
    debug_assert_eq!(ID.len(), 4);
    vec![
        Val::Addr(orig.0),
        Val::Port(orig.1),
        Val::Addr(resp.0),
        Val::Port(resp.1),
    ]
}

fn opt_str(s: &Option<String>) -> Val {
    match s {
        Some(v) => Val::Str(clip(v)),
        None => Val::Unset,
    }
}

fn clip(s: &str) -> String {
    if s.len() <= MAX_FIELD {
        return s.to_string();
    }
    let mut end = MAX_FIELD;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn proto_name(t: Transport) -> &'static str {
    match t {
        Transport::Tcp => "tcp",
        Transport::Udp => "udp",
        Transport::Icmp | Transport::Icmpv6 => "icmp",
        _ => "unknown_transport",
    }
}

/// Zeek's `service` names. Only payload-confirmed protocols are named, as Zeek names only what
/// its protocol detection confirmed; a port guess stays unset.
fn service(rec: &FlowRecord) -> Option<&'static str> {
    if rec.app_proto_src != Some("payload") {
        return None;
    }
    Some(match rec.app_proto.as_str() {
        "" => return None,
        "https" | "tls" => "ssl",
        "http" => "http",
        "dns" => "dns",
        "ssh" => "ssh",
        "quic" => "quic",
        "smtp" => "smtp",
        "ftp" => "ftp",
        "dhcp" => "dhcp",
        "ntp" => "ntp",
        "smb" => "smb",
        "kerberos" => "krb",
        "ldap" => "ldap",
        "rdp" => "rdp",
        "snmp" => "snmp",
        "sip" => "sip",
        "mqtt" => "mqtt",
        "modbus" => "modbus",
        "dnp3" => "dnp3",
        "imap" => "imap",
        "pop3" => "pop3",
        "irc" => "irc",
        "socks" => "socks",
        "mysql" => "mysql",
        "rfb" | "vnc" => "rfb",
        _ => return None,
    })
}

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

/// Zeek's `conn_state` from each direction's sticky TCP flags (no ordering is kept, so states that
/// hinge on order are approximated by their flag sets).
fn conn_state(tcp: bool, orig: u8, resp: u8, resp_pkts: u64) -> &'static str {
    if !tcp {
        return if resp_pkts > 0 { "SF" } else { "S0" };
    }
    let orig_syn = orig & SYN != 0;
    let resp_syn = resp & SYN != 0;
    if !orig_syn && !resp_syn {
        return "OTH";
    }
    if orig_syn && !resp_syn {
        if resp & RST != 0 {
            return "REJ";
        }
        if orig & FIN != 0 {
            return "SH";
        }
        if resp_pkts == 0 {
            return "S0";
        }
        return "OTH";
    }
    if !orig_syn {
        // The responder's SYN-ACK without the opening SYN: Zeek's "SHR"-style partial view.
        return if resp & FIN != 0 { "SHR" } else { "OTH" };
    }
    if resp & ACK == 0 {
        return "OTH";
    }
    if orig & RST != 0 {
        return "RSTO";
    }
    if resp & RST != 0 {
        return "RSTR";
    }
    match (orig & FIN != 0, resp & FIN != 0) {
        (true, true) => "SF",
        (true, false) => "S2",
        (false, true) => "S3",
        (false, false) => "S1",
    }
}

/// `TLS 1.2` -> Zeek's `TLSv12`.
fn tls_version(label: &str) -> String {
    match label {
        "SSL 3.0" => "SSLv3".into(),
        "TLS 1.0" => "TLSv10".into(),
        "TLS 1.1" => "TLSv11".into(),
        "TLS 1.2" => "TLSv12".into(),
        "TLS 1.3" => "TLSv13".into(),
        other => clip(other),
    }
}

fn mime_for(signatures: &[String]) -> Option<&'static str> {
    signatures.iter().find_map(|s| {
        let s = s.to_ascii_lowercase();
        Some(if s.contains("pe/dos") {
            "application/x-dosexec"
        } else if s.contains("elf") {
            "application/x-executable"
        } else if s.contains("pdf") {
            "application/pdf"
        } else if s.contains("zip") {
            "application/zip"
        } else if s.contains("ole") || s.contains("office") {
            "application/msword"
        } else if s.contains("script") || s.contains("powershell") {
            "text/plain"
        } else {
            return None;
        })
    })
}

/// A Unix time in seconds as Zeek's `#open`/`#close` header value, `YYYY-MM-DD-HH-MM-SS` (UTC).
pub fn header_time(unix_secs: i64) -> String {
    use time::macros::format_description;
    let fmt = format_description!("[year]-[month]-[day]-[hour]-[minute]-[second]");
    time::OffsetDateTime::from_unix_timestamp(unix_secs)
        .ok()
        .and_then(|dt| dt.format(&fmt).ok())
        .unwrap_or_else(|| "1970-01-01-00-00-00".into())
}

// ── uids ─────────────────────────────────────────────────────────────────────────────────────────

fn fnv64(seed: u64, bytes: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64 ^ seed;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn base62(prefix: char, bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut n = (u128::from(fnv64(1, bytes)) << 64) | u128::from(fnv64(2, bytes));
    let mut s = String::with_capacity(18);
    s.push(prefix);
    for _ in 0..17 {
        s.push(char::from(ALPHABET[(n % 62) as usize]));
        n /= 62;
    }
    s
}

fn ip_bytes(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v) => v.octets().to_vec(),
        IpAddr::V6(v) => v.octets().to_vec(),
    }
}

/// The deterministic Zeek-style connection uid (`C` + 17 base62 chars) of one flow instance.
pub fn conn_uid(key: &FlowKey, opened_ts_ns: i64) -> String {
    let mut b = ip_bytes(&key.lo_ip);
    b.extend_from_slice(&key.lo_port.to_be_bytes());
    b.extend(ip_bytes(&key.hi_ip));
    b.extend_from_slice(&key.hi_port.to_be_bytes());
    b.push(proto_name(key.transport).len() as u8);
    b.extend_from_slice(proto_name(key.transport).as_bytes());
    b.extend_from_slice(&opened_ts_ns.to_be_bytes());
    base62('C', &b)
}

fn file_uid(sha256: &str, client: &str, server: &str, ts: i64) -> String {
    let b = format!("{sha256}|{client}|{server}|{ts}");
    base62('F', b.as_bytes())
}

// ── rendering ────────────────────────────────────────────────────────────────────────────────────

fn tsv_header(path: &str, schema: Schema, open_time: &str) -> String {
    let names: Vec<&str> = schema.iter().map(|(n, _)| *n).collect();
    let types: Vec<&str> = schema.iter().map(|(_, t)| *t).collect();
    format!(
        "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\t{path}\n#open\t{open_time}\n#fields\t{}\n#types\t{}\n",
        names.join("\t"),
        types.join("\t"),
    )
}

/// Seconds with 6 decimals, as Zeek writes `time` and `interval`.
fn secs(ns: i64) -> String {
    let sign = if ns < 0 { "-" } else { "" };
    let n = ns.unsigned_abs();
    format!(
        "{sign}{}.{:06}",
        n / 1_000_000_000,
        (n % 1_000_000_000) / 1_000
    )
}

/// Zeek's ASCII escaping: separators, backslash and non-printable bytes become `\xHH`.
fn tsv_escape(s: &str, in_set: bool) -> String {
    if s.is_empty() {
        return "(empty)".into();
    }
    if s == "-" {
        return "\\x2d".into();
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\x5c"),
            ',' if in_set => out.push_str("\\x2c"),
            c if raw_byte(c).is_some() => {
                out.push_str(&format!("\\x{:02x}", raw_byte(c).unwrap_or(0)));
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn tsv_val(v: &Val) -> String {
    match v {
        Val::Time(ns) | Val::Interval(ns) => secs(*ns),
        Val::Str(s) => tsv_escape(s, false),
        Val::Addr(a) => a.to_string(),
        Val::Port(p) => p.to_string(),
        Val::Count(n) => n.to_string(),
        Val::Bool(b) => if *b { "T" } else { "F" }.into(),
        Val::List(items) if items.is_empty() => "(empty)".into(),
        Val::List(items) => items
            .iter()
            .map(|s| tsv_escape(s, true))
            .collect::<Vec<_>>()
            .join(","),
        Val::Unset => "-".into(),
    }
}

fn tsv_row(vals: &[Val]) -> String {
    let mut line = vals.iter().map(tsv_val).collect::<Vec<_>>().join("\t");
    line.push('\n');
    line
}

fn json_row(schema: Schema, vals: &[Val]) -> String {
    use serde_json::{Map, Value};
    let mut obj = Map::new();
    for ((name, ty), v) in schema.iter().zip(vals) {
        let value = match v {
            Val::Unset => continue,
            Val::Time(ns) | Val::Interval(ns) => Value::from(*ns as f64 / 1_000_000_000.0),
            Val::Str(s) => Value::from(json_text(s)),
            Val::Addr(a) => Value::from(a.to_string()),
            Val::Port(p) => Value::from(*p),
            Val::Count(n) => Value::from(*n),
            Val::Bool(b) => Value::from(*b),
            Val::List(items) if ty.contains("interval") => Value::from(
                items
                    .iter()
                    .map(|s| Value::from(s.parse::<f64>().unwrap_or(0.0)))
                    .collect::<Vec<_>>(),
            ),
            Val::List(items) => Value::from(items.iter().map(|s| json_text(s)).collect::<Vec<_>>()),
        };
        obj.insert((*name).to_string(), value);
    }
    let mut line = Value::Object(obj).to_string();
    line.push('\n');
    line
}

// ── DNS ──────────────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Default)]
struct DnsMessage {
    id: u16,
    response: bool,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: u8,
    rcode: u8,
    tcp: bool,
    /// `(name, qtype, qclass)` of the first question.
    question: Option<(String, u16, u16)>,
    /// `(rendered answer, ttl seconds)` per answer record.
    answers: Vec<(String, u32)>,
}

/// Parse a DNS message (header, first question, answer section). `None` when it isn't one.
fn parse_dns(b: &[u8]) -> Option<DnsMessage> {
    if b.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([b[2], b[3]]);
    let opcode = (flags >> 11) & 0xf;
    if opcode > 6 {
        return None;
    }
    let qd = u16::from_be_bytes([b[4], b[5]]);
    let an = u16::from_be_bytes([b[6], b[7]]);
    if qd > 16 || an > 256 {
        return None;
    }
    let mut m = DnsMessage {
        id: u16::from_be_bytes([b[0], b[1]]),
        response: flags & 0x8000 != 0,
        aa: flags & 0x0400 != 0,
        tc: flags & 0x0200 != 0,
        rd: flags & 0x0100 != 0,
        ra: flags & 0x0080 != 0,
        z: ((flags >> 4) & 0x7) as u8,
        rcode: (flags & 0xf) as u8,
        ..Default::default()
    };
    let mut off = 12;
    for i in 0..qd {
        let (name, next) = dns_name(b, off)?;
        if next + 4 > b.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([b[next], b[next + 1]]);
        let qclass = u16::from_be_bytes([b[next + 2], b[next + 3]]);
        if i == 0 {
            m.question = Some((name, qtype, qclass));
        }
        off = next + 4;
    }
    if qd == 0 && !m.response {
        return None;
    }
    for _ in 0..an {
        let Some((_, next)) = dns_name(b, off) else {
            break;
        };
        if next + 10 > b.len() {
            break;
        }
        let rtype = u16::from_be_bytes([b[next], b[next + 1]]);
        let ttl = u32::from_be_bytes([b[next + 4], b[next + 5], b[next + 6], b[next + 7]]);
        let rdlen = usize::from(u16::from_be_bytes([b[next + 8], b[next + 9]]));
        let rd = next + 10;
        if rd + rdlen > b.len() {
            break;
        }
        let data = &b[rd..rd + rdlen];
        let text = match rtype {
            1 if rdlen == 4 => Some(IpAddr::from([data[0], data[1], data[2], data[3]]).to_string()),
            28 if rdlen == 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(data);
                Some(IpAddr::from(a).to_string())
            }
            2 | 5 | 12 => dns_name(b, rd).map(|(n, _)| n),
            15 if rdlen > 2 => dns_name(b, rd + 2).map(|(n, _)| n),
            16 => {
                let mut parts = Vec::new();
                let mut i = 0;
                while i < data.len() {
                    let l = usize::from(data[i]);
                    let end = (i + 1 + l).min(data.len());
                    parts.push(escape_bytes(&data[i + 1..end]));
                    i = end;
                }
                Some(format!("TXT {} {}", data.len(), parts.join(" ")))
            }
            33 if rdlen > 6 => dns_name(b, rd + 6).map(|(n, _)| n),
            _ => None,
        };
        // Zeek renders record types it doesn't decode as `<unknown type=N>`.
        m.answers.push((
            text.unwrap_or_else(|| format!("<unknown type={rtype}>")),
            ttl,
        ));
        off = rd + rdlen;
    }
    Some(m)
}

/// Read a (possibly compressed) domain name at `off`; returns it and the offset after it.
fn dns_name(b: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    let mut total = 0usize;
    loop {
        let len = *b.get(off)?;
        if len == 0 {
            off += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            let ptr = usize::from(u16::from_be_bytes([len, *b.get(off + 1)?]) & 0x3fff);
            if end.is_none() {
                end = Some(off + 2);
            }
            jumps += 1;
            if jumps > 32 || ptr >= b.len() {
                return None;
            }
            off = ptr;
            continue;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        let l = usize::from(len);
        let label = b.get(off + 1..off + 1 + l)?;
        total += l + 1;
        if total > 255 {
            return None;
        }
        labels.push(escape_bytes(label));
        off += 1 + l;
    }
    let name = if labels.is_empty() {
        "<root>".to_string()
    } else {
        labels.join(".")
    };
    Some((name, end.unwrap_or(off)))
}

/// First of 256 private-use code points that carry a raw wire byte through a `String` until it is
/// written, where it becomes Zeek's `\xHH` exactly once.
const RAW_BYTE_BASE: u32 = 0xF700;

/// Printable ASCII as-is; every other byte as its raw-byte code point (see [`RAW_BYTE_BASE`]).
fn escape_bytes(b: &[u8]) -> String {
    b.iter()
        .map(|&c| {
            if (0x20..0x7f).contains(&c) {
                char::from(c)
            } else {
                char::from_u32(RAW_BYTE_BASE + u32::from(c)).unwrap_or('?')
            }
        })
        .collect()
}

/// The wire byte a raw-byte code point stands for.
fn raw_byte(c: char) -> Option<u8> {
    let v = c as u32;
    (RAW_BYTE_BASE..RAW_BYTE_BASE + 256)
        .contains(&v)
        .then(|| (v - RAW_BYTE_BASE) as u8)
}

/// JSON text for a string: raw bytes as the literal `\xHH`, as Zeek's JSON writer renders them.
fn json_text(s: &str) -> String {
    if !s.chars().any(|c| raw_byte(c).is_some()) {
        return s.to_string();
    }
    s.chars()
        .map(|c| match raw_byte(c) {
            Some(b) => format!("\\x{b:02x}"),
            None => c.to_string(),
        })
        .collect()
}

fn qclass_name(c: u16) -> String {
    match c {
        1 => "C_INTERNET".into(),
        3 => "C_CHAOS".into(),
        4 => "C_HESIOD".into(),
        254 => "C_NONE".into(),
        255 => "C_ANY".into(),
        // mDNS sets the top bit of qclass for "unicast response wanted".
        c if c & 0x7fff == 1 => "C_INTERNET".into(),
        c => format!("{c}"),
    }
}

fn qtype_name(t: u16) -> String {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        13 => "HINFO",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        35 => "NAPTR",
        41 => "OPT",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        64 => "SVCB",
        65 => "HTTPS",
        99 => "SPF",
        252 => "AXFR",
        255 => "*",
        257 => "CAA",
        t => return format!("query-{t}"),
    }
    .into()
}

fn rcode_name(r: u8) -> String {
    match r {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        r => return format!("rcode-{r}"),
    }
    .into()
}

// ── HTTP ─────────────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Default)]
struct HttpReq {
    method: String,
    uri: String,
    version: String,
    host: Option<String>,
    user_agent: Option<String>,
    referrer: Option<String>,
    origin: Option<String>,
    content_length: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Default)]
struct HttpResp {
    status: u16,
    reason: String,
    content_length: Option<u64>,
    content_type: Option<String>,
}

const METHODS: &[&str] = &[
    "GET",
    "POST",
    "HEAD",
    "PUT",
    "DELETE",
    "OPTIONS",
    "PATCH",
    "CONNECT",
    "TRACE",
    "PROPFIND",
    "PROPPATCH",
    "MKCOL",
    "COPY",
    "MOVE",
    "LOCK",
    "UNLOCK",
    "SEARCH",
    "REPORT",
];

/// The start line and headers of the segment, or `None` when it has no CRLF-terminated line.
fn http_lines(b: &[u8]) -> Option<(String, Vec<(String, String)>)> {
    let head = &b[..b.len().min(8192)];
    let text: String = head.iter().map(|&c| char::from(c)).collect();
    let mut lines = text.split("\r\n");
    let start = lines.next()?;
    if !text.contains("\r\n") {
        return None;
    }
    let mut headers = Vec::new();
    for l in lines {
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    Some((start.to_string(), headers))
}

fn header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers.iter().find(|(k, _)| k == name).map(|(_, v)| {
        clip(&escape_bytes(
            &v.chars().map(|c| c as u8).collect::<Vec<_>>(),
        ))
    })
}

fn parse_http_request(b: &[u8]) -> Option<HttpReq> {
    let method_end = b.iter().take(12).position(|&c| c == b' ')?;
    let method = std::str::from_utf8(&b[..method_end]).ok()?;
    if !METHODS.contains(&method) {
        return None;
    }
    let (start, headers) = http_lines(b)?;
    let mut parts = start.splitn(3, ' ');
    let _ = parts.next();
    let uri = parts.next()?;
    let version = parts.next()?.strip_prefix("HTTP/")?;
    Some(HttpReq {
        method: method.to_string(),
        uri: clip(&escape_bytes(
            &uri.chars().map(|c| c as u8).collect::<Vec<_>>(),
        )),
        version: clip(version),
        host: header(&headers, "host"),
        user_agent: header(&headers, "user-agent"),
        referrer: header(&headers, "referer"),
        origin: header(&headers, "origin"),
        content_length: header(&headers, "content-length").and_then(|v| v.parse().ok()),
    })
}

fn parse_http_response(b: &[u8]) -> Option<HttpResp> {
    if !b.starts_with(b"HTTP/") {
        return None;
    }
    let (start, headers) = http_lines(b)?;
    let mut parts = start.splitn(3, ' ');
    let _version = parts.next()?;
    let status: u16 = parts.next()?.parse().ok()?;
    if !(100..1000).contains(&status) {
        return None;
    }
    let reason = parts.next().unwrap_or("").to_string();
    Some(HttpResp {
        status,
        reason: clip(&escape_bytes(
            &reason.chars().map(|c| c as u8).collect::<Vec<_>>(),
        )),
        content_length: header(&headers, "content-length").and_then(|v| v.parse().ok()),
        content_type: header(&headers, "content-type").map(|v| {
            v.split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut b = vec![
            (id >> 8) as u8,
            id as u8,
            0x01,
            0x00,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        for l in name.split('.') {
            b.push(l.len() as u8);
            b.extend_from_slice(l.as_bytes());
        }
        b.push(0);
        b.extend_from_slice(&qtype.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b
    }

    fn dns_answer(id: u16, name: &str, ips: &[[u8; 4]], rcode: u8) -> Vec<u8> {
        let mut b = dns_query(id, name, 1);
        b[2] = 0x81;
        b[3] = 0x80 | rcode;
        b[7] = ips.len() as u8;
        for ip in ips {
            b.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4]);
            b.extend_from_slice(ip);
        }
        b
    }

    #[test]
    fn dns_messages_parse_with_compression() {
        let q = parse_dns(&dns_query(0x1234, "example.com", 1)).unwrap();
        assert!(!q.response);
        assert!(q.rd);
        assert_eq!(q.question, Some(("example.com".into(), 1, 1)));
        let a = parse_dns(&dns_answer(0x1234, "example.com", &[[93, 184, 216, 34]], 0)).unwrap();
        assert!(a.response);
        assert_eq!(a.answers, vec![("93.184.216.34".into(), 3600)]);
        assert_eq!(a.question, q.question);
        // A pointer loop is rejected, not followed forever.
        let mut bad = dns_query(1, "a", 1);
        bad.truncate(12);
        bad.extend_from_slice(&[0xc0, 12]);
        assert!(parse_dns(&bad).is_none());
        assert!(parse_dns(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn dns_names_escape_raw_bytes() {
        let mut b = vec![0u8; 12];
        b[5] = 1;
        b.extend_from_slice(&[3, b'a', 0x01, b'\t', 0, 0, 1, 0, 1]);
        let m = parse_dns(&b).unwrap();
        let name = m.question.unwrap().0;
        // Escaped once on output: a Zeek reader gets the original bytes back.
        assert_eq!(tsv_escape(&name, false), "a\\x01\\x09");
        assert_eq!(json_text(&name), "a\\x01\\x09");
        assert_eq!(tsv_escape("a\\b", false), "a\\x5cb");
    }

    #[test]
    fn http_request_and_response_lines_parse() {
        let r = parse_http_request(
            b"GET /a?b=1 HTTP/1.1\r\nHost: evil.test\r\nUser-Agent: curl/8\r\nReferer: http://x/\r\n\r\n",
        )
        .unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.uri, "/a?b=1");
        assert_eq!(r.version, "1.1");
        assert_eq!(r.host.as_deref(), Some("evil.test"));
        assert_eq!(r.user_agent.as_deref(), Some("curl/8"));
        assert_eq!(r.referrer.as_deref(), Some("http://x/"));
        let s = parse_http_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/x-msdownload; charset=x\r\nContent-Length: 42\r\n\r\nMZ",
        )
        .unwrap();
        assert_eq!(s.status, 200);
        assert_eq!(s.reason, "OK");
        assert_eq!(s.content_length, Some(42));
        assert_eq!(s.content_type.as_deref(), Some("application/x-msdownload"));
        assert!(parse_http_request(b"GETX / HTTP/1.1\r\n").is_none());
        assert!(parse_http_request(b"\x16\x03\x01").is_none());
    }

    #[test]
    fn conn_states_follow_the_flags() {
        assert_eq!(conn_state(true, SYN, 0, 0), "S0");
        assert_eq!(conn_state(true, SYN, RST | ACK, 1), "REJ");
        assert_eq!(conn_state(true, SYN | ACK | FIN, SYN | ACK | FIN, 5), "SF");
        assert_eq!(conn_state(true, SYN | ACK, SYN | ACK, 5), "S1");
        assert_eq!(conn_state(true, SYN | ACK | RST, SYN | ACK, 5), "RSTO");
        assert_eq!(conn_state(true, SYN | ACK, SYN | ACK | RST, 5), "RSTR");
        assert_eq!(conn_state(true, ACK, ACK, 5), "OTH");
        assert_eq!(conn_state(false, 0, 0, 0), "S0");
        assert_eq!(conn_state(false, 0, 0, 3), "SF");
    }

    #[test]
    fn tsv_escaping_matches_zeek() {
        assert_eq!(tsv_escape("", false), "(empty)");
        assert_eq!(tsv_escape("-", false), "\\x2d");
        assert_eq!(tsv_escape("a\tb\\c", false), "a\\x09b\\x5cc");
        assert_eq!(tsv_escape("a,b", true), "a\\x2cb");
        assert_eq!(tsv_escape("a,b", false), "a,b");
        assert_eq!(secs(1_700_000_000_123_456_789), "1700000000.123456");
        assert_eq!(secs(1_500_000), "0.001500");
    }

    #[test]
    fn header_times_use_zeeks_layout() {
        assert_eq!(header_time(1_700_000_000), "2023-11-14-22-13-20");
    }

    #[test]
    fn uids_are_deterministic_and_distinct() {
        let (k, _) = FlowKey::normalized(
            "10.0.0.1".parse().unwrap(),
            40000,
            "10.0.0.2".parse().unwrap(),
            80,
            Transport::Tcp,
        );
        let a = conn_uid(&k, 1);
        assert_eq!(a, conn_uid(&k, 1));
        assert_ne!(a, conn_uid(&k, 2));
        assert_eq!(a.len(), 18);
        assert!(a.starts_with('C'));
        assert!(a[1..].chars().all(|c| c.is_ascii_alphanumeric()));
    }

    fn analyze_with_zeek(
        scenario: crate::gen::Scenario,
        format: ZeekFormat,
    ) -> (AnalysisOutput, MemorySink, ZeekReport) {
        let mut pcap = Vec::new();
        crate::gen::SynthGen::new(crate::gen::GenConfig {
            scenario,
            packets: 4000,
            ..Default::default()
        })
        .write_to(&mut pcap)
        .unwrap();
        let len = pcap.len() as u64;
        let source = crate::reader::open_reader(std::io::Cursor::new(pcap), Some(len)).unwrap();
        let mut zeek = ZeekLogger::new(MemorySink::default(), format, "2026-10-29-00-00-00");
        let out = crate::run_source_observing(
            source,
            "mem",
            len,
            &crate::PipelineConfig::default(),
            &mut zeek,
            |_, _, _| {},
        )
        .unwrap();
        let (sink, report) = zeek.finish(&out, "2026-10-29-00-00-01").unwrap();
        (out, sink, report)
    }

    /// `(fields, rows)` of a TSV log, checking every row has one value per field.
    fn tsv(text: &str) -> (Vec<String>, Vec<Vec<String>>) {
        let fields: Vec<String> = text
            .lines()
            .find_map(|l| l.strip_prefix("#fields\t"))
            .expect("#fields")
            .split('\t')
            .map(String::from)
            .collect();
        let rows: Vec<Vec<String>> = text
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(|l| l.split('\t').map(String::from).collect::<Vec<_>>())
            .collect();
        for r in &rows {
            assert_eq!(r.len(), fields.len(), "{r:?}");
        }
        assert!(text.ends_with("#close\t2026-10-29-00-00-01\n"));
        (fields, rows)
    }

    fn col(fields: &[String], name: &str) -> usize {
        fields.iter().position(|f| f == name).unwrap()
    }

    #[test]
    fn a_mixed_capture_yields_linked_zeek_logs() {
        let (out, sink, report) = analyze_with_zeek(crate::gen::Scenario::Mixed, ZeekFormat::Tsv);
        let (cf, conn) = tsv(&sink.text("conn.log"));
        assert_eq!(conn.len() as u64, out.summary.total_flows);
        let uids: std::collections::HashSet<&str> =
            conn.iter().map(|r| r[col(&cf, "uid")].as_str()).collect();
        assert_eq!(uids.len(), conn.len(), "one uid per connection");

        for log in ["dns.log", "http.log", "ssl.log"] {
            let (f, rows) = tsv(&sink.text(log));
            assert!(!rows.is_empty(), "{log} has rows");
            for r in &rows {
                assert!(
                    uids.contains(r[col(&f, "uid")].as_str()),
                    "{log} uid joins conn"
                );
            }
        }
        let (df, dns) = tsv(&sink.text("dns.log"));
        assert!(dns.iter().any(|r| r[col(&df, "query")] != "-"));
        let (hf, http) = tsv(&sink.text("http.log"));
        assert!(http
            .iter()
            .all(|r| METHODS.contains(&r[col(&hf, "method")].as_str())));
        let conn_rows = report.logs.iter().find(|(l, _)| l == "conn").unwrap().1;
        assert_eq!(conn_rows, out.summary.total_flows);
    }

    #[test]
    fn findings_become_notices_and_json_lines_parse() {
        let (out, sink, _) = analyze_with_zeek(crate::gen::Scenario::AttackChain, ZeekFormat::Json);
        assert!(!out.summary.findings.is_empty());
        let notices: Vec<serde_json::Value> = sink
            .text("notice.log")
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(notices.len(), out.summary.findings.len());
        assert!(notices
            .iter()
            .all(|n| n["note"].as_str().unwrap().starts_with("PacketPilot::")));
        for line in sink.text("conn.log").lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(v["uid"].as_str().unwrap().starts_with('C'));
            assert!(v["ts"].as_f64().unwrap() > 1.6e9);
        }
        assert!(!sink.text("conn.log").contains("#fields"));
    }

    /// A raw-IP (DLT 101) pcap of `(ts offset ms, packet)` records.
    fn raw_pcap(packets: &[(i64, Vec<u8>)]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        b.extend_from_slice(&2u16.to_le_bytes());
        b.extend_from_slice(&4u16.to_le_bytes());
        b.extend_from_slice(&[0; 8]);
        b.extend_from_slice(&65535u32.to_le_bytes());
        b.extend_from_slice(&101u32.to_le_bytes());
        for (ms, p) in packets {
            let ts = 1_700_000_000i64 * 1000 + ms;
            b.extend_from_slice(&((ts / 1000) as u32).to_le_bytes());
            b.extend_from_slice(&(((ts % 1000) * 1000) as u32).to_le_bytes());
            b.extend_from_slice(&(p.len() as u32).to_le_bytes());
            b.extend_from_slice(&(p.len() as u32).to_le_bytes());
            b.extend_from_slice(p);
        }
        b
    }

    fn udp(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, p: &[u8]) -> Vec<u8> {
        use crate::gen::frames::{build_ipv4, build_udp};
        let (s, d) = (src.into(), dst.into());
        let seg = build_udp(s, d, sp, dp, p);
        let mut pkt = build_ipv4(s, d, 17, 64, seg.len());
        pkt.extend_from_slice(&seg);
        pkt
    }

    fn tcp(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, flags: u8, p: &[u8]) -> Vec<u8> {
        let mut seg = Vec::new();
        seg.extend_from_slice(&sp.to_be_bytes());
        seg.extend_from_slice(&dp.to_be_bytes());
        seg.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 0x50, flags, 0xfa, 0xf0, 0, 0, 0, 0]);
        seg.extend_from_slice(p);
        let mut pkt = crate::gen::frames::build_ipv4(src.into(), dst.into(), 6, 64, seg.len());
        pkt.extend_from_slice(&seg);
        pkt
    }

    fn run_pcap(pcap: Vec<u8>) -> (AnalysisOutput, MemorySink) {
        let len = pcap.len() as u64;
        let source = crate::reader::open_reader(std::io::Cursor::new(pcap), Some(len)).unwrap();
        let mut zeek = ZeekLogger::new(MemorySink::default(), ZeekFormat::Tsv, "o");
        let out = crate::run_source_observing(
            source,
            "mem",
            len,
            &crate::PipelineConfig::default(),
            &mut zeek,
            |_, _, _| {},
        )
        .unwrap();
        let (sink, _) = zeek.finish(&out, "2026-10-29-00-00-01").unwrap();
        (out, sink)
    }

    #[test]
    fn dns_and_http_exchanges_pair_into_one_row_each() {
        let (c, r, w) = ([10, 0, 0, 5], [10, 0, 0, 53], [93, 184, 216, 34]);
        const PA: u8 = 0x18;
        let pcap = raw_pcap(&[
            (0, udp(c, r, 40000, 53, &dns_query(7, "example.com", 1))),
            (
                12,
                udp(r, c, 53, 40000, &dns_answer(7, "example.com", &[w], 0)),
            ),
            (20, udp(c, r, 40001, 53, &dns_query(8, "nope.test", 1))),
            (
                25,
                udp(r, c, 53, 40001, &dns_answer(8, "nope.test", &[], 3)),
            ),
            (30, tcp(c, w, 50000, 80, SYN, b"")),
            (31, tcp(w, c, 80, 50000, SYN | ACK, b"")),
            (32, tcp(c, w, 50000, 80, ACK, b"")),
            (
                33,
                tcp(
                    c,
                    w,
                    50000,
                    80,
                    PA,
                    b"GET /x.exe HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t\r\n\r\n",
                ),
            ),
            (
                40,
                tcp(
                    w,
                    c,
                    80,
                    50000,
                    PA,
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
                ),
            ),
            (41, tcp(c, w, 50000, 80, FIN | ACK, b"")),
            (42, tcp(w, c, 80, 50000, FIN | ACK, b"")),
        ]);
        let (out, sink) = run_pcap(pcap);
        assert_eq!(out.summary.total_flows, 3);

        let (df, dns) = tsv(&sink.text("dns.log"));
        assert_eq!(dns.len(), 2, "query + answer make one row");
        let ok = &dns[0];
        assert_eq!(ok[col(&df, "id.orig_h")], "10.0.0.5");
        assert_eq!(ok[col(&df, "query")], "example.com");
        assert_eq!(ok[col(&df, "rtt")], "0.012000");
        assert_eq!(ok[col(&df, "rcode_name")], "NOERROR");
        assert_eq!(ok[col(&df, "answers")], "93.184.216.34");
        assert_eq!(ok[col(&df, "TTLs")], "3600.000000");
        assert_eq!(dns[1][col(&df, "rcode_name")], "NXDOMAIN");
        assert_eq!(dns[1][col(&df, "answers")], "-");

        let (hf, http) = tsv(&sink.text("http.log"));
        assert_eq!(http.len(), 1);
        let h = &http[0];
        assert_eq!(h[col(&hf, "method")], "GET");
        assert_eq!(h[col(&hf, "uri")], "/x.exe");
        assert_eq!(h[col(&hf, "host")], "example.com");
        assert_eq!(h[col(&hf, "status_code")], "404");
        assert_eq!(h[col(&hf, "status_msg")], "Not Found");

        let (cf, conn) = tsv(&sink.text("conn.log"));
        let web = conn
            .iter()
            .find(|r| r[col(&cf, "id.resp_p")] == "80")
            .unwrap();
        assert_eq!(web[col(&cf, "uid")], h[col(&hf, "uid")]);
        assert_eq!(web[col(&cf, "id.orig_h")], "10.0.0.5");
        assert_eq!(web[col(&cf, "conn_state")], "SF");
        assert_eq!(web[col(&cf, "service")], "http");
        assert_eq!(web[col(&cf, "orig_pkts")], "4");
        assert_eq!(web[col(&cf, "resp_bytes")], "45");
        let d = conn
            .iter()
            .find(|r| r[col(&cf, "uid")] == ok[col(&df, "uid")])
            .unwrap();
        assert_eq!(d[col(&cf, "service")], "dns");
        assert_eq!(d[col(&cf, "conn_state")], "SF");
    }

    #[test]
    fn json_rows_omit_unset_and_type_values() {
        let row = json_row(
            DNS,
            &[
                Val::Time(1_500_000_000),
                Val::Str("C1".into()),
                Val::Addr("10.0.0.1".parse().unwrap()),
                Val::Port(5353),
                Val::Addr("10.0.0.2".parse().unwrap()),
                Val::Port(53),
                Val::Str("udp".into()),
                Val::Count(7),
                Val::Unset,
                Val::Str("x.test".into()),
                Val::Count(1),
                Val::Str("C_INTERNET".into()),
                Val::Count(1),
                Val::Str("A".into()),
                Val::Count(0),
                Val::Str("NOERROR".into()),
                Val::Bool(false),
                Val::Bool(false),
                Val::Bool(true),
                Val::Bool(true),
                Val::Count(0),
                Val::List(vec!["1.2.3.4".into()]),
                Val::List(vec!["60.000000".into()]),
                Val::Bool(false),
            ],
        );
        let v: serde_json::Value = serde_json::from_str(&row).unwrap();
        assert_eq!(v["ts"], 1.5);
        assert_eq!(v["id.orig_p"], 5353);
        assert!(v.get("rtt").is_none());
        assert_eq!(v["answers"][0], "1.2.3.4");
        assert_eq!(v["TTLs"][0], 60.0);
        assert_eq!(v["RD"], true);
    }
}
