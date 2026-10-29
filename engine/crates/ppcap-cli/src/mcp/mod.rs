//! `ppcap mcp`: a local Model Context Protocol server over stdio.
//!
//! An agent host (Claude Desktop, Claude Code, Cursor, an Ollama-backed agent, ...) launches
//! `ppcap mcp <capture-or-summary>...` as a child process and exchanges newline-delimited
//! JSON-RPC 2.0 messages on stdin/stdout. Nothing listens on a socket and nothing leaves the
//! machine: the tools read the loaded analyses, the flows Parquet and the capture itself.
//!
//! Every tool is read-only by default. Two capabilities are opt-in at launch and their tools are
//! not even listed without them: writing carved pcaps (`--allow-write <DIR>`, confined to that
//! directory) and online reputation lookups (`--online`, using the provider API keys from the
//! environment). Logging goes to stderr; stdout carries protocol messages only.
//!
//! The protocol layer is hand-rolled on `serde_json` (initialize, ping, tools/*, prompts/*) so
//! the build stays C-compiler-free and adds no dependency.

pub(crate) mod capture;
mod flows;
mod time;
mod tools;

use std::io::{BufRead, Write};
use std::path::PathBuf;

use serde_json::{json, Value};

pub use capture::{Capture, LoadOptions};

/// MCP protocol revisions this server speaks, newest first. A client asking for one of these
/// gets it echoed back; any other request is answered with the newest.
const PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// Default ceiling on one tool response's text, so a careless query cannot flood the agent's
/// context. Tools also cap their own lists well below this.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 100_000;

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

/// What the server may do beyond reading, fixed at launch.
#[derive(Clone, Debug, Default)]
pub struct ServerOptions {
    /// `carve_pcap` is offered only when set, and writes only inside this directory.
    pub allow_write: Option<PathBuf>,
    /// Online reputation lookups in `lookup_indicator` (needs provider API keys).
    pub online: bool,
    /// See [`DEFAULT_MAX_RESPONSE_BYTES`].
    pub max_response_bytes: usize,
}

/// The loaded captures plus the launch-time options. One server per process.
pub struct Server {
    pub(crate) captures: Vec<Capture>,
    pub(crate) feed: Option<ppcap_core::ThreatFeed>,
    pub(crate) opts: ServerOptions,
}

impl Server {
    pub fn new(
        captures: Vec<Capture>,
        feed: Option<ppcap_core::ThreatFeed>,
        mut opts: ServerOptions,
    ) -> Server {
        if opts.max_response_bytes == 0 {
            opts.max_response_bytes = DEFAULT_MAX_RESPONSE_BYTES;
        }
        Server {
            captures,
            feed,
            opts,
        }
    }

    /// Handle one decoded JSON-RPC message (or batch). Returns the reply to write, or `None`
    /// for notifications and client responses, which get no reply.
    pub fn handle(&mut self, msg: Value) -> Option<Value> {
        match msg {
            Value::Array(items) => {
                if items.is_empty() {
                    return Some(error_reply(Value::Null, INVALID_REQUEST, "empty batch"));
                }
                let replies: Vec<Value> = items
                    .into_iter()
                    .filter_map(|m| self.handle_one(m))
                    .collect();
                if replies.is_empty() {
                    None
                } else {
                    Some(Value::Array(replies))
                }
            }
            other => self.handle_one(other),
        }
    }

    fn handle_one(&mut self, msg: Value) -> Option<Value> {
        let Value::Object(obj) = msg else {
            return Some(error_reply(
                Value::Null,
                INVALID_REQUEST,
                "a JSON-RPC message must be an object",
            ));
        };
        let id = obj.get("id").cloned();
        let Some(method) = obj.get("method").and_then(Value::as_str) else {
            // A response to a request we never send, or garbage: replies only to the latter.
            return match id {
                Some(id) if !obj.contains_key("result") && !obj.contains_key("error") => {
                    Some(error_reply(id, INVALID_REQUEST, "missing method"))
                }
                _ => None,
            };
        };
        let params = obj.get("params").cloned().unwrap_or(Value::Null);
        // Notifications (no id) never get a reply, even when unknown.
        let id = id?;
        let result = match method {
            "initialize" => Ok(self.initialize(&params)),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": tools::definitions(self) })),
            "tools/call" => self.call_tool(&params),
            "prompts/list" => Ok(json!({ "prompts": tools::prompt_definitions() })),
            "prompts/get" => tools::get_prompt(self, &params).map_err(|m| (INVALID_PARAMS, m)),
            _ => Err((METHOD_NOT_FOUND, format!("method not found: {method}"))),
        };
        Some(match result {
            Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
            Err((code, m)) => error_reply(id, code, &m),
        })
    }

    fn initialize(&self, params: &Value) -> Value {
        let asked = params.get("protocolVersion").and_then(Value::as_str);
        let version = asked
            .filter(|v| PROTOCOL_VERSIONS.contains(v))
            .unwrap_or(PROTOCOL_VERSIONS[0]);
        let loaded: Vec<&str> = self.captures.iter().map(|c| c.id.as_str()).collect();
        json!({
            "protocolVersion": version,
            "capabilities": {
                "tools": { "listChanged": false },
                "prompts": { "listChanged": false },
            },
            "serverInfo": {
                "name": "packetpilot",
                "title": "PacketPilot",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "instructions": format!(
                "PacketPilot exposes offline network-capture triage. Loaded captures: {}. Start \
                 with list_alerts (the ranked queue), drill in with get_alert and host_profile, \
                 and check every claim against the traffic itself with query_flows and \
                 get_packets before reporting it. Timestamps are UTC ISO-8601.",
                loaded.join(", ")
            ),
        })
    }

    fn call_tool(&mut self, params: &Value) -> Result<Value, (i64, String)> {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or((INVALID_PARAMS, "tools/call needs a tool name".to_string()))?;
        let args = params.get("arguments").cloned().unwrap_or(json!({}));
        if !args.is_object() {
            return Err((INVALID_PARAMS, "tool arguments must be an object".into()));
        }
        if !tools::definitions(self)
            .iter()
            .any(|t| t["name"].as_str() == Some(name))
        {
            return Err((INVALID_PARAMS, format!("unknown tool: {name}")));
        }
        // Tool failures (bad arguments, unknown alert id, ...) are results with isError, so the
        // agent sees the message and can correct itself; protocol errors are reserved above.
        Ok(match tools::call(self, name, &args) {
            Ok(v) => {
                let text = serde_json::to_string(&v).unwrap_or_else(|_| "null".into());
                if text.len() > self.opts.max_response_bytes {
                    tool_error(&format!(
                        "the result is {} bytes, over this server's {}-byte cap; narrow the \
                         query (filters, a smaller limit) and try again",
                        text.len(),
                        self.opts.max_response_bytes
                    ))
                } else {
                    json!({ "content": [{ "type": "text", "text": text }], "isError": false })
                }
            }
            Err(m) => tool_error(&m),
        })
    }
}

fn tool_error(message: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": message }], "isError": true })
}

fn error_reply(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Serve newline-delimited JSON-RPC on `input` until EOF, writing replies to `output`.
pub fn serve(
    server: &mut Server,
    input: impl BufRead,
    mut output: impl Write,
) -> std::io::Result<()> {
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(msg) => server.handle(msg),
            Err(e) => Some(error_reply(
                Value::Null,
                PARSE_ERROR,
                &format!("parse error: {e}"),
            )),
        };
        if let Some(r) = reply {
            serde_json::to_writer(&mut output, &r)?;
            output.write_all(b"\n")?;
            output.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
