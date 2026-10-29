//! End to end: `ppcap mcp` as an agent host runs it — a child process speaking newline-delimited
//! JSON-RPC on stdin/stdout, with logging kept off stdout.

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

#[test]
fn mcp_serves_a_capture_over_stdio() {
    let bin = env!("CARGO_BIN_EXE_ppcap");
    let dir = tempfile::tempdir().unwrap();
    let pcap = dir.path().join("chain.pcap");
    let st = Command::new(bin)
        .args([
            "gen",
            pcap.to_str().unwrap(),
            "--scenario",
            "attack-chain",
            "--packets",
            "3000",
        ])
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success());

    let mut child = Command::new(bin)
        .args(["mcp", pcap.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let msgs = [
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": { "protocolVersion": "2025-06-18", "capabilities": {},
                            "clientInfo": { "name": "test", "version": "0" } } }),
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
        json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": { "name": "list_alerts", "arguments": { "limit": 1 } } }),
    ];
    {
        let mut stdin = child.stdin.take().unwrap();
        for m in &msgs {
            writeln!(stdin, "{m}").unwrap();
        }
    } // EOF ends the session.
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Every stdout line is a JSON-RPC reply (progress went to stderr), one per request.
    let replies: Vec<Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).expect("stdout carries protocol only"))
        .collect();
    assert_eq!(replies.len(), 3);
    assert_eq!(replies[0]["result"]["protocolVersion"], "2025-06-18");
    let tools: Vec<&str> = replies[1]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(tools.contains(&"query_flows"));
    assert!(
        !tools.contains(&"carve_pcap"),
        "read-only unless --allow-write"
    );
    let text = replies[2]["result"]["content"][0]["text"].as_str().unwrap();
    let alerts: Value = serde_json::from_str(text).unwrap();
    assert_eq!(alerts["alerts"][0]["actor"], "10.13.37.7");
    assert!(String::from_utf8_lossy(&out.stderr).contains("serving on stdio"));
}
