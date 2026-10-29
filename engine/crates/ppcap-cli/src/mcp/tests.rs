use std::path::Path;

use serde_json::{json, Value};

use super::capture::{load, LoadOptions};
use super::*;

/// A small synthetic attack chain: 10.13.37.7 sweeps and brute-forces 10.66.0.1, which then
/// beacons and exfiltrates — one act-now chain alert with a timeline.
fn gen_capture(dir: &Path, name: &str) -> PathBuf {
    use ppcap_core::gen::{GenConfig, Scenario, SynthGen};
    let path = dir.join(name);
    SynthGen::new(GenConfig {
        scenario: Scenario::AttackChain,
        packets: 3000,
        ..Default::default()
    })
    .write_pcap(&path)
    .unwrap();
    path
}

fn opts(dir: &Path) -> LoadOptions {
    LoadOptions {
        threat_feed: None,
        suppress: Vec::new(),
        work_dir: dir.to_path_buf(),
        quiet: true,
    }
}

fn server_with(dir: &Path, allow_write: Option<PathBuf>) -> Server {
    let pcap = gen_capture(dir, "chain.pcap");
    let c = load(&pcap, &opts(dir), &[]).unwrap();
    Server::new(
        vec![c],
        Some(ppcap_core::ThreatFeed::empty()),
        ServerOptions {
            allow_write,
            ..Default::default()
        },
    )
}

fn rpc(s: &mut Server, method: &str, params: Value) -> Value {
    s.handle(json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
        .expect("a request gets a reply")
}

/// Call a tool; returns (isError, parsed JSON or the raw message as a string).
fn call(s: &mut Server, name: &str, args: Value) -> (bool, Value) {
    let r = rpc(s, "tools/call", json!({ "name": name, "arguments": args }));
    let res = &r["result"];
    let text = res["content"][0]["text"].as_str().unwrap().to_string();
    let v = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (res["isError"].as_bool().unwrap(), v)
}

fn ok(s: &mut Server, name: &str, args: Value) -> Value {
    let (err, v) = call(s, name, args);
    assert!(!err, "{name} failed: {v}");
    v
}

#[test]
fn initialize_negotiates_the_protocol_version() {
    let mut s = Server::new(Vec::new(), None, ServerOptions::default());
    let r = rpc(
        &mut s,
        "initialize",
        json!({ "protocolVersion": "2025-03-26" }),
    );
    assert_eq!(r["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(r["result"]["serverInfo"]["name"], "packetpilot");
    assert!(r["result"]["capabilities"]["tools"].is_object());
    let r = rpc(
        &mut s,
        "initialize",
        json!({ "protocolVersion": "1999-01-01" }),
    );
    assert_eq!(r["result"]["protocolVersion"], PROTOCOL_VERSIONS[0]);
}

#[test]
fn json_rpc_edge_cases() {
    let mut s = Server::new(Vec::new(), None, ServerOptions::default());
    // Notifications, known or not, get no reply.
    assert!(s
        .handle(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
        .is_none());
    assert!(s
        .handle(json!({ "jsonrpc": "2.0", "method": "whatever" }))
        .is_none());
    // A client's response to us is not answered either.
    assert!(s
        .handle(json!({ "jsonrpc": "2.0", "id": 7, "result": {} }))
        .is_none());
    let r = rpc(&mut s, "resources/list", json!({}));
    assert_eq!(r["error"]["code"], METHOD_NOT_FOUND);
    assert_eq!(rpc(&mut s, "ping", json!({}))["result"], json!({}));
    let r = rpc(&mut s, "tools/call", json!({ "name": "rm_rf" }));
    assert_eq!(r["error"]["code"], INVALID_PARAMS);
    // Batches answer every request in order.
    let r = s
        .handle(json!([
            { "jsonrpc": "2.0", "id": "a", "method": "ping" },
            { "jsonrpc": "2.0", "method": "notifications/initialized" },
            { "jsonrpc": "2.0", "id": "b", "method": "ping" }
        ]))
        .unwrap();
    assert_eq!(r.as_array().unwrap().len(), 2);
    assert_eq!(r[1]["id"], "b");
}

#[test]
fn serve_speaks_newline_delimited_json() {
    let mut s = Server::new(Vec::new(), None, ServerOptions::default());
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n\nnot json\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";
    let mut out = Vec::new();
    serve(&mut s, &input[..], &mut out).unwrap();
    let lines: Vec<Value> = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["id"], 1);
    assert_eq!(lines[1]["error"]["code"], PARSE_ERROR);
    assert_eq!(lines[1]["id"], Value::Null);
}

#[test]
fn carving_is_listed_only_when_writes_are_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = server_with(dir.path(), None);
    let names = |s: &mut Server| -> Vec<String> {
        rpc(s, "tools/list", json!({}))["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    };
    let ro = names(&mut s);
    assert!(ro.contains(&"get_packets".to_string()));
    assert!(!ro.contains(&"carve_pcap".to_string()));
    // Every listed tool is marked read-only.
    for t in rpc(&mut s, "tools/list", json!({}))["result"]["tools"]
        .as_array()
        .unwrap()
    {
        assert_eq!(t["annotations"]["readOnlyHint"], true, "{}", t["name"]);
        assert_eq!(t["inputSchema"]["type"], "object");
    }
    // An unlisted tool cannot be called.
    let r = rpc(
        &mut s,
        "tools/call",
        json!({ "name": "carve_pcap", "arguments": {} }),
    );
    assert_eq!(r["error"]["code"], INVALID_PARAMS);

    s.opts.allow_write = Some(dir.path().to_path_buf());
    assert!(names(&mut s).contains(&"carve_pcap".to_string()));
}

#[test]
fn alerts_drill_down_with_findings_and_timeline() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = server_with(dir.path(), None);
    let caps = ok(&mut s, "list_captures", json!({}));
    assert_eq!(caps["captures"][0]["id"], "chain");
    assert_eq!(caps["captures"][0]["packets_available"], true);
    assert_eq!(caps["flow_columns"].as_array().unwrap().len(), 35);

    let ov = ok(&mut s, "capture_overview", json!({}));
    assert_eq!(ov["packets"], 3000);
    assert!(ov["first_packet"].as_str().unwrap().ends_with('Z'));

    let list = ok(&mut s, "list_alerts", json!({ "min_band": "investigate" }));
    let alerts = list["alerts"].as_array().unwrap();
    assert!(!alerts.is_empty());
    let top = &alerts[0];
    assert_eq!(top["actor"], "10.13.37.7");
    let id = top["id"].as_str().unwrap().to_string();

    let a = ok(&mut s, "get_alert", json!({ "alert_id": id }));
    assert_eq!(a["alert"]["id"], id.as_str());
    assert!(!a["alert"]["narrative"].as_str().unwrap().is_empty());
    let findings = a["findings"].as_array().unwrap();
    assert_eq!(findings.len() as u64, a["findings_total"].as_u64().unwrap());
    assert!(!findings.is_empty());
    let events = a["timeline"]["events"].as_array().unwrap();
    assert!(!events.is_empty());
    // Instants leave as ISO strings, with no `_ns` keys left behind.
    let text = a.to_string();
    for k in ["\"ts_ns\"", "\"first_seen_ns\"", "\"start_ns\""] {
        assert!(!text.contains(k), "{k} leaked into get_alert");
    }

    // Without the prefix works too; an unknown id is a tool error the agent can read.
    let bare = id.trim_start_matches("alert:");
    ok(
        &mut s,
        "get_alert",
        json!({ "alert_id": bare, "include_findings": false }),
    );
    let (err, msg) = call(&mut s, "get_alert", json!({ "alert_id": "alert:nope" }));
    assert!(err);
    assert!(msg.as_str().unwrap().contains("list_alerts"));

    let host = ok(&mut s, "list_alerts", json!({ "host": "10.66.0.1" }));
    assert!(host["total"].as_u64().unwrap() >= 1);
    let none = ok(&mut s, "list_alerts", json!({ "host": "192.0.2.99" }));
    assert_eq!(none["total"], 0);
    let (err, _) = call(&mut s, "list_alerts", json!({ "min_band": "urgent" }));
    assert!(err);
}

#[test]
fn query_flows_filters_groups_and_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = server_with(dir.path(), None);
    let all = ok(&mut s, "query_flows", json!({ "limit": 5 }));
    let total = all["flows_scanned"].as_u64().unwrap();
    assert_eq!(all["flows_matched"].as_u64().unwrap(), total);
    let rows = all["flows"].as_array().unwrap();
    assert_eq!(rows.len(), 5);
    // Default sort: bytes, descending.
    let bytes: Vec<u64> = rows.iter().map(|r| r["bytes"].as_u64().unwrap()).collect();
    assert!(bytes.windows(2).all(|w| w[0] >= w[1]));

    let g = ok(
        &mut s,
        "query_flows",
        json!({ "group_by": "dst_port", "sort": "flows", "limit": 500 }),
    );
    let grouped: u64 = g["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["flows"].as_u64().unwrap())
        .sum();
    assert_eq!(grouped, total, "every flow lands in exactly one group");

    let ssh = ok(
        &mut s,
        "query_flows",
        json!({ "ip": "10.13.37.7", "peer": "10.66.0.1", "dst_port": 22, "proto": "tcp" }),
    );
    let n = ssh["flows_matched"].as_u64().unwrap();
    assert!(n >= 1);
    for r in ssh["flows"].as_array().unwrap() {
        assert_eq!(r["dst_port"], 22);
        assert_eq!(r["proto"], "TCP");
    }
    let windowed = ok(
        &mut s,
        "query_flows",
        json!({ "until": "2000-01-01T00:00:00Z" }),
    );
    assert_eq!(windowed["flows_matched"], 0);

    for bad in [
        json!({ "ip": "not-an-ip" }),
        json!({ "proto": "carrier-pigeon" }),
        json!({ "group_by": "colour" }),
        json!({ "sort": "flows" }),
        json!({ "peer": "10.0.0.1" }),
        json!({ "since": "last tuesday" }),
    ] {
        let (err, _) = call(&mut s, "query_flows", bad.clone());
        assert!(err, "{bad} should be rejected");
    }
}

#[test]
fn get_packets_reads_the_flow_back_from_the_capture() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = server_with(dir.path(), None);
    let q = ok(
        &mut s,
        "query_flows",
        json!({ "src_ip": "10.13.37.7", "dst_port": 22, "limit": 1 }),
    );
    let flow = &q["flows"][0];
    let id = flow["flow_id"].as_u64().unwrap();
    let p = ok(&mut s, "get_packets", json!({ "flow_id": id }));
    assert_eq!(p["total_packets"], flow["pkts"]);
    let pkts = p["packets"].as_array().unwrap();
    assert!(!pkts.is_empty());
    assert!(pkts[0]["flags"].as_str().unwrap().contains("SYN"));
    assert_eq!(pkts[0]["dir"], "c2s");

    // The same flow by 5-tuple.
    let t = ok(
        &mut s,
        "get_packets",
        json!({
            "src_ip": flow["src_ip"], "dst_ip": flow["dst_ip"],
            "src_port": flow["src_port"], "dst_port": flow["dst_port"], "proto": "tcp",
            "limit": 1
        }),
    );
    assert_eq!(t["returned"], 1);
    assert!(t["total_packets"].as_u64().unwrap() >= 1);

    let (err, msg) = call(&mut s, "get_packets", json!({ "src_ip": "10.0.0.1" }));
    assert!(err);
    assert!(msg.as_str().unwrap().contains("flow_id"));
}

#[test]
fn host_profile_and_indicator_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = server_with(dir.path(), None);
    let h = ok(&mut s, "host_profile", json!({ "ip": "10.13.37.7" }));
    assert_eq!(h["ip_class"], "private");
    assert!(!h["alerts"].as_array().unwrap().is_empty());
    assert!(h["traffic"]["flows_initiated"].as_u64().unwrap() > 0);
    assert!(h["traffic"]["top_peers"].as_array().unwrap().len() <= 10);

    let l = ok(&mut s, "lookup_indicator", json!({ "value": "10.66.0.1" }));
    assert_eq!(l["kind"], "ip");
    assert_eq!(l["captures"][0]["seen"], true);
    assert!(
        l["captures"][0]["matches"]["flows"]["count"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(l["threat_feed"]["listed"], false);
    assert!(l.get("reputation").is_none(), "offline by default");

    let unseen = ok(
        &mut s,
        "lookup_indicator",
        json!({ "value": "198.51.100.200" }),
    );
    assert_eq!(unseen["captures"][0]["seen"], false);
    let d = ok(
        &mut s,
        "lookup_indicator",
        json!({ "value": "Example.COM." }),
    );
    assert_eq!(d["kind"], "domain");
    assert_eq!(d["value"], "example.com");
    let (err, _) = call(
        &mut s,
        "lookup_indicator",
        json!({ "value": "hello world" }),
    );
    assert!(err);

    // A feed listing the C2 makes the lookup say so.
    s.feed = Some(
        ppcap_core::ThreatFeed::from_json_str(
            r#"{"version":1,"label":"test feed","bad_ips":["45.77.13.37"]}"#,
        )
        .unwrap(),
    );
    let f = ok(
        &mut s,
        "lookup_indicator",
        json!({ "value": "45.77.13.37" }),
    );
    assert_eq!(f["threat_feed"]["listed"], true);
    assert_eq!(f["threat_feed"]["feed"], "test feed");
}

#[test]
fn carve_pcap_stays_in_its_directory_and_never_overwrites() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("exports");
    std::fs::create_dir_all(&out).unwrap();
    let mut s = server_with(dir.path(), Some(out.clone()));
    let a = ok(
        &mut s,
        "carve_pcap",
        json!({ "host": "10.13.37.7", "peer": "10.66.0.1", "name": "../../escape" }),
    );
    let p1 = PathBuf::from(a["path"].as_str().unwrap());
    assert_eq!(p1.parent().unwrap(), out.as_path());
    assert!(a["packets"].as_u64().unwrap() > 0);
    // The carve is a valid capture holding exactly those packets.
    let src = ppcap_core::reader::open(&p1).unwrap();
    let mut src = src;
    let mut n = 0;
    while src.next_frame().unwrap().is_some() {
        n += 1;
    }
    assert_eq!(n, a["packets"].as_u64().unwrap());

    let b = ok(
        &mut s,
        "carve_pcap",
        json!({ "host": "10.13.37.7", "peer": "10.66.0.1", "name": "../../escape" }),
    );
    assert_ne!(a["path"], b["path"]);
    assert!(b["path"].as_str().unwrap().ends_with("-2.pcap"));
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 2);
}

#[test]
fn oversized_responses_ask_the_agent_to_narrow() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = server_with(dir.path(), None);
    s.opts.max_response_bytes = 200;
    let (err, msg) = call(&mut s, "query_flows", json!({ "limit": 100 }));
    assert!(err);
    assert!(msg.as_str().unwrap().contains("narrow"));
}

#[test]
fn summaries_load_with_their_pcap_and_flows_and_ids_disambiguate() {
    let dir = tempfile::tempdir().unwrap();
    let pcap = gen_capture(dir.path(), "chain.pcap");
    // The shape `analyze --json --parquet` leaves behind, with paths relative to the summary.
    let parquet = dir.path().join("chain.parquet");
    let cfg = ppcap_core::PipelineConfig {
        flows_parquet: Some(parquet.clone()),
        ..Default::default()
    };
    let mut out = ppcap_core::run(&pcap, &cfg, |_, _, _| {}).unwrap();
    out.source_path = "chain.pcap".into();
    out.flows_parquet_path = Some("chain.parquet".into());
    let summary = dir.path().join("chain.json");
    std::fs::write(&summary, out.to_json().unwrap()).unwrap();

    let work = dir.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let o = opts(&work);
    let a = load(&summary, &o, &[]).unwrap();
    assert_eq!(a.id, "chain");
    assert_eq!(a.pcap.as_deref(), Some(pcap.as_path()));
    assert_eq!(a.flows.as_deref(), Some(parquet.as_path()));
    let b = load(&pcap, &o, std::slice::from_ref(&a.id)).unwrap();
    assert_eq!(b.id, "chain-2");

    let mut s = Server::new(vec![a, b], None, ServerOptions::default());
    let (err, msg) = call(&mut s, "list_alerts", json!({}));
    assert!(err);
    assert!(msg.as_str().unwrap().contains("chain-2"));
    let x = ok(&mut s, "list_alerts", json!({ "capture": "chain-2" }));
    let y = ok(&mut s, "list_alerts", json!({ "capture": "chain" }));
    assert_eq!(x["alerts"][0]["id"], y["alerts"][0]["id"]);
    // An indicator lookup spans both captures by default.
    let l = ok(&mut s, "lookup_indicator", json!({ "value": "10.13.37.7" }));
    assert_eq!(l["captures"].as_array().unwrap().len(), 2);
    assert!(load(&dir.path().join("missing.pcap"), &o, &[]).is_err());
}

#[test]
fn triage_prompt_names_the_capture_and_focus() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = server_with(dir.path(), None);
    let list = rpc(&mut s, "prompts/list", json!({}));
    assert_eq!(list["result"]["prompts"][0]["name"], "triage");
    let r = rpc(
        &mut s,
        "prompts/get",
        json!({ "name": "triage", "arguments": { "focus": "10.66.0.1" } }),
    );
    let text = r["result"]["messages"][0]["content"]["text"]
        .as_str()
        .unwrap();
    assert!(text.contains("`chain`"));
    assert!(text.contains("10.66.0.1"));
    assert!(text.contains("get_packets"));
    let r = rpc(&mut s, "prompts/get", json!({ "name": "nope" }));
    assert_eq!(r["error"]["code"], INVALID_PARAMS);
}
