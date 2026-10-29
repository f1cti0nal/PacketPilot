//! End to end: `ppcap push` delivers a real analysis over HTTP to a local stand-in for a SIEM,
//! records the deliveries in its ledger, and sends nothing the second time.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use serde_json::Value;

#[derive(Debug, Clone)]
struct Request {
    line: String,
    headers: Vec<(String, String)>,
    body: String,
}

/// A one-thread HTTP/1.1 server answering every request with HEC's success body.
fn serve() -> (u16, Arc<Mutex<Vec<Request>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            let mut headers = Vec::new();
            let mut len = 0usize;
            loop {
                let mut h = String::new();
                reader.read_line(&mut h).unwrap();
                let h = h.trim_end();
                if h.is_empty() {
                    break;
                }
                if let Some((k, v)) = h.split_once(':') {
                    if k.eq_ignore_ascii_case("content-length") {
                        len = v.trim().parse().unwrap();
                    }
                    headers.push((k.to_ascii_lowercase(), v.trim().to_string()));
                }
            }
            let mut body = vec![0u8; len];
            reader.read_exact(&mut body).unwrap();
            log.lock().unwrap().push(Request {
                line: line.trim_end().to_string(),
                headers,
                body: String::from_utf8(body).unwrap(),
            });
            let answer = r#"{"text":"Success","code":0}"#;
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                answer.len()
            );
        }
    });
    (port, seen)
}

#[test]
fn push_delivers_over_http_and_dedupes_by_ledger() {
    let bin = env!("CARGO_BIN_EXE_ppcap");
    let dir = tempfile::tempdir().unwrap();
    let pcap = dir.path().join("chain.pcap");
    let summary = dir.path().join("summary.json");
    let ok = |args: &[&str]| {
        let st = Command::new(bin)
            .args(args)
            .stderr(Stdio::null())
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "ppcap {args:?}");
    };
    ok(&[
        "gen",
        pcap.to_str().unwrap(),
        "--scenario",
        "attack-chain",
        "--packets",
        "3000",
    ]);
    ok(&[
        "analyze",
        pcap.to_str().unwrap(),
        "--json",
        summary.to_str().unwrap(),
        "--quiet",
    ]);
    let analysis: Value =
        serde_json::from_str(&std::fs::read_to_string(&summary).unwrap()).unwrap();
    let alert_count = analysis["summary"]["alerts"].as_array().unwrap().len();
    assert!(alert_count > 0, "the attack-chain scenario raises alerts");

    let (port, seen) = serve();
    let dests = dir.path().join("destinations.json");
    std::fs::write(
        &dests,
        format!(
            r#"{{"destinations":[
                {{"name":"hec","kind":"splunk_hec","url":"http://127.0.0.1:{port}",
                  "token_env":"PPCAP_TEST_HEC"}},
                {{"name":"hook","kind":"webhook","url":"http://127.0.0.1:{port}/hook",
                  "min_band":"act_now"}}
            ]}}"#
        ),
    )
    .unwrap();

    let push = || {
        Command::new(bin)
            .args([
                "push",
                summary.to_str().unwrap(),
                "-d",
                dests.to_str().unwrap(),
                "--json",
                "-",
            ])
            .env("PPCAP_TEST_HEC", "hec-secret")
            .stderr(Stdio::piped())
            .output()
            .unwrap()
    };
    let first = push();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let report: Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(report["destinations"][0]["sent"], alert_count);

    let reqs = seen.lock().unwrap().clone();
    let hec = reqs
        .iter()
        .find(|r| r.line.starts_with("POST /services/collector/event "))
        .expect("HEC request");
    assert!(hec
        .headers
        .contains(&("authorization".into(), "Splunk hec-secret".into())));
    let events: Vec<Value> = hec
        .body
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(events.len(), alert_count);
    assert_eq!(events[0]["event"]["schema"], "packetpilot.alert/1");
    let act_now = analysis["summary"]["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["band"] == "act_now")
        .count();
    let hooks = reqs
        .iter()
        .filter(|r| r.line.starts_with("POST /hook "))
        .count();
    assert_eq!(hooks, act_now);

    let ledger: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join("push-ledger.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        ledger["sent"]["hec"].as_object().unwrap().len(),
        alert_count
    );

    // Second run: everything is already in the ledger, so nothing is sent.
    let before = seen.lock().unwrap().len();
    let second = push();
    assert!(second.status.success());
    let report: Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(report["destinations"][0]["sent"], 0);
    assert_eq!(report["destinations"][0]["already_sent"], alert_count);
    assert_eq!(seen.lock().unwrap().len(), before);
}

#[test]
fn push_example_parses_and_an_empty_queue_needs_no_secrets() {
    let bin = env!("CARGO_BIN_EXE_ppcap");
    let out = Command::new(bin)
        .args(["push", "--example"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("\"token_env\""));
    assert!(!text.to_lowercase().contains("\"token\""));

    let dir = tempfile::tempdir().unwrap();
    let summary = dir.path().join("s.json");
    std::fs::write(
        &summary,
        serde_json::to_string(&ppcap_core_like_summary()).unwrap(),
    )
    .unwrap();
    let dests = dir.path().join("d.json");
    std::fs::write(
        &dests,
        r#"{"destinations":[{"name":"h","kind":"splunk_hec","url":"https://hec.invalid",
            "token_env":"PPCAP_TEST_UNSET_TOKEN"}]}"#,
    )
    .unwrap();
    let out = Command::new(bin)
        .args([
            "push",
            summary.to_str().unwrap(),
            "-d",
            dests.to_str().unwrap(),
        ])
        .env_remove("PPCAP_TEST_UNSET_TOKEN")
        .output()
        .unwrap();
    // No alerts in an empty analysis: nothing to send, so a missing token is not an error.
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The smallest analysis JSON the CLI accepts: the serialized default output.
fn ppcap_core_like_summary() -> Value {
    let bin = env!("CARGO_BIN_EXE_ppcap");
    let dir = tempfile::tempdir().unwrap();
    let pcap = dir.path().join("web.pcap");
    let st = Command::new(bin)
        .args([
            "gen",
            pcap.to_str().unwrap(),
            "--scenario",
            "web-only",
            "--packets",
            "200",
        ])
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success());
    let out = Command::new(bin)
        .args(["analyze", pcap.to_str().unwrap(), "--quiet"])
        .output()
        .unwrap();
    let mut v: Value = serde_json::from_slice(&out.stdout).unwrap();
    v["summary"]["alerts"] = Value::Array(Vec::new());
    v["summary"]["findings"] = Value::Array(Vec::new());
    v
}
