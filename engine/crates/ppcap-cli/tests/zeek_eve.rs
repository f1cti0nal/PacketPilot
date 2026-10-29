//! End to end: `ppcap zeek` and `analyze --zeek` write linked Zeek logs, and Suricata EVE alerts
//! fold into the analysis through `analyze --eve` and `ppcap eve`.

use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::Value;

fn ppcap(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ppcap"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn ok(args: &[&str]) -> std::process::Output {
    let out = ppcap(args);
    assert!(
        out.status.success(),
        "ppcap {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn gen(dir: &Path, scenario: &str) -> String {
    let pcap = dir.join(format!("{scenario}.pcap"));
    let p = pcap.to_str().unwrap().to_string();
    ok(&["gen", &p, "--scenario", scenario, "--packets", "3000"]);
    p
}

/// `(fields, rows)` of a Zeek TSV log.
fn tsv(path: &Path) -> (Vec<String>, Vec<Vec<String>>) {
    let text = std::fs::read_to_string(path).unwrap();
    let fields: Vec<String> = text
        .lines()
        .find_map(|l| l.strip_prefix("#fields\t"))
        .unwrap()
        .split('\t')
        .map(String::from)
        .collect();
    let rows = text
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| l.split('\t').map(String::from).collect())
        .collect();
    (fields, rows)
}

const EVE: &str = r#"{"timestamp":"2023-11-14T22:13:21.000000+0000","event_type":"alert","src_ip":"10.9.9.9","src_port":4444,"dest_ip":"203.0.113.77","dest_port":8443,"proto":"TCP","alert":{"gid":1,"signature_id":9000001,"rev":1,"signature":"TEST sensor hit","category":"A Network Trojan was detected","severity":1,"metadata":{"mitre_technique_id":["T1071"]}}}
{"timestamp":"2023-11-14T22:13:22.000000+0000","event_type":"flow","src_ip":"10.9.9.9","dest_ip":"203.0.113.77"}
"#;

#[test]
fn zeek_command_writes_linked_logs() {
    let dir = tempfile::tempdir().unwrap();
    let pcap = gen(dir.path(), "attack-chain");
    let logs = dir.path().join("logs");
    let summary = dir.path().join("s.json");
    ok(&[
        "zeek",
        &pcap,
        "-o",
        logs.to_str().unwrap(),
        "--summary",
        summary.to_str().unwrap(),
        "--quiet",
    ]);
    let analysis: Value =
        serde_json::from_str(&std::fs::read_to_string(&summary).unwrap()).unwrap();

    let (cf, conn) = tsv(&logs.join("conn.log"));
    assert_eq!(
        conn.len() as u64,
        analysis["summary"]["total_flows"].as_u64().unwrap()
    );
    let uid = cf.iter().position(|f| f == "uid").unwrap();
    let uids: std::collections::HashSet<String> = conn.iter().map(|r| r[uid].clone()).collect();

    let (_, notices) = tsv(&logs.join("notice.log"));
    assert_eq!(
        notices.len(),
        analysis["summary"]["findings"].as_array().unwrap().len()
    );
    for log in ["dns.log", "http.log"] {
        let path = logs.join(log);
        if path.exists() {
            let (f, rows) = tsv(&path);
            let i = f.iter().position(|f| f == "uid").unwrap();
            assert!(
                rows.iter().all(|r| uids.contains(&r[i])),
                "{log} joins conn"
            );
        }
    }
}

#[test]
fn analyze_writes_zeek_json_and_folds_eve_alerts() {
    let dir = tempfile::tempdir().unwrap();
    let pcap = gen(dir.path(), "mixed");
    let eve = dir.path().join("eve.json");
    std::fs::write(&eve, EVE).unwrap();
    let logs = dir.path().join("zj");
    let summary = dir.path().join("a.json");
    ok(&[
        "analyze",
        &pcap,
        "--json",
        summary.to_str().unwrap(),
        "--eve",
        eve.to_str().unwrap(),
        "--zeek",
        logs.to_str().unwrap(),
        "--zeek-json",
        "--evidence",
        dir.path().join("case.json").to_str().unwrap(),
        "--quiet",
    ]);
    let analysis: Value =
        serde_json::from_str(&std::fs::read_to_string(&summary).unwrap()).unwrap();
    let hit = analysis["summary"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["title"] == "TEST sensor hit")
        .expect("EVE alert became a finding");
    assert_eq!(hit["kind"], "rule_match");
    assert_eq!(hit["severity"], "high");
    assert!(analysis["summary"]["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["host"] == "10.9.9.9" || a.to_string().contains("10.9.9.9")));

    let conn = std::fs::read_to_string(logs.join("conn.log")).unwrap();
    for line in conn.lines() {
        let v: Value = serde_json::from_str(line).unwrap();
        assert!(v["uid"].as_str().unwrap().starts_with('C'));
    }
    let notice = std::fs::read_to_string(logs.join("notice.log")).unwrap();
    assert!(notice
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .any(|n| n["msg"] == "TEST sensor hit" && n["note"] == "PacketPilot::rule_match"));

    // The evidence manifest covers the EVE input and every Zeek log.
    let case = dir.path().join("case.json");
    let manifest = std::fs::read_to_string(&case).unwrap();
    assert!(manifest.contains("\"eve_input\""));
    assert!(manifest.contains("notice.log"));
    ok(&["verify", case.to_str().unwrap()]);
    std::fs::write(logs.join("notice.log"), "tampered\n").unwrap();
    assert!(!ppcap(&["verify", case.to_str().unwrap()]).status.success());
}

#[test]
fn eve_command_updates_a_saved_analysis_once() {
    let dir = tempfile::tempdir().unwrap();
    let pcap = gen(dir.path(), "web-only");
    let summary = dir.path().join("a.json");
    ok(&[
        "analyze",
        &pcap,
        "--json",
        summary.to_str().unwrap(),
        "--quiet",
    ]);
    let eve = dir.path().join("eve.json");
    std::fs::write(&eve, EVE).unwrap();
    let s = summary.to_str().unwrap();
    let e = eve.to_str().unwrap();
    let count = |path: &str| {
        let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        v["summary"]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["title"] == "TEST sensor hit")
            .count()
    };
    ok(&["eve", s, e, "--json", s, "--quiet"]);
    assert_eq!(count(s), 1);
    ok(&["eve", s, e, "--json", s, "--quiet"]);
    assert_eq!(count(s), 1, "re-importing adds nothing");

    let bad = dir.path().join("bad.json");
    std::fs::write(&bad, "{\"x\":1}\n").unwrap();
    assert!(!ppcap(&["eve", s, bad.to_str().unwrap(), "--quiet"])
        .status
        .success());
}
