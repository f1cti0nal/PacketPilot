//! End to end: files carved from FTP and SMTP are matched by `--yara` rules, extracted with
//! `--carve-dir`, logged in Zeek's files.log, and sealed in the evidence manifest.

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

const SYN: u8 = 0x02;
const FIN: u8 = 0x01;
const ACK: u8 = 0x10;
const PSH: u8 = 0x08;

/// A pcap writer for hand-built Ethernet/IPv4/TCP frames (checksums are left zero; the engine
/// doesn't check them).
struct Pcap {
    bytes: Vec<u8>,
    ts: u32,
}

impl Pcap {
    fn new() -> Pcap {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&4u16.to_le_bytes());
        bytes.extend_from_slice(&[0; 8]);
        bytes.extend_from_slice(&65535u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        Pcap { bytes, ts: 0 }
    }

    #[allow(clippy::too_many_arguments)]
    fn tcp(
        &mut self,
        src: [u8; 4],
        sp: u16,
        dst: [u8; 4],
        dp: u16,
        seq: u32,
        flags: u8,
        data: &[u8],
    ) {
        let mut f = vec![0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1, 0x08, 0x00];
        let total = 20 + 20 + data.len();
        f.extend_from_slice(&[
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            0,
            0x40,
            0,
            64,
            6,
            0,
            0,
        ]);
        f.extend_from_slice(&src);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&sp.to_be_bytes());
        f.extend_from_slice(&dp.to_be_bytes());
        f.extend_from_slice(&seq.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 1, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        f.extend_from_slice(data);
        self.ts += 1;
        self.bytes
            .extend_from_slice(&(1_700_000_000 + self.ts / 1000).to_le_bytes());
        self.bytes
            .extend_from_slice(&((self.ts % 1000) * 1000).to_le_bytes());
        self.bytes
            .extend_from_slice(&(f.len() as u32).to_le_bytes());
        self.bytes
            .extend_from_slice(&(f.len() as u32).to_le_bytes());
        self.bytes.extend_from_slice(&f);
    }
}

/// One TCP connection's state while writing it.
struct Conn {
    ends: [([u8; 4], u16); 2],
    seq: [u32; 2],
}

impl Conn {
    fn open(p: &mut Pcap, client: ([u8; 4], u16), server: ([u8; 4], u16)) -> Conn {
        let mut c = Conn {
            ends: [client, server],
            seq: [100, 70_000],
        };
        c.pkt(p, 0, SYN, b"");
        c.pkt(p, 1, SYN | ACK, b"");
        c
    }

    fn pkt(&mut self, p: &mut Pcap, d: usize, flags: u8, data: &[u8]) {
        let ((s, sp), (t, tp)) = (self.ends[d], self.ends[1 - d]);
        p.tcp(s, sp, t, tp, self.seq[d], flags, data);
        self.seq[d] += data.len() as u32 + u32::from(flags & (SYN | FIN) != 0);
    }

    fn send(&mut self, p: &mut Pcap, d: usize, data: &[u8]) {
        for c in data.chunks(1200) {
            self.pkt(p, d, PSH | ACK, c);
        }
    }

    fn fin(&mut self, p: &mut Pcap) {
        self.pkt(p, 0, FIN | ACK, b"");
        self.pkt(p, 1, FIN | ACK, b"");
    }
}

const CLIENT: [u8; 4] = [10, 1, 2, 3];
const SERVER: [u8; 4] = [198, 51, 100, 7];

fn dropper() -> Vec<u8> {
    let mut v = b"MZ\x90\x00".to_vec();
    v.extend((0..6000u32).map(|i| (i * 13 % 251) as u8));
    v.extend_from_slice(b"stage2-loader");
    v
}

fn b64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for (i, c) in data.chunks(3).enumerate() {
        if i > 0 && i % 19 == 0 {
            out.push_str("\r\n");
        }
        let n = c.iter().fold(0u32, |a, &b| a << 8 | u32::from(b)) << (8 * (3 - c.len()));
        for j in 0..4 {
            out.push(if j <= c.len() {
                char::from(A[(n >> (18 - 6 * j) & 63) as usize])
            } else {
                '='
            });
        }
    }
    out
}

fn capture(dir: &Path) -> String {
    let mut p = Pcap::new();
    // FTP: passive download of the dropper.
    let mut ctl = Conn::open(&mut p, (CLIENT, 41000), (SERVER, 21));
    ctl.send(&mut p, 1, b"220 hi\r\n");
    ctl.send(&mut p, 0, b"USER anonymous\r\nPASV\r\n");
    ctl.send(
        &mut p,
        1,
        b"227 Entering Passive Mode (198,51,100,7,39,16).\r\n",
    );
    let mut data = Conn::open(&mut p, (CLIENT, 41001), (SERVER, 10000));
    ctl.send(&mut p, 0, b"RETR update.exe\r\n");
    data.send(&mut p, 1, &dropper());
    data.pkt(&mut p, 1, FIN | ACK, b"");
    ctl.send(&mut p, 1, b"226 done\r\n");
    ctl.fin(&mut p);

    // SMTP: the same dropper mailed out as an attachment.
    let mut m = Conn::open(&mut p, (CLIENT, 41002), (SERVER, 25));
    m.send(&mut p, 1, b"220 mx\r\n");
    m.send(
        &mut p,
        0,
        b"EHLO a\r\nMAIL FROM:<a@x.test>\r\nRCPT TO:<b@y.test>\r\nDATA\r\n",
    );
    m.send(&mut p, 1, b"250 a\r\n250 b\r\n250 c\r\n354 go\r\n");
    let msg = format!(
        "Subject: invoice\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b1\r\n\r\n\
         --b1\r\nContent-Type: text/plain\r\n\r\nhello\r\n\
         --b1\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"invoice.exe\"\r\n\
         Content-Transfer-Encoding: base64\r\n\r\n{}\r\n--b1--\r\n.\r\n",
        b64(&dropper())
    );
    m.send(&mut p, 0, msg.as_bytes());
    m.send(&mut p, 1, b"250 queued\r\n");
    m.fin(&mut p);

    let path = dir.join("transfers.pcap");
    std::fs::write(&path, &p.bytes).unwrap();
    path.to_str().unwrap().to_string()
}

const RULES: &str = r#"
rule Stage2_Loader : dropper {
    meta:
        description = "test loader marker"
        severity = "critical"
        mitre_attack = "T1105"
    strings:
        $m = "stage2-loader"
        $mz = { 4D 5A 90 00 }
    condition:
        $mz at 0 and $m and filesize < 1MB
}
rule Uses_Regex { strings: $r = /stage[0-9]/ condition: $r }
"#;

#[test]
fn carved_ftp_and_smtp_files_match_yara_and_are_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let pcap = capture(dir.path());
    let rules = dir.path().join("rules.yar");
    std::fs::write(&rules, RULES).unwrap();
    let summary = dir.path().join("a.json");
    let carve = dir.path().join("carved");
    let logs = dir.path().join("zeek");
    let case = dir.path().join("case.json");
    let out = ok(&[
        "analyze",
        &pcap,
        "--json",
        summary.to_str().unwrap(),
        "--yara",
        rules.to_str().unwrap(),
        "--carve-dir",
        carve.to_str().unwrap(),
        "--zeek",
        logs.to_str().unwrap(),
        "--evidence",
        case.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("skipped Uses_Regex"), "{stderr}");
    assert!(stderr.contains("1 rules loaded, 1 skipped"), "{stderr}");

    let a: Value = serde_json::from_str(&std::fs::read_to_string(&summary).unwrap()).unwrap();
    let files = a["summary"]["carved_files"].as_array().unwrap();
    let by_proto = |p: &str| files.iter().find(|f| f["protocol"] == p).unwrap().clone();
    let ftp = by_proto("ftp");
    let smtp = by_proto("smtp");
    assert_eq!(ftp["filename"], "update.exe");
    assert_eq!(smtp["filename"], "invoice.exe");
    assert_eq!(smtp["upload"], true);
    assert_eq!(ftp["sha256"], smtp["sha256"], "same bytes, same hash");
    for f in [&ftp, &smtp] {
        assert_eq!(f["yara"], serde_json::json!(["Stage2_Loader"]));
        let path = f["extracted_path"].as_str().unwrap();
        assert!(path.ends_with(".exe.quarantine"), "{path}");
    }

    let yara: Vec<&Value> = a["summary"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["title"] == "YARA Stage2_Loader")
        .collect();
    assert_eq!(yara.len(), 2);
    assert!(yara.iter().all(|f| f["kind"] == "rule_match"
        && f["severity"] == "critical"
        && f["attack"] == serde_json::json!(["T1105"])
        && f["src_ip"] == "10.1.2.3"));
    assert!(yara.iter().any(|f| f
        .to_string()
        .contains("email attachment sent via 198.51.100.7 (invoice.exe)")));

    let files_log = std::fs::read_to_string(logs.join("files.log")).unwrap();
    assert!(files_log.contains("\tFTP\t"), "{files_log}");
    assert!(files_log.contains("\tSMTP\t"), "{files_log}");
    assert!(files_log.contains("Stage2_Loader"));

    let manifest = std::fs::read_to_string(&case).unwrap();
    assert!(manifest.contains("\"yara_rules\""));
    assert!(manifest.contains("--yara"));
    ok(&["verify", case.to_str().unwrap()]);
    std::fs::write(&rules, "rule edited { condition: true }").unwrap();
    assert!(!ppcap(&["verify", case.to_str().unwrap()]).status.success());
}

#[test]
fn yara_without_usable_rules_fails_before_the_pass() {
    let dir = tempfile::tempdir().unwrap();
    let pcap = capture(dir.path());
    let rules = dir.path().join("bad.yar");
    std::fs::write(
        &rules,
        "rule only_regex { strings: $r = /x+/ condition: $r }",
    )
    .unwrap();
    let out = ppcap(&[
        "analyze",
        &pcap,
        "--yara",
        rules.to_str().unwrap(),
        "--quiet",
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no usable YARA rules"));
}

#[test]
fn zeek_command_takes_yara_rules() {
    let dir = tempfile::tempdir().unwrap();
    let pcap = capture(dir.path());
    let rules = dir.path().join("rules.yar");
    std::fs::write(&rules, RULES).unwrap();
    let logs = dir.path().join("z");
    ok(&[
        "zeek",
        &pcap,
        "-o",
        logs.to_str().unwrap(),
        "--yara",
        rules.to_str().unwrap(),
        "--quiet",
    ]);
    let notice = std::fs::read_to_string(logs.join("notice.log")).unwrap();
    assert!(notice.contains("YARA Stage2_Loader"), "{notice}");
}

#[test]
fn a_later_rule_file_can_reference_an_earlier_one() {
    let dir = tempfile::tempdir().unwrap();
    let pcap = capture(dir.path());
    let base = dir.path().join("base.yar");
    std::fs::write(
        &base,
        "private rule IsPE { condition: uint16(0) == 0x5A4D }",
    )
    .unwrap();
    let det = dir.path().join("det.yar");
    std::fs::write(&det, "rule PE_Over_Wire { condition: IsPE }").unwrap();
    let summary = dir.path().join("a.json");
    ok(&[
        "analyze",
        &pcap,
        "--json",
        summary.to_str().unwrap(),
        "--yara",
        base.to_str().unwrap(),
        "--yara",
        det.to_str().unwrap(),
        "--quiet",
    ]);
    let a: Value = serde_json::from_str(&std::fs::read_to_string(&summary).unwrap()).unwrap();
    assert!(a["summary"]["carved_files"]
        .as_array()
        .unwrap()
        .iter()
        .all(|f| f["yara"] == serde_json::json!(["PE_Over_Wire"])));
}
