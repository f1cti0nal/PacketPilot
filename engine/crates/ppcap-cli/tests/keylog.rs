//! End-to-end test for `ppcap analyze --keylog`.
//!
//! Hand-builds a capture holding one TLS 1.3 flow whose client sends the RFC 8448 §3
//! application-data record, writes a key-log mapping that flow's ClientHello random to the
//! RFC's client traffic secret, and shells out to the compiled `ppcap` binary. Frames are
//! byte-built (the core's frame builders are crate-private) to keep this a black-box test.

use std::process::Command;

const CLIENT_RANDOM: [u8; 32] = [0xab; 32];
/// RFC 8448 §3 "tls13 c ap traffic" secret.
const RFC_CLIENT_SECRET: &str = "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5";
/// RFC 8448 §3 client application_data record (decrypts to bytes 0x00..=0x31).
const RFC_APP_RECORD: &str = "1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f2b\
                              9819a8a5b46b395bd54a9a20441e2b62974e1f5a6292a2977014bd1e3deae63aee\
                              bb21694915e4";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn tls_record(content_type: u8, body: &[u8]) -> Vec<u8> {
    let mut rec = vec![content_type, 0x03, 0x03];
    rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
    rec.extend_from_slice(body);
    rec
}

fn handshake(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let len = body.len() as u32;
    let mut hs = vec![msg_type, (len >> 16) as u8, (len >> 8) as u8, len as u8];
    hs.extend_from_slice(body);
    tls_record(22, &hs)
}

/// Minimal ClientHello: legacy version, random, empty session id, one suite, null compression.
fn client_hello(random: &[u8; 32]) -> Vec<u8> {
    let mut b = vec![0x03, 0x03];
    b.extend_from_slice(random);
    b.extend_from_slice(&[0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x00]);
    handshake(1, &b)
}

/// TLS 1.3 ServerHello: legacy 0x0303 + supported_versions(0x0304), TLS_AES_128_GCM_SHA256.
fn server_hello() -> Vec<u8> {
    let mut b = vec![0x03, 0x03];
    b.extend_from_slice(&[0x5c; 32]);
    b.extend_from_slice(&[0x00, 0x13, 0x01, 0x00]); // sid len, cipher, compression
    b.extend_from_slice(&[0x00, 0x06, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    handshake(2, &b)
}

/// One Ethernet/IPv4/TCP frame (checksums left zero; the decoder does not verify them).
fn tcp_frame(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![4, 4, 4, 4, 4, 4, 2, 2, 2, 2, 2, 2, 0x08, 0x00];
    let total = (20 + 20 + payload.len()) as u16;
    f.extend_from_slice(&[0x45, 0x00]);
    f.extend_from_slice(&total.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0x40, 0x00, 64, 6, 0, 0]);
    f.extend_from_slice(&src);
    f.extend_from_slice(&dst);
    f.extend_from_slice(&sp.to_be_bytes());
    f.extend_from_slice(&dp.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 0x50, 0x18, 0xfa, 0xf0, 0, 0, 0, 0]);
    f.extend_from_slice(payload);
    f
}

fn write_capture(path: &std::path::Path) {
    let client = [10, 0, 0, 7];
    let server = [93, 184, 216, 34];
    let frames = [
        tcp_frame(client, server, 51000, 443, &client_hello(&CLIENT_RANDOM)),
        tcp_frame(server, client, 443, 51000, &server_hello()),
        tcp_frame(client, server, 51000, 443, &hex(RFC_APP_RECORD)),
    ];
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    buf.extend_from_slice(&[2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    buf.extend_from_slice(&65535u32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET
    for (i, f) in frames.iter().enumerate() {
        buf.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        buf.extend_from_slice(&(i as u32 * 1000).to_le_bytes());
        buf.extend_from_slice(&(f.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(f.len() as u32).to_le_bytes());
        buf.extend_from_slice(f);
    }
    std::fs::write(path, buf).unwrap();
}

fn analyze(args: &[&str]) -> (serde_json::Value, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_ppcap"))
        .arg("analyze")
        .args(args)
        .output()
        .expect("run ppcap");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "ppcap analyze failed: {stderr}");
    (
        serde_json::from_slice(&out.stdout).expect("JSON on stdout"),
        stderr,
    )
}

#[test]
fn keylog_decrypts_the_keyed_flow() {
    let dir = tempfile::tempdir().unwrap();
    let cap = dir.path().join("tls13.pcap");
    let keys = dir.path().join("sslkeys.log");
    write_capture(&cap);
    let cr: String = CLIENT_RANDOM.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(
        &keys,
        format!("# SSL/TLS secrets log file\nCLIENT_TRAFFIC_SECRET_0 {cr} {RFC_CLIENT_SECRET}\n"),
    )
    .unwrap();

    let (json, stderr) = analyze(&[cap.to_str().unwrap(), "--keylog", keys.to_str().unwrap()]);
    let k = &json["keylog"];
    assert_eq!(k["keylog_sessions"], 1);
    assert_eq!(k["keylog_sessions_used"], 1);
    assert_eq!(k["flows_keyed"], 1);
    assert_eq!(k["flows_decrypted"], 1);
    let f = &k["flows"][0];
    assert_eq!(f["decrypted"], true);
    assert_eq!(f["client_ip"], "10.0.0.7");
    assert_eq!(f["server_port"], 443);
    assert_eq!(f["version"], 0x0304);
    assert_eq!(f["records"], 1);
    assert!(
        stderr.contains("keylog: decrypted 1 of 1 keyed TLS flow"),
        "stderr: {stderr}"
    );

    // Without --keylog the output carries no keylog section at all.
    let (plain, _) = analyze(&[cap.to_str().unwrap(), "--quiet"]);
    assert!(plain.get("keylog").is_none());
}

#[test]
fn keylog_rejects_a_file_with_no_entries() {
    let dir = tempfile::tempdir().unwrap();
    let cap = dir.path().join("tls13.pcap");
    let keys = dir.path().join("empty.log");
    write_capture(&cap);
    std::fs::write(&keys, "# nothing here\n").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_ppcap"))
        .args([
            "analyze",
            cap.to_str().unwrap(),
            "--keylog",
            keys.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no NSS key-log entries"));
}
