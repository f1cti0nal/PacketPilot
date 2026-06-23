//! Export of behavioral findings as analyst/SIEM-friendly CSV and STIX 2.1.
//!
//! These turn PacketPilot from a consumer of threat intel into a *producer* of it: the
//! behavioral findings (and the IPs/techniques they implicate) become a CSV for a spreadsheet
//! or SIEM, and a STIX 2.1 bundle for TAXII / interchange with other tools.
//!
//! Both functions are pure over an [`AnalysisOutput`]. STIX object ids are derived
//! deterministically from content (no `rand` dependency — see [`det_uuid`]), so the same
//! analysis always produces the same bundle. The "created/modified" wall-clock time is supplied
//! by the caller (the engine has no clock), exactly like the HTML report.

use std::collections::{BTreeMap, BTreeSet};

use crate::model::output::AnalysisOutput;

/// Render the behavioral findings as CSV (one row per finding, with a header).
pub fn findings_csv(out: &AnalysisOutput) -> String {
    let mut s = String::from("kind,severity,score,src_ip,dst_ip,dst_port,attack,title,evidence\n");
    for f in &out.summary.findings {
        let cols = [
            f.kind.as_str().to_string(),
            f.severity.as_str().to_string(),
            f.score.to_string(),
            f.src_ip.clone(),
            f.dst_ip.clone().unwrap_or_default(),
            f.dst_port.map(|p| p.to_string()).unwrap_or_default(),
            f.attack.join(";"),
            f.title.clone(),
            f.evidence.join("; "),
        ];
        let row: Vec<String> = cols.iter().map(|c| csv_field(c)).collect();
        s.push_str(&row.join(","));
        s.push('\n');
    }
    s
}

/// Accumulated indicator state for one external IP.
struct IndicatorAcc {
    name: String,
    description: String,
    attack: BTreeSet<String>,
}

/// Render a STIX 2.1 bundle (indicators + attack-patterns + relationships) derived from the
/// findings. `generated_unix_secs` is the caller-supplied "created/modified" UTC time.
pub fn stix_bundle(out: &AnalysisOutput, generated_unix_secs: i64) -> String {
    let ts = iso(generated_unix_secs);

    // One indicator per external destination IP a finding implicates, plus the union of all
    // ATT&CK techniques seen.
    let mut indicators: BTreeMap<String, IndicatorAcc> = BTreeMap::new();
    let mut techniques: BTreeSet<String> = BTreeSet::new();
    for f in &out.summary.findings {
        for a in &f.attack {
            techniques.insert(a.clone());
        }
        if let Some(dst) = &f.dst_ip {
            let e = indicators
                .entry(dst.clone())
                .or_insert_with(|| IndicatorAcc {
                    name: format!("Malicious host {dst}"),
                    description: f.title.clone(),
                    attack: BTreeSet::new(),
                });
            for a in &f.attack {
                e.attack.insert(a.clone());
            }
        }
    }

    let mut objects: Vec<serde_json::Value> = Vec::new();

    // attack-pattern SDOs, one per technique, with a MITRE external reference.
    let mut ap_ids: BTreeMap<String, String> = BTreeMap::new();
    for t in &techniques {
        let id = format!(
            "attack-pattern--{}",
            det_uuid(&format!("attack-pattern:{t}"))
        );
        ap_ids.insert(t.clone(), id.clone());
        objects.push(serde_json::json!({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": id,
            "created": ts,
            "modified": ts,
            "name": t,
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": t,
                // Sub-technique ids (e.g. T1071.004) map to a /Txxxx/yyy URL path.
                "url": format!("https://attack.mitre.org/techniques/{}", t.replace('.', "/"))
            }]
        }));
    }

    // indicator SDOs + "indicates" relationships to the attack-patterns they implicate.
    for (ip, acc) in &indicators {
        let ind_id = format!("indicator--{}", det_uuid(&format!("indicator:{ip}")));
        objects.push(serde_json::json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": ts,
            "modified": ts,
            "name": acc.name,
            "description": acc.description,
            "indicator_types": ["malicious-activity"],
            "pattern": format!("[ipv4-addr:value = '{ip}']"),
            "pattern_type": "stix",
            "valid_from": ts
        }));
        for t in &acc.attack {
            if let Some(ap) = ap_ids.get(t) {
                let rid = format!("relationship--{}", det_uuid(&format!("rel:{ip}:{t}")));
                objects.push(serde_json::json!({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": rid,
                    "created": ts,
                    "modified": ts,
                    "relationship_type": "indicates",
                    "source_ref": ind_id,
                    "target_ref": ap
                }));
            }
        }
    }

    // JA3/JA4 fingerprint indicators (deduped across IPs; deterministic order).
    let mut fps: BTreeMap<String, &crate::model::summary::FingerprintHit> = BTreeMap::new();
    for t in &out.summary.ip_threats {
        for fp in &t.fingerprints {
            let key = format!(
                "{}|{}|{}",
                fp.ja3.as_deref().unwrap_or(""),
                fp.ja4.as_deref().unwrap_or(""),
                fp.label
            );
            fps.entry(key).or_insert(fp);
        }
    }
    for (key, fp) in &fps {
        let mut parts: Vec<String> = Vec::new();
        if let Some(j) = &fp.ja3 {
            parts.push(format!("x-tls-fingerprint:ja3 = '{j}'"));
        }
        if let Some(j) = &fp.ja4 {
            parts.push(format!("x-tls-fingerprint:ja4 = '{j}'"));
        }
        if parts.is_empty() {
            continue;
        }
        let ind_id = format!("indicator--{}", det_uuid(&format!("indicator:fp:{key}")));
        objects.push(serde_json::json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": ts,
            "modified": ts,
            "name": format!("Malicious TLS fingerprint ({})", fp.label),
            "description": format!("TLS client fingerprint attributed to {}", fp.label),
            "indicator_types": ["malicious-activity"],
            "pattern": format!("[{}]", parts.join(" OR ")),
            "pattern_type": "stix",
            "valid_from": ts
        }));
    }

    let bundle = serde_json::json!({
        "type": "bundle",
        "id": format!(
            "bundle--{}",
            det_uuid(&format!("bundle:{}:{generated_unix_secs}", out.source_path))
        ),
        "objects": objects
    });
    serde_json::to_string_pretty(&bundle).unwrap_or_else(|_| "{}".to_string())
}

/// Format Unix seconds as an RFC 3339 / STIX timestamp (UTC).
fn iso(secs: i64) -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

/// Quote a CSV field iff it contains a comma, quote, CR, or LF (RFC 4180), doubling quotes.
fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// A deterministic, syntactically-valid UUID derived from `seed` (no randomness). Uses two
/// FNV-1a-64 passes for 128 bits, then stamps the version (5) and variant nibbles so STIX
/// validators accept it; identical seeds always yield the same id.
fn det_uuid(seed: &str) -> String {
    fn fnv1a(bytes: &[u8], mut h: u64) -> u64 {
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
        }
        h
    }
    let a = fnv1a(seed.as_bytes(), 0xcbf2_9ce4_8422_2325);
    let b = fnv1a(seed.as_bytes(), a ^ 0x9E37_79B9_7F4A_7C15);
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&a.to_be_bytes());
    bytes[8..].copy_from_slice(&b.to_be_bytes());
    bytes[6] = (bytes[6] & 0x0F) | 0x50; // version 5 (name-based)
    bytes[8] = (bytes[8] & 0x3F) | 0x80; // RFC 4122 variant
    let h: String = bytes.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::IpClass;
    use crate::model::finding::{Finding, FindingKind};
    use crate::model::severity::Severity;
    use crate::model::summary::{FingerprintHit, IpThreat, Summary};

    fn finding(kind: FindingKind, sev: Severity, dst: Option<&str>, attack: &[&str]) -> Finding {
        Finding {
            kind,
            severity: sev,
            score: 70,
            title: format!("{} finding", kind.as_str()),
            src_ip: "10.0.0.5".to_string(),
            dst_ip: dst.map(|s| s.to_string()),
            dst_port: Some(443),
            attack: attack.iter().map(|s| s.to_string()).collect(),
            evidence: vec!["evidence, with comma".to_string()],
            interval_ns: None,
            jitter_cv: None,
            contacts: None,
        }
    }

    fn out_with(findings: Vec<Finding>) -> AnalysisOutput {
        let mut summary = Summary::empty();
        summary.findings = findings;
        AnalysisOutput {
            schema_version: 1,
            engine_version: "test".to_string(),
            source_path: "cap.pcap".to_string(),
            source_sha256: None,
            source_bytes: 0,
            link_type: "EN10MB".to_string(),
            summary,
            flows_parquet_path: None,
            elapsed_ms: 0,
        }
    }

    #[test]
    fn findings_csv_has_header_and_one_row_per_finding() {
        let out = out_with(vec![
            finding(
                FindingKind::Beacon,
                Severity::High,
                Some("8.8.8.8"),
                &["T1071"],
            ),
            finding(FindingKind::HostSweep, Severity::High, None, &["T1046"]),
        ]);
        let csv = findings_csv(&out);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 3, "header + 2 rows: {csv}");
        assert!(lines[0].starts_with("kind,severity,score,src_ip,dst_ip,dst_port,attack,title"));
        assert!(lines[1].contains("beacon"));
        assert!(lines[1].contains("8.8.8.8"));
        assert!(lines[1].contains("high"));
        // The evidence field has a comma, so it must be quoted (RFC 4180).
        assert!(csv.contains("\"evidence, with comma\""));
    }

    #[test]
    fn findings_csv_is_header_only_when_no_findings() {
        let csv = findings_csv(&out_with(vec![]));
        assert_eq!(csv.lines().count(), 1);
    }

    #[test]
    fn stix_bundle_has_indicator_attack_pattern_and_relationship() {
        let out = out_with(vec![finding(
            FindingKind::Beacon,
            Severity::High,
            Some("8.8.8.8"),
            &["T1071"],
        )]);
        let json = stix_bundle(&out, 1_700_000_000);
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(v["type"], "bundle");
        let objs = v["objects"].as_array().expect("objects array");

        let indicator = objs
            .iter()
            .find(|o| o["type"] == "indicator")
            .expect("an indicator");
        assert!(indicator["pattern"].as_str().unwrap().contains("8.8.8.8"));
        assert_eq!(indicator["spec_version"], "2.1");

        let ap = objs
            .iter()
            .find(|o| o["type"] == "attack-pattern")
            .expect("an attack-pattern");
        assert_eq!(ap["external_references"][0]["external_id"], "T1071");

        assert!(objs.iter().any(|o| o["type"] == "relationship"));
    }

    #[test]
    fn det_uuid_is_stable_and_well_formed() {
        let a = det_uuid("indicator:8.8.8.8");
        let b = det_uuid("indicator:8.8.8.8");
        assert_eq!(a, b);
        assert_ne!(a, det_uuid("indicator:1.1.1.1"));
        assert_eq!(a.len(), 36);
        assert_eq!(a.as_bytes()[14], b'5'); // version nibble
    }

    fn out_with_ip_threat() -> AnalysisOutput {
        let mut base = out_with(vec![]);
        base.summary.ip_threats = vec![IpThreat {
            ip: "198.51.100.1".to_string(),
            ip_class: IpClass::Public,
            severity: Severity::High,
            score: 80,
            flows: 1,
            bytes: 512,
            ioc: true,
            tags: vec!["public".to_string(), "ioc".to_string()],
            attack: vec!["T1071".to_string()],
            evidence: vec!["test evidence".to_string()],
            reputation: vec![],
            fingerprints: vec![],
        }];
        base
    }

    #[test]
    fn stix_emits_ja3_fingerprint_indicator() {
        let mut out = out_with_ip_threat();
        out.summary.ip_threats[0].fingerprints = vec![FingerprintHit {
            ja3: Some("e7d705a3286e19ea42f587b344ee6865".into()),
            ja4: None,
            label: "CobaltStrike".into(),
        }];
        let bundle = stix_bundle(&out, 1_700_000_000);
        assert!(bundle.contains("CobaltStrike"), "missing label: {bundle}");
        assert!(
            bundle.contains("e7d705a3286e19ea42f587b344ee6865"),
            "missing ja3 hash: {bundle}"
        );
        assert!(
            bundle.contains("x-tls-fingerprint:ja3"),
            "missing pattern field name: {bundle}"
        );
        // deterministic: same input => same bundle
        assert_eq!(bundle, stix_bundle(&out, 1_700_000_000));
    }
}
