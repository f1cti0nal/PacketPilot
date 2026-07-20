//! Export of behavioral findings into analyst/SIEM-friendly formats: CSV, STIX 2.1, MISP, CEF, and
//! Sigma detection rules.
//!
//! These turn PacketPilot from a consumer of threat intel into a *producer* of it: the behavioral
//! findings (and the IPs/techniques they implicate) become a CSV for a spreadsheet, a STIX 2.1
//! bundle for TAXII, a MISP event, CEF records for a SIEM, and Sigma rules for deployable detection.
//!
//! Every function is pure over an [`AnalysisOutput`]. STIX object ids are derived
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

    // grouping SDOs, one per reconstructed attack chain — a cross-host, ATT&CK-ordered sequence
    // that a SOC ingests as a single suspicious-activity story. Additive; deterministic id from the
    // chain id. STIX requires >=1 object_ref, so a chain with no resolvable refs is skipped.
    for c in &out.summary.attack_chains {
        let mut refs: Vec<String> = Vec::new();
        for t in &c.attack {
            if let Some(ap) = ap_ids.get(t) {
                refs.push(ap.clone());
            }
        }
        let mut peers: BTreeSet<String> = BTreeSet::new();
        for step in &c.steps {
            if let Some(p) = &step.peer {
                peers.insert(p.clone());
            }
        }
        for p in &peers {
            if indicators.contains_key(p) {
                refs.push(format!(
                    "indicator--{}",
                    det_uuid(&format!("indicator:{p}"))
                ));
            }
        }
        if refs.is_empty() {
            continue;
        }
        let gid = format!("grouping--{}", det_uuid(&format!("grouping:{}", c.id)));
        objects.push(serde_json::json!({
            "type": "grouping",
            "spec_version": "2.1",
            "id": gid,
            "created": ts,
            "modified": ts,
            "name": c.title,
            "description": c.narrative,
            "context": "suspicious-activity",
            "object_refs": refs
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

/// Escape a CEF extension value (CEF spec: backslash, pipe, equals, newline).
fn cef_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('=', "\\=")
        .replace('\n', "\\n")
        .replace('\r', "")
}

/// CEF severity 0..=10 from the engine severity band.
fn cef_severity(sev: crate::model::severity::Severity) -> u8 {
    use crate::model::severity::Severity;
    match sev {
        Severity::Critical => 10,
        Severity::High => 8,
        Severity::Medium => 5,
        Severity::Low => 3,
        Severity::Info => 1,
    }
}

/// MISP `threat_level_id` (1 High, 2 Medium, 3 Low, 4 Undefined) from the worst band present.
fn misp_threat_level(sc: &crate::model::summary::SeverityCounts) -> &'static str {
    if sc.critical > 0 || sc.high > 0 {
        "1"
    } else if sc.medium > 0 {
        "2"
    } else if sc.low > 0 {
        "3"
    } else {
        "4"
    }
}

/// Render the analysis as a MISP core-format Event JSON (flat Attributes). Deterministic;
/// `generated_unix_secs` stamps the event date/timestamp.
pub fn misp_event(out: &AnalysisOutput, generated_unix_secs: i64) -> String {
    use crate::enrich::RepStatus;
    let date = iso(generated_unix_secs)
        .split('T')
        .next()
        .unwrap_or("1970-01-01")
        .to_string();
    let base = out
        .source_path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("capture");

    let mut attrs: Vec<serde_json::Value> = Vec::new();
    let mut techniques: BTreeSet<String> = BTreeSet::new();
    let mut seen_ip: BTreeSet<String> = BTreeSet::new();

    let attr = |type_: &str, value: &str, to_ids: bool, comment: &str| {
        serde_json::json!({
            "uuid": det_uuid(&format!("misp:attr:{type_}:{value}")),
            "type": type_,
            "category": "Network activity",
            "value": value,
            "to_ids": to_ids,
            "comment": comment
        })
    };

    for f in &out.summary.findings {
        for a in &f.attack {
            techniques.insert(a.clone());
        }
        if let Some(dst) = &f.dst_ip {
            if seen_ip.insert(dst.clone()) {
                attrs.push(attr("ip-dst", dst, true, &f.title));
            }
        }
    }
    for d in &out.summary.domain_threats {
        let mal = d
            .reputation
            .iter()
            .any(|r| r.status == RepStatus::Malicious);
        attrs.push(attr("domain", &d.host, mal, ""));
    }
    let mut fps: BTreeMap<String, &crate::model::summary::FingerprintHit> = BTreeMap::new();
    for t in &out.summary.ip_threats {
        for fp in &t.fingerprints {
            fps.entry(format!(
                "{}|{}|{}",
                fp.ja3.as_deref().unwrap_or(""),
                fp.ja4.as_deref().unwrap_or(""),
                fp.label
            ))
            .or_insert(fp);
        }
    }
    for fp in fps.values() {
        if let Some(j) = &fp.ja3 {
            attrs.push(attr("ja3-fingerprint-md5", j, true, &fp.label));
        }
        if let Some(j) = &fp.ja4 {
            attrs.push(attr("ja4", j, true, &fp.label));
        }
    }

    let tags: Vec<serde_json::Value> = techniques
        .iter()
        .map(|t| serde_json::json!({ "name": format!("mitre-attack:{t}") }))
        .collect();

    let event = serde_json::json!({ "Event": {
        "uuid": det_uuid(&format!("misp:event:{}:{generated_unix_secs}", out.source_path)),
        "info": format!("PacketPilot analysis of {base} — {} findings", out.summary.findings.len()),
        "date": date,
        "threat_level_id": misp_threat_level(&out.summary.severity_counts),
        "analysis": "2",
        "published": false,
        "timestamp": generated_unix_secs.to_string(),
        "Attribute": attrs,
        "Tag": tags
    }});
    serde_json::to_string_pretty(&event).unwrap_or_else(|_| "{}".to_string())
}

/// Render the findings as CEF (one line per finding; ArcSight/syslog). Empty findings → "".
pub fn cef_records(out: &AnalysisOutput) -> String {
    let mut lines: Vec<String> = Vec::new();
    for f in &out.summary.findings {
        let mut ext = format!("src={}", cef_escape(&f.src_ip));
        if let Some(d) = &f.dst_ip {
            ext.push_str(&format!(" dst={}", cef_escape(d)));
        }
        if let Some(p) = f.dst_port {
            ext.push_str(&format!(" dpt={p}"));
        }
        if !f.attack.is_empty() {
            ext.push_str(&format!(
                " cs1Label=ATT&CK cs1={}",
                cef_escape(&f.attack.join(","))
            ));
        }
        ext.push_str(&format!(" cn1Label=score cn1={}", f.score));
        if !f.evidence.is_empty() {
            ext.push_str(&format!(" msg={}", cef_escape(&f.evidence.join("; "))));
        }
        lines.push(format!(
            "CEF:0|PacketPilot|PacketPilot|{}|{}|{}|{}|{}",
            cef_escape(&out.engine_version),
            cef_escape(f.kind.as_str()),
            cef_escape(&f.title),
            cef_severity(f.severity),
            ext
        ));
    }
    lines.join("\n")
}

/// Render the behavioral findings as Sigma detection rules — a multi-document YAML stream, one rule
/// per finding. Sigma is the open, vendor-neutral detection-rule format; this turns PacketPilot's
/// findings into rules an analyst can adapt and deploy in a SIEM (the spec's "auto-generate
/// Sigma/SIEM rules from observed threats"). Pure over [`AnalysisOutput`]; each rule's `id` is a
/// deterministic UUID derived from the finding (no randomness), so the same analysis always yields
/// the same rules.
pub fn sigma_rules(out: &AnalysisOutput) -> String {
    let mut docs: Vec<String> = Vec::new();
    for f in &out.summary.findings {
        let id = det_uuid(&format!(
            "sigma|{}|{}|{}|{}",
            f.kind.as_str(),
            f.src_ip,
            f.dst_ip.as_deref().unwrap_or(""),
            f.dst_port.map(|p| p.to_string()).unwrap_or_default()
        ));
        let mut doc = String::new();
        doc.push_str(&format!(
            "title: {}\n",
            yaml_str(&format!("PacketPilot: {}", f.title))
        ));
        doc.push_str(&format!("id: {id}\n"));
        doc.push_str("status: experimental\n");
        if !f.evidence.is_empty() {
            doc.push_str(&format!(
                "description: {}\n",
                yaml_str(&f.evidence.join("; "))
            ));
        }
        doc.push_str("author: PacketPilot\n");
        if !f.attack.is_empty() {
            doc.push_str("references:\n");
            for a in &f.attack {
                doc.push_str(&format!("  - {}\n", yaml_str(&attack_url(a))));
            }
        }
        doc.push_str(&format!(
            "logsource:\n  category: {}\n",
            sigma_category(f.kind)
        ));
        doc.push_str("detection:\n  selection:\n");
        if let Some(dst) = &f.dst_ip {
            doc.push_str(&format!("    dst_ip: {}\n", yaml_str(dst)));
            if let Some(p) = f.dst_port {
                doc.push_str(&format!("    dst_port: {p}\n"));
            }
        } else {
            // Fan-out findings (e.g. a host sweep) have no single destination — key on the actor.
            doc.push_str(&format!("    src_ip: {}\n", yaml_str(&f.src_ip)));
        }
        doc.push_str("  condition: selection\n");
        doc.push_str("fields:\n  - src_ip\n  - dst_ip\n  - dst_port\n");
        doc.push_str("falsepositives:\n  - Legitimate administrative or monitoring traffic\n");
        doc.push_str(&format!("level: {}\n", sigma_level(f.severity)));
        if !f.attack.is_empty() {
            doc.push_str("tags:\n");
            for a in &f.attack {
                doc.push_str(&format!("  - attack.{}\n", a.to_ascii_lowercase()));
            }
        }
        docs.push(doc);
    }
    docs.join("---\n")
}

/// A double-quoted YAML scalar with `\`, `"`, and control chars escaped/flattened.
fn yaml_str(s: &str) -> String {
    let cleaned = s.replace('\\', "\\\\").replace('"', "\\\"");
    let cleaned = cleaned.replace(['\n', '\r', '\t'], " ");
    format!("\"{cleaned}\"")
}

/// MITRE ATT&CK technique reference URL (sub-techniques map `Txxxx.yyy` -> `Txxxx/yyy`).
fn attack_url(id: &str) -> String {
    format!(
        "https://attack.mitre.org/techniques/{}/",
        id.replace('.', "/")
    )
}

/// Sigma `level` for a finding severity.
fn sigma_level(sev: crate::model::severity::Severity) -> &'static str {
    use crate::model::severity::Severity;
    match sev {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "informational",
    }
}

/// Sigma `logsource.category` best matching a finding kind's protocol.
fn sigma_category(kind: crate::model::finding::FindingKind) -> &'static str {
    use crate::model::finding::FindingKind;
    match kind {
        FindingKind::DnsTunnel | FindingKind::Dga => "dns",
        FindingKind::CleartextCreds | FindingKind::PiiExposure => "proxy",
        _ => "firewall",
    }
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
            first_seen_ns: None,
            last_seen_ns: None,
            victims: Vec::new(),
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
            baseline: None,
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
    fn stix_bundle_groups_attack_chains() {
        use crate::model::attack_chain::{AttackChain, ChainStep};
        let mut out = out_with(vec![finding(
            FindingKind::Beacon,
            Severity::High,
            Some("8.8.8.8"),
            &["T1071"],
        )]);
        out.summary.attack_chains = vec![AttackChain {
            id: "chain:00ff".into(),
            severity: Severity::Critical,
            score: 100,
            confidence: 90,
            title: "Cross-host attack chain: A -> B".into(),
            narrative: "A brute-forced B; then B beaconed to a C2.".into(),
            hosts: vec!["10.0.0.1".into(), "10.0.0.2".into()],
            steps: vec![ChainStep {
                order: 0,
                actor: "10.0.0.2".into(),
                tactic_ordinal: 4,
                tactic: "Command & Control".into(),
                kind: FindingKind::Beacon,
                techniques: vec![],
                peer: Some("8.8.8.8".into()),
                severity: Severity::High,
                score: 70,
                first_seen_ns: Some(1),
                last_seen_ns: Some(2),
                evidence: None,
                finding_index: 0,
            }],
            edges: vec![],
            tactics: vec![],
            attack: vec!["T1071".into()],
            campaign_id: None,
            first_ts_ns: Some(1),
            last_ts_ns: Some(2),
            host_count: 2,
            tactic_count: 1,
        }];
        let json = stix_bundle(&out, 1_700_000_000);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let objs = v["objects"].as_array().unwrap();

        let grouping = objs
            .iter()
            .find(|o| o["type"] == "grouping")
            .expect("a grouping SDO for the chain");
        assert_eq!(grouping["context"], "suspicious-activity");
        assert_eq!(grouping["name"], "Cross-host attack chain: A -> B");

        // The grouping references the T1071 attack-pattern and the 8.8.8.8 indicator.
        let ap_id = objs.iter().find(|o| o["type"] == "attack-pattern").unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        let refs = grouping["object_refs"].as_array().unwrap();
        assert!(
            refs.iter().any(|r| r.as_str() == Some(ap_id.as_str())),
            "grouping must reference the technique attack-pattern: {refs:?}"
        );
        assert!(
            refs.iter()
                .any(|r| r.as_str().is_some_and(|s| s.starts_with("indicator--"))),
            "grouping must reference the peer indicator: {refs:?}"
        );
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
            score_terms: vec![],
        }];
        base
    }

    /// A fixture with findings + an ip_threat (reused for MISP/CEF tests).
    fn sample_output_with_findings() -> AnalysisOutput {
        out_with(vec![
            finding(
                FindingKind::Beacon,
                Severity::High,
                Some("8.8.8.8"),
                &["T1071"],
            ),
            finding(FindingKind::HostSweep, Severity::Medium, None, &["T1046"]),
        ])
    }

    /// An empty-findings fixture (reused for MISP/CEF tests).
    fn empty_output() -> AnalysisOutput {
        out_with(vec![])
    }

    #[test]
    fn misp_event_has_attributes_and_is_deterministic() {
        let out = sample_output_with_findings();
        let s = misp_event(&out, 1_700_000_000);
        let v: serde_json::Value = serde_json::from_str(&s).expect("valid JSON");
        assert_eq!(v["Event"]["analysis"], "2");
        let attrs = v["Event"]["Attribute"].as_array().unwrap();
        assert!(attrs.iter().any(|a| a["type"] == "ip-dst")); // an external dst IP from a finding
                                                              // deterministic:
        assert_eq!(s, misp_event(&out, 1_700_000_000));
    }

    #[test]
    fn cef_records_one_escaped_line_per_finding() {
        let out = sample_output_with_findings();
        let s = cef_records(&out);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), out.summary.findings.len());
        assert!(lines
            .iter()
            .all(|l| l.starts_with("CEF:0|PacketPilot|PacketPilot|")));
        // severity is a 0-10 int in the 7th pipe field
        let f0 = &out.summary.findings[0];
        assert!(lines[0].contains(&format!("|{}|", cef_severity(f0.severity))));
    }

    #[test]
    fn cef_escape_escapes_specials() {
        assert_eq!(cef_escape("a|b=c\\d"), "a\\|b\\=c\\\\d");
    }

    #[test]
    fn sigma_rules_one_doc_per_finding_with_selectors_and_level() {
        let out = sample_output_with_findings();
        let s = sigma_rules(&out);
        // One YAML document per finding (joined by a `---` separator line).
        let docs: Vec<&str> = s.split("\n---\n").collect();
        assert_eq!(docs.len(), out.summary.findings.len());
        for d in &docs {
            assert!(d.contains("title: "));
            assert!(d.contains("id: "));
            assert!(d.contains("detection:"));
            assert!(d.contains("condition: selection"));
            assert!(d.contains("level: "));
            assert!(d.contains("logsource:"));
        }
        // The beacon (dst 8.8.8.8, High, T1071) keys on dst_ip and maps the level + ATT&CK tag.
        let beacon = docs
            .iter()
            .find(|d| d.contains("dst_ip: \"8.8.8.8\""))
            .unwrap();
        assert!(beacon.contains("level: high"));
        assert!(beacon.contains("attack.t1071"));
        // The host sweep (no dst) keys on src_ip instead.
        let sweep = docs.iter().find(|d| d.contains("attack.t1046")).unwrap();
        assert!(sweep.contains("src_ip: "));
        assert!(sweep.contains("level: medium"));
        // Deterministic.
        assert_eq!(s, sigma_rules(&out));
    }

    #[test]
    fn empty_summary_exports_are_valid() {
        let out = empty_output();
        assert!(serde_json::from_str::<serde_json::Value>(&misp_event(&out, 0)).is_ok());
        assert_eq!(cef_records(&out), "");
        assert_eq!(sigma_rules(&out), "");
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

    /// `misp_event` must emit a `ja3-fingerprint-md5` Attribute and a `ja4` Attribute when
    /// `summary.ip_threats` contains a `FingerprintHit` with both hashes set.
    #[test]
    fn misp_event_emits_ja3_and_ja4_attributes() {
        let mut out = out_with_ip_threat();
        out.summary.ip_threats[0].fingerprints = vec![FingerprintHit {
            ja3: Some("e7d705a3286e19ea42f587b344ee6865".into()),
            ja4: Some("t13d1516h2_8daaf6152771_e5627efa2ab1".into()),
            label: "CobaltStrike".into(),
        }];
        let s = misp_event(&out, 1_700_000_000);
        let v: serde_json::Value = serde_json::from_str(&s).expect("valid JSON");
        let attrs = v["Event"]["Attribute"].as_array().expect("Attribute array");

        let ja3_attr = attrs
            .iter()
            .find(|a| a["type"] == "ja3-fingerprint-md5")
            .expect("ja3-fingerprint-md5 attribute missing");
        assert_eq!(
            ja3_attr["value"], "e7d705a3286e19ea42f587b344ee6865",
            "wrong JA3 value"
        );
        assert_eq!(ja3_attr["to_ids"], true, "JA3 attr should have to_ids=true");

        let ja4_attr = attrs
            .iter()
            .find(|a| a["type"] == "ja4")
            .expect("ja4 attribute missing");
        assert_eq!(
            ja4_attr["value"], "t13d1516h2_8daaf6152771_e5627efa2ab1",
            "wrong JA4 value"
        );
        assert_eq!(ja4_attr["to_ids"], true, "JA4 attr should have to_ids=true");

        // deterministic: same input => same event
        assert_eq!(s, misp_event(&out, 1_700_000_000));
    }
}
