//! Suricata EVE import: `alert` events from an `eve.json` become [`FindingKind::RuleMatch`]
//! findings, so a sensor's signature hits rank, correlate and land on incident timelines next to
//! PacketPilot's own detections.
//!
//! EVE is newline-delimited JSON. [`read_eve`] streams it, so a multi-gigabyte file is fine; only
//! the aggregated findings are kept. Repeated hits of one signature between the same endpoints
//! fold into one finding with a contact count and a first/last-seen window, like the rules pass.
//! Severity maps Suricata's 1/2/3 to High/Medium/Low, and ATT&CK technique ids are read from the
//! rule metadata (`mitre_technique_id`, as Emerging Threats and Suricata's own rules write it).

use std::collections::{BTreeMap, HashMap};
use std::io::BufRead;
use std::net::IpAddr;

use crate::model::finding::{Finding, FindingKind};
use crate::model::severity::Severity;
use crate::model::summary::Summary;
use crate::model::timeline::{FirstContact, TimelineContext};

/// Most findings one import adds (matching the rules pass cap).
const MAX_EVE_FINDINGS: usize = 5000;
/// Endpoint pairs whose first contact is remembered for the timeline.
const MAX_EVE_CONTACTS: usize = 262_144;
/// The evidence line that marks a finding as imported from EVE.
const EVE_TAG: &str = "imported from Suricata EVE";

/// What one import read and produced.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EveImport {
    /// One finding per `(gid, sid, src, dst, dst port)`, in first-seen order.
    pub findings: Vec<Finding>,
    /// First contact per endpoint pair, from each alert's flow start.
    pub context: TimelineContext,
    /// Lines read (non-blank).
    pub lines: u64,
    /// `alert` events folded into findings.
    pub alerts: u64,
    /// Events of other types (`flow`, `dns`, `tls`, ...), which are not imported.
    pub other_events: u64,
    /// Lines that were not an EVE event (bad JSON, or an alert missing its addresses).
    pub skipped: u64,
}

/// Stream an EVE file and aggregate its alerts.
pub fn read_eve<R: BufRead>(reader: R) -> std::io::Result<EveImport> {
    let mut imp = EveImport::default();
    let mut index: HashMap<(u64, u64, String, String, Option<u16>), usize> = HashMap::new();
    let mut contacts: BTreeMap<(IpAddr, IpAddr), (i64, IpAddr, Option<u16>)> = BTreeMap::new();
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        imp.lines += 1;
        let Ok(ev) = serde_json::from_str::<serde_json::Value>(line) else {
            imp.skipped += 1;
            continue;
        };
        if ev.get("event_type").and_then(|v| v.as_str()) != Some("alert") {
            if ev.get("event_type").is_some() {
                imp.other_events += 1;
            } else {
                imp.skipped += 1;
            }
            continue;
        }
        let Some(hit) = Hit::from_event(&ev) else {
            imp.skipped += 1;
            continue;
        };
        imp.alerts += 1;
        if let (Some((ts, initiator, responder, port)), true) =
            (hit.flow_start, contacts.len() < MAX_EVE_CONTACTS)
        {
            let pair = if initiator <= responder {
                (initiator, responder)
            } else {
                (responder, initiator)
            };
            let e = contacts.entry(pair).or_insert((ts, initiator, port));
            if ts < e.0 {
                *e = (ts, initiator, port);
            }
        }
        let key = (
            hit.gid,
            hit.sid,
            hit.src.to_string(),
            hit.dst.to_string(),
            hit.dst_port,
        );
        match index.get(&key) {
            Some(&i) => widen(&mut imp.findings[i], hit.ts, 1),
            None if imp.findings.len() < MAX_EVE_FINDINGS => {
                index.insert(key, imp.findings.len());
                imp.findings.push(hit.finding());
            }
            None => {}
        }
    }
    imp.context.first_contacts = contacts
        .into_iter()
        .map(|((a, b), (ts, initiator, port))| FirstContact {
            initiator: initiator.to_string(),
            responder: if initiator == a { b } else { a }.to_string(),
            port,
            first_seen_ns: ts,
        })
        .collect();
    imp.context.first_contacts.sort_by(|a, b| {
        (a.initiator.as_str(), a.responder.as_str())
            .cmp(&(b.initiator.as_str(), b.responder.as_str()))
    });
    Ok(imp)
}

/// Fold an import into an analysis: new findings are added and the queue is re-derived, while a
/// finding already imported (same signature and endpoints, e.g. the same file imported twice)
/// only has its window and count widened. Returns how many findings were new.
pub fn fold_eve(summary: &mut Summary, imp: &EveImport) -> usize {
    let mut fresh = Vec::new();
    for f in &imp.findings {
        let existing = summary.findings.iter_mut().find(|e| {
            e.kind == FindingKind::RuleMatch
                && e.evidence.iter().any(|l| l == EVE_TAG)
                && e.evidence.first() == f.evidence.first()
                && e.src_ip == f.src_ip
                && e.dst_ip == f.dst_ip
                && e.dst_port == f.dst_port
        });
        match existing {
            Some(e) => {
                if let Some(t) = f.first_seen_ns {
                    widen(e, Some(t), 0);
                }
                if let Some(t) = f.last_seen_ns {
                    widen(e, Some(t), 0);
                }
                e.contacts = Some(e.contacts.unwrap_or(0).max(f.contacts.unwrap_or(0)));
            }
            None => fresh.push(f.clone()),
        }
    }
    crate::detect::fold_rule_findings_with_context(summary, &fresh, &imp.context);
    fresh.len()
}

fn widen(f: &mut Finding, ts: Option<i64>, add: u64) {
    if let Some(t) = ts {
        f.first_seen_ns = Some(f.first_seen_ns.map_or(t, |v| v.min(t)));
        f.last_seen_ns = Some(f.last_seen_ns.map_or(t, |v| v.max(t)));
    }
    f.contacts = Some(f.contacts.unwrap_or(0) + add);
}

/// One `alert` event, reduced to what a finding needs.
struct Hit {
    ts: Option<i64>,
    src: IpAddr,
    dst: IpAddr,
    dst_port: Option<u16>,
    proto: String,
    gid: u64,
    sid: u64,
    rev: Option<u64>,
    signature: String,
    category: Option<String>,
    severity: Severity,
    action: Option<String>,
    mitre: Vec<String>,
    /// `(start, initiator, responder, responder port)` of the alert's flow.
    flow_start: Option<(i64, IpAddr, IpAddr, Option<u16>)>,
}

fn str_of<'a>(v: &'a serde_json::Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(|x| x.as_str())
}

fn ip_of(v: &serde_json::Value, k: &str) -> Option<IpAddr> {
    str_of(v, k)?.trim().parse().ok()
}

fn port_of(v: &serde_json::Value, k: &str) -> Option<u16> {
    v.get(k)
        .and_then(|x| x.as_u64())
        .and_then(|p| u16::try_from(p).ok())
}

impl Hit {
    fn from_event(ev: &serde_json::Value) -> Option<Hit> {
        let alert = ev.get("alert")?;
        let src = ip_of(ev, "src_ip")?;
        let dst = ip_of(ev, "dest_ip")?;
        let ts = str_of(ev, "timestamp").and_then(parse_ts);
        let dst_port = port_of(ev, "dest_port").filter(|p| *p != 0);
        let sid = alert.get("signature_id").and_then(|v| v.as_u64())?;
        let severity = match alert.get("severity").and_then(|v| v.as_u64()) {
            Some(1) => Severity::High,
            Some(2) => Severity::Medium,
            Some(3) => Severity::Low,
            Some(_) => Severity::Info,
            None => Severity::Medium,
        };
        let mut mitre: Vec<String> = Vec::new();
        if let Some(meta) = alert.get("metadata").and_then(|m| m.as_object()) {
            for key in [
                "mitre_technique_id",
                "mitre_attack_technique_id",
                "mitre_technique",
            ] {
                for v in meta
                    .get(key)
                    .and_then(|v| v.as_array())
                    .into_iter()
                    .flatten()
                {
                    if let Some(id) = v.as_str().map(|s| s.trim().to_ascii_uppercase()) {
                        let valid = id.starts_with('T')
                            && id.len() <= 9
                            && id[1..].chars().all(|c| c.is_ascii_digit() || c == '.');
                        if valid && !mitre.contains(&id) {
                            mitre.push(id);
                        }
                    }
                }
            }
        }
        let flow = ev.get("flow");
        let flow_start = flow
            .and_then(|f| str_of(f, "start"))
            .and_then(parse_ts)
            .or(ts)
            .map(|start| {
                // Suricata 7 records the flow's own orientation under `flow`; older versions
                // orient the alert by its packet, which for a to-server hit is the same thing.
                let f = flow.unwrap_or(&serde_json::Value::Null);
                match (ip_of(f, "src_ip"), ip_of(f, "dest_ip")) {
                    (Some(i), Some(r)) => (start, i, r, port_of(f, "dest_port")),
                    _ => (start, src, dst, dst_port),
                }
            });
        Some(Hit {
            ts,
            src,
            dst,
            dst_port,
            proto: str_of(ev, "proto").unwrap_or("").to_ascii_lowercase(),
            gid: alert.get("gid").and_then(|v| v.as_u64()).unwrap_or(1),
            sid,
            rev: alert.get("rev").and_then(|v| v.as_u64()),
            signature: str_of(alert, "signature").unwrap_or("").to_string(),
            category: str_of(alert, "category")
                .filter(|c| !c.is_empty())
                .map(String::from),
            severity,
            action: str_of(alert, "action").map(String::from),
            mitre,
            flow_start,
        })
    }

    fn finding(&self) -> Finding {
        let mut evidence = vec![match self.rev {
            Some(rev) => format!("suricata {}:{}:{}", self.gid, self.sid, rev),
            None => format!("suricata {}:{}", self.gid, self.sid),
        }];
        if let Some(c) = &self.category {
            evidence.push(format!("category: {c}"));
        }
        if let Some(a) = self.action.as_deref().filter(|a| *a != "allowed") {
            evidence.push(format!("sensor action: {a}"));
        }
        if !self.proto.is_empty() {
            evidence.push(format!("protocol: {}", self.proto));
        }
        evidence.push(EVE_TAG.to_string());
        Finding {
            kind: FindingKind::RuleMatch,
            severity: self.severity,
            score: crate::detect::rules::score_for_severity(self.severity),
            title: if self.signature.is_empty() {
                format!("sid:{}", self.sid)
            } else {
                self.signature.clone()
            },
            src_ip: self.src.to_string(),
            dst_ip: Some(self.dst.to_string()),
            dst_port: self.dst_port,
            attack: self.mitre.clone(),
            evidence,
            interval_ns: None,
            jitter_cv: None,
            contacts: Some(1),
            first_seen_ns: self.ts,
            last_seen_ns: self.ts,
            victims: Vec::new(),
        }
    }
}

/// EVE's timestamp (`2026-10-29T12:00:00.123456+0000`, also `+00:00` or `Z`) as Unix ns.
fn parse_ts(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, rest) = s.split_once('T')?;
    let mut d = date.split('-');
    let year: i32 = d.next()?.parse().ok()?;
    let month: u8 = d.next()?.parse().ok()?;
    let day: u8 = d.next()?.parse().ok()?;
    let split = rest.find(['+', '-', 'Z']).unwrap_or(rest.len());
    let (clock, zone) = rest.split_at(split);
    let (hms, frac) = clock.split_once('.').unwrap_or((clock, ""));
    let mut t = hms.split(':');
    let h: u8 = t.next()?.parse().ok()?;
    let m: u8 = t.next()?.parse().ok()?;
    let sec: u8 = t.next()?.parse().ok()?;
    let digits: String = frac.chars().take(9).collect();
    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let nanos: u32 = if digits.is_empty() {
        0
    } else {
        format!("{digits:0<9}").parse().ok()?
    };
    let offset_secs: i32 = match zone {
        "" | "Z" => 0,
        z => {
            let sign = if z.starts_with('-') { -1 } else { 1 };
            let z: String = z[1..].chars().filter(|c| *c != ':').collect();
            if z.len() != 4 {
                return None;
            }
            let hh: i32 = z[..2].parse().ok()?;
            let mm: i32 = z[2..].parse().ok()?;
            sign * (hh * 3600 + mm * 60)
        }
    };
    let date =
        time::Date::from_calendar_date(year, time::Month::try_from(month).ok()?, day).ok()?;
    let clock = time::Time::from_hms_nano(h, m, sec, nanos).ok()?;
    let offset = time::UtcOffset::from_whole_seconds(offset_secs).ok()?;
    let dt = time::PrimitiveDateTime::new(date, clock).assume_offset(offset);
    i64::try_from(dt.unix_timestamp_nanos()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVE: &str = r#"
{"timestamp":"2023-11-14T22:13:21.250000+0000","flow_id":1,"event_type":"alert","src_ip":"10.0.0.5","src_port":50000,"dest_ip":"203.0.113.9","dest_port":443,"proto":"TCP","flow":{"start":"2023-11-14T22:13:20.500000+0000","src_ip":"10.0.0.5","dest_ip":"203.0.113.9","src_port":50000,"dest_port":443},"alert":{"action":"allowed","gid":1,"signature_id":2030000,"rev":2,"signature":"ET MALWARE Cobalt Strike Beacon","category":"A Network Trojan was detected","severity":1,"metadata":{"mitre_technique_id":["T1071","t1071.001"]}}}
{"timestamp":"2023-11-14T22:13:25.000000+0000","flow_id":1,"event_type":"alert","src_ip":"10.0.0.5","src_port":50001,"dest_ip":"203.0.113.9","dest_port":443,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2030000,"rev":2,"signature":"ET MALWARE Cobalt Strike Beacon","category":"A Network Trojan was detected","severity":1}}
{"timestamp":"2023-11-14T22:13:22.000000+0000","event_type":"alert","src_ip":"10.0.0.7","dest_ip":"10.0.0.8","dest_port":445,"proto":"TCP","alert":{"action":"blocked","signature_id":7,"signature":"","severity":3}}
{"timestamp":"2023-11-14T22:13:22.000000+0000","event_type":"flow","src_ip":"10.0.0.7","dest_ip":"10.0.0.8"}
{"event_type":"alert","alert":{"signature_id":1}}
not json
"#;

    #[test]
    fn alerts_aggregate_into_findings() {
        let imp = read_eve(EVE.as_bytes()).unwrap();
        assert_eq!(imp.lines, 6);
        assert_eq!(imp.alerts, 3);
        assert_eq!(imp.other_events, 1);
        assert_eq!(imp.skipped, 2);
        assert_eq!(imp.findings.len(), 2);
        let cs = &imp.findings[0];
        assert_eq!(cs.kind, FindingKind::RuleMatch);
        assert_eq!(cs.severity, Severity::High);
        assert_eq!(cs.title, "ET MALWARE Cobalt Strike Beacon");
        assert_eq!(cs.src_ip, "10.0.0.5");
        assert_eq!(cs.dst_port, Some(443));
        assert_eq!(cs.attack, vec!["T1071", "T1071.001"]);
        assert_eq!(cs.contacts, Some(2));
        assert_eq!(cs.first_seen_ns, Some(1_700_000_001_250_000_000));
        assert_eq!(cs.last_seen_ns, Some(1_700_000_005_000_000_000));
        assert_eq!(cs.evidence[0], "suricata 1:2030000:2");
        let smb = &imp.findings[1];
        assert_eq!(smb.severity, Severity::Low);
        assert_eq!(smb.title, "sid:7");
        assert!(smb.evidence.contains(&"sensor action: blocked".to_string()));
        let fc = &imp.context.first_contacts;
        assert_eq!(fc[0].initiator, "10.0.0.5");
        assert_eq!(fc[0].first_seen_ns, 1_700_000_000_500_000_000);
    }

    #[test]
    fn timestamps_accept_every_offset_form() {
        let base = 1_700_000_000_000_000_000;
        assert_eq!(parse_ts("2023-11-14T22:13:20.000000+0000"), Some(base));
        assert_eq!(parse_ts("2023-11-14T22:13:20Z"), Some(base));
        assert_eq!(
            parse_ts("2023-11-15T00:13:20.5+02:00"),
            Some(base + 500_000_000)
        );
        assert_eq!(parse_ts("2023-11-14T17:13:20-0500"), Some(base));
        assert_eq!(parse_ts("yesterday"), None);
    }

    #[test]
    fn folding_twice_adds_nothing_new() {
        let imp = read_eve(EVE.as_bytes()).unwrap();
        let mut s = Summary::empty();
        assert_eq!(fold_eve(&mut s, &imp), 2);
        assert_eq!(s.findings.len(), 2);
        assert!(!s.alerts.is_empty(), "imported hits reach the alert queue");
        assert_eq!(fold_eve(&mut s, &imp), 0);
        assert_eq!(s.findings.len(), 2);
    }
}
