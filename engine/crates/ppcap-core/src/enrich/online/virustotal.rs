//! VirusTotal API v3 adapter for IP (`/ip_addresses/{ip}`) and domain (`/domains/{d}`). Header
//! auth `x-apikey: <key>`. Score is the malicious ratio over the engine stats actually present —
//! never the signed `reputation` field. Missing stats / 404 ⇒ not "clean". See spec §7.3.

use super::{HttpGet, RepError};
use crate::enrich::{RepStatus, ReputationVerdict};
use std::net::IpAddr;

#[derive(serde::Deserialize)]
struct Resp {
    data: DataObj,
}
#[derive(serde::Deserialize)]
struct DataObj {
    attributes: Attrs,
}
#[derive(serde::Deserialize, Default)]
struct Attrs {
    #[serde(default)]
    last_analysis_stats: Option<Stats>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    as_owner: Option<String>,
    #[serde(default)]
    country: Option<String>,
}
#[derive(serde::Deserialize, Default)]
struct Stats {
    #[serde(default)]
    malicious: u32,
    #[serde(default)]
    suspicious: u32,
    #[serde(default)]
    harmless: u32,
    #[serde(default)]
    undetected: u32,
}

const SOURCE: &str = "virustotal";

fn simple(status: RepStatus, score: Option<u8>, now: i64) -> ReputationVerdict {
    ReputationVerdict {
        source: SOURCE.to_string(), status, malicious: status == RepStatus::Malicious,
        score, tags: vec![], link: None, fetched_at: now,
    }
}

fn parse(body: &str, status_code: u16, link: String, now: i64) -> ReputationVerdict {
    match status_code {
        404 => return simple(RepStatus::NotFound, None, now),
        200 => {}
        _ => return simple(RepStatus::Unavailable, None, now),
    }
    let Ok(r) = serde_json::from_str::<Resp>(body) else {
        return simple(RepStatus::Unavailable, None, now);
    };
    let Some(st) = r.data.attributes.last_analysis_stats else {
        return simple(RepStatus::Unknown, None, now); // analyzed-but-no-stats ⇒ unknown, not clean
    };
    let total = (st.malicious + st.suspicious + st.harmless + st.undetected).max(1);
    let score = (((100u32 * st.malicious) + (total / 2)) / total) as u8;
    let status = if st.malicious > 0 {
        RepStatus::Malicious
    } else if st.suspicious == 0 && st.harmless > 0 {
        RepStatus::Clean
    } else {
        RepStatus::Unknown
    };
    let mut tags = r.data.attributes.tags;
    if let Some(o) = r.data.attributes.as_owner { tags.push(o); }
    if let Some(c) = r.data.attributes.country { tags.push(c); }
    ReputationVerdict {
        source: SOURCE.to_string(),
        status,
        malicious: status == RepStatus::Malicious,
        score: Some(score),
        tags,
        link: Some(link),
        fetched_at: now,
    }
}

pub fn verdict_ip(http: &dyn HttpGet, key: &str, ip: IpAddr, now: i64) -> ReputationVerdict {
    let url = format!("https://www.virustotal.com/api/v3/ip_addresses/{ip}");
    match http.get(&url, &[("x-apikey", key)]) {
        Ok(r) => parse(&r.body, r.status, format!("https://www.virustotal.com/gui/ip-address/{ip}"), now),
        Err(RepError::Network(_)) => simple(RepStatus::Unavailable, None, now),
    }
}

pub fn verdict_domain(http: &dyn HttpGet, key: &str, domain: &str, now: i64) -> ReputationVerdict {
    let url = format!("https://www.virustotal.com/api/v3/domains/{domain}");
    match http.get(&url, &[("x-apikey", key)]) {
        Ok(r) => parse(&r.body, r.status, format!("https://www.virustotal.com/gui/domain/{domain}"), now),
        Err(RepError::Network(_)) => simple(RepStatus::Unavailable, None, now),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::online::FakeHttp;
    use std::net::IpAddr;
    fn ip() -> IpAddr { "203.0.113.7".parse().unwrap() }

    #[test]
    fn malicious_engines_flag() {
        let body = r#"{"data":{"id":"203.0.113.7","type":"ip_address","attributes":{
            "last_analysis_stats":{"malicious":8,"suspicious":2,"harmless":70,"undetected":10,"timeout":0},
            "tags":["malware"],"as_owner":"EvilCorp","country":"NL"}}}"#;
        let v = verdict_ip(&FakeHttp::new(200, body), "k", ip(), 0);
        assert_eq!(v.status, RepStatus::Malicious);
        assert_eq!(v.score, Some(9)); // round(100*8/90)
        assert!(v.tags.iter().any(|t| t == "malware"));
    }

    #[test]
    fn all_harmless_is_clean() {
        let body = r#"{"data":{"attributes":{"last_analysis_stats":
            {"malicious":0,"suspicious":0,"harmless":85,"undetected":5,"timeout":0}}}}"#;
        let v = verdict_ip(&FakeHttp::new(200, body), "k", ip(), 0);
        assert_eq!(v.status, RepStatus::Clean);
        assert_eq!(v.score, Some(0));
    }

    #[test]
    fn not_found_is_notfound() {
        let v = verdict_ip(&FakeHttp::new(404, r#"{"error":{"code":"NotFoundError"}}"#), "k", ip(), 0);
        assert_eq!(v.status, RepStatus::NotFound);
    }

    #[test]
    fn domain_uses_same_parser() {
        let body = r#"{"data":{"attributes":{"last_analysis_stats":
            {"malicious":3,"suspicious":0,"harmless":60,"undetected":7,"timeout":0}}}}"#;
        let v = verdict_domain(&FakeHttp::new(200, body), "k", "evil.example.com", 0);
        assert_eq!(v.status, RepStatus::Malicious);
        assert_eq!(v.link.as_deref(), Some("https://www.virustotal.com/gui/domain/evil.example.com"));
    }
}
