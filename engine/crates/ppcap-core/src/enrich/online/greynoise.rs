//! GreyNoise Community API `/v3/community/{ip}` adapter (IP only). Header auth `key: <key>`.
//! `classification` is the verdict gate; benign/RIOT are the false-positive suppressors. 404 is a
//! real "not observed" body, NOT clean. See spec §7.2.

use super::{HttpGet, RepError};
use crate::enrich::{RepStatus, ReputationVerdict};
use std::net::IpAddr;

#[derive(serde::Deserialize, Default)]
struct Resp {
    #[serde(default)]
    noise: bool,
    #[serde(default)]
    riot: bool,
    #[serde(default)]
    classification: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    link: Option<String>,
}

const SOURCE: &str = "greynoise";

fn simple(status: RepStatus, score: Option<u8>, now: i64) -> ReputationVerdict {
    ReputationVerdict {
        source: SOURCE.to_string(),
        status,
        malicious: status == RepStatus::Malicious,
        score,
        tags: vec![],
        link: None,
        fetched_at: now,
    }
}

pub fn verdict(http: &dyn HttpGet, key: &str, ip: IpAddr, now: i64) -> ReputationVerdict {
    let url = format!("https://api.greynoise.io/v3/community/{ip}");
    let resp = match http.get(&url, &[("key", key)]) {
        Ok(r) => r,
        Err(RepError::Network(_)) => return simple(RepStatus::Unavailable, None, now),
    };
    match resp.status {
        404 => return simple(RepStatus::NotFound, Some(0), now),
        200 => {}
        _ => return simple(RepStatus::Unavailable, None, now),
    }
    let Ok(r) = serde_json::from_str::<Resp>(&resp.body) else {
        return simple(RepStatus::Unavailable, None, now);
    };

    let (status, score) = if r.classification == "malicious" {
        (RepStatus::Malicious, Some(95))
    } else if r.classification == "benign" || r.riot {
        (RepStatus::Benign, Some(5))
    } else {
        (RepStatus::Unknown, Some(if r.noise { 50 } else { 0 }))
    };

    let mut tags = Vec::new();
    if !r.name.is_empty() && r.name != "unknown" {
        tags.push(r.name);
    }
    if r.riot {
        tags.push("business-service".to_string());
    }
    if r.noise {
        tags.push("internet-scanner".to_string());
    }

    ReputationVerdict {
        source: SOURCE.to_string(),
        status,
        malicious: status == RepStatus::Malicious,
        score,
        tags,
        link: r
            .link
            .or_else(|| Some(format!("https://viz.greynoise.io/ip/{ip}"))),
        fetched_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::online::FakeHttp;
    use crate::enrich::RepStatus;
    use std::net::IpAddr;
    fn ip() -> IpAddr {
        "203.0.113.7".parse().unwrap()
    }

    #[test]
    fn classification_malicious() {
        let body = r#"{"ip":"203.0.113.7","noise":true,"riot":false,"classification":"malicious",
            "name":"unknown","link":"https://viz.greynoise.io/ip/203.0.113.7","last_seen":"2026-06-20"}"#;
        let v = verdict(&FakeHttp::new(200, body), "k", ip(), 0);
        assert_eq!(v.status, RepStatus::Malicious);
        assert!(v.malicious);
    }

    #[test]
    fn benign_actor_suppresses() {
        let body = r#"{"ip":"203.0.113.7","noise":true,"riot":false,"classification":"benign",
            "name":"Shodan.io","link":"x","last_seen":"2026-06-20"}"#;
        let v = verdict(&FakeHttp::new(200, body), "k", ip(), 0);
        assert_eq!(v.status, RepStatus::Benign);
        assert!(v.tags.iter().any(|t| t == "Shodan.io"));
    }

    #[test]
    fn riot_is_benign_context() {
        let body = r#"{"ip":"8.8.8.8","noise":false,"riot":true,"classification":"unknown","name":"Google"}"#;
        let v = verdict(&FakeHttp::new(200, body), "k", ip(), 0);
        assert_eq!(v.status, RepStatus::Benign);
        assert!(v.tags.iter().any(|t| t == "business-service"));
    }

    #[test]
    fn not_found_404_is_notfound_not_clean() {
        let body =
            r#"{"ip":"203.0.113.7","noise":false,"riot":false,"message":"IP not observed..."}"#;
        let v = verdict(&FakeHttp::new(404, body), "k", ip(), 0);
        assert_eq!(v.status, RepStatus::NotFound);
    }

    #[test]
    fn forbidden_403_is_unavailable() {
        let v = verdict(&FakeHttp::new(403, ""), "k", ip(), 0);
        assert_eq!(v.status, RepStatus::Unavailable);
    }
}
