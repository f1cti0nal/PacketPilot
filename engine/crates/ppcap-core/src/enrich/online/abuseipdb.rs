//! AbuseIPDB API v2 `/check` adapter (IP only). Header auth `Key: <key>`; score is the native
//! `abuseConfidenceScore` (0..=100). See spec §7.1.

use super::{HttpGet, RepError};
use crate::enrich::{RepStatus, ReputationVerdict};
use std::net::IpAddr;

#[derive(serde::Deserialize)]
struct Resp {
    data: Data,
}
#[derive(serde::Deserialize)]
struct Data {
    #[serde(rename = "abuseConfidenceScore")]
    abuse_confidence_score: u8,
    #[serde(rename = "totalReports", default)]
    total_reports: u64,
    #[serde(rename = "usageType", default)]
    usage_type: Option<String>,
    #[serde(rename = "isTor", default)]
    is_tor: Option<bool>,
    #[serde(rename = "countryCode", default)]
    country_code: Option<String>,
}

const SOURCE: &str = "abuseipdb";

fn unavailable(now: i64) -> ReputationVerdict {
    ReputationVerdict {
        source: SOURCE.to_string(), status: RepStatus::Unavailable, malicious: false,
        score: None, tags: vec![], link: None, fetched_at: now,
    }
}

/// Look up one IP. Network errors / non-200 / parse failures degrade to `Unavailable`.
pub fn verdict(http: &dyn HttpGet, key: &str, ip: IpAddr, now: i64) -> ReputationVerdict {
    let url = format!("https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90");
    let resp = match http.get(&url, &[("Key", key), ("Accept", "application/json")]) {
        Ok(r) => r,
        Err(RepError::Network(_)) => return unavailable(now),
    };
    if resp.status != 200 {
        return unavailable(now);
    }
    let Ok(parsed) = serde_json::from_str::<Resp>(&resp.body) else {
        return unavailable(now);
    };
    let d = parsed.data;
    let score = d.abuse_confidence_score;
    let status = if score >= 75 {
        RepStatus::Malicious
    } else if score >= 25 {
        RepStatus::Unknown
    } else if d.total_reports == 0 {
        RepStatus::Clean
    } else {
        RepStatus::Unknown
    };
    let mut tags = Vec::new();
    if let Some(u) = d.usage_type { tags.push(u); }
    if d.is_tor == Some(true) { tags.push("tor".to_string()); }
    if let Some(c) = d.country_code { tags.push(c); }
    ReputationVerdict {
        source: SOURCE.to_string(),
        status,
        malicious: status == RepStatus::Malicious,
        score: Some(score),
        tags,
        link: Some(format!("https://www.abuseipdb.com/check/{ip}")),
        fetched_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::online::FakeHttp;
    use crate::enrich::RepStatus;
    use std::net::IpAddr;

    fn ip() -> IpAddr { "203.0.113.7".parse().unwrap() }

    #[test]
    fn high_confidence_is_malicious() {
        let body = r#"{"data":{"abuseConfidenceScore":96,"totalReports":42,"isWhitelisted":false,
            "usageType":"Data Center/Web Hosting/Transit","isTor":false,"countryCode":"NL"}}"#;
        let v = verdict(&FakeHttp::new(200, body), "k", ip(), 1234);
        assert_eq!(v.status, RepStatus::Malicious);
        assert!(v.malicious);
        assert_eq!(v.score, Some(96));
        assert_eq!(v.source, "abuseipdb");
        assert_eq!(v.fetched_at, 1234);
        assert!(v.tags.iter().any(|t| t.contains("Data Center")));
        assert_eq!(v.link.as_deref(), Some("https://www.abuseipdb.com/check/203.0.113.7"));
    }

    #[test]
    fn zero_reports_is_clean_not_malicious() {
        let body = r#"{"data":{"abuseConfidenceScore":0,"totalReports":0}}"#;
        let v = verdict(&FakeHttp::new(200, body), "k", ip(), 0);
        assert_eq!(v.status, RepStatus::Clean);
        assert!(!v.malicious);
        assert_eq!(v.score, Some(0));
    }

    #[test]
    fn rate_limited_is_unavailable() {
        let v = verdict(&FakeHttp::new(429, "{}"), "k", ip(), 0);
        assert_eq!(v.status, RepStatus::Unavailable);
        assert_eq!(v.score, None);
    }
}
