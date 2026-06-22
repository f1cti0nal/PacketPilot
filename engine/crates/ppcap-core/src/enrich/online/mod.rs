//! Native-only online reputation lookups (feature `online`). Provider adapters map each API's
//! response into `ReputationVerdict`; a keyed on-disk cache + per-provider daily budget keep the
//! free tiers usable. The pure scoring fold lives in `crate::enrich::reputation` (always compiled).

use std::net::IpAddr;

pub mod abuseipdb;
mod budget;
mod cache;
pub mod greynoise;
pub mod virustotal;

pub use budget::Budget;
pub use cache::ReputationCache;

/// Minimal HTTP response surface the adapters need.
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// Transport errors (the adapter turns these into a `RepStatus::Unavailable` verdict).
#[derive(Debug)]
pub enum RepError {
    Network(String),
}

/// A blocking HTTP GET. Real impl is `UreqClient`; tests inject a fake. Adapters depend on the
/// trait, never on `ureq` directly, so they unit-test with zero network.
pub trait HttpGet {
    fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse, RepError>;
}

/// The three provider API keys; a provider is active iff its key is `Some`.
#[derive(Debug, Clone, Default)]
pub struct ReputationKeys {
    pub abuseipdb: Option<String>,
    pub greynoise: Option<String>,
    pub virustotal: Option<String>,
}

impl ReputationKeys {
    /// True when no provider is configured (the pass is a no-op).
    pub fn is_empty(&self) -> bool {
        self.abuseipdb.is_none() && self.greynoise.is_none() && self.virustotal.is_none()
    }
}

#[cfg(test)]
pub(crate) struct FakeHttp {
    /// (status, body) returned for every call; the URL is captured for assertions.
    pub response: (u16, String),
    pub last_url: std::cell::RefCell<String>,
    call_count: std::cell::Cell<usize>,
}

#[cfg(test)]
impl HttpGet for FakeHttp {
    fn get(&self, url: &str, _headers: &[(&str, &str)]) -> Result<HttpResponse, RepError> {
        *self.last_url.borrow_mut() = url.to_string();
        self.call_count.set(self.call_count.get() + 1);
        Ok(HttpResponse {
            status: self.response.0,
            body: self.response.1.clone(),
        })
    }
}

#[cfg(test)]
impl FakeHttp {
    pub fn new(status: u16, body: &str) -> Self {
        FakeHttp {
            response: (status, body.to_string()),
            last_url: std::cell::RefCell::new(String::new()),
            call_count: std::cell::Cell::new(0),
        }
    }

    /// Return total number of HTTP calls made so far.
    pub fn calls(&self) -> usize {
        self.call_count.get()
    }

    /// Construct a fake that returns a VT domain response flagged as malicious.
    pub fn vt_domain_malicious() -> Self {
        let body = r#"{"data":{"attributes":{"last_analysis_stats":{"malicious":5,"suspicious":1,"harmless":60,"undetected":4,"timeout":0}}}}"#;
        FakeHttp::new(200, body)
    }
}

/// Helper: is this address worth a lookup (public/routable)?
/// Only `IpClass::Public` addresses are looked up — matches the filter in `apply_reputation`.
pub(crate) fn is_lookupable(ip: IpAddr) -> bool {
    crate::enrich::classify_ip(ip).is_external()
}

// ─── Orchestrator ────────────────────────────────────────────────────────────

use crate::enrich::{RepStatus, ReputationVerdict};
use std::collections::BTreeMap;
use std::path::Path;

/// Per-provider cache TTLs in seconds (spec §8). Tunable later via config.
pub struct Ttls {
    pub abuseipdb: i64,
    pub greynoise: i64,
    pub virustotal: i64,
}
impl Default for Ttls {
    fn default() -> Self {
        Ttls {
            abuseipdb: 18 * 3600,
            greynoise: 24 * 3600,
            virustotal: 12 * 3600,
        }
    }
}

fn quota_unavailable(source: &str, now: i64) -> ReputationVerdict {
    ReputationVerdict {
        source: source.to_string(),
        status: RepStatus::Unavailable,
        malicious: false,
        score: None,
        tags: vec!["quota".to_string()],
        link: None,
        fetched_at: now,
    }
}

/// Look up every public IP against every active provider, cache-first, budget-bounded. `ips`
/// should already be priority-ordered (most-suspicious first) by the caller. Cache is mutated +
/// the caller is responsible for `cache.save()`.
#[allow(clippy::too_many_arguments)]
pub fn lookup_reputation(
    http: &dyn HttpGet,
    ips: &[IpAddr],
    keys: &ReputationKeys,
    cache: &mut ReputationCache,
    budget: &mut Budget,
    ttls: &Ttls,
    now: i64,
) -> BTreeMap<String, Vec<ReputationVerdict>> {
    let mut out: BTreeMap<String, Vec<ReputationVerdict>> = BTreeMap::new();
    for &ip in ips {
        if !is_lookupable(ip) {
            continue;
        }
        let ind = ip.to_string();
        let mut verdicts = Vec::new();

        // One closure per active provider keeps the cache/budget/fetch flow uniform.
        let run = |source: &str,
                   ttl: i64,
                   verdicts: &mut Vec<ReputationVerdict>,
                   cache: &mut ReputationCache,
                   budget: &mut Budget,
                   fetch: &dyn Fn() -> ReputationVerdict| {
            if let Some(hit) = cache.get(source, &ind, now, ttl) {
                verdicts.push(hit.clone());
            } else if budget.try_spend(source) {
                let v = fetch();
                cache.put(source, &ind, v.clone());
                verdicts.push(v);
            } else {
                verdicts.push(quota_unavailable(source, now));
            }
        };

        if let Some(k) = &keys.abuseipdb {
            run(
                "abuseipdb",
                ttls.abuseipdb,
                &mut verdicts,
                cache,
                budget,
                &|| abuseipdb::verdict(http, k, ip, now),
            );
        }
        if let Some(k) = &keys.greynoise {
            run(
                "greynoise",
                ttls.greynoise,
                &mut verdicts,
                cache,
                budget,
                &|| greynoise::verdict(http, k, ip, now),
            );
        }
        if let Some(k) = &keys.virustotal {
            run(
                "virustotal",
                ttls.virustotal,
                &mut verdicts,
                cache,
                budget,
                &|| virustotal::verdict_ip(http, k, ip, now),
            );
        }

        if !verdicts.is_empty() {
            out.insert(ind, verdicts);
        }
    }
    out
}

// ─── Real ureq-backed HTTP client ────────────────────────────────────────────

/// The real `ureq`-backed HTTP client (only this struct needs the `online` feature's dep).
#[cfg(feature = "online")]
pub struct UreqClient {
    agent: ureq::Agent,
}

#[cfg(feature = "online")]
impl Default for UreqClient {
    fn default() -> Self {
        UreqClient {
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(8))
                .user_agent("PacketPilot/reputation")
                .build(),
        }
    }
}

#[cfg(feature = "online")]
impl HttpGet for UreqClient {
    fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse, RepError> {
        let mut req = self.agent.get(url);
        for (k, v) in headers {
            req = req.set(k, v);
        }
        match req.call() {
            Ok(resp) => {
                let status = resp.status();
                let body = resp
                    .into_string()
                    .map_err(|e| RepError::Network(e.to_string()))?;
                Ok(HttpResponse { status, body })
            }
            // ureq 2.x surfaces 4xx/5xx as Err(Status) — we still want the body (GreyNoise 404).
            Err(ureq::Error::Status(code, resp)) => Ok(HttpResponse {
                status: code,
                body: resp.into_string().unwrap_or_default(),
            }),
            Err(e) => Err(RepError::Network(e.to_string())),
        }
    }
}

/// Convenience for native callers (CLI/Tauri): build a `UreqClient`, load the cache, look up, save.
#[cfg(feature = "online")]
pub fn lookup_reputation_native(
    ips: &[IpAddr],
    keys: &ReputationKeys,
    cache_dir: &Path,
    now: i64,
) -> BTreeMap<String, Vec<ReputationVerdict>> {
    let http = UreqClient::default();
    let mut cache = ReputationCache::load(cache_dir);
    let mut budget = Budget::with_defaults();
    let out = lookup_reputation(
        &http,
        ips,
        keys,
        &mut cache,
        &mut budget,
        &Ttls::default(),
        now,
    );
    let _ = cache.save();
    out
}

// ─── Domain reputation ────────────────────────────────────────────────────────

/// Look up VirusTotal domain reputation for `hosts`, reusing the existing cache + budget
/// (keyed `virustotal|<host>`). VT-only — the other providers don't do domains.
#[allow(clippy::too_many_arguments)]
pub fn lookup_domain_reputation(
    http: &dyn HttpGet,
    hosts: &[String],
    keys: &ReputationKeys,
    cache: &mut ReputationCache,
    budget: &mut Budget,
    ttls: &Ttls,
    now: i64,
) -> BTreeMap<String, Vec<ReputationVerdict>> {
    let mut out: BTreeMap<String, Vec<ReputationVerdict>> = BTreeMap::new();
    let Some(k) = &keys.virustotal else {
        return out;
    };
    for host in hosts {
        let source = "virustotal";
        let v = if let Some(hit) = cache.get(source, host, now, ttls.virustotal) {
            hit.clone()
        } else if budget.try_spend(source) {
            let v = virustotal::verdict_domain(http, k, host, now);
            cache.put(source, host, v.clone());
            v
        } else {
            quota_unavailable(source, now)
        };
        out.insert(host.clone(), vec![v]);
    }
    out
}

/// Native convenience wrapper (CLI/Tauri): loads/saves the on-disk cache.
#[cfg(feature = "online")]
pub fn lookup_domain_reputation_native(
    hosts: &[String],
    keys: &ReputationKeys,
    cache_dir: &Path,
    now: i64,
) -> BTreeMap<String, Vec<ReputationVerdict>> {
    let http = UreqClient::default();
    let mut cache = ReputationCache::load(cache_dir);
    let mut budget = Budget::with_defaults();
    let out = lookup_domain_reputation(
        &http,
        hosts,
        keys,
        &mut cache,
        &mut budget,
        &Ttls::default(),
        now,
    );
    let _ = cache.save();
    out
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_http_captures_url() {
        let client = FakeHttp::new(200, r#"{"ok":true}"#);
        let resp = client
            .get("https://example.com/api", &[("X-Key", "abc")])
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, r#"{"ok":true}"#);
        assert_eq!(*client.last_url.borrow(), "https://example.com/api");
    }

    #[test]
    fn reputation_keys_is_empty() {
        let k = ReputationKeys::default();
        assert!(k.is_empty());
        let k2 = ReputationKeys {
            abuseipdb: Some("key".into()),
            ..Default::default()
        };
        assert!(!k2.is_empty());
    }

    #[test]
    fn is_lookupable_public_vs_private() {
        assert!(is_lookupable("8.8.8.8".parse().unwrap()));
        assert!(!is_lookupable("10.0.0.1".parse().unwrap()));
        assert!(!is_lookupable("192.168.1.1".parse().unwrap()));
        // Documentation-range IPs (RFC 5737) must NOT be looked up — apply_reputation skips them.
        assert!(!is_lookupable("203.0.113.7".parse().unwrap()));
    }
}

#[cfg(test)]
mod orchestrator_tests {
    use super::*;
    use crate::enrich::RepStatus;

    #[test]
    fn only_active_providers_run_and_results_key_by_ip() {
        let body = r#"{"data":{"abuseConfidenceScore":96,"totalReports":5}}"#;
        let http = FakeHttp::new(200, body);
        let keys = ReputationKeys {
            abuseipdb: Some("k".into()),
            greynoise: None,
            virustotal: None,
        };
        let mut cache = ReputationCache::load(std::env::temp_dir().as_path());
        let mut budget = Budget::with_defaults();
        let ips = vec!["8.8.8.8".parse().unwrap()];
        let out = lookup_reputation(
            &http,
            &ips,
            &keys,
            &mut cache,
            &mut budget,
            &Ttls::default(),
            1000,
        );
        let vs = out.get("8.8.8.8").unwrap();
        assert_eq!(vs.len(), 1); // only abuseipdb active
        assert_eq!(vs[0].source, "abuseipdb");
        assert_eq!(vs[0].status, RepStatus::Malicious);
    }

    #[test]
    fn private_ips_are_skipped() {
        let http = FakeHttp::new(200, "{}");
        let keys = ReputationKeys {
            abuseipdb: Some("k".into()),
            ..Default::default()
        };
        let mut cache = ReputationCache::load(std::env::temp_dir().as_path());
        let mut budget = Budget::with_defaults();
        let ips = vec!["10.0.0.5".parse().unwrap()];
        let out = lookup_reputation(
            &http,
            &ips,
            &keys,
            &mut cache,
            &mut budget,
            &Ttls::default(),
            0,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn exhausted_budget_yields_unavailable_not_skip() {
        let http = FakeHttp::new(
            200,
            r#"{"data":{"abuseConfidenceScore":10,"totalReports":0}}"#,
        );
        let keys = ReputationKeys {
            abuseipdb: Some("k".into()),
            ..Default::default()
        };
        let mut cache = ReputationCache::load(std::env::temp_dir().as_path());
        let mut budget = Budget::with_defaults();
        // Drain abuseipdb.
        while budget.try_spend("abuseipdb") {}
        let ips = vec!["8.8.8.8".parse().unwrap()];
        let out = lookup_reputation(
            &http,
            &ips,
            &keys,
            &mut cache,
            &mut budget,
            &Ttls::default(),
            0,
        );
        assert_eq!(
            out.get("8.8.8.8").unwrap()[0].status,
            RepStatus::Unavailable
        );
    }

    #[test]
    fn domain_lookup_uses_vt_caches_and_budgets() {
        let http = FakeHttp::vt_domain_malicious();
        let keys = ReputationKeys {
            abuseipdb: None,
            greynoise: None,
            virustotal: Some("k".into()),
        };
        let cache_dir = std::env::temp_dir().join("ppcap_sni_domain_lookup_test");
        let _ = std::fs::remove_dir_all(&cache_dir);
        let mut cache = ReputationCache::load(&cache_dir);
        let mut budget = Budget::with_defaults();
        let hosts = vec!["evil.example".to_string()];
        let out = lookup_domain_reputation(
            &http,
            &hosts,
            &keys,
            &mut cache,
            &mut budget,
            &Ttls::default(),
            0,
        );
        assert_eq!(
            out.get("evil.example").unwrap()[0].status,
            RepStatus::Malicious
        );
        // Second call hits the cache (no new http call):
        let before = http.calls();
        let _ = lookup_domain_reputation(
            &http,
            &hosts,
            &keys,
            &mut cache,
            &mut budget,
            &Ttls::default(),
            0,
        );
        assert_eq!(
            http.calls(),
            before,
            "second lookup should be served from cache"
        );
    }
}
