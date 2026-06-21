//! Native-only online reputation lookups (feature `online`). Provider adapters map each API's
//! response into `ReputationVerdict`; a keyed on-disk cache + per-provider daily budget keep the
//! free tiers usable. The pure scoring fold lives in `crate::enrich::reputation` (always compiled).

use std::net::IpAddr;

pub mod abuseipdb;
pub mod greynoise;
pub mod virustotal;
mod budget;
mod cache;

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
}

#[cfg(test)]
impl HttpGet for FakeHttp {
    fn get(&self, url: &str, _headers: &[(&str, &str)]) -> Result<HttpResponse, RepError> {
        *self.last_url.borrow_mut() = url.to_string();
        Ok(HttpResponse { status: self.response.0, body: self.response.1.clone() })
    }
}

#[cfg(test)]
impl FakeHttp {
    pub fn new(status: u16, body: &str) -> Self {
        FakeHttp { response: (status, body.to_string()), last_url: std::cell::RefCell::new(String::new()) }
    }
}

/// Helper: is this address worth a lookup (public/routable)?
#[allow(dead_code)] // consumed by the B7 orchestrator; remove the allow when lookup_reputation lands
pub(crate) fn is_lookupable(ip: IpAddr) -> bool {
    crate::enrich::classify_ip(ip).is_external()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_http_captures_url() {
        let client = FakeHttp::new(200, r#"{"ok":true}"#);
        let resp = client.get("https://example.com/api", &[("X-Key", "abc")]).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, r#"{"ok":true}"#);
        assert_eq!(*client.last_url.borrow(), "https://example.com/api");
    }

    #[test]
    fn reputation_keys_is_empty() {
        let k = ReputationKeys::default();
        assert!(k.is_empty());
        let k2 = ReputationKeys { abuseipdb: Some("key".into()), ..Default::default() };
        assert!(!k2.is_empty());
    }

    #[test]
    fn is_lookupable_public_vs_private() {
        assert!(is_lookupable("8.8.8.8".parse().unwrap()));
        assert!(!is_lookupable("10.0.0.1".parse().unwrap()));
        assert!(!is_lookupable("192.168.1.1".parse().unwrap()));
    }
}
