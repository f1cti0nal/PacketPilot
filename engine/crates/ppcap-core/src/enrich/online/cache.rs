//! Keyed on-disk reputation cache. A single JSON map under `<cache_dir>/reputation.json`, written
//! atomically (tmp + rename). Private/local-only per provider ToS; the caller chooses the TTL.

use crate::enrich::ReputationVerdict;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub struct ReputationCache {
    path: PathBuf,
    entries: BTreeMap<String, ReputationVerdict>,
}

fn key(source: &str, indicator: &str) -> String {
    format!("{source}|{indicator}")
}

impl ReputationCache {
    /// Load (or start empty) from `<cache_dir>/reputation.json`. Never fails — a missing/corrupt
    /// file yields an empty cache (best-effort, like the UI's IndexedDB cache).
    pub fn load(cache_dir: &Path) -> Self {
        let path = cache_dir.join("reputation.json");
        let entries = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        ReputationCache { path, entries }
    }

    /// Fresh verdict for `(source, indicator)` if `now - fetched_at <= ttl_secs`, else `None`.
    pub fn get(
        &self,
        source: &str,
        indicator: &str,
        now: i64,
        ttl_secs: i64,
    ) -> Option<&ReputationVerdict> {
        self.entries
            .get(&key(source, indicator))
            .filter(|v| now.saturating_sub(v.fetched_at) <= ttl_secs)
    }

    pub fn put(&mut self, source: &str, indicator: &str, verdict: ReputationVerdict) {
        self.entries.insert(key(source, indicator), verdict);
    }

    /// Atomically persist (tmp file + rename). Best-effort; returns the io error if the rename fails.
    pub fn save(&self) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(
            &tmp,
            serde_json::to_string(&self.entries).unwrap_or_default(),
        )?;
        std::fs::rename(&tmp, &self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::{RepStatus, ReputationVerdict};

    fn v(now: i64) -> ReputationVerdict {
        ReputationVerdict {
            source: "abuseipdb".to_string(),
            status: RepStatus::Malicious,
            malicious: true,
            score: Some(90),
            tags: vec![],
            link: None,
            fetched_at: now,
        }
    }

    #[test]
    fn hit_within_ttl_miss_after() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = ReputationCache::load(dir.path());
        c.put("abuseipdb", "203.0.113.7", v(1000)); // fetched_at = 1000
                                                    // now=1100, ttl=600 -> age 100 <= 600 -> fresh (hit).
        assert!(c.get("abuseipdb", "203.0.113.7", 1100, 600).is_some());
        // now=2000, ttl=600 -> age 1000 > 600 -> stale (miss).
        assert!(c.get("abuseipdb", "203.0.113.7", 2000, 600).is_none());
    }

    #[test]
    fn persists_across_load() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut c = ReputationCache::load(dir.path());
            c.put("greynoise", "203.0.113.7", v(1000));
            c.save().unwrap();
        }
        let c2 = ReputationCache::load(dir.path());
        assert!(c2.get("greynoise", "203.0.113.7", 1100, 600).is_some());
    }
}
