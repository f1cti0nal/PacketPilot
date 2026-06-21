//! Per-provider daily lookup budget (the binding constraint on free tiers: GreyNoise ~10/day,
//! VirusTotal 500/day, AbuseIPDB 1000/day — each with a safety margin). Cache hits cost nothing;
//! only live fetches call `try_spend`. Over-budget indicators are surfaced, never silently dropped.

use std::collections::HashMap;

pub struct Budget {
    remaining: HashMap<&'static str, u32>,
}

impl Budget {
    /// Conservative defaults (free quota minus margin). Tunable later via config.
    pub fn with_defaults() -> Self {
        let mut remaining = HashMap::new();
        remaining.insert("greynoise", 9); // ~10/day
        remaining.insert("virustotal", 480); // 500/day
        remaining.insert("abuseipdb", 950); // 1000/day
        Budget { remaining }
    }

    /// Try to consume one unit for `source`; `false` if exhausted (or unknown source).
    pub fn try_spend(&mut self, source: &str) -> bool {
        match self.remaining.get_mut(source) {
            Some(n) if *n > 0 => {
                *n -= 1;
                true
            }
            _ => false,
        }
    }

    pub fn exhausted(&self, source: &str) -> bool {
        self.remaining.get(source).copied().unwrap_or(0) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_reflect_free_tiers() {
        let mut b = Budget::with_defaults();
        // GreyNoise is the tightest; should run out long before AbuseIPDB.
        assert!(b.try_spend("greynoise"));
        for _ in 0..50 {
            b.try_spend("greynoise");
        }
        assert!(b.exhausted("greynoise"));
        assert!(b.try_spend("abuseipdb")); // still has plenty
    }
}
