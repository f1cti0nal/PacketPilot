//! Deterministic PRNG (SplitMix64) and the protocol-mix scheduler for the generator.
//!
//! SplitMix64 is a tiny, fast, fully-specified generator: same seed => same sequence on
//! every platform, so generated captures are byte-identical and reproducible without a
//! `rand` dependency. The mix scheduler turns a `(scenario, packets, include_edge_cases)`
//! triple into an exact per-protocol count plan whose buckets sum to `packets`.

use crate::gen::Scenario;
use crate::model::summary::ProtoCounts;

/// SplitMix64 PRNG state.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Seed the generator.
    pub fn new(seed: u64) -> SplitMix64 {
        SplitMix64 { state: seed }
    }

    /// Next 64-bit value (the canonical SplitMix64 step).
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform value in `[0, n)` via Lemire-style multiply-high reduction.
    ///
    /// Not perfectly unbiased (no rejection step), but deterministic and more than good
    /// enough for synthetic-traffic shaping. `below(0) == 0`.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        let v = self.next_u64();
        (((v as u128) * (n as u128)) >> 64) as u64
    }
}

/// The leaf weights for a scenario, as a 5-tuple
/// `(http, tls, dns, other_tcp, other_udp)`. The weights need not sum to any particular
/// constant; allocation is proportional.
fn weights_for(scenario: Scenario) -> (u64, u64, u64, u64, u64) {
    match scenario {
        // HTTP 22 / TLS 28 / DNS 20 / other-TCP 14 / other-UDP 14 (+edge 2 handled
        // separately). 22+28+20+14+14 == 98, leaving the "edge" 2% to the edge-case carve.
        Scenario::Mixed => (22, 28, 20, 14, 14),
        // Web traffic only: HTTP + TLS, TLS dominant.
        Scenario::WebOnly => (40, 60, 0, 0, 0),
        // Pure DNS over UDP.
        Scenario::DnsFlood => (0, 0, 100, 0, 0),
        // Many TCP SYNs to assorted ports (modeled as other_tcp).
        Scenario::PortScan => (0, 0, 0, 100, 0),
        // Periodic small TLS beacons with a little DNS resolution noise.
        Scenario::Beacon => (0, 90, 10, 0, 0),
        // Bulk transfer: large HTTP responses dominate, a little TLS.
        Scenario::BulkTransfer => (70, 20, 0, 10, 0),
    }
}

/// Largest-remainder apportionment of `total` items across the given integer `weights`.
///
/// Returns one count per weight such that the counts sum to `total` EXACTLY. Buckets with
/// a larger fractional remainder receive the leftover units first; ties break toward the
/// lower index so the result is fully deterministic.
fn apportion(total: u64, weights: &[u64]) -> Vec<u64> {
    let n = weights.len();
    let mut out = vec![0u64; n];
    let wsum: u64 = weights.iter().copied().sum();
    if wsum == 0 || total == 0 {
        // Degenerate: no weight mass. Dump everything in the first bucket so the sum is
        // still preserved and the function never panics.
        if n > 0 {
            out[0] = total;
        }
        return out;
    }

    // floor(total * w / wsum) per bucket, tracking the remainder numerators.
    let mut allocated: u64 = 0;
    // (remainder_numerator, index)
    let mut remainders: Vec<(u64, usize)> = Vec::with_capacity(n);
    for (i, &w) in weights.iter().enumerate() {
        let numer = total as u128 * w as u128;
        let q = (numer / wsum as u128) as u64;
        let r = (numer % wsum as u128) as u64;
        out[i] = q;
        allocated += q;
        remainders.push((r, i));
    }

    let mut leftover = total - allocated;
    // Largest remainder first; tie -> lower index. Sort descending by remainder, ascending
    // by index.
    remainders.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    for &(_, idx) in remainders.iter() {
        if leftover == 0 {
            break;
        }
        out[idx] += 1;
        leftover -= 1;
    }
    out
}

/// Compute the exact per-protocol count plan for a scenario. Buckets sum to `packets`.
/// Independent of seed (only depends on `scenario`, `packets`, `include_edge_cases`).
///
/// Invariants guaranteed for every input:
/// - `http + tls + other_tcp == tcp`
/// - `dns + other_udp == udp`
/// - `tcp + udp + non_ipv4 == packets` (so the grand total is conserved)
/// - when `include_edge_cases` and `packets >= 2`: `truncated == 1` and `non_ipv4 == 1`.
///
/// The `truncated` edge frame is a *malformed IPv4/TCP* frame, so it is still counted in
/// the `tcp` aggregate (it carves a unit out of `other_tcp`). The `non_ipv4` edge frame is
/// an ARP frame and is the only contributor to the `non_ipv4` bucket.
pub fn counts_for(scenario: Scenario, packets: u64, include_edge_cases: bool) -> ProtoCounts {
    let mut counts = ProtoCounts::default();
    if packets == 0 {
        return counts;
    }

    // Reserve the two edge frames first (only when enabled and there is room).
    let edge_active = include_edge_cases && packets >= 2;
    let non_ipv4 = if edge_active { 1 } else { 0 };
    let truncated = if edge_active { 1 } else { 0 };

    // The non_ipv4 (ARP) frame is carved out of the IP traffic budget entirely.
    let ip_budget = packets - non_ipv4;

    let (w_http, w_tls, w_dns, w_otcp, w_oudp) = weights_for(scenario);
    let weights = [w_http, w_tls, w_dns, w_otcp, w_oudp];
    let alloc = apportion(ip_budget, &weights);

    let mut http = alloc[0];
    let mut tls = alloc[1];
    let mut dns = alloc[2];
    let mut other_tcp = alloc[3];
    let mut other_udp = alloc[4];

    // The truncated edge frame is a (broken) TCP frame: it is a *tag* on one existing
    // `other_tcp` unit (it stays inside the tcp aggregate, so the tcp/udp split is
    // unchanged). The schedule later carves exactly `truncated` units out of `other_tcp`
    // and emits them as malformed frames, so we must guarantee `other_tcp >= truncated`.
    // If apportion gave other_tcp too few units, move units in from the largest other leaf;
    // this preserves `http+tls+dns+other_tcp+other_udp == ip_budget`.
    if truncated > other_tcp {
        let mut need = truncated - other_tcp;
        // Donors in priority order: http, tls, other_udp, dns. Each donation shifts a unit
        // from a leaf into other_tcp. Note: donating from a UDP leaf moves a packet from the
        // udp aggregate to the tcp aggregate — acceptable, since edge cases only nudge a
        // single unit and conservation (tcp+udp+non_ipv4==packets) is preserved.
        for donor in [&mut http, &mut tls, &mut other_udp, &mut dns] {
            while need > 0 && *donor > 0 {
                *donor -= 1;
                other_tcp += 1;
                need -= 1;
            }
            if need == 0 {
                break;
            }
        }
        // `need` is now 0 whenever ip_budget >= truncated, which always holds for the
        // packets>=2 path that activates edges.
    }

    // Defensive: guarantee the conservation law tcp + udp + non_ipv4 == packets. The
    // apportion() over ip_budget already guarantees http+tls+dns+other_tcp+other_udp ==
    // ip_budget, and ip_budget + non_ipv4 == packets, so this holds. Recompute to be sure
    // and nudge the largest leaf if rounding ever drifted (it cannot, but stay panic-safe).
    let leaf_sum = http + tls + dns + other_tcp + other_udp;
    if leaf_sum != ip_budget {
        // Adjust other_tcp (or, if zero, the largest leaf) to absorb any drift.
        let diff = ip_budget as i128 - leaf_sum as i128;
        let target = if other_tcp > 0 {
            &mut other_tcp
        } else if other_udp > 0 {
            &mut other_udp
        } else if http > 0 {
            &mut http
        } else if tls > 0 {
            &mut tls
        } else {
            &mut dns
        };
        if diff >= 0 {
            *target += diff as u64;
        } else {
            *target = target.saturating_sub((-diff) as u64);
        }
    }

    counts.http = http;
    counts.tls = tls;
    counts.dns = dns;
    counts.other_tcp = other_tcp;
    counts.other_udp = other_udp;
    counts.tcp = http + tls + other_tcp;
    counts.udp = dns + other_udp;
    counts.truncated = truncated;
    counts.non_ipv4 = non_ipv4;
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitmix64_matches_reference_sequence() {
        // Reference SplitMix64 output for seed 0 (well-known vectors).
        let mut r = SplitMix64::new(0);
        assert_eq!(r.next_u64(), 0xE220A8397B1DCDAF);
        assert_eq!(r.next_u64(), 0x6E789E6AA1B965F4);
        assert_eq!(r.next_u64(), 0x06C45D188009454F);
    }

    #[test]
    fn below_is_in_range_and_deterministic() {
        let mut a = SplitMix64::new(42);
        let mut b = SplitMix64::new(42);
        for _ in 0..1000 {
            let x = a.below(7);
            assert!(x < 7);
            assert_eq!(x, b.below(7));
        }
        assert_eq!(SplitMix64::new(1).below(0), 0);
        // below(1) is always 0.
        let mut c = SplitMix64::new(99);
        for _ in 0..100 {
            assert_eq!(c.below(1), 0);
        }
    }

    #[test]
    fn apportion_conserves_total() {
        for &total in &[0u64, 1, 2, 97, 1000, 100_000, 999_999] {
            let w = [22, 28, 20, 14, 14];
            let a = apportion(total, &w);
            assert_eq!(a.iter().sum::<u64>(), total, "total={total}");
        }
    }

    #[test]
    fn apportion_zero_weight_does_not_panic() {
        let a = apportion(50, &[0, 0, 0]);
        assert_eq!(a.iter().sum::<u64>(), 50);
    }

    #[test]
    fn counts_sum_to_packets_no_edges() {
        for &packets in &[1u64, 2, 97, 1000, 100_000] {
            let c = counts_for(Scenario::Mixed, packets, false);
            assert_eq!(c.tcp + c.udp + c.non_ipv4, packets, "packets={packets}");
            assert_eq!(c.http + c.tls + c.other_tcp, c.tcp);
            assert_eq!(c.dns + c.other_udp, c.udp);
            assert_eq!(c.non_ipv4, 0);
            assert_eq!(c.truncated, 0);
        }
    }

    #[test]
    fn counts_with_edges_inject_one_each() {
        for &packets in &[2u64, 97, 1000, 100_000] {
            let c = counts_for(Scenario::Mixed, packets, true);
            assert_eq!(c.truncated, 1, "packets={packets}");
            assert_eq!(c.non_ipv4, 1, "packets={packets}");
            // Grand total still conserved: tcp + udp + non_ipv4 == packets.
            assert_eq!(c.tcp + c.udp + c.non_ipv4, packets, "packets={packets}");
            assert_eq!(c.http + c.tls + c.other_tcp, c.tcp);
            assert_eq!(c.dns + c.other_udp, c.udp);
        }
    }

    #[test]
    fn edges_ignored_for_tiny_captures() {
        // With packets == 1 there is no room for two edge frames.
        let c = counts_for(Scenario::Mixed, 1, true);
        assert_eq!(c.non_ipv4, 0);
        assert_eq!(c.truncated, 0);
        assert_eq!(c.tcp + c.udp, 1);
    }

    #[test]
    fn counts_seed_independent_by_construction() {
        // counts_for has no seed parameter at all, so it is trivially seed-independent;
        // assert it is also a pure function (same inputs => same output).
        let a = counts_for(Scenario::Mixed, 10_000, false);
        let b = counts_for(Scenario::Mixed, 10_000, false);
        assert_eq!(a, b);
    }

    #[test]
    fn edges_reserve_a_tcp_slot_even_for_web_only() {
        // WebOnly has no other_tcp by weight, but the truncated edge frame must still have a
        // TCP home: other_tcp ends up >= truncated and the total is conserved.
        let c = counts_for(Scenario::WebOnly, 500, true);
        assert_eq!(c.truncated, 1);
        assert_eq!(c.non_ipv4, 1);
        assert!(c.other_tcp >= c.truncated);
        assert_eq!(c.tcp + c.udp + c.non_ipv4, 500);
        assert_eq!(c.http + c.tls + c.other_tcp, c.tcp);
    }

    #[test]
    fn edges_reserve_a_tcp_slot_even_for_dns_flood() {
        // DnsFlood has no TCP at all by weight; one unit must migrate into other_tcp.
        let c = counts_for(Scenario::DnsFlood, 500, true);
        assert_eq!(c.truncated, 1);
        assert!(c.other_tcp >= 1);
        assert_eq!(c.tcp + c.udp + c.non_ipv4, 500);
    }

    #[test]
    fn specialized_scenarios_have_expected_shapes() {
        let dns = counts_for(Scenario::DnsFlood, 1000, false);
        assert_eq!(dns.udp, 1000);
        assert_eq!(dns.dns, 1000);
        assert_eq!(dns.tcp, 0);

        let scan = counts_for(Scenario::PortScan, 1000, false);
        assert_eq!(scan.tcp, 1000);
        assert_eq!(scan.other_tcp, 1000);
        assert_eq!(scan.udp, 0);

        let web = counts_for(Scenario::WebOnly, 1000, false);
        assert_eq!(web.tcp, 1000);
        assert_eq!(web.dns, 0);
        assert!(web.http > 0 && web.tls > 0);
    }
}
