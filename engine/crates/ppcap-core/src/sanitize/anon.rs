//! Keyed, deterministic pseudonymization primitives for Safe Share.
//!
//! Everything here is driven by one per-run 256-bit secret and the vendored SHA-256
//! (no new dependencies, C-free). Within a run the mapping is a *function* of
//! (key, input), so identical inputs always map to identical outputs even when the
//! bounded memo caches overflow — the caches are a speedup, never a correctness
//! dependency. The key lives only in memory and is never written to the output or
//! the manifest, so the mapping cannot be reversed after the process exits.
//!
//! ## Address mapping guarantees
//! - **Bijective**: both the prefix-preserving walk (Crypto-PAn construction) and the
//!   flat mode (4-round Feistel network) are permutations, so distinct inputs never
//!   collide.
//! - **Structure pinning**: special-use addresses (loopback, multicast, broadcast,
//!   unspecified) pass through unchanged, and private/reserved block membership is
//!   always preserved (10/8 stays inside 10/8, fe80::/10 stays link-local, …) so a
//!   sanitized capture still *reads* like the same kind of network.
//! - `preserve_prefix = true` (default) additionally preserves shared-prefix
//!   relationships between addresses (Crypto-PAn semantics): hosts of one /24 stay
//!   together in some pseudonymous /24.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::analyze::sha256 as sha256_once;

/// Cap for each memo cache; beyond this, values are computed on the fly (still
/// deterministic). Keeps the sanitizer inside the engine's bounded-memory budget.
const CACHE_CAP: usize = 1 << 18;

/// PRF domain-separation tags. One byte each, prepended after the key.
const DOM_V4_WALK: u8 = 1;
const DOM_V6_WALK: u8 = 2;
const DOM_FEISTEL: u8 = 3;
const DOM_MAC: u8 = 4;
const DOM_NAME_LABEL: u8 = 5;
const DOM_TOKEN: u8 = 6;

/// The keyed transform engine. One instance per sanitize run.
pub struct Anonymizer {
    key: [u8; 32],
    preserve_prefix: bool,
    preserve_oui: bool,
    v4_cache: HashMap<Ipv4Addr, Ipv4Addr>,
    v6_cache: HashMap<Ipv6Addr, Ipv6Addr>,
    mac_cache: HashMap<[u8; 6], [u8; 6]>,
}

impl Anonymizer {
    /// Build from an explicit 256-bit key (callers on native use [`fresh_key`]; the
    /// wasm binding passes bytes from `crypto.getRandomValues`).
    pub fn from_key(key: [u8; 32], preserve_prefix: bool, preserve_oui: bool) -> Self {
        Anonymizer {
            key,
            preserve_prefix,
            preserve_oui,
            v4_cache: HashMap::new(),
            v6_cache: HashMap::new(),
            mac_cache: HashMap::new(),
        }
    }

    /// Number of distinct values pseudonymized so far (for the manifest). Values
    /// beyond the memo cap are not counted — the counts are floors, not totals.
    pub fn unique_counts(&self) -> (u64, u64, u64) {
        (
            self.v4_cache.len() as u64,
            self.v6_cache.len() as u64,
            self.mac_cache.len() as u64,
        )
    }

    /// Keyed PRF: SHA-256(key || domain || data). 32 bytes out.
    fn prf(&self, domain: u8, data: &[u8]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(33 + data.len());
        buf.extend_from_slice(&self.key);
        buf.push(domain);
        buf.extend_from_slice(data);
        sha256_once(&buf)
    }

    /// First eight PRF bytes as a big-endian u64.
    fn prf64(&self, domain: u8, data: &[u8]) -> u64 {
        let h = self.prf(domain, data);
        u64::from_be_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]])
    }

    // -----------------------------------------------------------------------
    // IP addresses
    // -----------------------------------------------------------------------

    /// Pseudonymize an IPv4 address. Special-use addresses pass through; private /
    /// reserved block membership is pinned; the remaining suffix bits are permuted.
    pub fn ipv4(&mut self, ip: Ipv4Addr) -> Ipv4Addr {
        if v4_is_special(ip) {
            return ip;
        }
        if let Some(hit) = self.v4_cache.get(&ip) {
            return *hit;
        }
        let fixed = v4_pinned_prefix_len(ip);
        let bits = u32::from(ip) as u128;
        let out_bits = self.permute(DOM_V4_WALK, bits, 32, fixed) as u32;
        let out = Ipv4Addr::from(out_bits);
        if self.v4_cache.len() < CACHE_CAP {
            self.v4_cache.insert(ip, out);
        }
        out
    }

    /// Pseudonymize an IPv6 address (same pinning rules as v4; see module docs).
    pub fn ipv6(&mut self, ip: Ipv6Addr) -> Ipv6Addr {
        if v6_is_special(ip) {
            return ip;
        }
        if let Some(hit) = self.v6_cache.get(&ip) {
            return *hit;
        }
        let fixed = v6_pinned_prefix_len(ip);
        let bits = u128::from(ip);
        let out_bits = self.permute(DOM_V6_WALK, bits, 128, fixed);
        let out = Ipv6Addr::from(out_bits);
        if self.v6_cache.len() < CACHE_CAP {
            self.v6_cache.insert(ip, out);
        }
        out
    }

    /// Permute the low `width - fixed` bits of `bits` (a `width`-bit value), leaving
    /// the top `fixed` bits untouched. Prefix-preserving (Crypto-PAn walk) or flat
    /// (Feistel), depending on the run option. Both are bijections on the suffix.
    fn permute(&self, walk_dom: u8, bits: u128, width: u32, fixed: u32) -> u128 {
        if fixed >= width {
            return bits;
        }
        if self.preserve_prefix {
            self.prefix_preserving_walk(walk_dom, bits, width, fixed)
        } else {
            let suffix_bits = width - fixed;
            let mask = mask_u128(suffix_bits);
            let suffix = bits & mask;
            let permuted = self.feistel(walk_dom, suffix, suffix_bits);
            (bits & !mask) | (permuted & mask)
        }
    }

    /// Crypto-PAn construction: output bit i = input bit i XOR lsb(PRF(prefix_i)),
    /// where prefix_i is the *original* address's first i bits. Bijective and
    /// prefix-preserving: addresses sharing a k-bit prefix share the pseudonymous
    /// k-bit prefix, and nothing else is preserved.
    fn prefix_preserving_walk(&self, dom: u8, bits: u128, width: u32, fixed: u32) -> u128 {
        let mut out = bits;
        for i in fixed..width {
            // The top i bits of the original value, as a right-aligned integer.
            let prefix = if i == 0 { 0 } else { bits >> (width - i) };
            let mut data = [0u8; 21];
            data[0] = dom; // separates the v4 and v6 walks even at equal widths
            data[1..5].copy_from_slice(&i.to_be_bytes());
            data[5..21].copy_from_slice(&prefix.to_be_bytes());
            let flip = (self.prf64(DOM_V4_WALK, &data) & 1) as u128;
            out ^= flip << (width - 1 - i);
        }
        out
    }

    /// 4-round unbalanced Feistel permutation over a `width`-bit value (width ≤ 64
    /// per half is guaranteed since width ≤ 128). Bijective for any width ≥ 1.
    fn feistel(&self, dom: u8, val: u128, width: u32) -> u128 {
        if width == 0 {
            return val;
        }
        if width == 1 {
            // Degenerate: flip (or not) based on the key alone — still a bijection.
            return val ^ (self.prf64(DOM_FEISTEL, &[dom, 1]) & 1) as u128;
        }
        let mut a_bits = width / 2; // current width of `l`
        let mut b_bits = width - a_bits; // current width of `r`
        let mut l = val >> b_bits;
        let mut r = val & mask_u128(b_bits);
        for round in 0..4u8 {
            // Round function: r (b_bits wide) -> a_bits wide, keyed + domain-tagged.
            let mut data = [0u8; 19];
            data[0] = dom;
            data[1] = round;
            data[2] = width as u8;
            data[3..19].copy_from_slice(&r.to_be_bytes());
            let f = (self.prf64(DOM_FEISTEL, &data) as u128) & mask_u128(a_bits);
            let nl = r;
            let nr = l ^ f;
            l = nl;
            r = nr;
            std::mem::swap(&mut a_bits, &mut b_bits);
        }
        // Four rounds = even number of swaps, so widths are back to the original split.
        (l << b_bits) | r
    }

    // -----------------------------------------------------------------------
    // MAC addresses
    // -----------------------------------------------------------------------

    /// Pseudonymize a MAC address. Group (multicast/broadcast) and all-zero
    /// addresses pass through; unicast addresses are replaced with a stable
    /// pseudonym. With `preserve_oui` the vendor prefix (first three bytes) is kept
    /// and only the NIC-specific half is replaced; otherwise the whole address is
    /// replaced and flagged locally-administered so it cannot collide with a real
    /// vendor assignment.
    pub fn mac(&mut self, mac: [u8; 6]) -> [u8; 6] {
        if mac[0] & 0x01 != 0 || mac == [0u8; 6] {
            return mac; // group address (broadcast/multicast) or placeholder
        }
        if let Some(hit) = self.mac_cache.get(&mac) {
            return *hit;
        }
        let h = self.prf(DOM_MAC, &mac);
        let out = if self.preserve_oui {
            [mac[0], mac[1], mac[2], h[0], h[1], h[2]]
        } else {
            // Unicast (clear bit 0) + locally administered (set bit 1).
            [(h[0] & 0xFC) | 0x02, h[1], h[2], h[3], h[4], h[5]]
        };
        if self.mac_cache.len() < CACHE_CAP {
            self.mac_cache.insert(mac, out);
        }
        out
    }

    // -----------------------------------------------------------------------
    // L7 string tokens
    // -----------------------------------------------------------------------

    /// Stable same-length token for one hostname label. Case-insensitive on input
    /// (DNS semantics) so `Example` and `example` map to the same token. The same
    /// domain tag is used for DNS names, TLS SNI, and HTTP Host, so one real label
    /// maps to one pseudonymous label across all three protocols.
    pub fn name_label_token(&self, label: &[u8], out: &mut [u8]) {
        let lower: Vec<u8> = label.iter().map(|b| b.to_ascii_lowercase()).collect();
        self.fill_token(DOM_NAME_LABEL, &lower, out);
    }

    /// Stable same-length token for an opaque sensitive value (URI, credential,
    /// header value). Distinct domain from hostname labels.
    pub fn value_token(&self, value: &[u8], out: &mut [u8]) {
        self.fill_token(DOM_TOKEN, value, out);
    }

    /// Fill `out` with `[a-z0-9]` token bytes derived from PRF(domain, value),
    /// re-hashing with a counter for outputs longer than one digest.
    fn fill_token(&self, domain: u8, value: &[u8], out: &mut [u8]) {
        const CHARSET: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let mut counter = 0u32;
        let mut filled = 0usize;
        while filled < out.len() {
            let mut data = Vec::with_capacity(4 + value.len());
            data.extend_from_slice(&counter.to_be_bytes());
            data.extend_from_slice(value);
            let h = self.prf(domain, &data);
            for byte in h.iter() {
                if filled >= out.len() {
                    break;
                }
                out[filled] = CHARSET[(*byte as usize) % CHARSET.len()];
                filled += 1;
            }
            counter += 1;
        }
    }
}

/// A `width`-bit all-ones mask (width ≤ 128).
fn mask_u128(width: u32) -> u128 {
    if width >= 128 {
        u128::MAX
    } else {
        (1u128 << width) - 1
    }
}

/// IPv4 addresses that pass through unchanged: unspecified, loopback, multicast,
/// limited broadcast.
fn v4_is_special(ip: Ipv4Addr) -> bool {
    ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast()
}

/// Bits of prefix pinned so the pseudonym stays inside the same special-use block.
/// Public addresses return 0 (the whole 32 bits are permuted).
fn v4_pinned_prefix_len(ip: Ipv4Addr) -> u32 {
    let o = ip.octets();
    match o[0] {
        10 => 8,                                 // RFC 1918
        172 if (16..=31).contains(&o[1]) => 12,  // RFC 1918
        192 if o[1] == 168 => 16,                // RFC 1918
        100 if (64..=127).contains(&o[1]) => 10, // RFC 6598 CGNAT
        169 if o[1] == 254 => 16,                // link-local
        _ => 0,
    }
}

/// IPv6 addresses that pass through unchanged: unspecified, loopback, multicast.
fn v6_is_special(ip: Ipv6Addr) -> bool {
    ip.is_unspecified() || ip.is_loopback() || ip.is_multicast()
}

/// Bits pinned for IPv6 special-use blocks (ULA fc00::/7, link-local fe80::/10).
fn v6_pinned_prefix_len(ip: Ipv6Addr) -> u32 {
    let s = ip.segments();
    if (s[0] & 0xFE00) == 0xFC00 {
        7 // ULA
    } else if (s[0] & 0xFFC0) == 0xFE80 {
        10 // link-local (interface id may embed a real MAC — must be permuted)
    } else {
        0
    }
}

/// Native-only fresh key: OS-entropy-backed `RandomState` hashes mixed with the
/// wall clock and PID through SHA-256. Not available on wasm (no OS entropy there;
/// the browser passes key bytes from `crypto.getRandomValues` instead).
#[cfg(not(target_arch = "wasm32"))]
pub fn fresh_key() -> [u8; 32] {
    use std::hash::{BuildHasher, Hasher};
    let mut seed = Vec::with_capacity(64);
    for i in 0u8..4 {
        // Each RandomState carries its own 128-bit OS-random key; hashing a
        // constant extracts 64 key-dependent bits.
        let s = std::collections::hash_map::RandomState::new();
        let mut h = s.build_hasher();
        h.write(&[i]);
        seed.extend_from_slice(&h.finish().to_be_bytes());
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    seed.extend_from_slice(&nanos.to_be_bytes());
    seed.extend_from_slice(&std::process::id().to_be_bytes());
    sha256_once(&seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anon(preserve_prefix: bool) -> Anonymizer {
        Anonymizer::from_key([7u8; 32], preserve_prefix, false)
    }

    #[test]
    fn v4_mapping_is_deterministic_and_distinct() {
        let mut a = anon(true);
        let x = a.ipv4("203.0.113.7".parse().unwrap());
        let y = a.ipv4("203.0.113.7".parse().unwrap());
        assert_eq!(x, y, "same input, same run => same output");
        let z = a.ipv4("203.0.113.8".parse().unwrap());
        assert_ne!(x, z, "distinct inputs must stay distinct");
        assert_ne!(x, "203.0.113.7".parse::<Ipv4Addr>().unwrap(), "must change");
    }

    #[test]
    fn v4_mapping_differs_across_keys() {
        let mut a = Anonymizer::from_key([1u8; 32], true, false);
        let mut b = Anonymizer::from_key([2u8; 32], true, false);
        let ip = "198.51.100.20".parse().unwrap();
        assert_ne!(a.ipv4(ip), b.ipv4(ip));
    }

    #[test]
    fn v4_prefix_relationships_preserved_when_enabled() {
        let mut a = anon(true);
        let x = a.ipv4("203.0.113.10".parse().unwrap());
        let y = a.ipv4("203.0.113.99".parse().unwrap());
        // Same /24 in => same /24 out under the Crypto-PAn walk.
        assert_eq!(u32::from(x) >> 8, u32::from(y) >> 8);
        // And a different /24 diverges within the shared /16's suffix bits.
        let z = a.ipv4("203.0.112.10".parse().unwrap());
        assert_eq!(u32::from(x) >> 16, u32::from(z) >> 16); // shared 16-bit prefix kept
        assert_ne!(u32::from(x) >> 8, u32::from(z) >> 8); // distinct /24s stay distinct
    }

    #[test]
    fn v4_private_blocks_are_pinned_in_both_modes() {
        for pp in [true, false] {
            let mut a = anon(pp);
            let x = a.ipv4("10.1.2.3".parse().unwrap());
            assert_eq!(x.octets()[0], 10, "10/8 must stay in 10/8 (pp={pp})");
            let y = a.ipv4("192.168.4.5".parse().unwrap());
            assert_eq!(&y.octets()[..2], &[192, 168], "192.168/16 pinned (pp={pp})");
            let z = a.ipv4("172.20.1.1".parse().unwrap());
            assert_eq!(z.octets()[0], 172);
            assert!((16..=31).contains(&z.octets()[1]), "172.16/12 pinned");
        }
    }

    #[test]
    fn v4_flat_mode_breaks_subnet_structure() {
        let mut a = anon(false);
        // With enough sibling pairs, at least one pair must split /24s in flat mode.
        let mut any_split = false;
        for i in 0..8u8 {
            let x = a.ipv4(format!("203.0.{i}.10").parse().unwrap());
            let y = a.ipv4(format!("203.0.{i}.99").parse().unwrap());
            if u32::from(x) >> 8 != u32::from(y) >> 8 {
                any_split = true;
            }
        }
        assert!(any_split, "flat mode should not preserve /24 grouping");
    }

    #[test]
    fn v4_specials_pass_through() {
        let mut a = anon(true);
        for s in ["127.0.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.251"] {
            let ip: Ipv4Addr = s.parse().unwrap();
            assert_eq!(a.ipv4(ip), ip, "{s} must be preserved");
        }
    }

    #[test]
    fn v4_permutation_is_injective_on_a_dense_range() {
        // Bijectivity spot check: 4096 consecutive addresses, no collisions, both modes.
        for pp in [true, false] {
            let mut a = anon(pp);
            let mut seen = std::collections::HashSet::new();
            for i in 0..4096u32 {
                let ip = Ipv4Addr::from(0xCB00_7100u32 + i); // 203.0.113.0 onward
                assert!(seen.insert(a.ipv4(ip)), "collision at {ip} (pp={pp})");
            }
        }
    }

    #[test]
    fn v6_mapping_pins_blocks_and_specials() {
        let mut a = anon(true);
        let ll: Ipv6Addr = "fe80::1234:5678:9abc:def0".parse().unwrap();
        let out = a.ipv6(ll);
        assert_ne!(out, ll);
        assert_eq!(out.segments()[0] & 0xFFC0, 0xFE80, "stays link-local");
        let ula: Ipv6Addr = "fd00::42".parse().unwrap();
        assert_eq!(a.ipv6(ula).segments()[0] & 0xFE00, 0xFC00, "stays ULA");
        for s in ["::1", "::", "ff02::1"] {
            let ip: Ipv6Addr = s.parse().unwrap();
            assert_eq!(a.ipv6(ip), ip, "{s} must be preserved");
        }
        let global: Ipv6Addr = "2001:db8::5".parse().unwrap();
        assert_ne!(a.ipv6(global), global);
    }

    #[test]
    fn mac_rules() {
        let mut a = anon(true);
        let m = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let out = a.mac(m);
        assert_ne!(out, m);
        assert_eq!(out[0] & 0x01, 0, "pseudonym must stay unicast");
        assert_eq!(
            out[0] & 0x02,
            0x02,
            "pseudonym must be locally administered"
        );
        assert_eq!(a.mac(m), out, "stable within a run");
        // Broadcast + multicast + zero pass through.
        assert_eq!(a.mac([0xFF; 6]), [0xFF; 6]);
        let mc = [0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB];
        assert_eq!(a.mac(mc), mc);
        assert_eq!(a.mac([0u8; 6]), [0u8; 6]);
        // OUI preservation.
        let mut b = Anonymizer::from_key([7u8; 32], true, true);
        let kept = b.mac(m);
        assert_eq!(&kept[..3], &m[..3]);
        assert_ne!(&kept[3..], &m[3..]);
    }

    #[test]
    fn tokens_are_stable_case_insensitive_and_charset_bounded() {
        let a = anon(true);
        let mut t1 = [0u8; 8];
        let mut t2 = [0u8; 8];
        a.name_label_token(b"Example", &mut t1);
        a.name_label_token(b"example", &mut t2);
        assert_eq!(t1, t2, "hostname labels are case-insensitive");
        assert!(t1
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()));
        let mut t3 = [0u8; 8];
        a.name_label_token(b"other", &mut t3);
        assert_ne!(t1, t3);
        // Long outputs (multi-digest) work.
        let mut long = [0u8; 100];
        a.value_token(b"secret", &mut long);
        assert!(long
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn fresh_keys_differ() {
        assert_ne!(fresh_key(), fresh_key());
    }
}
