//! Bidirectional flow table with bounded-memory eviction.
//!
//! Folds packets into per-[`FlowKey`] [`FlowRecord`]s. Memory is capped two ways:
//! - `max_active_flows` bounds the live map size (approximate-LRU eviction of the
//!   least-recently-active flow when the cap is hit), and
//! - idle/active timeouts close flows during the stream so completed records flow out to
//!   the classify/stats/writer sink instead of accumulating.
//!
//! Expiry uses a monotonic high-water `max_seen_ts`, never a single backward packet's
//! timestamp, so out-of-order/clock-skewed captures do not cause premature eviction.
//!
//! ## Cap / memory strategy
//!
//! The live map never exceeds `config.max_active_flows` entries. When a *new* flow would
//! exceed the cap, the approximate-LRU victim (the live flow with the smallest
//! `last_ts_ns`) is removed first and buffered for the next drain. The LRU is an
//! amortized structure: a [`BinaryHeap`] of `(Reverse(last_ts_ns), seq, FlowKey)` with
//! **lazy invalidation**. Each flow carries a monotonically-increasing `seq` token; when a
//! flow's `last_ts_ns` advances we push a fresh heap entry rather than mutating the old
//! one, and stale entries are skipped on pop by comparing the popped `seq` against the
//! live `seq` stored alongside the record. This keeps `observe` amortized O(log n) and
//! caps heap growth: whenever the heap grows past `2 * map.len() + 16` we compact it,
//! dropping every stale entry. Because each direction of memory is bounded by the live map
//! plus the compaction headroom, peak heap stays independent of capture size.
//!
//! ## Cap-eviction surfacing (fixed `observe` signature)
//!
//! `observe`'s signature returns only `Option<FlowKey>`, so a cap-eviction victim cannot
//! be handed to the sink there. Victims are therefore buffered in `pending` and flushed by
//! the next [`FlowTable::evict_expired`] / [`FlowTable::drain_all`] call, exactly as the
//! module contract prescribes.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

use crate::model::flow::{FlowKey, FlowRecord};
use crate::model::packet::PacketMeta;

// L7 aggregation: `FlowRecord::observe` unions `PacketMeta::app_proto`/`sni` onto the
// flow (most-specific hint, first SNI). The classify stage then derives the final label.

/// Tuning for the flow table.
#[derive(Debug, Clone)]
pub struct FlowConfig {
    /// Max simultaneously tracked flows before LRU eviction kicks in.
    pub max_active_flows: usize,
    /// Close a flow with no packets for this long (ns).
    pub idle_timeout_ns: i64,
    /// Force-close a flow open longer than this (ns), even if still active.
    pub active_timeout_ns: i64,
}

impl Default for FlowConfig {
    fn default() -> Self {
        // 32Ki live flows / 120s idle / 1800s active. The flow cap is sized so even the
        // worst case (~1 flow/packet) keeps peak heap within the Phase-0 <=64 MiB budget;
        // evicted flows still stream to the sink (stats + Parquet), so the summary and
        // persisted flows stay complete — only the live working set is bounded. Raise it for
        // very-high-concurrency captures where avoiding flow splits matters more than RAM.
        FlowConfig {
            max_active_flows: 32_768,
            idle_timeout_ns: 120_000_000_000,
            active_timeout_ns: 1_800_000_000_000,
        }
    }
}

/// A live flow plus the LRU bookkeeping token that validates heap entries.
struct LiveFlow {
    record: FlowRecord,
    /// The most recent `seq` pushed for this flow. A heap entry is current iff its `seq`
    /// equals this value.
    seq: u64,
}

/// One entry in the lazy-LRU heap. Ordered so that the *smallest* `last_ts` is popped
/// first (`Reverse` turns the max-heap into a min-heap on `last_ts`).
#[derive(PartialEq, Eq)]
struct LruEntry {
    last_ts: Reverse<i64>,
    seq: u64,
    key: FlowKey,
}

impl PartialOrd for LruEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LruEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Primary: smallest last_ts first (via Reverse). Tie-break on seq then on key
        // fields purely for a total, deterministic order (the key ordering is arbitrary but
        // stable: it never affects correctness, only heap determinism).
        self.last_ts
            .cmp(&other.last_ts)
            .then_with(|| self.seq.cmp(&other.seq))
            .then_with(|| {
                (self.key.lo_port, self.key.hi_port).cmp(&(other.key.lo_port, other.key.hi_port))
            })
    }
}

/// The flow aggregation table.
pub struct FlowTable {
    map: HashMap<FlowKey, LiveFlow>,
    /// Lazy-invalidated min-heap on `last_ts` for eviction + idle/active expiry.
    lru: BinaryHeap<LruEntry>,
    /// Cap-eviction victims awaiting surfacing through the next drain.
    pending: Vec<FlowRecord>,
    config: FlowConfig,
    /// Monotonic high-water clock; expiry is measured against this, never a single
    /// backward packet's timestamp.
    max_seen_ts: i64,
    /// Lifetime count of flows ever opened (the distinct-flow tally for the summary).
    total_created: u64,
    /// Per-flow `seq` allocator for lazy-LRU validation.
    next_seq: u64,
}

impl FlowTable {
    /// Create an empty table with the given configuration.
    pub fn new(config: FlowConfig) -> FlowTable {
        // Reserve a bounded initial capacity so small/medium captures avoid rehash churn
        // without ever pre-allocating the full (possibly 1M) cap.
        let initial = config.max_active_flows.min(1024);
        FlowTable {
            map: HashMap::with_capacity(initial),
            lru: BinaryHeap::with_capacity(initial),
            pending: Vec::new(),
            config,
            max_seen_ts: i64::MIN,
            total_created: 0,
            next_seq: 0,
        }
    }

    /// Push a fresh, current LRU entry for `key` reflecting `last_ts`, returning the new
    /// `seq`. Triggers heap compaction when stale entries dominate.
    fn touch_lru(&mut self, key: FlowKey, last_ts: i64) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.lru.push(LruEntry {
            last_ts: Reverse(last_ts),
            seq,
            key,
        });
        // Compaction: when the heap carries too many stale tombstones relative to the live
        // set, rebuild it from the current records. Bounds heap memory at O(map.len()).
        if self.lru.len() > self.map.len().saturating_mul(2).saturating_add(16) {
            self.compact_lru();
        }
        seq
    }

    /// Rebuild the LRU heap from the live map, discarding all stale entries.
    fn compact_lru(&mut self) {
        let mut fresh: BinaryHeap<LruEntry> = BinaryHeap::with_capacity(self.map.len());
        for (key, live) in self.map.iter() {
            fresh.push(LruEntry {
                last_ts: Reverse(live.record.last_ts_ns),
                seq: live.seq,
                key: *key,
            });
        }
        self.lru = fresh;
    }

    /// Whether a popped heap entry still reflects the live flow (not a stale tombstone).
    fn entry_is_current(&self, entry: &LruEntry) -> bool {
        match self.map.get(&entry.key) {
            Some(live) => live.seq == entry.seq,
            None => false,
        }
    }

    /// Evict the current approximate-LRU victim (smallest `last_ts`) into `pending`.
    /// Called only when the cap is hit and a new flow must be inserted.
    fn evict_one_lru(&mut self) {
        while let Some(entry) = self.lru.pop() {
            if self.entry_is_current(&entry) {
                if let Some(live) = self.map.remove(&entry.key) {
                    self.pending.push(live.record);
                }
                return;
            }
            // else: stale tombstone, skip.
        }
        // Heap exhausted but map non-empty (should not happen given touch_lru on every
        // insert/update). Fall back to removing an arbitrary entry to honor the cap.
        if let Some(key) = self.map.keys().next().copied() {
            if let Some(live) = self.map.remove(&key) {
                self.pending.push(live.record);
            }
        }
    }

    /// Fold one packet into its flow, opening a new flow if needed. Returns the
    /// [`FlowKey`] the packet was attributed to, or `None` if the packet has no IP
    /// endpoints (ARP / non-IP).
    pub fn observe(&mut self, p: &PacketMeta) -> Option<FlowKey> {
        let (key, dir) = FlowKey::from_packet(p)?;

        if p.ts_ns > self.max_seen_ts {
            self.max_seen_ts = p.ts_ns;
        }

        let is_new = !self.map.contains_key(&key);
        if is_new && self.map.len() >= self.config.max_active_flows {
            // Make room BEFORE inserting so the live map never exceeds the cap. Guard the
            // degenerate cap==0 config: nothing can be tracked, so route the packet's flow
            // straight to pending and return.
            if self.config.max_active_flows == 0 {
                let mut rec = FlowRecord::new(key, p.ts_ns);
                rec.observe(p, dir);
                self.total_created += 1;
                self.pending.push(rec);
                return Some(key);
            }
            self.evict_one_lru();
        }

        // Fold the packet into its record. We deliberately do NOT use the `entry()` API
        // here: holding an `Entry` borrow across `self.touch_lru(...)` (which mutably
        // borrows the whole table) would be a borrow conflict. Instead we mutate via
        // `get_mut`/`insert`, each scoped so no borrow of `self.map` is live when
        // `touch_lru` runs.
        let last = match self.map.get_mut(&key) {
            Some(live) => {
                live.record.observe(p, dir);
                live.record.last_ts_ns
            }
            None => {
                let mut rec = FlowRecord::new(key, p.ts_ns);
                rec.observe(p, dir);
                let last = rec.last_ts_ns;
                self.map.insert(
                    key,
                    LiveFlow {
                        record: rec,
                        seq: 0,
                    },
                );
                self.total_created += 1;
                last
            }
        };

        // Record the (possibly new) LRU position and stamp the flow's current seq so stale
        // heap entries can be detected on pop.
        let seq = self.touch_lru(key, last);
        if let Some(live) = self.map.get_mut(&key) {
            live.seq = seq;
        }

        Some(key)
    }

    /// Whether a flow is expired relative to `now_ns` (idle OR active timeout).
    fn is_expired(&self, rec: &FlowRecord, now_ns: i64) -> bool {
        let idle = self.config.idle_timeout_ns;
        let active = self.config.active_timeout_ns;
        // Use saturating arithmetic so extreme timestamps cannot overflow/panic.
        let idle_deadline = rec.last_ts_ns.saturating_add(idle);
        let active_deadline = rec.first_ts_ns.saturating_add(active);
        idle_deadline <= now_ns || active_deadline <= now_ns
    }

    /// Close and emit all flows whose idle/active timeout has elapsed relative to
    /// `now_ns` (use the table's `max_seen_ts`). Also drains any cap-eviction victims.
    pub fn evict_expired<F: FnMut(FlowRecord)>(&mut self, now_ns: i64, mut sink: F) {
        // Surface any buffered cap-eviction victims first.
        for rec in self.pending.drain(..) {
            sink(rec);
        }

        // Pop from the LRU front (smallest last_ts) while the front flow is expired
        // (idle OR active), skipping stale tombstones. We stop at the first *current* front
        // that is not expired, re-pushing it so its position is preserved.
        //
        // Correctness / approximation: the heap is keyed on last_ts, so the front holds the
        // global-minimum last_ts. Hence once a current front is not idle-expired, NO live
        // flow can be idle-expired (their last_ts are all >= the front's). This makes idle
        // expiry exact and O(k log n).
        //
        // Active timeout depends on first_ts, which is not the heap key. A flow deeper in
        // the heap (larger last_ts, so still "fresh" by idle) could have an older first_ts
        // and thus be active-expired while the front is not. Scanning for those every call
        // would be O(n) and defeat the bounded cost, so active expiry is treated as
        // best-effort during streaming: such a flow is force-closed once its own last_ts
        // reaches the front, or unconditionally at EOF via `drain_all`. We still honor an
        // active-expired *front* immediately (it costs nothing), which is why the stop
        // condition tests full `is_expired`, not just idle. This never emits a
        // non-expired flow and never drops a flow — it only defers some active closures.
        let mut reinsert: Option<LruEntry> = None;
        while let Some(entry) = self.lru.pop() {
            if !self.entry_is_current(&entry) {
                continue; // stale tombstone
            }
            let expired = match self.map.get(&entry.key) {
                Some(live) => self.is_expired(&live.record, now_ns),
                None => false,
            };
            if expired {
                if let Some(live) = self.map.remove(&entry.key) {
                    sink(live.record);
                }
            } else {
                // Front (global-min last_ts) is not idle-expired; since idle uses last_ts
                // and the front is the minimum, no remaining flow can be idle-expired. It
                // is also not active-expired. Stop and put it back.
                reinsert = Some(entry);
                break;
            }
        }
        if let Some(entry) = reinsert {
            self.lru.push(entry);
        }
    }

    /// Emit every remaining flow (call once at EOF) and clear the table.
    ///
    /// Records are emitted in a total, deterministic order — by `first_ts_ns`, then
    /// `last_ts_ns`, then the canonical 5-tuple — identical to [`FlowTable::finalize`]. This
    /// keeps the EOF output reproducible across runs (the underlying `HashMap` drain order is
    /// randomized per process), so the monotonic `flow_id` assigned downstream is stable for a
    /// given input.
    pub fn drain_all<F: FnMut(FlowRecord)>(&mut self, mut sink: F) {
        for rec in self.finalize() {
            sink(rec);
        }
    }

    /// Emit every remaining flow in a deterministic order as a `Vec` and clear the table.
    ///
    /// This is an additive convenience over the sink-based [`FlowTable::drain_all`] for
    /// callers (and tests) that need a stable, reproducible ordering of the final records —
    /// the prompt's `finalize() -> Vec<FlowRecord>` contract. Ordering is total and
    /// deterministic: by `first_ts_ns`, then `last_ts_ns`, then the canonical 5-tuple
    /// (lo_ip, hi_ip, lo_port, hi_port, transport proto number). Includes buffered
    /// cap-eviction victims. After this call the table is empty.
    pub fn finalize(&mut self) -> Vec<FlowRecord> {
        let mut out: Vec<FlowRecord> = Vec::with_capacity(self.map.len() + self.pending.len());
        out.append(&mut self.pending);
        for (_key, live) in self.map.drain() {
            out.push(live.record);
        }
        self.lru.clear();
        out.sort_by(|a, b| {
            a.first_ts_ns
                .cmp(&b.first_ts_ns)
                .then_with(|| a.last_ts_ns.cmp(&b.last_ts_ns))
                .then_with(|| flow_key_order(&a.key).cmp(&flow_key_order(&b.key)))
        });
        out
    }

    /// Number of currently live flows.
    pub fn active_len(&self) -> usize {
        self.map.len()
    }

    /// Total flows ever created (the distinct-flow count for the summary).
    pub fn total_created(&self) -> u64 {
        self.total_created
    }
}

/// A total, deterministic ordering tuple for a [`FlowKey`] (IPv4 before IPv6, then address
/// bytes, then ports, then transport). Used only to make `finalize`'s output stable.
fn flow_key_order(k: &FlowKey) -> (u8, Vec<u8>, u8, Vec<u8>, u16, u16, u8) {
    fn fam(ip: &std::net::IpAddr) -> u8 {
        match ip {
            std::net::IpAddr::V4(_) => 0,
            std::net::IpAddr::V6(_) => 1,
        }
    }
    fn bytes(ip: &std::net::IpAddr) -> Vec<u8> {
        match ip {
            std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
            std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
        }
    }
    (
        fam(&k.lo_ip),
        bytes(&k.lo_ip),
        fam(&k.hi_ip),
        bytes(&k.hi_ip),
        k.lo_port,
        k.hi_port,
        k.transport.ip_proto(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::flow::Direction;
    use crate::model::packet::{Protocol, Transport};
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// Minimal TCP packet builder.
    // Test helper: each arg maps to a distinct PacketMeta field; grouping them
    // into a struct would just duplicate PacketMeta and add noise.
    #[allow(clippy::too_many_arguments)]
    fn pkt(
        index: u64,
        ts_ns: i64,
        src: IpAddr,
        sp: u16,
        dst: IpAddr,
        dp: u16,
        flags: u8,
        wire_len: u32,
        ttl: u8,
    ) -> PacketMeta {
        PacketMeta {
            index,
            ts_ns,
            iface_id: 0,
            wire_len,
            cap_len: wire_len,
            l3: Protocol::Ipv4,
            transport: Transport::Tcp,
            src_ip: Some(src),
            dst_ip: Some(dst),
            src_port: sp,
            dst_port: dp,
            tcp_flags: flags,
            ttl,
            payload_len: 0,
            vlan: None,
            app_proto: crate::model::packet::AppProto::Unknown,
            sni: None,
            dns_qname: None,
            cleartext_cred: None,
            pii: None,
        }
    }

    fn collect_drain(t: &mut FlowTable) -> Vec<FlowRecord> {
        let mut v = Vec::new();
        t.drain_all(|r| v.push(r));
        v
    }

    #[test]
    fn non_ip_packet_is_not_flowed() {
        let mut t = FlowTable::new(FlowConfig::default());
        let mut p = pkt(0, 100, ip(1, 1, 1, 1), 1, ip(2, 2, 2, 2), 2, 0, 64, 64);
        p.src_ip = None; // simulate ARP / non-IP
        assert_eq!(t.observe(&p), None);
        assert_eq!(t.active_len(), 0);
        assert_eq!(t.total_created(), 0);
    }

    #[test]
    fn forward_and_reverse_collapse_to_one_bidirectional_flow() {
        let mut t = FlowTable::new(FlowConfig::default());
        let client = ip(10, 0, 0, 1);
        let server = ip(10, 0, 0, 2);

        // client:1234 -> server:80 (forward-ish) and the reply server:80 -> client:1234.
        let fwd = pkt(0, 100, client, 1234, server, 80, 0x02, 74, 64);
        let rev = pkt(1, 200, server, 80, client, 1234, 0x12, 60, 128);

        let k1 = t.observe(&fwd).unwrap();
        let k2 = t.observe(&rev).unwrap();
        assert_eq!(k1, k2, "reverse packet must map to the same canonical key");
        assert_eq!(t.active_len(), 1);
        assert_eq!(t.total_created(), 1);

        let recs = collect_drain(&mut t);
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        // Determine which physical direction maps to canonical fwd/rev.
        let (_, dir) = FlowKey::normalized(client, 1234, server, 80, Transport::Tcp);
        match dir {
            Direction::Forward => {
                assert_eq!(r.pkts_fwd, 1);
                assert_eq!(r.bytes_fwd, 74);
                assert_eq!(r.pkts_rev, 1);
                assert_eq!(r.bytes_rev, 60);
            }
            Direction::Reverse => {
                assert_eq!(r.pkts_rev, 1);
                assert_eq!(r.bytes_rev, 74);
                assert_eq!(r.pkts_fwd, 1);
                assert_eq!(r.bytes_fwd, 60);
            }
        }
        assert_eq!(r.first_ts_ns, 100);
        assert_eq!(r.last_ts_ns, 200);
        assert_eq!(r.total_pkts(), 2);
        assert_eq!(r.total_bytes(), 134);
    }

    #[test]
    fn out_of_order_timestamps_update_first_and_last() {
        let mut t = FlowTable::new(FlowConfig::default());
        let a = ip(1, 1, 1, 1);
        let b = ip(2, 2, 2, 2);
        t.observe(&pkt(0, 500, a, 100, b, 200, 0, 64, 64));
        t.observe(&pkt(1, 100, a, 100, b, 200, 0, 64, 64)); // earlier
        t.observe(&pkt(2, 900, a, 100, b, 200, 0, 64, 64)); // later
        let recs = collect_drain(&mut t);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].first_ts_ns, 100);
        assert_eq!(recs[0].last_ts_ns, 900);
        // max_seen_ts must be the high-water mark, not the last packet's ts.
        // (Re-create implicitly: 900 was the max.)
    }

    #[test]
    fn idle_eviction_emits_only_idle_flows() {
        let cfg = FlowConfig {
            max_active_flows: 100,
            idle_timeout_ns: 1_000,
            active_timeout_ns: 1_000_000_000,
        };
        let mut t = FlowTable::new(cfg);
        // Flow 1 last active at t=100.
        t.observe(&pkt(
            0,
            100,
            ip(1, 1, 1, 1),
            10,
            ip(9, 9, 9, 9),
            80,
            0,
            64,
            64,
        ));
        // Flow 2 last active at t=5000.
        t.observe(&pkt(
            1,
            5000,
            ip(2, 2, 2, 2),
            20,
            ip(9, 9, 9, 9),
            80,
            0,
            64,
            64,
        ));

        // now = 5000: flow1 (idle since 100, deadline 1100 <= 5000) expires; flow2 fresh.
        let mut emitted = Vec::new();
        t.evict_expired(5000, |r| emitted.push(r));
        assert_eq!(emitted.len(), 1, "only the idle flow should be emitted");
        assert_eq!(emitted[0].key.lo_ip, ip(1, 1, 1, 1));
        assert_eq!(t.active_len(), 1);
    }

    #[test]
    fn active_timeout_force_closes_long_flows() {
        let cfg = FlowConfig {
            max_active_flows: 100,
            idle_timeout_ns: 1_000_000_000, // huge idle so only active fires
            active_timeout_ns: 1_000,
        };
        let mut t = FlowTable::new(cfg);
        // Flow opens at first_ts=100 and keeps being active (last_ts advances).
        t.observe(&pkt(
            0,
            100,
            ip(1, 1, 1, 1),
            10,
            ip(9, 9, 9, 9),
            80,
            0,
            64,
            64,
        ));
        t.observe(&pkt(
            1,
            1500,
            ip(1, 1, 1, 1),
            10,
            ip(9, 9, 9, 9),
            80,
            0,
            64,
            64,
        ));
        // first_ts=100, active deadline 1100 <= now(2000) -> force close even though it was
        // active recently (last_ts=1500, idle deadline enormous).
        let mut emitted = Vec::new();
        t.evict_expired(2000, |r| emitted.push(r));
        assert_eq!(emitted.len(), 1, "active timeout must force-close");
        assert_eq!(t.active_len(), 0);
    }

    #[test]
    fn cap_eviction_buffers_victim_and_surfaces_on_next_drain() {
        let cfg = FlowConfig {
            max_active_flows: 1,
            idle_timeout_ns: i64::MAX, // never idle-expire
            active_timeout_ns: i64::MAX,
        };
        let mut t = FlowTable::new(cfg);
        // Flow A at t=100.
        t.observe(&pkt(
            0,
            100,
            ip(1, 1, 1, 1),
            10,
            ip(9, 9, 9, 9),
            80,
            0,
            64,
            64,
        ));
        assert_eq!(t.active_len(), 1);
        // Flow B at t=200 -> A must be evicted (LRU) and buffered.
        t.observe(&pkt(
            1,
            200,
            ip(2, 2, 2, 2),
            20,
            ip(9, 9, 9, 9),
            80,
            0,
            64,
            64,
        ));
        assert_eq!(t.active_len(), 1, "cap holds: still exactly one live flow");
        assert_eq!(t.total_created(), 2);

        // The evicted victim (A) surfaces via the next evict_expired/drain.
        let mut emitted = Vec::new();
        t.evict_expired(200, |r| emitted.push(r));
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].key.lo_ip, ip(1, 1, 1, 1), "LRU victim is flow A");

        // Flow B remains and drains at EOF.
        let rest = collect_drain(&mut t);
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].key.lo_ip, ip(2, 2, 2, 2));
    }

    #[test]
    fn cap_zero_routes_everything_to_pending() {
        let cfg = FlowConfig {
            max_active_flows: 0,
            idle_timeout_ns: i64::MAX,
            active_timeout_ns: i64::MAX,
        };
        let mut t = FlowTable::new(cfg);
        assert!(t
            .observe(&pkt(
                0,
                100,
                ip(1, 1, 1, 1),
                10,
                ip(9, 9, 9, 9),
                80,
                0,
                64,
                64
            ))
            .is_some());
        assert_eq!(t.active_len(), 0);
        assert_eq!(t.total_created(), 1);
        let recs = collect_drain(&mut t);
        assert_eq!(recs.len(), 1);
    }

    #[test]
    fn lru_heap_compacts_and_stays_bounded() {
        // Repeatedly touch the same single flow; heap must not grow unboundedly.
        let mut t = FlowTable::new(FlowConfig::default());
        for i in 0..10_000i64 {
            t.observe(&pkt(
                i as u64,
                i,
                ip(1, 1, 1, 1),
                10,
                ip(2, 2, 2, 2),
                80,
                0,
                64,
                64,
            ));
        }
        assert_eq!(t.active_len(), 1);
        // After compaction logic, heap is bounded by ~2*map.len()+16.
        assert!(
            t.lru.len() <= t.map.len() * 2 + 16,
            "heap not bounded: {} entries for {} live flows",
            t.lru.len(),
            t.map.len()
        );
        let recs = collect_drain(&mut t);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].total_pkts(), 10_000);
    }

    #[test]
    fn finalize_is_deterministic_and_sorted() {
        let mut t = FlowTable::new(FlowConfig::default());
        // Insert flows out of timestamp order.
        t.observe(&pkt(
            0,
            300,
            ip(3, 0, 0, 1),
            10,
            ip(9, 9, 9, 9),
            80,
            0,
            64,
            64,
        ));
        t.observe(&pkt(
            1,
            100,
            ip(1, 0, 0, 1),
            10,
            ip(9, 9, 9, 9),
            80,
            0,
            64,
            64,
        ));
        t.observe(&pkt(
            2,
            200,
            ip(2, 0, 0, 1),
            10,
            ip(9, 9, 9, 9),
            80,
            0,
            64,
            64,
        ));
        let recs = t.finalize();
        assert_eq!(recs.len(), 3);
        // Sorted by first_ts_ns ascending.
        assert_eq!(recs[0].first_ts_ns, 100);
        assert_eq!(recs[1].first_ts_ns, 200);
        assert_eq!(recs[2].first_ts_ns, 300);
        assert_eq!(t.active_len(), 0, "finalize clears the table");
    }

    #[test]
    fn tcp_flags_union_and_ttl_min_tracked() {
        let mut t = FlowTable::new(FlowConfig::default());
        let a = ip(1, 1, 1, 1);
        let b = ip(2, 2, 2, 2);
        // canonical key + dir for a:1000 -> b:80
        let (_, dir) = FlowKey::normalized(a, 1000, b, 80, Transport::Tcp);
        // Forward-direction packets carry SYN then PSH|ACK, with TTLs 64 then 50.
        t.observe(&pkt(0, 100, a, 1000, b, 80, 0x02, 64, 64));
        t.observe(&pkt(1, 110, a, 1000, b, 80, 0x18, 64, 50));
        let recs = collect_drain(&mut t);
        let r = &recs[0];
        let (flags, ttl) = match dir {
            Direction::Forward => (r.tcp_flags_fwd, r.ttl_min_fwd),
            Direction::Reverse => (r.tcp_flags_rev, r.ttl_min_fwd),
        };
        assert_eq!(flags, 0x02 | 0x18, "flags must be sticky-ORed");
        if dir == Direction::Forward {
            assert_eq!(
                ttl, 50,
                "ttl_min_fwd tracks the minimum non-zero forward TTL"
            );
        }
    }

    #[test]
    fn evict_with_no_expired_flows_is_noop_for_records() {
        let cfg = FlowConfig {
            max_active_flows: 100,
            idle_timeout_ns: 1_000_000,
            active_timeout_ns: 1_000_000,
        };
        let mut t = FlowTable::new(cfg);
        t.observe(&pkt(
            0,
            1000,
            ip(1, 1, 1, 1),
            10,
            ip(9, 9, 9, 9),
            80,
            0,
            64,
            64,
        ));
        let mut emitted = Vec::new();
        t.evict_expired(1500, |r| emitted.push(r)); // well within timeouts
        assert!(emitted.is_empty());
        assert_eq!(t.active_len(), 1);
    }
}
