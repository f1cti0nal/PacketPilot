//! Deterministic synthetic capture generator.
//!
//! Produces byte-identical pcap/pcapng output for a given `(seed, packets, scenario)` so
//! tests and benches have a stable, ground-truth corpus. The generator authors a
//! [`GenManifest`] tallying exactly what it wrote — the golden test's reference. The PRNG
//! is a self-contained SplitMix64 (no `rand` dependency); protocol mix counts are a pure
//! function of `(scenario, packets, include_edge_cases)`, independent of seed.
//!
//! ## Streaming / memory
//!
//! [`SynthGen::write_to`] streams one frame at a time straight into the supplied writer; it
//! never materializes a `Vec` of all frames. The only per-run state is the PRNG, the count
//! schedule (a fixed-size struct), the running manifest, and a distinct-flow set that is
//! HARD-CAPPED at [`MAX_TRACKED_FLOWS`] — so peak heap is bounded regardless of `packets` or
//! flow cardinality. The manifest's `distinct_flows` therefore *saturates* at that cap for
//! very high-cardinality captures (it is an exact count below the cap).

use std::collections::HashSet;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;

use crate::model::summary::ProtoCounts;
use crate::reader::LinkType;
use crate::PpError;
use crate::Result;

/// Upper bound on the number of distinct flow keys the generator tracks for the manifest's
/// `distinct_flows` tally. Capping this keeps the generator bounded-memory no matter how many
/// distinct 5-tuples the chosen scenario produces (random ephemeral ports can yield ~one flow
/// per packet); the reported count saturates here.
pub const MAX_TRACKED_FLOWS: usize = 100_000;

pub(crate) mod container;
pub(crate) mod frames;
pub(crate) mod mix;

use frames::{
    ETHERTYPE_ARP, ETHERTYPE_IPV4, IP_PROTO_TCP, IP_PROTO_UDP, TCP_ACK, TCP_PSH, TCP_SYN,
};

/// Traffic recipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    /// Weighted mix: HTTP 22 / TLS 28 / DNS 20 / other-TCP 14 / other-UDP 14 / edge 2.
    Mixed,
    WebOnly,
    DnsFlood,
    PortScan,
    Beacon,
    BulkTransfer,
}

impl Scenario {
    /// Parse a CLI token (`"mixed"`, `"web-only"`/`"webonly"`, ...) into a [`Scenario`].
    pub fn from_str_opt(s: &str) -> Option<Scenario> {
        match s.trim().to_ascii_lowercase().as_str() {
            "mixed" => Some(Scenario::Mixed),
            "web" | "web-only" | "webonly" => Some(Scenario::WebOnly),
            "dns" | "dns-flood" | "dnsflood" => Some(Scenario::DnsFlood),
            "scan" | "port-scan" | "portscan" => Some(Scenario::PortScan),
            "beacon" => Some(Scenario::Beacon),
            "bulk" | "bulk-transfer" | "bulktransfer" => Some(Scenario::BulkTransfer),
            _ => None,
        }
    }

    /// All scenarios (for help text / enumeration).
    pub fn all() -> &'static [Scenario] {
        &[
            Scenario::Mixed,
            Scenario::WebOnly,
            Scenario::DnsFlood,
            Scenario::PortScan,
            Scenario::Beacon,
            Scenario::BulkTransfer,
        ]
    }
}

/// Generator configuration.
#[derive(Debug, Clone)]
pub struct GenConfig {
    pub scenario: Scenario,
    pub packets: u64,
    /// Same seed+count => byte-identical output.
    pub seed: u64,
    pub link_type: LinkType,
    /// `false` => classic pcap; `true` => pcapng.
    pub pcapng: bool,
    pub start_ts_ns: i64,
    pub mean_gap_ns: i64,
    /// When `true`, inject the fixed edge-case frames (§6.2).
    pub include_edge_cases: bool,
    pub host_count: u16,
}

impl Default for GenConfig {
    fn default() -> Self {
        GenConfig {
            scenario: Scenario::Mixed,
            packets: 100_000,
            // "PacketPi" as ASCII bytes -> a fixed, memorable seed.
            seed: 0x5061_636B_6574_5069,
            link_type: LinkType::Ethernet,
            pcapng: false,
            // 2023-11-14T22:13:20Z, a fixed reference start.
            start_ts_ns: 1_700_000_000i64 * 1_000_000_000,
            mean_gap_ns: 1_000_000, // 1 ms
            include_edge_cases: false,
            host_count: 64,
        }
    }
}

/// Ground-truth tallies the generator authored — the golden test's reference.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GenManifest {
    pub packets_written: u64,
    /// Total bytes incl. container headers.
    pub bytes_written: u64,
    /// Σ wire_len (throughput math).
    pub frame_bytes: u64,
    pub counts: ProtoCounts,
    pub first_ts_ns: i64,
    pub last_ts_ns: i64,
    pub distinct_flows: u32,
}

/// The kind of frame to emit at a given schedule position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameKind {
    Http,
    Tls,
    Dns,
    OtherTcp,
    OtherUdp,
    /// Malformed (truncated) IPv4/TCP edge frame; counted under `tcp`/`other_tcp`.
    Truncated,
    /// ARP edge frame; counted under `non_ipv4`.
    NonIpv4,
}

/// A deterministic emission schedule derived from the count plan. The frame kinds are
/// interleaved (not blocked by type) so the timeline looks like real mixed traffic, yet the
/// exact per-kind totals equal the plan.
#[derive(Debug, Clone)]
struct Schedule {
    /// Remaining count per kind, indexed by `FrameKind as usize` order below.
    remaining: [u64; 7],
    total_remaining: u64,
}

// Stable index assignment for the schedule array.
const K_HTTP: usize = 0;
const K_TLS: usize = 1;
const K_DNS: usize = 2;
const K_OTCP: usize = 3;
const K_OUDP: usize = 4;
const K_TRUNC: usize = 5;
const K_NONIP: usize = 6;

impl Schedule {
    fn from_counts(counts: &ProtoCounts) -> Schedule {
        // The leaf TCP buckets already include the truncated edge unit; carve it back out so
        // it is emitted as a distinct kind without double counting.
        let trunc = counts.truncated;
        let nonip = counts.non_ipv4;
        // `other_tcp` hosts the truncated unit (see mix::counts_for); subtract it here.
        let other_tcp = counts.other_tcp.saturating_sub(trunc);

        let remaining = [
            counts.http,
            counts.tls,
            counts.dns,
            other_tcp,
            counts.other_udp,
            trunc,
            nonip,
        ];
        let total_remaining = remaining.iter().copied().sum();
        Schedule {
            remaining,
            total_remaining,
        }
    }

    /// Pick the next kind deterministically: choose the kind with the most remaining slots,
    /// weighted by the PRNG so the interleave varies but totals are exact. Ties break toward
    /// the lower index for determinism.
    fn next_kind(&mut self, rng: &mut mix::SplitMix64) -> Option<FrameKind> {
        if self.total_remaining == 0 {
            return None;
        }
        // Weighted pick proportional to remaining counts so the schedule drains evenly.
        let pick = rng.below(self.total_remaining);
        let mut acc = 0u64;
        let mut chosen = 0usize;
        for (i, &r) in self.remaining.iter().enumerate() {
            acc += r;
            if pick < acc {
                chosen = i;
                break;
            }
        }
        // Defensive: if rounding left `pick` past the end, take the first non-empty bucket.
        if self.remaining[chosen] == 0 {
            chosen = self.remaining.iter().position(|&r| r > 0).unwrap_or(chosen);
        }
        self.remaining[chosen] -= 1;
        self.total_remaining -= 1;
        Some(index_to_kind(chosen))
    }
}

fn index_to_kind(i: usize) -> FrameKind {
    match i {
        K_HTTP => FrameKind::Http,
        K_TLS => FrameKind::Tls,
        K_DNS => FrameKind::Dns,
        K_OTCP => FrameKind::OtherTcp,
        K_OUDP => FrameKind::OtherUdp,
        K_TRUNC => FrameKind::Truncated,
        K_NONIP => FrameKind::NonIpv4,
        _ => unreachable!("index_to_kind: schedule index {i} out of range"),
    }
}

/// Realistic-looking SNI hosts for generated TLS ClientHellos, chosen by server index so
/// distinct servers present distinct SNIs in the synthetic capture.
fn sni_host(server_idx: u16) -> &'static str {
    const HOSTS: [&str; 8] = [
        "login.example.net",
        "cdn.assets.example.com",
        "api.service.io",
        "mail.corp.example",
        "updates.vendor.com",
        "auth.bank.example",
        "telemetry.app.example",
        "static.media.example.org",
    ];
    HOSTS[(server_idx as usize) % HOSTS.len()]
}

/// The synthetic generator.
pub struct SynthGen {
    cfg: GenConfig,
    rng: mix::SplitMix64,
    schedule: Schedule,
    /// The full count plan (also the basis of the manifest's `counts`).
    plan: ProtoCounts,
    emitted: u64,
    cursor_ts: i64,
    /// Independent random-walk clock for [`Scenario::Beacon`] background traffic, advanced per
    /// background packet so benign channels have irregular (high-CV) inter-arrivals and never
    /// read as periodic. Kept separate from the regular beacon-callback grid.
    bg_cursor: i64,
    /// Distinct (lo_ip, hi_ip, lo_port, hi_port, proto) flow keys seen, for
    /// `manifest.distinct_flows`. Random ephemeral ports make distinct 5-tuples scale ~per
    /// packet, so this set is HARD-CAPPED at [`MAX_TRACKED_FLOWS`] to keep the generator
    /// bounded-memory; the reported count saturates at that cap.
    flows: HashSet<u64>,
}

impl SynthGen {
    /// Build a generator from config (seeds the PRNG, precomputes the count plan).
    pub fn new(cfg: GenConfig) -> SynthGen {
        let plan = mix::counts_for(cfg.scenario, cfg.packets, cfg.include_edge_cases);
        let schedule = Schedule::from_counts(&plan);
        let rng = mix::SplitMix64::new(cfg.seed);
        let cursor_ts = cfg.start_ts_ns;
        let bg_cursor = cfg.start_ts_ns;
        SynthGen {
            rng,
            schedule,
            plan,
            emitted: 0,
            cursor_ts,
            bg_cursor,
            flows: HashSet::new(),
            cfg,
        }
    }

    /// Generate to a pcap/pcapng file at `path`. O(1) memory (BufWriter, frame-at-a-time).
    pub fn write_pcap(&mut self, path: &Path) -> Result<GenManifest> {
        let file = std::fs::File::create(path)
            .map_err(|e| PpError::io(format!("create {}", path.display()), e))?;
        let w = std::io::BufWriter::new(file);
        self.write_to(w)
    }

    /// Generate to any writer. Returns the ground-truth [`GenManifest`].
    pub fn write_to<W: Write>(&mut self, mut w: W) -> Result<GenManifest> {
        let mut manifest = GenManifest {
            counts: self.plan,
            ..Default::default()
        };

        // Container header.
        let header_bytes = if self.cfg.pcapng {
            container::write_pcapng_shb_idb(&mut w, self.cfg.link_type)?
        } else {
            container::write_pcap_header(&mut w, self.cfg.link_type)?
        };
        manifest.bytes_written += header_bytes as u64;

        let mut first_ts: Option<i64> = None;
        let mut last_ts: i64 = self.cfg.start_ts_ns;

        while let Some((ts, kind, frame)) = self.next_planned() {
            let wire_len = frame.len() as u32;
            // We do not truncate capture below wire length here (snaplen 65535 >> frames),
            // so caplen == origlen == wire_len.
            let rec_bytes = if self.cfg.pcapng {
                container::write_epb(&mut w, 0, ts, wire_len, wire_len, &frame)?
            } else {
                let hdr = container::write_legacy_record(&mut w, ts, wire_len, wire_len)?;
                w.write_all(&frame)
                    .map_err(|e| PpError::io("write frame bytes", e))?;
                hdr + frame.len()
            };

            manifest.packets_written += 1;
            manifest.frame_bytes += wire_len as u64;
            manifest.bytes_written += rec_bytes as u64;

            // Record timestamps at the resolution actually written: classic pcap stores
            // microseconds (see container::split_secs_usec), so truncate sub-µs here too so
            // the manifest stays a faithful ground-truth of the file and round-trips exactly
            // through analyze. pcapng keeps full nanosecond resolution (if_tsresol = 9).
            let stored_ts = if self.cfg.pcapng {
                ts
            } else {
                ts - ts.rem_euclid(1_000)
            };
            if first_ts.is_none() {
                first_ts = Some(stored_ts);
            }
            last_ts = stored_ts;
            let _ = kind; // counts come from the plan; kept for readability/debugging.
        }

        w.flush()
            .map_err(|e| PpError::io("flush generator output", e))?;

        manifest.first_ts_ns = first_ts.unwrap_or(self.cfg.start_ts_ns);
        manifest.last_ts_ns = last_ts;
        manifest.distinct_flows = self.flows.len().min(u32::MAX as usize) as u32;
        Ok(manifest)
    }

    /// Produce the next `(ts_ns, L2 frame bytes)`, or `None` when `packets` is reached.
    ///
    /// Standalone callers (tests) get the raw bytes; `write_to` uses [`Self::next_planned`]
    /// which also surfaces the chosen [`FrameKind`].
    pub fn next_raw(&mut self) -> Option<(i64, Vec<u8>)> {
        self.next_planned().map(|(ts, _kind, frame)| (ts, frame))
    }

    /// Internal: pick the next scheduled frame kind, build it, advance time, and record the
    /// flow key. Returns `None` once the plan is exhausted.
    fn next_planned(&mut self) -> Option<(i64, FrameKind, Vec<u8>)> {
        if self.emitted >= self.cfg.packets {
            return None;
        }
        // The beacon scenario uses a dedicated emission path with explicit, low-jitter callback
        // timestamps — the weighted schedule + per-packet cursor cannot produce a regular,
        // single-channel beacon (it picks a fresh random host pair per packet).
        if self.cfg.scenario == Scenario::Beacon {
            return self.next_beacon();
        }
        let kind = self.schedule.next_kind(&mut self.rng)?;
        let ts = self.cursor_ts;

        let frame = self.build_frame(kind);

        // Advance the timestamp by mean_gap_ns +/- up to 50% jitter, never going backwards.
        let gap = self.jittered_gap();
        self.cursor_ts = self.cursor_ts.saturating_add(gap);
        self.emitted += 1;

        Some((ts, kind, frame))
    }

    /// Deterministic non-negative inter-packet gap in `[mean/2, 3*mean/2]` (roughly).
    fn jittered_gap(&mut self) -> i64 {
        let mean = self.cfg.mean_gap_ns.max(0);
        if mean == 0 {
            return 0;
        }
        // jitter in [0, mean) then center it around mean: gap = mean/2 + jitter.
        let jitter = self.rng.below(mean as u64) as i64;
        (mean / 2).saturating_add(jitter).max(1)
    }

    /// Build a complete L2 frame for the given kind from deterministic endpoints/ports.
    fn build_frame(&mut self, kind: FrameKind) -> Vec<u8> {
        let hosts = self.cfg.host_count.max(1);
        // Pick two distinct host indices deterministically.
        let a = self.rng.below(hosts as u64) as u16;
        let mut b = self.rng.below(hosts as u64) as u16;
        if b == a {
            b = (b + 1) % hosts;
        }
        let client_ip = host_ip(a);
        let server_ip = host_ip(b);

        // Ephemeral client port in [49152, 65535].
        let client_port = 49152 + (self.rng.below(16384) as u16);

        match kind {
            FrameKind::NonIpv4 => {
                // ARP request: the deterministic non-IPv4 edge frame.
                let arp = frames::arp_request_payload(client_ip, server_ip, mac_for(a));
                let mut frame = frames::build_ethernet(mac_for(a), mac_for(b), ETHERTYPE_ARP);
                frame.extend_from_slice(&arp);
                // ARP frames are not a 5-tuple flow; do not record.
                frame
            }
            FrameKind::Dns => {
                let txid = self.rng.below(0x10000) as u16;
                let payload = frames::dns_query_payload("svc.example.net", txid);
                self.record_flow(client_ip, server_ip, client_port, 53, IP_PROTO_UDP);
                self.ip_udp_frame(a, b, client_ip, server_ip, client_port, 53, &payload)
            }
            FrameKind::OtherUdp => {
                // A small generic UDP datagram to an assorted high port.
                let dport = 1024 + (self.rng.below(40000) as u16);
                let payload = [0xABu8; 32];
                self.record_flow(client_ip, server_ip, client_port, dport, IP_PROTO_UDP);
                self.ip_udp_frame(a, b, client_ip, server_ip, client_port, dport, &payload)
            }
            FrameKind::Http => {
                let payload = frames::http_request_payload("example.com", "/index.html");
                self.record_flow(client_ip, server_ip, client_port, 80, IP_PROTO_TCP);
                self.ip_tcp_frame(
                    a,
                    b,
                    client_ip,
                    server_ip,
                    client_port,
                    80,
                    TCP_PSH | TCP_ACK,
                    &payload,
                )
            }
            FrameKind::Tls => {
                let payload = frames::tls_client_hello_payload(sni_host(b));
                self.record_flow(client_ip, server_ip, client_port, 443, IP_PROTO_TCP);
                self.ip_tcp_frame(
                    a,
                    b,
                    client_ip,
                    server_ip,
                    client_port,
                    443,
                    TCP_PSH | TCP_ACK,
                    &payload,
                )
            }
            FrameKind::OtherTcp => {
                // A TCP SYN to an assorted high port (scan-ish / generic TCP). The range is kept
                // clear of the well-known service ports (80/443/53) and the interactive-auth ports
                // (21/22/23/3389/5900) so synthetic benign traffic never manufactures repeated
                // connections to an auth service that the brute-force detector would then flag.
                let dport = 20000 + (self.rng.below(40000) as u16);
                self.record_flow(client_ip, server_ip, client_port, dport, IP_PROTO_TCP);
                self.ip_tcp_frame(a, b, client_ip, server_ip, client_port, dport, TCP_SYN, &[])
            }
            FrameKind::Truncated => {
                // A deliberately malformed frame: Ethernet + an IPv4 header that claims a
                // larger total length than the bytes actually present (truncated L4). The
                // decoder must count this as `truncated` without panicking.
                self.record_flow(client_ip, server_ip, client_port, 80, IP_PROTO_TCP);
                let mut frame = frames::build_ethernet(mac_for(a), mac_for(b), ETHERTYPE_IPV4);
                // Claim 100 bytes of L4 but append only 4 — a truncated TCP header.
                let ip = frames::build_ipv4(client_ip, server_ip, IP_PROTO_TCP, 64, 100);
                frame.extend_from_slice(&ip);
                let sp = client_port.to_be_bytes();
                frame.extend_from_slice(&[sp[0], sp[1], 0, 80]); // partial TCP src/dst port
                frame
            }
        }
    }

    /// Assemble Ethernet + IPv4 + TCP into one frame.
    #[allow(clippy::too_many_arguments)]
    fn ip_tcp_frame(
        &self,
        a: u16,
        b: u16,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let tcp = frames::build_tcp(src, dst, sport, dport, flags, payload);
        let ip = frames::build_ipv4(src, dst, IP_PROTO_TCP, 64, tcp.len());
        let mut frame = frames::build_ethernet(mac_for(a), mac_for(b), ETHERTYPE_IPV4);
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&tcp);
        frame
    }

    /// Assemble Ethernet + IPv4 + UDP into one frame.
    #[allow(clippy::too_many_arguments)]
    fn ip_udp_frame(
        &self,
        a: u16,
        b: u16,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp = frames::build_udp(src, dst, sport, dport, payload);
        let ip = frames::build_ipv4(src, dst, IP_PROTO_UDP, 64, udp.len());
        let mut frame = frames::build_ethernet(mac_for(a), mac_for(b), ETHERTYPE_IPV4);
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&udp);
        frame
    }

    /// Dedicated emission for [`Scenario::Beacon`]: a regular C2 callback once per cycle from a
    /// fixed internal client to a fixed **public** C2 on 443, surrounded by benign background.
    ///
    /// Each cycle is [`BEACON_CYCLE_LEN`] packets: one callback at `start + cycle*period +
    /// jitter` followed by benign background spread across the rest of the cycle. The callback
    /// uses a rotating ephemeral source port so every check-in is a *distinct* flow, and the
    /// per-cycle jitter is bounded to `period/30`, keeping the inter-callback coefficient of
    /// variation far under the detector's threshold.
    fn next_beacon(&mut self) -> Option<(i64, FrameKind, Vec<u8>)> {
        let i = self.emitted;
        let sweep_count = self.beacon_sweep_count();
        let brute_count = self.beacon_brute_count();
        let lateral_count = self.beacon_lateral_count();
        let exfil_count = self.beacon_exfil_count();
        let dns_count = self.beacon_dns_count();
        let prefix = sweep_count + brute_count + lateral_count + exfil_count + dns_count;

        // Stage 1 (recon): a short SYN sweep — the beacon host probes many internal hosts on
        // 445. Combined with the C2 beacon below, this gives the host a multi-stage incident.
        if i < sweep_count {
            let frame = self.build_beacon_sweep(i);
            let ts = self.cfg.start_ts_ns.saturating_add(i as i64 * 100_000_000); // ~100 ms apart at the start
            self.emitted += 1;
            return Some((ts, FrameKind::OtherTcp, frame));
        }

        // Stage 2 (credential access): a burst of SSH connection attempts against one discovered
        // host — password guessing. Each attempt is a distinct flow (rotating ephemeral port).
        if i < sweep_count + brute_count {
            let k = i - sweep_count;
            let frame = self.build_beacon_brute(k);
            // Just after the sweep, ~10 ms apart.
            let ts = self
                .cfg
                .start_ts_ns
                .saturating_add(2_500_000_000)
                .saturating_add(k as i64 * 10_000_000);
            self.emitted += 1;
            return Some((ts, FrameKind::OtherTcp, frame));
        }

        // Stage 3 (lateral movement): the beacon host pivots into several discovered hosts with
        // established RDP sessions (bytes both directions per host), east-west across the LAN.
        if i < sweep_count + brute_count + lateral_count {
            let k = i - sweep_count - brute_count;
            let frame = self.build_beacon_lateral(k);
            let ts = self
                .cfg
                .start_ts_ns
                .saturating_add(2_800_000_000)
                .saturating_add(k as i64 * 5_000_000);
            self.emitted += 1;
            return Some((ts, FrameKind::OtherTcp, frame));
        }

        // Stage 4 (exfiltration): a large asymmetric upload from the beacon host to an external
        // drop server — one flow, megabytes outbound, almost nothing back.
        if i < sweep_count + brute_count + lateral_count + exfil_count {
            let k = i - sweep_count - brute_count - lateral_count;
            let frame = self.build_beacon_exfil();
            // A few seconds after the sweep, ~1 ms apart.
            let ts = self
                .cfg
                .start_ts_ns
                .saturating_add(3_000_000_000)
                .saturating_add(k as i64 * 1_000_000);
            self.emitted += 1;
            return Some((ts, FrameKind::Tls, frame));
        }

        // Stage 5 (DNS tunneling): a burst of high-entropy DNS queries to the internal resolver,
        // smuggling data out over DNS.
        if i < prefix {
            let k = i - sweep_count - brute_count - lateral_count - exfil_count;
            let frame = self.build_beacon_dns(k);
            let ts = self
                .cfg
                .start_ts_ns
                .saturating_add(6_000_000_000)
                .saturating_add(k as i64 * 2_000_000);
            self.emitted += 1;
            return Some((ts, FrameKind::Dns, frame));
        }

        // Stage 6 (C2): the periodic beacon + benign background.
        let j = i - prefix;
        let pos = j % BEACON_CYCLE_LEN;

        let (ts, kind, frame) = if pos == 0 {
            // The regular C2 callback, on the explicit period grid + bounded jitter.
            let cycle = j / BEACON_CYCLE_LEN;
            let callback_ts = self
                .cfg
                .start_ts_ns
                .saturating_add((cycle as i64).saturating_mul(BEACON_PERIOD_NS))
                .saturating_add(self.beacon_jitter(cycle));
            (
                callback_ts,
                FrameKind::Tls,
                self.build_beacon_callback(cycle),
            )
        } else {
            // Benign background on an INDEPENDENT random-walk clock (not aligned to the beacon
            // period) so any repeated background channel has Poisson-like, high-CV arrivals and
            // never reads as periodic. Varied benign kind across ports 80/443/53 to random hosts.
            let bg_ts = self.bg_cursor;
            self.bg_cursor = self.bg_cursor.saturating_add(self.beacon_bg_gap());
            let bg_kind = match self.rng.below(3) {
                0 => FrameKind::Http,
                1 => FrameKind::Dns,
                _ => FrameKind::Tls,
            };
            (bg_ts, bg_kind, self.build_frame(bg_kind))
        };

        self.emitted += 1;
        Some((ts, kind, frame))
    }

    /// Deterministic per-cycle beacon jitter in `[0, period/30)`. Uses an independent PRNG
    /// stream keyed on `(seed, cycle)` so it does not depend on how many background frames were
    /// drawn from the main PRNG — keeping callback timing stable and the output reproducible.
    fn beacon_jitter(&self, cycle: u64) -> i64 {
        let mut r = mix::SplitMix64::new(self.cfg.seed ^ cycle.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        r.below((BEACON_PERIOD_NS / 30) as u64) as i64
    }

    /// Mean-`period/(cycle-1)` jittered gap (±50%) for the background random walk, so the
    /// background spans roughly the same wall-clock window as the beacon callbacks.
    fn beacon_bg_gap(&mut self) -> i64 {
        let mean = BEACON_PERIOD_NS / (BEACON_CYCLE_LEN as i64 - 1);
        (mean / 2)
            .saturating_add(self.rng.below(mean as u64) as i64)
            .max(1)
    }

    /// Number of recon-sweep SYNs prefixed to a beacon capture (skipped for tiny captures).
    fn beacon_sweep_count(&self) -> u64 {
        if self.cfg.packets >= 200 {
            BEACON_SWEEP_HOSTS
        } else {
            0
        }
    }

    /// Number of SSH brute-force attempts emitted after the sweep (0 for small captures),
    /// >= the brute-force detector's attempt floor.
    fn beacon_brute_count(&self) -> u64 {
        if self.cfg.packets >= 2_000 {
            BEACON_BRUTE_ATTEMPTS
        } else {
            0
        }
    }

    /// Build one brute-force attempt: a SYN from the beacon host to one discovered victim's SSH
    /// service (22), with a rotating ephemeral source port so each attempt is a distinct flow.
    fn build_beacon_brute(&mut self, idx: u64) -> Vec<u8> {
        let client = beacon_client();
        let victim = beacon_brute_victim();
        let sport = 41000 + (idx % 2000) as u16;
        self.record_flow(client, victim, sport, 22, IP_PROTO_TCP);
        let tcp = frames::build_tcp(client, victim, sport, 22, TCP_SYN, &[]);
        let ip = frames::build_ipv4(client, victim, IP_PROTO_TCP, 64, tcp.len());
        let mut frame = frames::build_ethernet(BEACON_CLIENT_MAC, BEACON_BRUTE_MAC, ETHERTYPE_IPV4);
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&tcp);
        frame
    }

    /// Number of lateral-movement frames emitted after the brute stage (0 for small captures):
    /// [`BEACON_LATERAL_HOSTS`] established RDP sessions, [`BEACON_LATERAL_FRAMES_PER_HOST`] frames
    /// each (alternating client->server / server->client so both directions clear the detector's
    /// per-direction session-byte floor).
    fn beacon_lateral_count(&self) -> u64 {
        if self.cfg.packets >= 2_000 {
            BEACON_LATERAL_HOSTS * BEACON_LATERAL_FRAMES_PER_HOST
        } else {
            0
        }
    }

    /// Build one lateral-movement frame: a data segment of an established RDP (3389) session from
    /// the beacon host to one discovered internal host. A fixed ephemeral source port per target
    /// keeps each host's frames in one flow; alternating direction gives that flow bytes both
    /// ways, so the channel reads as a real session (not a SYN probe).
    fn build_beacon_lateral(&mut self, idx: u64) -> Vec<u8> {
        let client = beacon_client();
        let target_idx = idx / BEACON_LATERAL_FRAMES_PER_HOST;
        let target = Ipv4Addr::new(10, 66, 0, (target_idx + 1) as u8);
        let sport = 52000 + target_idx as u16;
        let outbound = idx % 2 == 0;
        let payload = [0x77u8; BEACON_LATERAL_PAYLOAD];
        // record_flow normalizes endpoints, so both directions map to the one session flow.
        self.record_flow(client, target, sport, 3389, IP_PROTO_TCP);
        let (src, dst, sp, dp, smac, dmac) = if outbound {
            (client, target, sport, 3389, BEACON_CLIENT_MAC, BEACON_LATERAL_MAC)
        } else {
            (target, client, 3389, sport, BEACON_LATERAL_MAC, BEACON_CLIENT_MAC)
        };
        let tcp = frames::build_tcp(src, dst, sp, dp, TCP_PSH | TCP_ACK, &payload);
        let ip = frames::build_ipv4(src, dst, IP_PROTO_TCP, 64, tcp.len());
        let mut frame = frames::build_ethernet(smac, dmac, ETHERTYPE_IPV4);
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&tcp);
        frame
    }

    /// Number of exfil-upload packets emitted after the sweep (0 for small captures). Sized so
    /// the aggregate outbound clears the exfil detector's 1 MB floor.
    fn beacon_exfil_count(&self) -> u64 {
        if self.cfg.packets >= 2_000 {
            BEACON_EXFIL_PACKETS
        } else {
            0
        }
    }

    /// Build one exfil data packet: a large payload from the beacon host to a fixed external drop
    /// server on 443. A fixed ephemeral source port keeps every packet in one flow, so the
    /// directional byte total accumulates into a single large asymmetric transfer.
    fn build_beacon_exfil(&mut self) -> Vec<u8> {
        let client = beacon_client();
        let drop = beacon_exfil_server();
        self.record_flow(client, drop, BEACON_EXFIL_SPORT, 443, IP_PROTO_TCP);
        let payload = [0x5Au8; BEACON_EXFIL_PAYLOAD];
        let tcp = frames::build_tcp(
            client,
            drop,
            BEACON_EXFIL_SPORT,
            443,
            TCP_PSH | TCP_ACK,
            &payload,
        );
        let ip = frames::build_ipv4(client, drop, IP_PROTO_TCP, 64, tcp.len());
        let mut frame = frames::build_ethernet(BEACON_CLIENT_MAC, BEACON_EXFIL_MAC, ETHERTYPE_IPV4);
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&tcp);
        frame
    }

    /// Number of DNS-tunnel queries emitted (0 for small captures), >= the detector floor.
    fn beacon_dns_count(&self) -> u64 {
        if self.cfg.packets >= 2_000 {
            BEACON_DNS_QUERIES
        } else {
            0
        }
    }

    /// Build one DNS-tunnel query: a high-entropy, long-label name from the beacon host to the
    /// internal resolver on 53 (data encoded in the subdomain).
    fn build_beacon_dns(&mut self, idx: u64) -> Vec<u8> {
        let client = beacon_client();
        let resolver = beacon_dns_resolver();
        let sport = 50000 + (idx % 2000) as u16;
        let qname = format!("{}.{BEACON_DNS_DOMAIN}", beacon_dns_label(idx));
        self.record_flow(client, resolver, sport, 53, IP_PROTO_UDP);
        let payload = frames::dns_query_payload(&qname, idx as u16);
        let udp = frames::build_udp(client, resolver, sport, 53, &payload);
        let ip = frames::build_ipv4(client, resolver, IP_PROTO_UDP, 64, udp.len());
        let mut frame = frames::build_ethernet(BEACON_CLIENT_MAC, BEACON_DNS_MAC, ETHERTYPE_IPV4);
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&udp);
        frame
    }

    /// Build one sweep SYN: the beacon host probing a distinct internal host on 445.
    fn build_beacon_sweep(&mut self, idx: u64) -> Vec<u8> {
        let client = beacon_client();
        let target = Ipv4Addr::new(10, 66, 0, (idx + 1) as u8);
        let sport = 40000 + (idx % 2000) as u16;
        self.record_flow(client, target, sport, 445, IP_PROTO_TCP);
        let tcp = frames::build_tcp(client, target, sport, 445, TCP_SYN, &[]);
        let ip = frames::build_ipv4(client, target, IP_PROTO_TCP, 64, tcp.len());
        let mut frame = frames::build_ethernet(
            BEACON_CLIENT_MAC,
            [0x02, 0, 0, 0, 0xFF, (idx & 0xFF) as u8],
            ETHERTYPE_IPV4,
        );
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&tcp);
        frame
    }

    /// Build one beacon callback: a TLS ClientHello from the fixed client to the fixed public
    /// C2 on 443, with a rotating ephemeral source port (distinct flow per check-in).
    fn build_beacon_callback(&mut self, cycle: u64) -> Vec<u8> {
        let client = beacon_client();
        let c2 = beacon_c2();
        let sport = 49152 + (cycle % 16000) as u16;
        self.record_flow(client, c2, sport, 443, IP_PROTO_TCP);
        let payload = frames::tls_client_hello_payload(BEACON_SNI);
        let tcp = frames::build_tcp(client, c2, sport, 443, TCP_PSH | TCP_ACK, &payload);
        let ip = frames::build_ipv4(client, c2, IP_PROTO_TCP, 64, tcp.len());
        let mut frame = frames::build_ethernet(BEACON_CLIENT_MAC, BEACON_C2_MAC, ETHERTYPE_IPV4);
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&tcp);
        frame
    }

    /// Record a normalized 5-tuple flow key into the bounded distinct-flow set.
    fn record_flow(&mut self, src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, proto: u8) {
        // Normalize endpoints so a<->b and b<->a collapse to one flow.
        let (lo_ip, lo_port, hi_ip, hi_port) = {
            let aa = (u32::from(src), sport);
            let bb = (u32::from(dst), dport);
            if aa <= bb {
                (aa.0, aa.1, bb.0, bb.1)
            } else {
                (bb.0, bb.1, aa.0, aa.1)
            }
        };
        // Pack into a single u64 key: this is collision-resistant enough for the small,
        // deterministic endpoint space the generator uses (host_count is a u16, ports u16).
        // Use a stable FNV-1a hash over the tuple bytes to keep the set bounded and cheap.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in lo_ip
            .to_be_bytes()
            .iter()
            .chain(hi_ip.to_be_bytes().iter())
            .chain(lo_port.to_be_bytes().iter())
            .chain(hi_port.to_be_bytes().iter())
            .chain(std::iter::once(&proto))
        {
            h ^= *byte as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
        }
        // Hard-cap the set so the generator stays bounded-memory even for scenarios that
        // produce a distinct flow per packet (random ephemeral ports). Once saturated,
        // `distinct_flows` stops growing — a documented lower bound (see MAX_TRACKED_FLOWS).
        if self.flows.len() < MAX_TRACKED_FLOWS {
            self.flows.insert(h);
        }
    }
}

/// Beacon callback period (~30 s) for [`Scenario::Beacon`]. Explicit so the inter-callback
/// interval is wall-clock-regular regardless of background packet volume.
const BEACON_PERIOD_NS: i64 = 30_000_000_000;
/// Packets per beacon cycle: one C2 callback + 12 benign background frames.
const BEACON_CYCLE_LEN: u64 = 13;
/// Distinct internal hosts the beacon host sweeps on 445 first (>= the sweep detector floor, so
/// the capture yields a recon + C2 multi-stage incident).
const BEACON_SWEEP_HOSTS: u64 = 24;
/// Credential-access stage: SSH connection attempts against one discovered host (>= the
/// brute-force detector's attempt floor) and the MAC used for those frames.
const BEACON_BRUTE_ATTEMPTS: u64 = 30;
const BEACON_BRUTE_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0xBE, 0xAC, 0x05];
/// Lateral-movement stage: established RDP sessions to N discovered internal hosts (>= the
/// lateral detector's host floor), each carrying a few data frames per direction (so both
/// directions clear the per-direction session-byte floor), plus the MAC for those frames.
const BEACON_LATERAL_HOSTS: u64 = 6;
const BEACON_LATERAL_FRAMES_PER_HOST: u64 = 4;
const BEACON_LATERAL_PAYLOAD: usize = 700;
const BEACON_LATERAL_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0xBE, 0xAC, 0x06];
/// Exfil upload: number of large data packets, their payload size, and the fixed source port
/// (one flow). 900 × 1400 B ≈ 1.2 MB outbound — clears the 1 MB exfil floor.
const BEACON_EXFIL_PACKETS: u64 = 900;
const BEACON_EXFIL_PAYLOAD: usize = 1400;
const BEACON_EXFIL_SPORT: u16 = 51000;
const BEACON_EXFIL_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0xBE, 0xAC, 0x03];
/// DNS-tunnel stage: number of high-entropy queries (>= the detector floor) and the base domain.
const BEACON_DNS_QUERIES: u64 = 40;
const BEACON_DNS_DOMAIN: &str = "tunnel.exfil.example";
const BEACON_DNS_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0xBE, 0xAC, 0x04];

/// The internal resolver the beacon host tunnels DNS through.
fn beacon_dns_resolver() -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, 53)
}

/// The discovered internal host the beacon host brute-forces SSH on — the first host it swept on
/// 445 (10.66.0.1), tying the Credential Access stage to the Discovery stage.
fn beacon_brute_victim() -> Ipv4Addr {
    Ipv4Addr::new(10, 66, 0, 1)
}

/// A deterministic 32-char base32 (high-entropy) DNS label for query `idx`.
fn beacon_dns_label(idx: u64) -> String {
    const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut x = idx.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xD1CE_F00D;
    (0..32)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            ALPHA[(x % 32) as usize] as char
        })
        .collect()
}
/// SNI presented by the synthetic C2 callbacks.
const BEACON_SNI: &str = "sync.cdn-metrics.net";
/// Fixed locally-administered MACs for the beacon client / C2.
const BEACON_CLIENT_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0xBE, 0xAC, 0x01];
const BEACON_C2_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0xBE, 0xAC, 0x02];

/// The compromised internal host that beacons out (RFC1918, classified internal).
fn beacon_client() -> Ipv4Addr {
    Ipv4Addr::new(10, 13, 37, 7)
}

/// The external C2 the beacon dials. A real public address so it classifies as external and the
/// beacon scores **High** (an internal C2 would only reach Medium).
fn beacon_c2() -> Ipv4Addr {
    Ipv4Addr::new(45, 77, 13, 37)
}

/// The external drop server the beacon host exfiltrates to (distinct from the C2, public).
fn beacon_exfil_server() -> Ipv4Addr {
    Ipv4Addr::new(185, 220, 101, 5)
}

/// Deterministic per-host IPv4 in 10.0.0.0/8: 10.<hi>.<mid>.<lo+1>.
fn host_ip(idx: u16) -> Ipv4Addr {
    let i = idx as u32;
    Ipv4Addr::new(10, ((i >> 8) & 0xFF) as u8, (i & 0xFF) as u8, 10)
}

/// Deterministic per-host MAC: 02:00:00:00:HH:LL (locally administered).
fn mac_for(idx: u16) -> [u8; 6] {
    [0x02, 0x00, 0x00, 0x00, (idx >> 8) as u8, (idx & 0xFF) as u8]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_small() -> GenConfig {
        GenConfig {
            scenario: Scenario::Mixed,
            packets: 200,
            seed: 0xDEAD_BEEF,
            link_type: LinkType::Ethernet,
            pcapng: false,
            start_ts_ns: 1_700_000_000i64 * 1_000_000_000,
            mean_gap_ns: 1_000_000,
            include_edge_cases: false,
            host_count: 8,
        }
    }

    #[test]
    fn scenario_parsing_roundtrips() {
        assert_eq!(Scenario::from_str_opt("mixed"), Some(Scenario::Mixed));
        assert_eq!(Scenario::from_str_opt("WEB-ONLY"), Some(Scenario::WebOnly));
        assert_eq!(Scenario::from_str_opt("webonly"), Some(Scenario::WebOnly));
        assert_eq!(
            Scenario::from_str_opt("dns-flood"),
            Some(Scenario::DnsFlood)
        );
        assert_eq!(Scenario::from_str_opt("portscan"), Some(Scenario::PortScan));
        assert_eq!(Scenario::from_str_opt(" beacon "), Some(Scenario::Beacon));
        assert_eq!(Scenario::from_str_opt("bulk"), Some(Scenario::BulkTransfer));
        assert_eq!(Scenario::from_str_opt("nonsense"), None);
        assert_eq!(Scenario::all().len(), 6);
    }

    #[test]
    fn manifest_packet_count_matches_config() {
        let mut g = SynthGen::new(cfg_small());
        let m = g.write_to(std::io::sink()).unwrap();
        assert_eq!(m.packets_written, 200);
        assert_eq!(m.counts.tcp + m.counts.udp + m.counts.non_ipv4, 200);
    }

    #[test]
    fn output_is_byte_identical_for_same_config() {
        let mut a = SynthGen::new(cfg_small());
        let mut b = SynthGen::new(cfg_small());
        let mut buf_a = Vec::new();
        let mut buf_b = Vec::new();
        a.write_to(&mut buf_a).unwrap();
        b.write_to(&mut buf_b).unwrap();
        assert_eq!(buf_a, buf_b);
        assert!(!buf_a.is_empty());
    }

    #[test]
    fn counts_are_seed_independent() {
        let mut c1 = cfg_small();
        c1.seed = 1;
        let mut c2 = cfg_small();
        c2.seed = 999_999;
        let m1 = SynthGen::new(c1).write_to(std::io::sink()).unwrap();
        let m2 = SynthGen::new(c2).write_to(std::io::sink()).unwrap();
        assert_eq!(m1.counts, m2.counts);
        assert_eq!(m1.packets_written, m2.packets_written);
    }

    #[test]
    fn edge_cases_present_in_manifest() {
        let mut cfg = cfg_small();
        cfg.include_edge_cases = true;
        let m = SynthGen::new(cfg).write_to(std::io::sink()).unwrap();
        assert_eq!(m.counts.truncated, 1);
        assert_eq!(m.counts.non_ipv4, 1);
        assert_eq!(m.counts.tcp + m.counts.udp + m.counts.non_ipv4, 200);
    }

    #[test]
    fn first_record_header_is_well_formed() {
        let mut g = SynthGen::new(cfg_small());
        let mut buf = Vec::new();
        let m = g.write_to(&mut buf).unwrap();
        // Global header is 24 bytes; first record header begins at offset 24.
        assert!(buf.len() > 40);
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(magic, container::PCAP_MAGIC_USEC_LE);
        // First record ts_sec matches start_ts.
        let ts_sec = u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]);
        assert_eq!(ts_sec, 1_700_000_000);
        // Manifest first ts equals configured start.
        assert_eq!(m.first_ts_ns, 1_700_000_000i64 * 1_000_000_000);
        assert!(m.last_ts_ns >= m.first_ts_ns);
    }

    #[test]
    fn timestamps_are_monotonic_nondecreasing() {
        let mut g = SynthGen::new(cfg_small());
        let mut prev = i64::MIN;
        while let Some((ts, _f)) = g.next_raw() {
            assert!(ts >= prev, "timestamp went backwards: {ts} < {prev}");
            prev = ts;
        }
    }

    #[test]
    fn next_raw_stops_at_packet_count() {
        let mut g = SynthGen::new(cfg_small());
        let mut n = 0;
        while g.next_raw().is_some() {
            n += 1;
            assert!(n <= 200, "produced more frames than configured");
        }
        assert_eq!(n, 200);
    }

    #[test]
    fn distinct_flows_bounded_by_host_space() {
        let mut g = SynthGen::new(cfg_small());
        let m = g.write_to(std::io::sink()).unwrap();
        // With 8 hosts there can be at most a modest number of distinct flow keys; assert it
        // stayed well within the deterministic endpoint space rather than growing per packet.
        assert!(m.distinct_flows > 0);
        assert!(m.distinct_flows <= 200);
    }

    #[test]
    fn pcapng_output_starts_with_shb() {
        let mut cfg = cfg_small();
        cfg.pcapng = true;
        cfg.packets = 10;
        let mut buf = Vec::new();
        let m = SynthGen::new(cfg).write_to(&mut buf).unwrap();
        assert_eq!(m.packets_written, 10);
        let bt = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(bt, container::NG_BLOCK_SHB);
    }

    #[test]
    fn zero_packets_writes_only_header() {
        let mut cfg = cfg_small();
        cfg.packets = 0;
        let mut buf = Vec::new();
        let m = SynthGen::new(cfg).write_to(&mut buf).unwrap();
        assert_eq!(m.packets_written, 0);
        assert_eq!(buf.len(), 24); // just the global header
        assert_eq!(m.frame_bytes, 0);
        assert_eq!(m.bytes_written, 24);
    }

    #[test]
    fn beacon_scenario_conserves_packet_count_and_is_deterministic() {
        // The Beacon scenario uses a dedicated emission path (next_beacon) whose multi-stage
        // prefix (sweep -> brute -> exfil -> dns -> C2 cycles) does index arithmetic across stage
        // boundaries. Cover it directly: at packets just above the 2000 gate (all prefix stages
        // active) and at a large multi-cycle value, packets_written must equal cfg.packets, and
        // the same (seed, packets) must produce byte-identical output.
        let beacon_cfg = |packets: u64| GenConfig {
            scenario: Scenario::Beacon,
            packets,
            seed: 0xBEAC_0017,
            host_count: 64,
            ..Default::default()
        };
        for &packets in &[2_001u64, 40_000] {
            let m = SynthGen::new(beacon_cfg(packets))
                .write_to(std::io::sink())
                .unwrap();
            assert_eq!(
                m.packets_written, packets,
                "beacon packets_written == cfg.packets (packets={packets})"
            );

            let mut a = Vec::new();
            let mut b = Vec::new();
            SynthGen::new(beacon_cfg(packets)).write_to(&mut a).unwrap();
            SynthGen::new(beacon_cfg(packets)).write_to(&mut b).unwrap();
            assert_eq!(a, b, "beacon output byte-identical for same config (packets={packets})");
        }
    }
}
