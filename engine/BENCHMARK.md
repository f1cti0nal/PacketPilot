# PacketPilot Engine — Phase-0 Benchmark

> **Status: measured locally, 2026-06-19.** Built and run with the project toolchain
> (rustc/cargo **1.96.0**, target `x86_64-pc-windows-gnu`, GCC 16.1.0 mingw linker). All
> Phase-0 budget metrics **pass**. Numbers below are from `cargo bench` on this host.

The engine's headline guarantee is **bounded peak heap, independent of capture size** — the
streaming contract. Throughput is the secondary guarantee.

---

## 1. Phase-0 budget (the contract under test)

Source of truth: `crates/ppcap-core/src/metrics/mod.rs` (`PHASE0_BUDGET`).

| Metric                | Budget                  | Notes                                                       |
|-----------------------|-------------------------|------------------------------------------------------------|
| Peak heap             | **≤ 64 MiB**            | constant w.r.t. pcap size — the streaming contract         |
| Throughput (packets)  | **≥ 250,000 packets/s** | synthetic Mixed scenario, single core                      |
| Throughput (bytes)    | **≥ 40 MiB/s**          | of wire bytes; the synthetic mix is tiny-frame/packet-bound |
| Wall (100k packets)   | **< 2 s**               | end-to-end `analyze::run`                                   |

> The byte-rate floor is 40 MiB/s because the synthetic Mixed frames are tiny (~83 B avg:
> DNS/handshake fragments, bare SYNs), so the workload is **packet-rate-bound**. At the same
> packet rate, real MTU-sized traffic is an order of magnitude higher in MiB/s.

---

## 2. Why peak heap is bounded (design, not luck)

Every stage is bounded independently of `packets`:

- **Reader** (`reader/`): `pcap-parser` over a fixed **64 KiB** refill buffer
  (`REFILL_CAPACITY`); one `RawFrame` borrowed at a time (lending iterator); no whole-file
  buffering. pcapng interface table capped at `MAX_INTERFACES`.
- **Decode** (`decode/`): fixed-size `PacketMeta`; **no payload retained**.
- **Flow table** (`flow/`): live map capped at `max_active_flows` (**default 32,768**) with
  approximate-LRU cap eviction + idle/active timeouts. Cap-eviction victims are drained every
  `evict_interval_pkts` (**default 16,384**) so the victim buffer can't accumulate a full
  interval. Closed/evicted flows stream out to the sink (stats + Parquet) — they never
  accumulate, so the **summary and persisted flows stay complete** even though the live
  working set is bounded.
- **Stats** (`stats/`): every per-key map (talkers/ports/paths/seconds/scan-spread) bounded by
  `max_tracked_keys` with heavy-hitter-preserving eviction; scan spread capped per source
  (`SCAN_PORTS_PER_SRC_CAP`).
- **Parquet writer** (`columnar/`): at most one row group (`row_group_size` = **32,768** rows)
  held in Arrow builders before flush + reset.

The instrumented allocator (`peak_alloc::PeakAlloc`) is installed **only** in
`benches/ingest.rs`; the shipped binary uses the system allocator.

### Tuning history (this is what the bench caught)

The first run peaked at **143 MiB** at 1M packets — the bounded-memory guarantee was cap-based
but the *defaults* were far too high for a 64 MiB ceiling on the worst-case (~1 flow/packet)
synthetic mix. Three default changes brought it within budget with no loss of output
completeness (every flow is still processed exactly once):

| Change | 1M-packet peak |
|---|---|
| `max_active_flows` 1,000,000 (original) | 143 MiB |
| → 65,536 | 87 MiB |
| + `evict_interval_pkts` 100,000 → 16,384 | 74 MiB |
| + `max_active_flows` → 32,768 | **38 MiB** ✅ |

---

## 3. Methodology

```sh
cargo bench -p ppcap-core
```

- Pre-generates Mixed captures of **10k / 100k / 1M** packets to a tempfile (generation cost
  excluded from timing); measures `analyze::run` only.
- The bench binary is the only place `peak_alloc` is the global allocator, so its out-of-band
  timed run prints the real headline line per size:
  `[ingest mixed_<N>] <pps> pps, <mibps> MiB/s, peak <MiB> MiB, wall <dur>`.

End-to-end CLI cross-check (debug build, 200k packets, `--edge-cases`): produced a correct
summary (`total_packets` reconciles: `tcp+udp+non_ipv4 == total`), a realistic category
breakdown (web/dns/voip/scan/…), the two injected edge cases (`decode_errors=1`,
`non_ip_frames=1`), a SHA-256 of the source, and a ~2.9 MB Snappy Parquet of flows.

---

## 4. Results

### 4a. Criterion (`cargo bench -p ppcap-core`) — single core

| Capture (Mixed) | packets/s | MiB/s | Peak heap | Wall (criterion median) | Budget |
|-----------------|-----------|-------|-----------|-------------------------|--------|
| 10,000          | 962,816   | 76.3  | **5.96 MiB** | 9.15 ms              | ✅ pass |
| 100,000         | 1,166,325 | 92.5  | **24.32 MiB** | 89.9 ms             | ✅ pass |
| 1,000,000       | 1,176,321 | 93.3  | **38.16 MiB** | 858 ms              | ✅ pass |

Peak heap is bounded and plateaus well under budget as caps saturate (5.96 → 24.32 → 38.16
MiB across a 100× packet range), versus Wireshark's load-everything growth.

### 4b. Budget verdict

| Budget item            | Threshold        | Observed (1M run)        | Pass/Fail |
|------------------------|------------------|--------------------------|-----------|
| Peak heap ≤ 64 MiB     | 67,108,864 bytes | 38.16 MiB                | ✅ pass    |
| packets/s ≥ 250,000    | 250,000          | 1,176,321 (4.7×)         | ✅ pass    |
| MiB/s ≥ 40             | 40               | 93.3                     | ✅ pass    |
| Wall (100k) < 2 s      | 2 s              | ~0.09 s                  | ✅ pass    |

---

## 5. Environment

- Host: Windows 10 Pro, x86-64, 20 logical cores (analyze is single-threaded in Phase 0).
- Toolchain: rustc/cargo **1.96.0**, target `x86_64-pc-windows-gnu`; linker GCC **16.1.0**
  (WinLibs mingw-w64 UCRT). MSRV 1.85, edition 2021.
- Bench profile: `opt-level=3`, `lto="thin"`, `codegen-units=1`.

---

## 6. Notes & Phase-1 follow-ups

- The synthetic Mixed scenario is an adversarial ~1-flow-per-packet workload (random ephemeral
  ports) — a worst case for the flow table. Real multi-packet-flow traffic uses far less memory
  at the same packet count.
- The 32,768 live-flow cap trades a little flow-split risk under extreme concurrency for the
  ≤64 MiB guarantee; it's configurable (`FlowConfig::max_active_flows`).
- Phase 1: real-pcap baselines on 5–10 GB captures; multi-threaded dissection; peak-RSS
  (not just heap) sampling; stream `packet_index` Parquet for deep-dive drill-down.
