# PacketPilot Engine — Phase 0

A streaming, bounded-memory pcap/pcapng analysis engine written in pure Rust. The
**shipped** engine builds with no C compiler; only the dev-time `cargo bench` pulls a C
dependency (`peak_alloc → alloca → cc`), so the purity gate below scopes to `-e no-dev`.
Phase 0 ingests a capture in a single pass, derives per-flow records and a
capture-wide summary, and persists flows as Snappy-compressed Parquet that an external
DuckDB sidecar (CLI or Wasm) queries via a view.

Inputs: classic pcap (both endiannesses, µs and ns magics) and pcapng (multi-interface,
per-interface `tsresol`). `.gz`-wrapped captures are detected but **rejected** pending a
pure-Rust inflate backend (see the gzip note under "Run").

## Workspace layout

```
engine/
├── crates/ppcap-core   # library: reader, decode, flow, classify, stats, columnar, analyze, gen, metrics
└── crates/ppcap-cli    # binary `ppcap`: analyze / gen / init-db subcommands
```

## Toolchain

- Rust **stable**, MSRV **1.85** (arrow/parquet 59 floor)
- Target **`x86_64-pc-windows-gnu`** (rustup-bundled mingw linker; no MSVC C build tools required)
- Edition **2021**

The toolchain and target are pinned in `rust-toolchain.toml`; the target is also set in
`.cargo/config.toml`.

## Build

```sh
cargo build                      # debug, whole workspace
cargo build --release            # optimized (lto=thin, codegen-units=1, panic=abort)
cargo build -p ppcap-cli --release
```

## Run

```sh
# Analyze a capture -> summary JSON on stdout, optional flows Parquet.
# NOTE: --parquet takes a single FILE path (the engine writes one Parquet file, not a
# directory of parts). Its parent directory must already exist (the CLI does not mkdir).
mkdir -p out
cargo run -p ppcap-cli --release -- analyze capture.pcap --json - --parquet out/flow.parquet

# Strict mode (abort on first malformed packet) + source hashing
cargo run -p ppcap-cli --release -- analyze capture.pcapng --strict --hash

# Generate a deterministic synthetic capture (byte-identical for a given seed+count)
cargo run -p ppcap-cli --release -- gen out/mixed.pcap --scenario mixed --packets 100000 --seed 0

# Emit the embedded DuckDB DDL for the external sidecar / DuckDB-Wasm
cargo run -p ppcap-cli --release -- init-db --out schema.sql --case-dir /abs/case/dir
```

Conventions: progress is written to **stderr**, summary JSON to **stdout** (pipeable).
Exit codes: `0` ok, `1` fatal engine error, `2` CLI usage error (clap).

The DuckDB `flow` view globs `{CASE_DIR}/parquet/flow/*.parquet`, so when staging output
for the sidecar, write the engine's single Parquet file into that directory layout, e.g.
`--parquet <CASE_DIR>/parquet/flow/flow.parquet`.

> **gzip note:** `.gz`-wrapped captures are **not yet supported**. The reader sniffs the
> gzip magic and rejects such inputs up front with a clear error; a pure-Rust inflate
> backend (miniz_oxide / `flate2 rust_backend`) is the documented drop-in (see the
> integration note in `crates/ppcap-core/src/reader/gzip.rs`). Pass an uncompressed
> `.pcap`/`.pcapng` for now.

## Test

```sh
cargo test                                   # whole workspace, fast (golden 5k + units)
cargo test -p ppcap-core                     # core only
cargo test -p ppcap-core -- --ignored        # incl. golden_100k_budget (throughput floors)
```

Key tests (in `crates/ppcap-core/tests/`):
- `gen_container` / `gen_frames` / `gen_mix` — generator byte-exactness & ground-truth tallies
- `decode_vectors` — hand-crafted frame -> `PacketMeta` (no panics on truncation)
- `flow_symmetry` — bidirectional `FlowKey` normalization & ordering
- `columnar_roundtrip` — Parquet write -> read-back, codec & KV metadata
- `schema_drift` — CI guard: SQL view SELECT == Arrow schema == `flow_columns_in_order()`
- `golden_e2e` — the gate: conservation/fidelity invariants against the generator manifest

## Bench

```sh
cargo bench -p ppcap-core            # criterion `ingest` bench (10k / 100k / 1M packets)
```

The bench measures `analyze::run` only (captures are pre-generated to a tempfile). It
installs `peak_alloc` as the global allocator **only in the bench binary** and prints
packets/s, MiB/s, peak heap, and wall. Budget assertions live in the golden test, not the
bench, so `cargo bench` never fails the build.

For an end-to-end CLI benchmark on a large synthetic capture (the recipe `BENCHMARK.md`
documents), `--parquet` is a single file path and its parent dir must exist:

```sh
cargo run --release -p ppcap-cli -- gen tmp_bench.pcap --packets 2000000
mkdir -p pq
cargo run --release -p ppcap-cli -- analyze tmp_bench.pcap --json out.json --parquet pq/flow.parquet
rm -f tmp_bench.pcap
```

Wall time and packets/sec for that run come from the `elapsed_ms` field in `out.json`
(or an external timer); peak heap is reported only by the instrumented `cargo bench`
binary. See `BENCHMARK.md` for the methodology and recorded results.

## Phase-0 performance budget

The headline guarantee is **bounded memory independent of capture size**.

| Metric | Budget | Notes |
|---|---|---|
| Peak heap | **≤ 64 MiB** | constant w.r.t. pcap size — the streaming contract |
| Throughput | **≥ 250,000 packets/s** | synthetic mix, single core |
| Throughput | **≥ 40 MiB/s** | of wire bytes (synthetic mix is tiny-frame / packet-bound; real MTU traffic is far higher) |
| Wall (100k pkts) | **< 2 s** | end-to-end analyze |

Throughput floors are intentionally set ~3–5× below expected so CI stays non-flaky on slow
runners; they tighten once real 5–10 GB hardware baselines exist.

## On-disk format & compression

- Flows persisted as **Snappy** Parquet (pure-Rust codec; universal). `lz4_flex` is an
  opt-in escalation. **No** zstd/gzip/brotli — those C paths are unreachable by construction
  (parquet built with `default-features = false`, features `arrow,snap,base64,lz4`).
- Timestamps are `i64` nanoseconds end-to-end; Parquet `Timestamp(Nanosecond, UTC)`.
- DuckDB is **not linked**. The engine ships the case DDL at
  `crates/ppcap-core/sql/schema.sql` (emitted by `ppcap init-db`); `flow` is a DuckDB
  **view over Parquet**. All Phase-0 summary stats are computed in-Rust.

### C-compiler-free verification gate (CI)

The **shipped** engine (the `-e no-dev` graph) pulls no C-compiled crate. Only the dev/bench
graph does — `peak_alloc → alloca → cc`, used solely by `cargo bench` — which is why the gate
scopes to `-e no-dev`.

```sh
cargo tree -e no-dev | grep -Ei "zstd-sys|lz4-sys|cc |cmake|bzip2-sys|openssl-sys|zlib" && exit 1 || exit 0
```

### `online` cargo feature (native-only)

```toml
# ppcap-core/Cargo.toml
[features]
online = ["dep:ureq"]   # pulls ureq (rustls TLS + ring crypto) → requires a C compiler
```

The `online` feature enables the native reputation adapters
(`enrich::online::{abuseipdb,greynoise,virustotal}`) used by the CLI (`--reputation`) and the
Tauri desktop backend. It is **not** compiled into `ppcap-wasm` or the default engine build —
those remain C-compiler-free.

`apply_reputation` (the severity fold that applies provider verdicts to per-IP threat cards) is
**always compiled and wasm-safe** — it has no network I/O and no dependency on `ureq`. The
Browser build calls the same function via the WASM export, giving cross-surface scoring parity
without the native HTTP stack.

To build the CLI with reputation support:

```sh
cargo build -p ppcap-cli --release --features ppcap-core/online
```
