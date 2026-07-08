//! The `ppcap` command-line surface (clap) and dispatch.
//!
//! Thin shell over `ppcap-core`: parse args, build the core configs, call into the engine,
//! and map [`ppcap_core::PpError`] to an exit code. Progress goes to **stderr**, JSON to
//! **stdout** (pipeable). `anyhow` and `clap` live only here; the core stays typed.
//!
//! The command structure and argument parsing below are COMPLETE and stable, and `dispatch`
//! is now fully wired to the engine (analyze / gen / init-db). The CLI signatures must not
//! change.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{anyhow, Context};
use clap::{Parser, Subcommand};

/// Top-level CLI.
#[derive(Parser, Debug)]
#[command(
    name = "ppcap",
    version,
    about = "PacketPilot pcap analysis engine (Phase 0)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Analyze a pcap/pcapng (optionally .gz): summary JSON (+ optional flows Parquet).
    Analyze {
        /// Input capture path (.pcap / .pcapng, optionally .gz).
        input: PathBuf,
        /// JSON output path; "-" or omitted => stdout.
        #[arg(long)]
        json: Option<String>,
        /// Self-contained HTML triage report output path (prints to PDF from any browser).
        #[arg(long)]
        html: Option<PathBuf>,
        /// Flows Parquet output path; omit => skip Parquet.
        #[arg(long)]
        parquet: Option<PathBuf>,
        /// Abort on the first malformed packet (default: count & continue).
        #[arg(long)]
        strict: bool,
        /// Compute SHA-256 of the source (extra read pass).
        #[arg(long)]
        hash: bool,
        /// Suppress stderr progress.
        #[arg(long)]
        quiet: bool,
        /// Local IOC threat-feed JSON (offline enrichment); omit => no enrichment.
        #[arg(long = "threat-feed")]
        threat_feed: Option<PathBuf>,
        /// Opt-in: extract each carved cleartext HTTP download to this directory (`<sha256>.<ext>`;
        /// known-bad/suspicious files get a `.quarantine` suffix). Off by default — no bytes written.
        #[arg(long = "carve-dir")]
        carve_dir: Option<PathBuf>,
        /// Export behavioral findings as CSV to this path.
        #[arg(long)]
        csv: Option<PathBuf>,
        /// Export a STIX 2.1 bundle (indicators + ATT&CK) to this path.
        #[arg(long)]
        stix: Option<PathBuf>,
        /// Enrich public IPs with online reputation (AbuseIPDB / GreyNoise / VirusTotal).
        /// Requires at least one of ABUSEIPDB_API_KEY / GREYNOISE_API_KEY / VIRUSTOTAL_API_KEY.
        #[arg(long)]
        reputation: bool,
        /// Apply a Suricata-style ruleset (content matches → findings).
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Time Machine: also write a compact capture-indicator index (JSON) here for
        /// later `ppcap rescan` against updated threat intel.
        #[arg(long)]
        index: Option<PathBuf>,
    },
    /// Time Machine: re-evaluate saved capture indices against an updated threat feed,
    /// reporting indicators that were clean at capture time but are dirty now.
    Rescan {
        /// One or more capture-index JSON files (from `analyze --index`).
        indices: Vec<PathBuf>,
        /// Updated threat-feed JSON to re-evaluate against.
        #[arg(long = "threat-feed")]
        threat_feed: PathBuf,
        /// Write the full JSON report here; omit => human summary to stderr only.
        #[arg(long)]
        json: Option<String>,
        /// Also report indicators that were ALREADY flagged at capture time.
        #[arg(long)]
        include_known: bool,
    },
    /// Generate a synthetic capture for testing.
    Gen {
        /// Output capture path.
        output: PathBuf,
        /// Scenario: mixed | web-only | dns-flood | port-scan | beacon | bulk-transfer.
        #[arg(long, default_value = "mixed")]
        scenario: String,
        /// Number of packets to emit.
        #[arg(long, default_value_t = 100_000)]
        packets: u64,
        /// PRNG seed (same seed+count => byte-identical output).
        #[arg(long, default_value_t = 0)]
        seed: u64,
        /// Emit pcapng instead of classic pcap.
        #[arg(long)]
        pcapng: bool,
        /// Inject the fixed edge-case frames.
        #[arg(long)]
        edge_cases: bool,
        /// Number of distinct synthetic hosts the background traffic spreads across (default 64).
        /// Raise it to thin out per-service connection counts (e.g. avoid emergent half-open floods).
        #[arg(long, default_value_t = 64)]
        hosts: u16,
    },
    /// Emit the embedded DuckDB DDL to stdout or a file (for the external duckdb sidecar/Wasm).
    InitDb {
        /// Output path; omit => stdout.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Substitutes the {CASE_DIR} token in the DDL.
        #[arg(long)]
        case_dir: Option<String>,
    },
}

/// Embedded DuckDB DDL (shipped so the sidecar/Wasm can create the schema without the repo).
const DUCKDB_SCHEMA: &str = include_str!("../../ppcap-core/sql/schema.sql");

/// Parse args, dispatch, and map errors to a process exit code.
///
/// Exit codes: `0` ok, `1` fatal engine error, `2` usage error (clap handles `2` itself by
/// printing help/usage and exiting before this returns).
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}

/// Testable inner dispatch (no process exit). Returns `anyhow::Result` so the CLI can add
/// human context to typed core errors.
pub fn dispatch(cli: Cli) -> anyhow::Result<()> {
    // IMPL: match cli.command and translate flags into core configs, then call the engine.
    match cli.command {
        Command::Analyze {
            input,
            json,
            html,
            parquet,
            strict,
            hash,
            quiet,
            threat_feed,
            carve_dir,
            csv,
            stix,
            reputation,
            rules,
            index,
        } => {
            // IMPL:
            //  - Build ppcap_core::PipelineConfig::default(), then set:
            //      strict_decode = strict; hash_source = hash;
            //      flows_parquet = parquet.clone();
            //      writer.capture_id = derive from input (or 0).
            //  - progress closure: if quiet, a no-op; else write a throttled
            //      "\rpkts=… bytes=… (pct)" line to stderr.
            //  - out = ppcap_core::run(&input, &cfg, progress)?;  (PpError -> anyhow via ?)
            //  - let s = out.to_json_pretty()?;
            //  - if json is None or Some("-") => println!("{s}") to stdout;
            //    else write s to the json path (anyhow context on io error).
            use std::io::Write as _;

            // Derive a stable capture id from the input path (cheap FNV-1a hash) so distinct
            // captures get distinct ids in the Parquet footer; falls back to 0 on empty path.
            let cfg = ppcap_core::PipelineConfig {
                strict_decode: strict,
                hash_source: hash,
                flows_parquet: parquet.clone(),
                threat_feed: threat_feed.clone(),
                carve_dir: carve_dir.clone(),
                writer: ppcap_core::columnar::WriterConfig {
                    capture_id: fnv1a64(input.to_string_lossy().as_bytes()),
                    ..Default::default()
                },
                ..Default::default()
            };

            // Progress: throttled single-line stderr updates unless --quiet. The closure only
            // borrows a local `last_emit` counter; it writes nothing to stdout.
            let mut last_tick: u64 = 0;
            let progress = |pkts: u64, bytes: u64, size_hint: Option<u64>| {
                if quiet {
                    return;
                }
                // Throttle: only repaint when the packet count advanced past the last tick.
                if pkts == last_tick {
                    return;
                }
                last_tick = pkts;
                let pct = match size_hint {
                    Some(total) if total > 0 => {
                        format!(" ({:.0}%)", (bytes as f64 / total as f64) * 100.0)
                    }
                    _ => String::new(),
                };
                let mut err = std::io::stderr();
                let _ = write!(err, "\rpkts={pkts} bytes={bytes}{pct}");
                let _ = err.flush();
            };

            let mut out = ppcap_core::run(&input, &cfg, progress)?;
            if !quiet {
                // Terminate the in-place progress line.
                let _ = writeln!(std::io::stderr());
            }

            if reputation {
                let keys = ppcap_core::ReputationKeys {
                    abuseipdb: std::env::var("ABUSEIPDB_API_KEY")
                        .ok()
                        .filter(|s| !s.is_empty()),
                    greynoise: std::env::var("GREYNOISE_API_KEY")
                        .ok()
                        .filter(|s| !s.is_empty()),
                    virustotal: std::env::var("VIRUSTOTAL_API_KEY")
                        .ok()
                        .filter(|s| !s.is_empty()),
                };
                if keys.is_empty() {
                    if !quiet {
                        let _ = writeln!(std::io::stderr(),
                            "reputation: no provider key set (ABUSEIPDB_API_KEY / GREYNOISE_API_KEY / VIRUSTOTAL_API_KEY); skipping");
                    }
                } else {
                    let ips: Vec<std::net::IpAddr> = out
                        .summary
                        .ip_threats
                        .iter()
                        .filter_map(|t| t.ip.parse().ok())
                        .filter(|ip| ppcap_core::enrich::classify_ip(*ip).is_external())
                        .collect();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    let cache_dir = dirs::cache_dir()
                        .unwrap_or_else(std::env::temp_dir)
                        .join("packetpilot");
                    let verdicts =
                        ppcap_core::lookup_reputation_native(&ips, &keys, &cache_dir, now);
                    ppcap_core::apply_reputation(&mut out.summary, &verdicts);

                    // Domain (SNI) reputation — VT-only; same keys/cache/timestamp.
                    let hosts: Vec<String> = out
                        .summary
                        .domain_threats
                        .iter()
                        .map(|d| d.host.clone())
                        .collect();
                    if !hosts.is_empty() {
                        let domain_verdicts = ppcap_core::lookup_domain_reputation_native(
                            &hosts, &keys, &cache_dir, now,
                        );
                        ppcap_core::apply_domain_reputation(&mut out.summary, &domain_verdicts);
                    }
                }
            }

            if let Some(rules_path) = rules {
                let text = std::fs::read_to_string(&rules_path)
                    .with_context(|| format!("reading rules file {}", rules_path.display()))?;
                let parsed = ppcap_core::parse_rules(&text);
                let rf = match std::fs::File::open(&input) {
                    Ok(f) => {
                        let len = std::fs::metadata(&input).ok().map(|m| m.len());
                        ppcap_core::apply_rules(f, len, &parsed.rules)
                    }
                    Err(_) => Vec::new(),
                };
                ppcap_core::fold_rule_findings(&mut out.summary, &rf);
                eprintln!(
                    "rules: {} loaded, {} skipped, {} matches",
                    parsed.rules.len(),
                    parsed.skipped.len(),
                    rf.len()
                );
            }

            let s = out.to_json_pretty()?;
            match json.as_deref() {
                None | Some("-") => {
                    println!("{s}");
                }
                Some(path) => {
                    std::fs::write(path, &s)
                        .with_context(|| format!("write JSON output to {path}"))?;
                }
            }

            if let Some(html_path) = html.as_ref() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0); // pre-epoch clock -> 0; report still renders
                let doc = ppcap_core::render_html(&out, now, None);
                std::fs::write(html_path, doc)
                    .with_context(|| format!("write HTML report to {}", html_path.display()))?;
                if !quiet {
                    eprintln!("wrote HTML report -> {}", html_path.display());
                }
            }

            if let Some(csv_path) = csv.as_ref() {
                std::fs::write(csv_path, ppcap_core::export::findings_csv(&out))
                    .with_context(|| format!("write findings CSV to {}", csv_path.display()))?;
                if !quiet {
                    eprintln!("wrote findings CSV -> {}", csv_path.display());
                }
            }

            if let Some(stix_path) = stix.as_ref() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                std::fs::write(stix_path, ppcap_core::export::stix_bundle(&out, now))
                    .with_context(|| format!("write STIX bundle to {}", stix_path.display()))?;
                if !quiet {
                    eprintln!("wrote STIX 2.1 bundle -> {}", stix_path.display());
                }
            }

            if let Some(index_path) = index.as_ref() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let idx = ppcap_core::build_index(&out, now);
                let n = idx.indicators.len();
                std::fs::write(index_path, idx.to_json_pretty()?)
                    .with_context(|| format!("write capture index to {}", index_path.display()))?;
                if !quiet {
                    eprintln!(
                        "wrote Time Machine index ({n} indicators) -> {}",
                        index_path.display()
                    );
                }
            }
            Ok(())
        }
        Command::Rescan {
            indices,
            threat_feed,
            json,
            include_known,
        } => {
            if indices.is_empty() {
                return Err(anyhow!("rescan needs at least one capture-index file"));
            }
            let feed = ppcap_core::ThreatFeed::load(&threat_feed)
                .with_context(|| format!("load threat feed {}", threat_feed.display()))?;

            let mut loaded = Vec::with_capacity(indices.len());
            for p in &indices {
                let text = std::fs::read_to_string(p)
                    .with_context(|| format!("read capture index {}", p.display()))?;
                let idx = ppcap_core::CaptureIndex::from_json_str(&text)
                    .with_context(|| format!("parse capture index {}", p.display()))?;
                loaded.push(idx);
            }

            let report = ppcap_core::rescan(&loaded, &feed);

            // Human summary → stderr.
            eprintln!(
                "rescan: {} indices, {} indicators evaluated — {} newly flagged, {} already known",
                report.indices_scanned,
                report.indicators_evaluated,
                report.newly_flagged.len(),
                report.still_flagged.len(),
            );
            for h in &report.newly_flagged {
                eprintln!(
                    "  NEW  {:<6} {}  ({}){}",
                    h.kind.as_str(),
                    h.value,
                    h.source_path,
                    h.label
                        .as_ref()
                        .map(|l| format!(" [{l}]"))
                        .unwrap_or_default(),
                );
            }
            if include_known {
                for h in &report.still_flagged {
                    eprintln!(
                        "  known {:<6} {}  ({})",
                        h.kind.as_str(),
                        h.value,
                        h.source_path
                    );
                }
            }

            if let Some(path) = json.as_deref() {
                let s = serde_json::to_string_pretty(&report)?;
                match path {
                    "-" => println!("{s}"),
                    p => std::fs::write(p, &s)
                        .with_context(|| format!("write rescan report to {p}"))?,
                }
            }
            Ok(())
        }
        Command::Gen {
            output,
            scenario,
            packets,
            seed,
            pcapng,
            edge_cases,
            hosts,
        } => {
            // IMPL:
            //  - let sc = ppcap_core::gen::Scenario::from_str_opt(&scenario)
            //        .ok_or_else(|| anyhow!("unknown scenario: {scenario}"))?;
            //  - Build GenConfig { scenario: sc, packets, seed, link_type: Ethernet,
            //        pcapng, include_edge_cases: edge_cases, ..Default::default() }.
            //  - let mut g = SynthGen::new(cfg);
            //  - let manifest = g.write_pcap(&output)?;  (PpError -> anyhow)
            //  - eprintln a one-line summary (packets_written, bytes_written, distinct_flows).
            use ppcap_core::gen::{GenConfig, Scenario, SynthGen};

            let sc = Scenario::from_str_opt(&scenario)
                .ok_or_else(|| anyhow!("unknown scenario: {scenario}"))?;
            let cfg = GenConfig {
                scenario: sc,
                packets,
                seed,
                pcapng,
                include_edge_cases: edge_cases,
                host_count: hosts,
                ..Default::default()
            };
            let mut g = SynthGen::new(cfg);
            let manifest = g
                .write_pcap(&output)
                .with_context(|| format!("write synthetic capture to {}", output.display()))?;
            eprintln!(
                "generated {} packets, {} bytes, {} distinct flows -> {}",
                manifest.packets_written,
                manifest.bytes_written,
                manifest.distinct_flows,
                output.display()
            );
            Ok(())
        }
        Command::InitDb { out, case_dir } => {
            // IMPL:
            //  - let ddl = match case_dir { Some(d) => DUCKDB_SCHEMA.replace("{CASE_DIR}", &d),
            //        None => DUCKDB_SCHEMA.to_string() };
            //  - match out { Some(p) => std::fs::write(&p, ddl) with anyhow context,
            //        None => print!("{ddl}") to stdout }.
            //  This path links NO DuckDB; it only emits text.
            let ddl = match case_dir {
                Some(d) => DUCKDB_SCHEMA.replace("{CASE_DIR}", &d),
                None => DUCKDB_SCHEMA.to_string(),
            };
            match out {
                Some(p) => {
                    std::fs::write(&p, ddl)
                        .with_context(|| format!("write DDL to {}", p.display()))?;
                }
                None => {
                    print!("{ddl}");
                }
            }
            Ok(())
        }
    }
}

/// FNV-1a 64-bit hash of a byte slice. Used to derive a stable, non-zero capture id from the
/// input path so distinct captures get distinct ids in the Parquet footer.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

#[cfg(test)]
mod reputation_cli_tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn reputation_flag_parses() {
        let cli = Cli::try_parse_from(["ppcap", "analyze", "x.pcap", "--reputation"]).unwrap();
        match cli.command {
            Command::Analyze { reputation, .. } => assert!(reputation),
            _ => panic!("expected Analyze"),
        }
    }

    #[test]
    fn reputation_defaults_off() {
        let cli = Cli::try_parse_from(["ppcap", "analyze", "x.pcap"]).unwrap();
        match cli.command {
            Command::Analyze { reputation, .. } => assert!(!reputation),
            _ => panic!("expected Analyze"),
        }
    }

    #[test]
    fn rules_flag_parses() {
        let cli =
            Cli::try_parse_from(["ppcap", "analyze", "x.pcap", "--rules", "r.rules"]).unwrap();
        match cli.command {
            Command::Analyze { rules, .. } => {
                assert_eq!(rules.as_deref(), Some(std::path::Path::new("r.rules")))
            }
            _ => panic!("expected Analyze"),
        }
    }

    #[test]
    fn analyze_index_flag_parses() {
        let cli = Cli::try_parse_from(["ppcap", "analyze", "x.pcap", "--index", "cap.index.json"])
            .unwrap();
        match cli.command {
            Command::Analyze { index, .. } => {
                assert_eq!(
                    index.as_deref(),
                    Some(std::path::Path::new("cap.index.json"))
                )
            }
            _ => panic!("expected Analyze"),
        }
    }

    #[test]
    fn rescan_parses_indices_and_feed() {
        let cli = Cli::try_parse_from([
            "ppcap",
            "rescan",
            "a.index.json",
            "b.index.json",
            "--threat-feed",
            "feed.json",
            "--json",
            "-",
        ])
        .unwrap();
        match cli.command {
            Command::Rescan {
                indices,
                threat_feed,
                json,
                include_known,
            } => {
                assert_eq!(indices.len(), 2);
                assert_eq!(threat_feed, std::path::Path::new("feed.json"));
                assert_eq!(json.as_deref(), Some("-"));
                assert!(!include_known);
            }
            _ => panic!("expected Rescan"),
        }
    }

    #[test]
    fn rescan_requires_a_feed() {
        // Missing the required --threat-feed → clap parse error.
        assert!(Cli::try_parse_from(["ppcap", "rescan", "a.index.json"]).is_err());
    }
}
