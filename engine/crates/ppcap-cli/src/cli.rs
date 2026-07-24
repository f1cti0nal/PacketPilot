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
// The `Analyze` variant intentionally carries every analyze flag as a field (clap ergonomics);
// it dwarfs `Gen`/`InitDb`, but boxing clap-derive fields is awkward and this enum is only ever
// held briefly on the stack during dispatch.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Analyze a pcap/pcapng (optionally .gz): summary JSON (+ optional flows Parquet).
    ///
    /// Batch mode: pass `--batch <DIR>` (instead of a single `input`) to triage a *folder* of
    /// captures into one case directory + a ranked `case.json` / `case.html` with cross-capture
    /// indicator correlation.
    Analyze {
        /// Input capture path (.pcap / .pcapng, optionally .gz). Omit when using `--batch`.
        input: Option<PathBuf>,
        /// Batch mode: analyze every capture under this directory (mutually exclusive with `input`).
        #[arg(long, conflicts_with = "input")]
        batch: Option<PathBuf>,
        /// Batch mode: recurse into subdirectories when discovering captures.
        #[arg(long)]
        recursive: bool,
        /// Batch mode: case output root (holds `parquet/`, `captures/`, `case.json`, `case.html`).
        /// Defaults to `./case`.
        #[arg(long = "case-out")]
        case_out: Option<PathBuf>,
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
        /// Behavioral Baseline: compare this capture's per-host egress against a saved baseline
        /// JSON and raise deviation findings (read-only; findings appear in --json/--html/--csv).
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Behavioral Baseline: learn/merge this capture into the baseline JSON at this path,
        /// creating it if absent (a sidecar side-channel, like --index).
        #[arg(long = "update-baseline")]
        update_baseline: Option<PathBuf>,
        /// Predictive Anomaly Detection: disable the per-host traffic forecaster. It is ON by
        /// default (single-capture, no sidecar), raising `traffic_anomaly` findings for hosts whose
        /// volume departed from their own one-step forecast; pass this to skip that stage.
        #[arg(long = "no-forecast")]
        no_forecast: bool,
        /// Predictive Anomaly Detection: forecaster sensitivity — the prediction-band half-width in
        /// residual σ (default 4.0). A bin flags when it lands more than this many σ off its
        /// one-step forecast, so a *lower* value is more sensitive (more findings). Must be > 0.
        #[arg(long = "forecast-z", value_parser = parse_forecast_z)]
        forecast_z: Option<f64>,
        /// Predictive Anomaly Detection: warm-up length — leading bins folded into the forecaster
        /// before its band is trusted (default 8). Lower surfaces anomalies earlier in short
        /// captures at the cost of a colder, noisier band.
        #[arg(long = "forecast-min-bins")]
        forecast_min_bins: Option<usize>,
        /// Evidence mode: write a sealed chain-of-custody manifest here after the run — the
        /// input's SHA-256, every produced artifact's SHA-256 + size, the tool version and
        /// effective settings, all made tamper-evident by a seal. Verify later with
        /// `ppcap verify <manifest>`.
        #[arg(long)]
        evidence: Option<PathBuf>,
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
    /// Behavioral Baseline: inspect or combine per-host baseline profile sidecars.
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },
    /// Smart Alerting: re-derive and print the ranked alert queue of an analyzed capture
    /// (a pure, re-analysis-free transform over an `analyze --json` output).
    Alerts {
        /// The analysis-output JSON (from `analyze --json`).
        summary: PathBuf,
        /// Diff mode: an OLDER analysis of the same network to compare against — reports
        /// new / resolved / changed stories matched by their stable alert ids.
        #[arg(long)]
        diff: Option<PathBuf>,
        /// Write JSON here ("-" => stdout): the updated analysis, or with `--diff` the
        /// AlertDiff report.
        #[arg(long)]
        json: Option<String>,
    },
    /// Evidence: verify a sealed chain-of-custody manifest — recompute the seal, then re-hash
    /// the source capture and every recorded artifact, reporting intact / missing / modified.
    Verify {
        /// The evidence manifest JSON (from `analyze --evidence`). Relative artifact paths
        /// resolve against this file's directory, so a bundle moved whole stays verifiable.
        manifest: PathBuf,
        /// Write the machine-readable verification report here; "-" => stdout.
        #[arg(long)]
        json: Option<String>,
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
    /// Safe Share: write a sanitized/anonymized copy of a capture for safe sharing.
    Sanitize {
        /// Input capture path (.pcap / .pcapng, optionally .gz).
        input: PathBuf,
        /// Sanitized capture output path (.pcapng extension => pcapng, else classic pcap).
        #[arg(long)]
        out: PathBuf,
        /// Manifest sidecar path (default: "<out>.manifest.json").
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Payload policy: scrub (zero all payload bytes; default) or keep
        /// (retain payloads; sensitive L7 fields are still redacted).
        #[arg(long, default_value = "scrub")]
        payload: String,
        /// In scrub mode, retain the first N payload bytes per packet for protocol ID.
        #[arg(long, default_value_t = 0)]
        keep_first: usize,
        /// Disable prefix-preserving address mapping (use a flat per-block permutation).
        #[arg(long)]
        no_preserve_prefix: bool,
        /// Keep the vendor OUI (first 3 bytes) of pseudonymized MAC addresses.
        #[arg(long)]
        preserve_oui: bool,
        /// Disable L7 redaction (DNS names / HTTP fields / TLS SNI / credentials).
        #[arg(long)]
        no_redact: bool,
        /// Shift every timestamp by this many seconds (blunts timing correlation).
        #[arg(long, default_value_t = 0)]
        time_shift: i64,
        /// Force pcapng output regardless of the --out extension.
        #[arg(long)]
        pcapng: bool,
        /// Suppress stderr progress.
        #[arg(long)]
        quiet: bool,
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

/// `ppcap baseline` sub-actions: pure transforms over baseline profile sidecars.
#[derive(Subcommand, Debug)]
pub enum BaselineAction {
    /// Print a human summary of a baseline profile to stderr (+ optional --json to a path/stdout).
    Show {
        /// The baseline profile JSON to inspect.
        baseline: PathBuf,
        /// Also write the profile JSON here; "-" or omitted => stderr summary only.
        #[arg(long)]
        json: Option<String>,
    },
    /// Merge two or more baseline profiles into one (folding per-host running statistics).
    Merge {
        /// The baseline profile JSON files to merge (at least two).
        baselines: Vec<PathBuf>,
        /// Output path for the merged baseline; "-" or omitted => stdout.
        #[arg(long)]
        out: Option<String>,
    },
    /// Build a baseline by folding one or more analyzed captures (each an `analyze --json` output
    /// carrying a per-host snapshot, i.e. produced with `--update-baseline`/`--baseline`).
    Build {
        /// Analysis-output JSON files to fold in.
        summaries: Vec<PathBuf>,
        /// Output path for the baseline; "-" or omitted => stdout.
        #[arg(long)]
        out: Option<String>,
    },
    /// Compare an analyzed capture against a baseline and report the per-host deviations (a
    /// re-analysis-free `analyze --baseline`).
    Diff {
        /// The reference baseline profile JSON.
        baseline: PathBuf,
        /// The analysis-output JSON to compare (must carry a per-host snapshot).
        summary: PathBuf,
        /// Write the full deviation report here; "-" or omitted => human summary to stderr only.
        #[arg(long)]
        json: Option<String>,
    },
}

/// Embedded DuckDB DDL (shipped so the sidecar/Wasm can create the schema without the repo).
const DUCKDB_SCHEMA: &str = include_str!("../../ppcap-core/sql/schema.sql");

/// The Smart Alerting stderr one-liner: `alerts: 6 from 41 findings — 1 act-now, 2 investigate,
/// 3 review; top: "…"`. Shared by `analyze` (after all post-hoc passes) and `ppcap alerts`.
fn alerts_summary_line(summary: &ppcap_core::Summary) -> String {
    use ppcap_core::PriorityBand;
    let count = |b: PriorityBand| summary.alerts.iter().filter(|a| a.band == b).count();
    format!(
        "alerts: {} from {} findings — {} act-now, {} investigate, {} review; top: \"{}\"",
        summary.alerts.len(),
        summary.findings.len(),
        count(PriorityBand::ActNow),
        count(PriorityBand::Investigate),
        count(PriorityBand::Review),
        summary
            .alerts
            .first()
            .map(|a| a.title.as_str())
            .unwrap_or(""),
    )
}

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
            batch,
            recursive,
            case_out,
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
            baseline,
            update_baseline,
            no_forecast,
            forecast_z,
            forecast_min_bins,
            evidence,
        } => {
            // Batch / case mode: fan the pipeline over a folder into a ranked case index. Single-
            // capture output flags (--json/--html/--parquet/--csv/--stix/--rules/--reputation) do
            // not apply here; the case artifacts live under --case-out.
            if let Some(dir) = batch.as_ref() {
                return dispatch_batch(
                    dir,
                    recursive,
                    case_out.as_deref(),
                    threat_feed.as_deref(),
                    hash,
                    strict,
                    quiet,
                );
            }

            let input = input
                .ok_or_else(|| anyhow!("analyze needs an input capture path or --batch <DIR>"))?;
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
                // Behavioral Baseline: compare against a saved profile, and/or snapshot this
                // capture's per-host egress so it can be folded into a baseline after the run.
                baseline_in: baseline.clone(),
                update_baseline: update_baseline.is_some(),
                // Predictive Anomaly Detection: on by default (single-capture, no sidecar); the
                // `--no-forecast` flag opts out. `--forecast-z` / `--forecast-min-bins` optionally
                // override the sensitivity knobs; every other threshold stays default.
                forecast: ppcap_core::ForecastParams {
                    enabled: !no_forecast,
                    z: forecast_z.unwrap_or(ppcap_core::ForecastParams::default().z),
                    min_bins: forecast_min_bins
                        .unwrap_or(ppcap_core::ForecastParams::default().min_bins),
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

            if baseline.is_some() && !quiet {
                let n = out
                    .summary
                    .findings
                    .iter()
                    .filter(|f| f.kind == ppcap_core::FindingKind::BaselineDeviation)
                    .count();
                eprintln!(
                    "baseline: {n} host deviation{} vs the saved profile",
                    if n == 1 { "" } else { "s" }
                );
            }

            if !no_forecast && !quiet {
                let n = out
                    .summary
                    .findings
                    .iter()
                    .filter(|f| f.kind == ppcap_core::FindingKind::TrafficAnomaly)
                    .count();
                if n > 0 {
                    eprintln!(
                        "forecast: {n} predictive traffic anomal{}",
                        if n == 1 { "y" } else { "ies" }
                    );
                }
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

            if let Some(rules_path) = rules.as_ref() {
                let text = std::fs::read_to_string(rules_path)
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

            // Smart Alerting one-liner — printed after ALL summary-mutating passes (reputation,
            // rules) so the counts match the JSON that follows.
            if !quiet && !out.summary.alerts.is_empty() {
                eprintln!("{}", alerts_summary_line(&out.summary));
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

            if let Some(bpath) = update_baseline.as_ref() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                // Load the existing sidecar (create-or-merge); a missing file starts empty.
                let prior = match std::fs::read_to_string(bpath) {
                    Ok(t) => ppcap_core::BaselineProfile::from_json_str(&t)
                        .with_context(|| format!("parse baseline {}", bpath.display()))?,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        ppcap_core::BaselineProfile::new()
                    }
                    Err(e) => {
                        return Err(anyhow::Error::new(e))
                            .with_context(|| format!("read baseline {}", bpath.display()));
                    }
                };
                let params = ppcap_core::BaselineParams::default();
                let updated = ppcap_core::update_baseline(prior, &out, now, &params);
                std::fs::write(bpath, updated.to_json_pretty()?)
                    .with_context(|| format!("write baseline to {}", bpath.display()))?;
                if !quiet {
                    eprintln!(
                        "updated behavioral baseline ({} hosts, {} captures) -> {}",
                        updated.hosts.len(),
                        updated.captures_merged,
                        bpath.display()
                    );
                }
            }

            // Evidence mode: the sealed chain-of-custody manifest is assembled LAST — every
            // artifact-writing block above must precede this one so the manifest can hash the
            // final bytes of everything the run produced.
            if let Some(evidence_path) = evidence.as_ref() {
                // The reproducibility recipe: every settings flag that shapes the artifacts'
                // bytes, in CLI declaration order. Artifact PATHS live in the artifact records;
                // --reputation is recorded honestly even though its network verdicts make that
                // one pass non-reproducible offline (documented in docs/evidence-custody.md).
                let mut settings: Vec<String> = Vec::new();
                if strict {
                    settings.push("--strict".to_string());
                }
                if hash {
                    settings.push("--hash".to_string());
                }
                if let Some(p) = threat_feed.as_ref() {
                    settings.push(format!("--threat-feed {}", p.display()));
                }
                if let Some(p) = carve_dir.as_ref() {
                    settings.push(format!("--carve-dir {}", p.display()));
                }
                if reputation {
                    settings.push("--reputation".to_string());
                }
                if let Some(p) = rules.as_ref() {
                    settings.push(format!("--rules {}", p.display()));
                }
                if let Some(p) = baseline.as_ref() {
                    settings.push(format!("--baseline {}", p.display()));
                }
                if let Some(p) = update_baseline.as_ref() {
                    settings.push(format!("--update-baseline {}", p.display()));
                }
                if no_forecast {
                    settings.push("--no-forecast".to_string());
                }
                if let Some(z) = forecast_z {
                    settings.push(format!("--forecast-z {z}"));
                }
                if let Some(n) = forecast_min_bins {
                    settings.push(format!("--forecast-min-bins {n}"));
                }

                // Input hash: reuse the --hash pass's result when present, else hash now —
                // an unhashed input is not evidence.
                let (src_sha, src_bytes) = match out.source_sha256.as_ref() {
                    Some(sha) => (sha.clone(), out.source_bytes),
                    None => ppcap_core::hash_file(&input)
                        .with_context(|| format!("hash source {}", input.display()))?,
                };

                // Hash every file artifact this run wrote (stdout streams are unverifiable
                // and deliberately unrecorded).
                let mut artifacts: Vec<ppcap_core::ArtifactRecord> = Vec::new();
                let mut record = |role: &str, path: &std::path::Path| -> anyhow::Result<()> {
                    let (sha256, bytes) = ppcap_core::hash_file(path)
                        .with_context(|| format!("hash artifact {}", path.display()))?;
                    artifacts.push(ppcap_core::ArtifactRecord {
                        role: role.to_string(),
                        path: path.display().to_string(),
                        sha256,
                        bytes,
                    });
                    Ok(())
                };
                if let Some(p) = json.as_deref() {
                    if p != "-" {
                        record("summary_json", std::path::Path::new(p))?;
                    }
                }
                if let Some(p) = parquet.as_ref() {
                    record("flows_parquet", p)?;
                }
                if let Some(p) = html.as_ref() {
                    record("html_report", p)?;
                }
                if let Some(p) = csv.as_ref() {
                    record("findings_csv", p)?;
                }
                if let Some(p) = stix.as_ref() {
                    record("stix_bundle", p)?;
                }
                if let Some(p) = index.as_ref() {
                    record("capture_index", p)?;
                }
                if let Some(p) = update_baseline.as_ref() {
                    record("baseline_profile", p)?;
                }

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let mut manifest = ppcap_core::EvidenceManifest::new(
                    &out.engine_version,
                    now,
                    settings,
                    &input.display().to_string(),
                    &src_sha,
                    src_bytes,
                    &out.summary,
                    artifacts,
                );
                manifest.seal().context("seal evidence manifest")?;
                let n = manifest.artifacts.len();
                std::fs::write(evidence_path, manifest.to_json_pretty()?).with_context(|| {
                    format!("write evidence manifest to {}", evidence_path.display())
                })?;
                if !quiet {
                    let short: String = src_sha.chars().take(12).collect();
                    eprintln!(
                        "evidence: sealed manifest ({n} artifact{}, input {short}…) -> {}",
                        if n == 1 { "" } else { "s" },
                        evidence_path.display()
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
        Command::Baseline { action } => match action {
            BaselineAction::Show { baseline, json } => {
                let text = std::fs::read_to_string(&baseline)
                    .with_context(|| format!("read baseline {}", baseline.display()))?;
                let profile = ppcap_core::BaselineProfile::from_json_str(&text)
                    .with_context(|| format!("parse baseline {}", baseline.display()))?;
                eprintln!(
                    "baseline: {} hosts, {} captures merged (engine {})",
                    profile.hosts.len(),
                    profile.captures_merged,
                    profile.engine_version
                );
                for h in profile.hosts.iter().take(20) {
                    eprintln!(
                        "  {:<20} seen x{:<4} peers={:<4} ports={:<4} out~{:.0}B",
                        h.host,
                        h.captures_seen,
                        h.peers.len(),
                        h.services.len(),
                        h.bytes_out.mean
                    );
                }
                if profile.hosts.len() > 20 {
                    eprintln!("  ... and {} more hosts", profile.hosts.len() - 20);
                }
                if let Some(j) = json.as_deref() {
                    let s = profile.to_json_pretty()?;
                    match j {
                        "-" => println!("{s}"),
                        path => std::fs::write(path, &s)
                            .with_context(|| format!("write baseline JSON to {path}"))?,
                    }
                }
                Ok(())
            }
            BaselineAction::Merge { baselines, out } => {
                if baselines.len() < 2 {
                    return Err(anyhow!("baseline merge needs at least two profiles"));
                }
                let params = ppcap_core::BaselineParams::default();
                let mut acc: Option<ppcap_core::BaselineProfile> = None;
                for p in &baselines {
                    let text = std::fs::read_to_string(p)
                        .with_context(|| format!("read baseline {}", p.display()))?;
                    let profile = ppcap_core::BaselineProfile::from_json_str(&text)
                        .with_context(|| format!("parse baseline {}", p.display()))?;
                    acc = Some(match acc {
                        None => profile,
                        Some(a) => ppcap_core::merge_baselines(a, profile, &params),
                    });
                }
                let merged = acc.expect("at least two profiles were merged");
                let s = merged.to_json_pretty()?;
                match out.as_deref() {
                    None | Some("-") => println!("{s}"),
                    Some(path) => std::fs::write(path, &s)
                        .with_context(|| format!("write merged baseline to {path}"))?,
                }
                eprintln!(
                    "merged {} baselines -> {} hosts, {} captures",
                    baselines.len(),
                    merged.hosts.len(),
                    merged.captures_merged
                );
                Ok(())
            }
            BaselineAction::Build { summaries, out } => {
                if summaries.is_empty() {
                    return Err(anyhow!(
                        "baseline build needs at least one analysis-output file"
                    ));
                }
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let params = ppcap_core::BaselineParams::default();
                let mut loaded = Vec::with_capacity(summaries.len());
                for p in &summaries {
                    let text = std::fs::read_to_string(p)
                        .with_context(|| format!("read analysis output {}", p.display()))?;
                    let out_json: ppcap_core::AnalysisOutput = serde_json::from_str(&text)
                        .with_context(|| format!("parse analysis output {}", p.display()))?;
                    loaded.push(out_json);
                }
                let with_snapshot = loaded.iter().filter(|o| o.baseline.is_some()).count();
                let refs: Vec<&ppcap_core::AnalysisOutput> = loaded.iter().collect();
                let profile = ppcap_core::build_baseline(&refs, now, &params);
                let s = profile.to_json_pretty()?;
                match out.as_deref() {
                    None | Some("-") => println!("{s}"),
                    Some(path) => std::fs::write(path, &s)
                        .with_context(|| format!("write baseline to {path}"))?,
                }
                eprintln!(
                    "built baseline from {}/{} captures carrying a snapshot -> {} hosts",
                    with_snapshot,
                    summaries.len(),
                    profile.hosts.len()
                );
                Ok(())
            }
            BaselineAction::Diff {
                baseline,
                summary,
                json,
            } => {
                let btext = std::fs::read_to_string(&baseline)
                    .with_context(|| format!("read baseline {}", baseline.display()))?;
                let base = ppcap_core::BaselineProfile::from_json_str(&btext)
                    .with_context(|| format!("parse baseline {}", baseline.display()))?;
                let stext = std::fs::read_to_string(&summary)
                    .with_context(|| format!("read analysis output {}", summary.display()))?;
                let out_json: ppcap_core::AnalysisOutput = serde_json::from_str(&stext)
                    .with_context(|| format!("parse analysis output {}", summary.display()))?;
                // Phase the seasonal forecast on the capture's own wall-clock start when available.
                let capture_unix = out_json
                    .summary
                    .first_ts_ns
                    .map(|ns| ns.div_euclid(1_000_000_000))
                    .unwrap_or(0);
                let prof = out_json.baseline.ok_or_else(|| {
                    anyhow!(
                        "{} has no per-host snapshot (analyze with --update-baseline/--baseline)",
                        summary.display()
                    )
                })?;
                let params = ppcap_core::BaselineParams::default();
                let report =
                    ppcap_core::compare_to_baseline_at(&base, &prof, capture_unix, &params);
                eprintln!(
                    "baseline diff: {} host(s) compared, {} deviation(s)",
                    report.hosts_compared,
                    report.deviations.len()
                );
                for d in &report.deviations {
                    eprintln!("  {:<8} {}", d.severity.as_str(), d.title);
                }
                if let Some(path) = json.as_deref() {
                    let s = serde_json::to_string_pretty(&report)?;
                    match path {
                        "-" => println!("{s}"),
                        p => std::fs::write(p, &s)
                            .with_context(|| format!("write deviation report to {p}"))?,
                    }
                }
                Ok(())
            }
        },
        Command::Alerts {
            summary,
            diff,
            json,
        } => {
            let text = std::fs::read_to_string(&summary)
                .with_context(|| format!("read analysis output {}", summary.display()))?;
            let mut out: ppcap_core::AnalysisOutput = serde_json::from_str(&text)
                .with_context(|| format!("parse analysis output {}", summary.display()))?;
            // Idempotent pure re-derive over the loaded summary (same fn as the analyze seam).
            out.summary.alerts = ppcap_core::derive_alerts(&out.summary);

            // Diff mode: compare against an OLDER analysis, matched by stable alert ids.
            if let Some(old_path) = diff.as_ref() {
                let old_text = std::fs::read_to_string(old_path)
                    .with_context(|| format!("read older analysis {}", old_path.display()))?;
                let mut old: ppcap_core::AnalysisOutput = serde_json::from_str(&old_text)
                    .with_context(|| format!("parse older analysis {}", old_path.display()))?;
                // Re-derive on the old side too, so pre-alerting summaries diff correctly.
                old.summary.alerts = ppcap_core::derive_alerts(&old.summary);
                let d = ppcap_core::diff_alerts(&old.summary.alerts, &out.summary.alerts);
                eprintln!(
                    "alert diff: {} new, {} resolved, {} changed, {} unchanged (old: {} alerts, new: {})",
                    d.new_alerts.len(),
                    d.resolved.len(),
                    d.changed.len(),
                    d.unchanged,
                    old.summary.alerts.len(),
                    out.summary.alerts.len(),
                );
                for e in &d.new_alerts {
                    eprintln!(
                        "  NEW      [{:<11} {:>3}/100] {}",
                        e.band.as_str(),
                        e.priority,
                        e.title
                    );
                }
                for e in &d.resolved {
                    eprintln!(
                        "  RESOLVED [{:<11} {:>3}/100] {}",
                        e.band.as_str(),
                        e.priority,
                        e.title
                    );
                }
                for c in &d.changed {
                    eprintln!(
                        "  CHANGED  [{}→{} {:+}] {}",
                        c.before_band.as_str(),
                        c.after_band.as_str(),
                        c.delta,
                        c.title
                    );
                }
                if let Some(path) = json.as_deref() {
                    let s = serde_json::to_string_pretty(&d)?;
                    match path {
                        "-" => println!("{s}"),
                        p => std::fs::write(p, &s)
                            .with_context(|| format!("write alert diff to {p}"))?,
                    }
                }
                return Ok(());
            }
            if out.summary.alerts.is_empty() {
                eprintln!("alerts: none — no findings rose above informational");
            } else {
                eprintln!("{}", alerts_summary_line(&out.summary));
                for (i, a) in out.summary.alerts.iter().enumerate() {
                    eprintln!(
                        "  {:>2}. [{:<11} {:>3}/100 conf {:>3}%] {}",
                        i + 1,
                        a.band.as_str(),
                        a.priority,
                        a.confidence,
                        a.title,
                    );
                    eprintln!("      do: {}", a.action);
                }
            }
            if let Some(path) = json.as_deref() {
                let s = out.to_json_pretty()?;
                match path {
                    "-" => println!("{s}"),
                    p => std::fs::write(p, &s)
                        .with_context(|| format!("write updated analysis JSON to {p}"))?,
                }
            }
            Ok(())
        }
        Command::Verify { manifest, json } => {
            let text = std::fs::read_to_string(&manifest)
                .with_context(|| format!("read evidence manifest {}", manifest.display()))?;
            let m = ppcap_core::EvidenceManifest::from_json_str(&text)
                .with_context(|| format!("parse evidence manifest {}", manifest.display()))?;
            // Relative recorded paths resolve against the manifest's own directory.
            let dir = manifest
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map(std::path::Path::to_path_buf)
                .unwrap_or_else(|| std::path::PathBuf::from("."));
            let report = ppcap_core::verify_manifest(&m, &dir);

            let outcome_word = |o: &ppcap_core::VerifyOutcome| match o {
                ppcap_core::VerifyOutcome::Ok => "OK",
                ppcap_core::VerifyOutcome::Missing => "MISSING",
                ppcap_core::VerifyOutcome::HashMismatch => "MODIFIED (hash mismatch)",
                ppcap_core::VerifyOutcome::SizeMismatch => "MODIFIED (size mismatch)",
            };
            eprintln!(
                "seal: {} (schema v{}, {} {}, created @{})",
                if report.seal_ok {
                    "OK"
                } else {
                    "BROKEN — the manifest itself was edited after sealing"
                },
                m.schema_version,
                m.tool,
                m.engine_version,
                m.created_unix_secs,
            );
            let short: String = report.source.record.sha256.chars().take(12).collect();
            eprintln!(
                "source: {:<24} {} ({} bytes, sha256 {short}…)",
                outcome_word(&report.source.outcome),
                report.source.record.path,
                report.source.record.bytes,
            );
            for a in &report.artifacts {
                eprintln!(
                    "{}: {:<24} {}",
                    a.record.role,
                    outcome_word(&a.outcome),
                    a.record.path,
                );
            }

            if let Some(path) = json.as_deref() {
                let s = serde_json::to_string_pretty(&report)?;
                match path {
                    "-" => println!("{s}"),
                    p => std::fs::write(p, &s)
                        .with_context(|| format!("write verification report to {p}"))?,
                }
            }

            let total = report.artifacts.len() + 1; // + source
            if report.all_ok() {
                eprintln!("verify: all {total} files intact");
                Ok(())
            } else {
                Err(anyhow!(
                    "verify: {} of {total} files failed{}",
                    report.failed_count(),
                    if report.seal_ok {
                        ""
                    } else {
                        " (and the seal is broken)"
                    }
                ))
            }
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
        Command::Sanitize {
            input,
            out,
            manifest,
            payload,
            keep_first,
            no_preserve_prefix,
            preserve_oui,
            no_redact,
            time_shift,
            pcapng,
            quiet,
        } => {
            use std::io::Write as _;

            let payload_mode = match payload.as_str() {
                "scrub" => ppcap_core::PayloadMode::Scrub,
                "keep" => ppcap_core::PayloadMode::Keep,
                other => return Err(anyhow!("unknown payload mode: {other} (scrub | keep)")),
            };
            let format = if pcapng
                || out
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("pcapng"))
            {
                ppcap_core::SanitizeFormat::PcapNg
            } else {
                ppcap_core::SanitizeFormat::Pcap
            };
            let opts = ppcap_core::SanitizeOptions {
                payload: payload_mode,
                keep_first,
                preserve_prefix: !no_preserve_prefix,
                preserve_oui,
                redact_l7: !no_redact,
                time_shift_secs: time_shift,
                format,
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);

            let mut last_tick: u64 = 0;
            let progress = |pkts: u64, bytes: u64, size_hint: Option<u64>| {
                if quiet || pkts == last_tick {
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

            let m =
                ppcap_core::sanitize_file(&input, &out, manifest.as_deref(), &opts, now, progress)
                    .with_context(|| {
                        format!("sanitize {} -> {}", input.display(), out.display())
                    })?;

            if !quiet {
                let _ = writeln!(std::io::stderr());
                eprintln!(
                    "sanitized {} packets -> {} ({} IPv4 / {} IPv6 / {} MAC pseudonyms, \
                     {} DNS names, {} HTTP fields, {} SNI, {} credentials redacted, \
                     {} payload bytes scrubbed)",
                    m.counts.packets_written,
                    out.display(),
                    m.counts.unique_ipv4,
                    m.counts.unique_ipv6,
                    m.counts.unique_macs,
                    m.counts.dns_names_redacted,
                    m.counts.http_fields_redacted,
                    m.counts.tls_snis_redacted,
                    m.counts.credentials_redacted,
                    m.counts.payload_bytes_scrubbed,
                );
            }
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

/// Batch / case triage dispatch: analyze every capture under `dir` into a case directory and
/// write `case.json` + `case.html`. Per-capture errors are skipped (recorded in the index) unless
/// `strict`. Progress is one line per capture on stderr unless `quiet`.
fn dispatch_batch(
    dir: &std::path::Path,
    recursive: bool,
    case_out: Option<&std::path::Path>,
    threat_feed: Option<&std::path::Path>,
    hash: bool,
    strict: bool,
    quiet: bool,
) -> anyhow::Result<()> {
    use std::io::Write as _;

    let case_out = case_out
        .unwrap_or_else(|| std::path::Path::new("case"))
        .to_path_buf();

    let case_cfg = ppcap_core::CaseConfig {
        case_out: case_out.clone(),
        recursive,
        strict,
        per_capture_html: true,
    };
    // Per-capture base pipeline: same detection/enrichment as a single-capture run. `hash_source`
    // carries each capture's SHA-256 into its summary JSON (useful case provenance).
    let base = ppcap_core::PipelineConfig {
        hash_source: hash,
        threat_feed: threat_feed.map(|p| p.to_path_buf()),
        ..Default::default()
    };

    let generated = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let on_capture = |idx: usize, total: usize, path: &std::path::Path| {
        if !quiet {
            let mut err = std::io::stderr();
            let _ = writeln!(err, "[{}/{}] {}", idx + 1, total, path.display());
        }
    };

    let case = ppcap_core::run_case(dir, &case_cfg, &base, generated, on_capture)?;

    // Case-level artifacts (pure serializations of the returned summary).
    std::fs::create_dir_all(&case_out)
        .with_context(|| format!("create case dir {}", case_out.display()))?;
    let case_json = case_out.join("case.json");
    std::fs::write(&case_json, case.to_json_pretty()?)
        .with_context(|| format!("write {}", case_json.display()))?;
    let case_html = case_out.join("case.html");
    std::fs::write(&case_html, ppcap_core::case_html(&case, generated))
        .with_context(|| format!("write {}", case_html.display()))?;

    if !quiet {
        eprintln!(
            "case: {} captures ({} error), {} shared indicators -> {}",
            case.total_captures,
            case.error_captures,
            case.shared_indicators.len(),
            case_out.display()
        );
        if !case.case_alerts.is_empty() {
            use ppcap_core::PriorityBand;
            let count = |b: PriorityBand| case.case_alerts.iter().filter(|a| a.band == b).count();
            eprintln!(
                "case alerts: {} across {} captures — {} act-now, {} investigate; top: \"{}\"",
                case.total_case_alerts,
                case.total_captures,
                count(PriorityBand::ActNow),
                count(PriorityBand::Investigate),
                case.case_alerts[0].title,
            );
        }
    }
    Ok(())
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

/// Parse+validate `--forecast-z`: the prediction-band half-width must be a finite, strictly
/// positive number (a `z <= 0` band would flag every bin; `NaN`/`inf` never would).
fn parse_forecast_z(s: &str) -> Result<f64, String> {
    let z: f64 = s.parse().map_err(|_| format!("`{s}` is not a number"))?;
    if !z.is_finite() || z <= 0.0 {
        return Err(format!("forecast-z must be a positive number, got `{s}`"));
    }
    Ok(z)
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
    fn sanitize_parses_with_defaults() {
        let cli =
            Cli::try_parse_from(["ppcap", "sanitize", "in.pcap", "--out", "out.pcap"]).unwrap();
        match cli.command {
            Command::Sanitize {
                payload,
                keep_first,
                no_preserve_prefix,
                preserve_oui,
                no_redact,
                time_shift,
                pcapng,
                ..
            } => {
                assert_eq!(payload, "scrub");
                assert_eq!(keep_first, 0);
                assert!(!no_preserve_prefix);
                assert!(!preserve_oui);
                assert!(!no_redact);
                assert_eq!(time_shift, 0);
                assert!(!pcapng);
            }
            _ => panic!("expected Sanitize"),
        }
    }

    #[test]
    fn sanitize_rejects_bad_payload_mode() {
        let cli = Cli::try_parse_from([
            "ppcap",
            "sanitize",
            "in.pcap",
            "--out",
            "o.pcap",
            "--payload",
            "nope",
        ])
        .unwrap();
        assert!(dispatch(cli).is_err());
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
    fn analyze_no_forecast_flag_parses() {
        // Default: forecast on (the flag is absent).
        let on = Cli::try_parse_from(["ppcap", "analyze", "x.pcap"]).unwrap();
        match on.command {
            Command::Analyze { no_forecast, .. } => assert!(!no_forecast),
            _ => panic!("expected Analyze"),
        }
        // Opt out.
        let off = Cli::try_parse_from(["ppcap", "analyze", "x.pcap", "--no-forecast"]).unwrap();
        match off.command {
            Command::Analyze { no_forecast, .. } => assert!(no_forecast),
            _ => panic!("expected Analyze"),
        }
    }

    #[test]
    fn analyze_forecast_sensitivity_flags_parse() {
        // Absent → None (defaults are applied downstream).
        let bare = Cli::try_parse_from(["ppcap", "analyze", "x.pcap"]).unwrap();
        match bare.command {
            Command::Analyze {
                forecast_z,
                forecast_min_bins,
                ..
            } => {
                assert_eq!(forecast_z, None);
                assert_eq!(forecast_min_bins, None);
            }
            _ => panic!("expected Analyze"),
        }
        // Provided → parsed through.
        let tuned = Cli::try_parse_from([
            "ppcap",
            "analyze",
            "x.pcap",
            "--forecast-z",
            "2.5",
            "--forecast-min-bins",
            "4",
        ])
        .unwrap();
        match tuned.command {
            Command::Analyze {
                forecast_z,
                forecast_min_bins,
                ..
            } => {
                assert_eq!(forecast_z, Some(2.5));
                assert_eq!(forecast_min_bins, Some(4));
            }
            _ => panic!("expected Analyze"),
        }
    }

    #[test]
    fn analyze_forecast_z_rejects_non_positive_and_nonfinite() {
        for bad in ["0", "-1", "-0.5", "nan", "inf", "abc"] {
            assert!(
                Cli::try_parse_from(["ppcap", "analyze", "x.pcap", "--forecast-z", bad]).is_err(),
                "forecast-z `{bad}` must be rejected",
            );
        }
        // A sane positive value is accepted.
        assert!(Cli::try_parse_from(["ppcap", "analyze", "x.pcap", "--forecast-z", "3.5"]).is_ok(),);
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
    fn alerts_subcommand_parses() {
        let cli = Cli::try_parse_from(["ppcap", "alerts", "out.json", "--json", "-"]).unwrap();
        match cli.command {
            Command::Alerts {
                summary,
                diff,
                json,
            } => {
                assert_eq!(summary, std::path::PathBuf::from("out.json"));
                assert_eq!(diff, None);
                assert_eq!(json.as_deref(), Some("-"));
            }
            _ => panic!("expected Alerts"),
        }
    }

    #[test]
    fn alerts_diff_reports_new_and_changed() {
        // Two hand-built analyses of the "same network": the old one has a Medium beacon on
        // one host; the new one has that host climbing plus a brand-new story. The diff must
        // report one CHANGED and one NEW, and --json must emit the AlertDiff report.
        let mk = |hosts: &[(&str, u16)]| -> ppcap_core::AnalysisOutput {
            let mut summary = ppcap_core::Summary::empty();
            summary.findings = hosts
                .iter()
                .map(|(host, score)| ppcap_core::Finding {
                    kind: ppcap_core::FindingKind::Beacon,
                    severity: ppcap_core::Severity::from_score(*score),
                    score: *score,
                    title: format!("beacon: {host}"),
                    src_ip: host.to_string(),
                    dst_ip: Some("45.77.13.37".to_string()),
                    dst_port: Some(443),
                    attack: vec!["T1071".to_string()],
                    evidence: vec!["periodic callbacks".to_string()],
                    interval_ns: None,
                    jitter_cv: None,
                    contacts: None,
                    first_seen_ns: Some(1_000_000_000),
                    last_seen_ns: Some(2_000_000_000),
                    victims: Vec::new(),
                })
                .collect();
            ppcap_core::AnalysisOutput {
                schema_version: 1,
                engine_version: "0.0.0".to_string(),
                source_path: "t.pcap".to_string(),
                source_sha256: None,
                source_bytes: 0,
                link_type: "EN10MB".to_string(),
                summary,
                flows_parquet_path: None,
                elapsed_ms: 0,
                baseline: None,
            }
        };
        let old_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            old_file.path(),
            mk(&[("10.0.0.1", 45)]).to_json_pretty().unwrap(),
        )
        .unwrap();
        let new_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            new_file.path(),
            mk(&[("10.0.0.1", 70), ("10.0.0.2", 45)])
                .to_json_pretty()
                .unwrap(),
        )
        .unwrap();
        let report_file = tempfile::NamedTempFile::new().unwrap();
        let cli = Cli::try_parse_from([
            "ppcap",
            "alerts",
            new_file.path().to_str().unwrap(),
            "--diff",
            old_file.path().to_str().unwrap(),
            "--json",
            report_file.path().to_str().unwrap(),
        ])
        .unwrap();
        dispatch(cli).unwrap();
        let d: ppcap_core::AlertDiff =
            serde_json::from_str(&std::fs::read_to_string(report_file.path()).unwrap()).unwrap();
        assert_eq!(d.new_alerts.len(), 1);
        assert_eq!(d.new_alerts[0].actor, "10.0.0.2");
        assert_eq!(d.changed.len(), 1);
        assert!(d.changed[0].delta > 0);
        assert_eq!(d.resolved.len(), 0);
    }

    #[test]
    fn alerts_subcommand_rederives_and_writes_json() {
        // A minimal analysis output with one High beacon finding: the pure transform must
        // derive a non-empty queue and write the updated JSON.
        let mut summary = ppcap_core::Summary::empty();
        summary.findings = vec![ppcap_core::Finding {
            kind: ppcap_core::FindingKind::Beacon,
            severity: ppcap_core::Severity::High,
            score: 70,
            title: "beacon".to_string(),
            src_ip: "10.0.0.9".to_string(),
            dst_ip: Some("45.77.13.37".to_string()),
            dst_port: Some(443),
            attack: vec!["T1071".to_string()],
            evidence: vec!["periodic callbacks".to_string()],
            interval_ns: None,
            jitter_cv: None,
            contacts: None,
            first_seen_ns: None,
            last_seen_ns: None,
            victims: Vec::new(),
        }];
        let out = ppcap_core::AnalysisOutput {
            schema_version: 1,
            engine_version: "0.0.0".to_string(),
            source_path: "t.pcap".to_string(),
            source_sha256: None,
            source_bytes: 0,
            link_type: "EN10MB".to_string(),
            summary,
            flows_parquet_path: None,
            elapsed_ms: 0,
            baseline: None,
        };
        let input = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(input.path(), out.to_json_pretty().unwrap()).unwrap();
        let output = tempfile::NamedTempFile::new().unwrap();
        let cli = Cli::try_parse_from([
            "ppcap",
            "alerts",
            input.path().to_str().unwrap(),
            "--json",
            output.path().to_str().unwrap(),
        ])
        .unwrap();
        dispatch(cli).unwrap();
        let updated: ppcap_core::AnalysisOutput =
            serde_json::from_str(&std::fs::read_to_string(output.path()).unwrap()).unwrap();
        assert!(!updated.summary.alerts.is_empty());
        assert_eq!(updated.summary.alerts[0].actor, "10.0.0.9");
    }

    #[test]
    fn evidence_flag_and_verify_subcommand_parse() {
        let cli = Cli::try_parse_from([
            "ppcap",
            "analyze",
            "x.pcap",
            "--evidence",
            "case.evidence.json",
        ])
        .unwrap();
        match cli.command {
            Command::Analyze { evidence, .. } => {
                assert_eq!(
                    evidence.as_deref(),
                    Some(std::path::Path::new("case.evidence.json"))
                );
            }
            _ => panic!("expected Analyze"),
        }
        let cli =
            Cli::try_parse_from(["ppcap", "verify", "case.evidence.json", "--json", "-"]).unwrap();
        match cli.command {
            Command::Verify { manifest, json } => {
                assert_eq!(manifest, std::path::PathBuf::from("case.evidence.json"));
                assert_eq!(json.as_deref(), Some("-"));
            }
            _ => panic!("expected Verify"),
        }
    }

    #[test]
    fn analyze_evidence_then_verify_roundtrip_and_tamper_detection() {
        // gen a small capture -> analyze with --json/--html/--evidence -> verify OK ->
        // tamper the HTML -> verify fails. All inside one tempdir with RELATIVE artifact
        // paths, proving the moved-bundle resolution too.
        let dir = tempfile::tempdir().unwrap();
        let old_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let run = (|| -> anyhow::Result<()> {
            let gen = Cli::try_parse_from([
                "ppcap",
                "gen",
                "in.pcap",
                "--scenario",
                "beacon",
                "--packets",
                "2000",
            ])
            .unwrap();
            dispatch(gen)?;
            let analyze = Cli::try_parse_from([
                "ppcap",
                "analyze",
                "in.pcap",
                "--json",
                "out.json",
                "--html",
                "report.html",
                "--evidence",
                "case.evidence.json",
                "--quiet",
            ])
            .unwrap();
            dispatch(analyze)?;

            // The manifest exists, is sealed, and records the two file artifacts.
            let text = std::fs::read_to_string("case.evidence.json")?;
            let m = ppcap_core::EvidenceManifest::from_json_str(&text)?;
            assert!(m.verify_seal());
            assert_eq!(m.source_sha256.len(), 64);
            let roles: Vec<&str> = m.artifacts.iter().map(|a| a.role.as_str()).collect();
            assert_eq!(roles, ["html_report", "summary_json"], "sorted by role");

            // Verify passes on the intact bundle.
            let verify = Cli::try_parse_from(["ppcap", "verify", "case.evidence.json"]).unwrap();
            dispatch(verify)?;

            // Tamper one artifact: verify must fail with a nonzero outcome.
            let mut html = std::fs::read("report.html")?;
            let last = html.len() - 1;
            html[last] ^= 0x01;
            std::fs::write("report.html", &html)?;
            let verify = Cli::try_parse_from(["ppcap", "verify", "case.evidence.json"]).unwrap();
            let err = dispatch(verify).unwrap_err();
            assert!(err.to_string().contains("files failed"), "{err}");
            Ok(())
        })();
        std::env::set_current_dir(old_cwd).unwrap();
        run.unwrap();
    }

    #[test]
    fn analyze_baseline_flags_parse() {
        let cli = Cli::try_parse_from([
            "ppcap",
            "analyze",
            "x.pcap",
            "--baseline",
            "net.baseline.json",
            "--update-baseline",
            "net.baseline.json",
        ])
        .unwrap();
        match cli.command {
            Command::Analyze {
                baseline,
                update_baseline,
                ..
            } => {
                assert_eq!(
                    baseline.as_deref(),
                    Some(std::path::Path::new("net.baseline.json"))
                );
                assert_eq!(
                    update_baseline.as_deref(),
                    Some(std::path::Path::new("net.baseline.json"))
                );
            }
            _ => panic!("expected Analyze"),
        }
    }

    #[test]
    fn baseline_show_and_merge_parse() {
        let show = Cli::try_parse_from(["ppcap", "baseline", "show", "net.baseline.json"]).unwrap();
        match show.command {
            Command::Baseline {
                action: BaselineAction::Show { baseline, json },
            } => {
                assert_eq!(baseline, std::path::Path::new("net.baseline.json"));
                assert!(json.is_none());
            }
            _ => panic!("expected Baseline::Show"),
        }
        let merge = Cli::try_parse_from([
            "ppcap", "baseline", "merge", "a.json", "b.json", "--out", "-",
        ])
        .unwrap();
        match merge.command {
            Command::Baseline {
                action: BaselineAction::Merge { baselines, out },
            } => {
                assert_eq!(baselines.len(), 2);
                assert_eq!(out.as_deref(), Some("-"));
            }
            _ => panic!("expected Baseline::Merge"),
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

    #[test]
    fn baseline_merge_and_show_dispatch() {
        // A minimal valid single-host baseline profile (schema v1).
        let mk = |sha: &str| {
            format!(
                r#"{{"schema_version":1,"engine_version":"t","captures_merged":1,"source_sha256s":["{sha}"],"first_analyzed_unix_secs":0,"last_analyzed_unix_secs":0,"first_ts_ns":0,"last_ts_ns":0,"hosts":[{{"host":"10.0.0.5","captures_seen":1,"bytes_out":{{"count":1,"mean":1000.0,"m2":0.0,"min":1000.0,"max":1000.0,"ewma":1000.0}},"bytes_in":{{"count":1,"mean":0.0,"m2":0.0,"min":0.0,"max":0.0,"ewma":0.0}},"flows":{{"count":1,"mean":1.0,"m2":0.0,"min":1.0,"max":1.0,"ewma":1.0}},"peers":[],"services":[],"first_seen_unix":0,"last_seen_unix":0}}]}}"#
            )
        };
        let a = tempfile::NamedTempFile::new().unwrap();
        let b = tempfile::NamedTempFile::new().unwrap();
        let out = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(a.path(), mk("aa")).unwrap();
        std::fs::write(b.path(), mk("bb")).unwrap();

        // `baseline merge a b --out <out>` runs the dispatch body (not just clap parsing).
        let cli = Cli::try_parse_from([
            "ppcap",
            "baseline",
            "merge",
            a.path().to_str().unwrap(),
            b.path().to_str().unwrap(),
            "--out",
            out.path().to_str().unwrap(),
        ])
        .unwrap();
        dispatch(cli).unwrap();
        let merged: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(out.path()).unwrap()).unwrap();
        assert_eq!(merged["captures_merged"], 2);
        assert_eq!(merged["hosts"][0]["captures_seen"], 2);

        // `baseline show <merged>` runs its dispatch body without error.
        let cli2 = Cli::try_parse_from(["ppcap", "baseline", "show", out.path().to_str().unwrap()])
            .unwrap();
        dispatch(cli2).unwrap();

        // `baseline merge <one>` is a usage error (needs >= 2).
        let one = Cli::try_parse_from(["ppcap", "baseline", "merge", a.path().to_str().unwrap()])
            .unwrap();
        assert!(dispatch(one).is_err());
    }

    #[test]
    fn baseline_build_and_diff_dispatch() {
        // An analysis output carrying a per-host egress snapshot (as `--update-baseline` emits).
        let out = ppcap_core::AnalysisOutput {
            engine_version: "t".to_string(),
            baseline: Some(ppcap_core::CaptureProfile {
                hosts: vec![ppcap_core::HostObservation {
                    host: "10.0.0.5".to_string(),
                    bytes_out: 1000,
                    bytes_in: 100,
                    flows: 1,
                    peers: vec!["203.0.113.7".to_string()],
                    services: vec![443],
                    ..Default::default()
                }],
            }),
            ..Default::default()
        };
        let sfile = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(sfile.path(), out.to_json_pretty().unwrap()).unwrap();
        let bfile = tempfile::NamedTempFile::new().unwrap();

        // build: fold the summary into a fresh baseline.
        let cli = Cli::try_parse_from([
            "ppcap",
            "baseline",
            "build",
            sfile.path().to_str().unwrap(),
            "--out",
            bfile.path().to_str().unwrap(),
        ])
        .unwrap();
        dispatch(cli).unwrap();
        let base: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(bfile.path()).unwrap()).unwrap();
        assert_eq!(base["captures_merged"], 1);
        assert!(base["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["host"] == "10.0.0.5"));

        // diff: compare the same capture against its 1-capture baseline (warm-up not met -> 0
        // deviations, but the host is counted as compared and the report is valid JSON).
        let rep = tempfile::NamedTempFile::new().unwrap();
        let cli2 = Cli::try_parse_from([
            "ppcap",
            "baseline",
            "diff",
            bfile.path().to_str().unwrap(),
            sfile.path().to_str().unwrap(),
            "--json",
            rep.path().to_str().unwrap(),
        ])
        .unwrap();
        dispatch(cli2).unwrap();
        let report: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(rep.path()).unwrap()).unwrap();
        assert_eq!(report["hosts_compared"], 1);
        assert!(report["deviations"].is_array());

        // diff on a summary with no snapshot is a hard error.
        let plain = ppcap_core::AnalysisOutput::default();
        let pfile = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(pfile.path(), plain.to_json_pretty().unwrap()).unwrap();
        let cli3 = Cli::try_parse_from([
            "ppcap",
            "baseline",
            "diff",
            bfile.path().to_str().unwrap(),
            pfile.path().to_str().unwrap(),
        ])
        .unwrap();
        assert!(dispatch(cli3).is_err());
    }
}
