//! The `ppcap` command-line surface (clap) and dispatch.
//!
//! Thin shell over `ppcap-core`: parse args, build the core configs, call into the engine,
//! and map [`ppcap_core::PpError`] to an exit code. Progress goes to **stderr**, JSON to
//! **stdout** (pipeable). `anyhow` and `clap` live only here; the core stays typed.
//!
//! The command structure and argument parsing below are COMPLETE and stable, and `dispatch`
//! is now fully wired to the engine (analyze / gen / init-db). The CLI signatures must not
//! change.

use std::path::{Path, PathBuf};
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
        /// Opt-in: extract each carved file (HTTP, FTP, SMTP/POP3 attachments, SMB2) to this
        /// directory (`<sha256>.<ext>`; known-bad/suspicious/YARA-matched files get a `.quarantine`
        /// suffix). Off by default — no bytes written.
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
        /// Encrypted Traffic Analysis: disable the keyless encrypted-traffic detectors. They are
        /// ON by default, raising `encrypted_unknown_protocol` (a high-entropy channel no protocol
        /// identifies), `missing_sni`, `port_protocol_mismatch`, and `ssh_posture` findings.
        /// Fingerprint extraction (JA4S, QUIC server metadata, the SSH identification line) is
        /// metadata rather than detection and stays on.
        #[arg(long = "no-encrypted-analysis")]
        no_encrypted_analysis: bool,
        /// Windows identity attacks: disable the Kerberos / DCE-RPC / LDAP parsers and their
        /// detectors. They are ON by default, raising `kerberoasting`, `asrep_roasting`, `dcsync`,
        /// `ad_recon`, and `legacy_auth` findings.
        #[arg(long = "no-identity")]
        no_identity: bool,
        /// Windows identity attacks: known domain controllers (comma-separated IPs), in addition to
        /// the ones inferred from the capture. Replication from a DC is never reported as DCSync —
        /// list a directory-sync server here too if it should not be.
        #[arg(long = "dc", value_delimiter = ',')]
        dc: Vec<std::net::IpAddr>,
        /// Key-log decryption: an NSS `SSLKEYLOGFILE` (as written by browsers/curl/OpenSSL). TLS 1.2
        /// / 1.3 flows whose ClientHello random has secrets in it are decrypted in one extra bounded
        /// pass, and the cleartext HTTP transactions + carved files are reported under `keylog` in
        /// the JSON. The key-log is read locally and never leaves the machine. Off by default.
        #[arg(long, conflicts_with = "batch")]
        keylog: Option<PathBuf>,
        /// Teach it once: apply analyst suppression rules (a `suppressions.json` from
        /// `ppcap suppress add` or the UI). Repeatable — e.g. a team file then a personal one;
        /// a rule id seen twice keeps the first. Matching findings leave the alert queue and are
        /// listed under `suppressions` in the JSON. Expired rules are skipped.
        #[arg(long = "suppress", conflicts_with = "batch")]
        suppress: Vec<PathBuf>,
        /// Suricata EVE in: fold the `alert` events of this `eve.json` into the analysis as
        /// findings, so sensor hits rank and correlate with PacketPilot's own. Repeatable.
        #[arg(long = "eve", conflicts_with = "batch")]
        eve: Vec<PathBuf>,
        /// Zeek logs out: also write conn/dns/http/ssl/ssh/files/notice logs to this directory,
        /// from the same pass.
        #[arg(long = "zeek", conflicts_with = "batch")]
        zeek: Option<PathBuf>,
        /// Write the `--zeek` logs as Zeek JSON (one object per line) instead of tab-separated.
        #[arg(long = "zeek-json", requires = "zeek")]
        zeek_json: bool,
        /// Noise budget: the team's review-time rates (`review-rates.json`, version 1) for the
        /// "time saved" estimate. Fields left out keep the defaults (5 min per 1k flows, 10 per
        /// finding, 15 per story). The rates are carried in the JSON so later re-derives keep them.
        #[arg(long = "review-rates", conflicts_with = "batch")]
        review_rates: Option<PathBuf>,
        /// Match these YARA rules over every carved file; each match is a finding. Repeatable.
        /// Rules using features outside the supported subset (regex, modules, `for` loops) are
        /// listed and skipped.
        #[arg(long = "yara", conflicts_with = "batch")]
        yara: Vec<PathBuf>,
    },
    /// Zeek logs out: analyze a capture and write Zeek-format logs (conn, dns, http, ssl, ssh,
    /// files, plus notice for PacketPilot's findings) that share one connection uid, ready for a
    /// SIEM pipeline that already reads Zeek.
    Zeek {
        /// The capture (pcap / pcapng, optionally .gz).
        input: PathBuf,
        /// Directory for the logs (created if missing).
        #[arg(short = 'o', long = "out-dir", default_value = "zeek-logs")]
        out_dir: PathBuf,
        /// Zeek JSON (one object per line) instead of Zeek's tab-separated format.
        #[arg(long)]
        json: bool,
        /// Suricata EVE files whose alerts join the findings in notice.log. Repeatable.
        #[arg(long = "eve")]
        eve: Vec<PathBuf>,
        /// YARA rules matched over every carved file (matches land in files.log and notice.log).
        /// Repeatable.
        #[arg(long = "yara")]
        yara: Vec<PathBuf>,
        /// Also write the analysis JSON here.
        #[arg(long)]
        summary: Option<PathBuf>,
        /// Suppress stderr progress.
        #[arg(long)]
        quiet: bool,
    },
    /// Suricata EVE in: fold the `alert` events of one or more `eve.json` files into an existing
    /// analysis, re-deriving its alert queue. Importing the same file twice adds nothing new.
    Eve {
        /// The analysis-output JSON (from `analyze --json`).
        summary: PathBuf,
        /// Suricata EVE files (one JSON event per line).
        #[arg(required = true)]
        eve: Vec<PathBuf>,
        /// Write the updated analysis here ("-" => stdout; default: stdout).
        #[arg(long)]
        json: Option<String>,
        /// Suppress the stderr summary.
        #[arg(long)]
        quiet: bool,
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
        /// Teach it once: re-apply the queue under these suppression rule files (replacing any
        /// rules the analysis already carries). Repeatable; first file wins on a duplicate id.
        #[arg(long = "suppress")]
        suppress: Vec<PathBuf>,
    },
    /// Incident timeline: print each alert as one chronological, cross-host story (first
    /// contact, DNS answers, downloads, detections, lateral hops), ready for a ticket or
    /// hand-off. Every row carries the capture filter that pulls its packets.
    Timeline {
        /// The analysis-output JSON (from `analyze --json`).
        summary: PathBuf,
        /// Only these alert id(s) (`alert:…`, as printed by `ppcap alerts`). Repeatable;
        /// default: every alert, in queue order.
        #[arg(long = "alert")]
        alerts: Vec<String>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = TimelineFormat::Markdown)]
        format: TimelineFormat,
        /// Write here instead of stdout ("-" => stdout).
        #[arg(long)]
        out: Option<String>,
    },
    /// Push integrations: send the alert queue to Slack, Teams, Jira, TheHive, Splunk HEC,
    /// Elastic (ECS), an OCSF collector or a webhook, as listed in a destinations file.
    ///
    /// The destinations file is plain JSON, safe to commit and share: secrets are named by
    /// environment variable (`url_env`, `token_env`, `user_env`), never written in it. A sent
    /// ledger beside it keeps re-runs from opening duplicate tickets; an alert whose band rises
    /// is sent again. `--dry-run` and `--out-dir` never touch the network.
    Push {
        /// The analysis-output JSON (from `analyze --json`). Not needed with `--example`.
        #[arg(required_unless_present = "example")]
        summary: Option<PathBuf>,
        /// The destinations file.
        #[arg(long, short = 'd', default_value = "destinations.json")]
        destinations: PathBuf,
        /// Only these destinations, by name (repeatable; may name a disabled one). Default:
        /// every enabled destination.
        #[arg(long = "to")]
        to: Vec<String>,
        /// Only alerts at or above this band: act_now, investigate, review, log, info. A
        /// destination's own `min_band` still applies when it is stricter.
        #[arg(long = "min-band", value_parser = crate::push::parse_band)]
        min_band: Option<ppcap_core::PriorityBand>,
        /// Only these alert id(s) (`alert:…`, as printed by `ppcap alerts`). Repeatable.
        #[arg(long = "alert")]
        alerts: Vec<String>,
        /// Teach it once: re-derive the queue under these suppression rule files first.
        #[arg(long = "suppress")]
        suppress: Vec<PathBuf>,
        /// Print every request that would be sent (secret URLs and tokens hidden) and send nothing.
        #[arg(long = "dry-run", conflicts_with = "out_dir")]
        dry_run: bool,
        /// Write each request body into this directory instead of sending (offline hand-off of
        /// ECS NDJSON, OCSF, HEC or webhook JSON). Needs no secrets and ignores the ledger.
        #[arg(long = "out-dir")]
        out_dir: Option<PathBuf>,
        /// The sent ledger. Default: `push-ledger.json` beside the destinations file.
        #[arg(long)]
        ledger: Option<PathBuf>,
        /// Send alerts the ledger says were already delivered.
        #[arg(long)]
        resend: bool,
        /// Print a starter destinations file (every kind, all disabled) and exit.
        #[arg(long)]
        example: bool,
        /// Write the per-destination report as JSON here ("-" => stdout).
        #[arg(long)]
        json: Option<String>,
        /// Suppress stderr progress.
        #[arg(long)]
        quiet: bool,
    },
    /// Teach it once: turn "this alert is benign" into reusable suppression rules, and inspect
    /// or test rule files. Rules are plain JSON, safe to commit and share.
    Suppress {
        #[command(subcommand)]
        action: SuppressAction,
    },
    /// Guided hunt playbooks: a step-by-step checklist per alert type, with every pivot (SQL,
    /// flow filter, capture filter) already filled in from the alert. Teams override or extend
    /// the built-in set with plain JSON files, safe to commit and share.
    Playbook {
        #[command(subcommand)]
        action: PlaybookAction,
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
    /// Agents: serve the loaded captures to an AI agent over the Model Context Protocol (stdio).
    ///
    /// Point an MCP host (Claude Desktop, Claude Code, Cursor, an Ollama-backed agent) at
    /// `ppcap mcp <capture-or-summary>...`. Tools are read-only (alerts, timelines, host profiles,
    /// flow queries, packets, indicator lookups) and offline; nothing listens on a socket.
    Mcp {
        /// Captures (.pcap / .pcapng, optionally .gz; analysed at launch) and/or `analyze --json`
        /// outputs (served as is, with their recorded pcap and flows Parquet).
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
        /// Local IOC threat-feed JSON, used when analysing captures and by `lookup_indicator`.
        #[arg(long = "threat-feed")]
        threat_feed: Option<PathBuf>,
        /// Teach it once: apply these suppression rule files (repeatable; first file wins on a
        /// duplicate id). For a summary they replace the rules it carries.
        #[arg(long = "suppress")]
        suppress: Vec<PathBuf>,
        /// Team hunt playbook files for `get_playbook`, applied over the built-ins (repeatable).
        #[arg(long = "playbooks")]
        playbooks: Vec<PathBuf>,
        /// Offer `carve_pcap`, which writes carved pcaps into this directory (and nowhere else).
        /// Without it the server never writes a file.
        #[arg(long = "allow-write")]
        allow_write: Option<PathBuf>,
        /// Let `lookup_indicator` query online reputation (AbuseIPDB / GreyNoise / VirusTotal,
        /// keys from ABUSEIPDB_API_KEY / GREYNOISE_API_KEY / VIRUSTOTAL_API_KEY). Off by default:
        /// without it nothing leaves the machine.
        #[arg(long)]
        online: bool,
        /// Largest tool response, in bytes, before the server asks the agent to narrow its query.
        #[arg(long = "max-response-bytes", default_value_t = crate::mcp::DEFAULT_MAX_RESPONSE_BYTES)]
        max_response_bytes: usize,
        /// Suppress stderr progress.
        #[arg(long)]
        quiet: bool,
    },
    /// Generate a synthetic capture for testing.
    Gen {
        /// Output capture path.
        output: PathBuf,
        /// Scenario: mixed | web-only | dns-flood | port-scan | beacon | bulk-transfer | attack-chain | traffic-spike | encrypted-anomaly.
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

/// `ppcap playbook` sub-actions.
#[derive(Subcommand, Debug)]
pub enum PlaybookAction {
    /// List the active playbooks and the alert kinds each covers.
    List {
        /// Team playbook files, applied over the built-ins in order (same id replaces; for each
        /// alert kind the last playbook naming it wins). Repeatable.
        #[arg(long = "playbooks")]
        playbooks: Vec<PathBuf>,
    },
    /// Print the hunt checklist for the alerts of an analyzed capture.
    Show {
        /// The analysis-output JSON (from `analyze --json`).
        summary: PathBuf,
        /// Only these alert id(s) (`alert:…`, as printed by `ppcap alerts`). Repeatable;
        /// default: every alert, in queue order.
        #[arg(long = "alert")]
        alerts: Vec<String>,
        /// Team playbook files (see `ppcap playbook list`). Repeatable.
        #[arg(long = "playbooks")]
        playbooks: Vec<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = PlaybookFormat::Markdown)]
        format: PlaybookFormat,
        /// Write here instead of stdout ("-" => stdout).
        #[arg(long)]
        out: Option<String>,
    },
    /// Check a team playbook file: format version, ids, placeholders and SQL pivots.
    Lint { file: PathBuf },
    /// Print the built-in playbook file: the starting point for a team's own copy.
    Builtin,
}

/// `--format` values for `ppcap playbook show`.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlaybookFormat {
    /// A Markdown checklist (paste into case notes or a ticket).
    Markdown,
    /// The rendered playbooks as JSON.
    Json,
}

/// `ppcap suppress` sub-actions: teach, list and test analyst suppression rule files.
#[derive(Subcommand, Debug)]
pub enum SuppressAction {
    /// Mark one or more alerts of an analyzed capture benign, appending one rule per member
    /// finding to a rule file (created if absent; existing rules are kept).
    Add {
        /// The analysis-output JSON (from `analyze --json`) holding the alerts.
        summary: PathBuf,
        /// Alert id(s) to teach (`alert:…`, as printed by `ppcap alerts --json`).
        #[arg(long = "alert", required = true)]
        alerts: Vec<String>,
        /// Why these are benign — stored on every rule and shown wherever a rule hides something.
        #[arg(long)]
        reason: String,
        /// How broadly the verdict generalizes: `exact` (same source, destination and port),
        /// `source` (this host to anywhere), or `destination` (any host to this destination and
        /// port; for scans and sweeps with no single destination, any host to this port).
        #[arg(long, value_enum, default_value_t = ScopeArg::Exact)]
        scope: ScopeArg,
        /// Who is teaching it (a name, handle or email).
        #[arg(long)]
        author: Option<String>,
        /// Days until the rules expire (default 90). Ignored with `--no-expiry`.
        #[arg(long = "expires-days", default_value_t = ppcap_core::DEFAULT_RULE_TTL_DAYS)]
        expires_days: i64,
        /// Never expire these rules.
        #[arg(long = "no-expiry")]
        no_expiry: bool,
        /// The rule file to append to.
        #[arg(long, default_value = "suppressions.json")]
        file: PathBuf,
    },
    /// Print the rules in one or more files with their status (active / expired / invalid).
    List {
        /// Rule files, in priority order.
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
    /// Show what rule files would hide in an analyzed capture, without re-analyzing it.
    Test {
        /// The analysis-output JSON (from `analyze --json`).
        summary: PathBuf,
        /// Rule files, in priority order.
        #[arg(long = "suppress", required = true)]
        suppress: Vec<PathBuf>,
        /// Write the suppression hits as JSON here ("-" => stdout).
        #[arg(long)]
        json: Option<String>,
    },
}

/// `--format` values for `ppcap timeline`.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimelineFormat {
    /// One Markdown section per alert (paste into a ticket).
    Markdown,
    /// One CSV row per event, every alert (spreadsheets, SIEM import).
    Csv,
    /// The timeline objects as JSON.
    Json,
}

/// `--scope` values for `ppcap suppress add`.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeArg {
    Exact,
    Source,
    Destination,
}

impl From<ScopeArg> for ppcap_core::TeachScope {
    fn from(s: ScopeArg) -> Self {
        match s {
            ScopeArg::Exact => ppcap_core::TeachScope::Exact,
            ScopeArg::Source => ppcap_core::TeachScope::Source,
            ScopeArg::Destination => ppcap_core::TeachScope::Destination,
        }
    }
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

/// Seconds since the Unix epoch (a pre-epoch clock reads as 0).
pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Read suppression rule files (all must exist and parse).
fn read_suppression_files(paths: &[PathBuf]) -> anyhow::Result<Vec<ppcap_core::SuppressionFile>> {
    paths
        .iter()
        .map(|p| {
            let text = std::fs::read_to_string(p)
                .with_context(|| format!("read suppression rules {}", p.display()))?;
            serde_json::from_str(&text)
                .with_context(|| format!("parse suppression rules {}", p.display()))
        })
        .collect()
}

/// Load and merge suppression rule files as of today, warning on stderr about every rule that
/// will not apply (expired, invalid) or cannot match in this build (unknown kind).
fn load_suppression_rules(
    paths: &[PathBuf],
    quiet: bool,
) -> anyhow::Result<Vec<ppcap_core::SuppressionRule>> {
    let files = read_suppression_files(paths)?;
    let today = ppcap_core::ymd_from_unix_secs(unix_now());
    let loaded = ppcap_core::load_suppression_rules(&files, Some(&today));
    if !quiet {
        for r in &loaded.expired {
            eprintln!(
                "suppress: skipping expired rule {} ({} expired {})",
                r.id,
                r.kind,
                r.expires.as_deref().unwrap_or("")
            );
        }
        for (r, why) in &loaded.invalid {
            eprintln!("suppress: skipping invalid rule {}: {why}", r.id);
        }
        for r in &loaded.unknown_kind {
            eprintln!(
                "suppress: rule {} names unknown finding kind {:?}; it will never match",
                r.id, r.kind
            );
        }
    }
    Ok(loaded.active)
}

/// A checked `review-rates.json` and the digest of the exact bytes read (for the manifest).
#[derive(Debug)]
struct LoadedReviewRates {
    rates: ppcap_core::ReviewRates,
    sha256: String,
    bytes: u64,
}

/// Read and check a `review-rates.json`.
fn load_review_rates(path: &Path) -> anyhow::Result<LoadedReviewRates> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read review rates {}", path.display()))?;
    let rates = ppcap_core::parse_review_rates(&text).map_err(|problems| {
        anyhow::anyhow!(
            "review rates {} has problems:\n  {}",
            path.display(),
            problems.join("\n  ")
        )
    })?;
    Ok(LoadedReviewRates {
        rates,
        sha256: ppcap_core::sha256_hex(text.as_bytes()),
        bytes: text.len() as u64,
    })
}

/// `noise budget: 4.2M packets → 61k flows → 9 stories, about 6 h saved (estimate)`.
fn noise_budget_line(summary: &ppcap_core::Summary) -> Option<String> {
    summary
        .noise_budget
        .as_ref()
        .map(|b| format!("noise budget: {}\n  {}", b.headline(), b.explain()))
}

/// `suppressions: 4 findings hidden by 2 rules, 1 kept by guardrails (threat_intel)`.
fn suppression_summary_line(summary: &ppcap_core::Summary) -> String {
    use ppcap_core::model::SuppressionOutcome;
    let hidden: Vec<_> = summary
        .suppressions
        .iter()
        .filter(|h| h.outcome == SuppressionOutcome::Suppressed)
        .collect();
    let rules: std::collections::BTreeSet<&str> =
        hidden.iter().map(|h| h.rule_id.as_str()).collect();
    let blocked: Vec<&str> = summary
        .suppressions
        .iter()
        .filter_map(|h| match h.outcome {
            SuppressionOutcome::Blocked(why) => Some(why.as_str()),
            SuppressionOutcome::Suppressed => None,
        })
        .collect();
    let mut line = format!(
        "suppressions: {} finding{} hidden by {} rule{} ({} rule{} loaded)",
        hidden.len(),
        if hidden.len() == 1 { "" } else { "s" },
        rules.len(),
        if rules.len() == 1 { "" } else { "s" },
        summary.suppression_rules.len(),
        if summary.suppression_rules.len() == 1 {
            ""
        } else {
            "s"
        },
    );
    if !blocked.is_empty() {
        let reasons: std::collections::BTreeSet<&str> = blocked.iter().copied().collect();
        line.push_str(&format!(
            ", {} kept by guardrails ({})",
            blocked.len(),
            reasons.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    line
}

/// `ppcap mcp`: load every input, then serve MCP on stdin/stdout until the client hangs up.
#[allow(clippy::too_many_arguments)]
fn dispatch_mcp(
    inputs: &[PathBuf],
    threat_feed: Option<PathBuf>,
    suppress: &[PathBuf],
    playbooks: &[PathBuf],
    allow_write: Option<PathBuf>,
    online: bool,
    max_response_bytes: usize,
    quiet: bool,
) -> anyhow::Result<()> {
    let playbooks = load_playbooks(playbooks)?;
    // Load the feed up front so a typo fails before any (possibly long) analysis.
    let feed = match threat_feed.as_ref() {
        Some(p) => ppcap_core::ThreatFeed::load(p)
            .with_context(|| format!("load threat feed {}", p.display()))?,
        None => ppcap_core::ThreatFeed::empty(),
    };
    let allow_write = match allow_write {
        Some(dir) => {
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("create export directory {}", dir.display()))?;
            Some(
                dir.canonicalize()
                    .with_context(|| format!("resolve export directory {}", dir.display()))?,
            )
        }
        None => None,
    };
    let rules = if suppress.is_empty() {
        None
    } else {
        Some(load_suppression_rules(suppress, quiet)?)
    };
    let work = crate::mcp::capture::WorkDir::create()?;
    let opts = crate::mcp::LoadOptions {
        threat_feed,
        suppress: rules,
        work_dir: work.0.clone(),
        quiet,
    };
    let mut captures: Vec<crate::mcp::Capture> = Vec::new();
    for input in inputs {
        let taken: Vec<String> = captures.iter().map(|c| c.id.clone()).collect();
        let c = crate::mcp::capture::load(input, &opts, &taken)?;
        if !quiet {
            eprintln!(
                "mcp: loaded {} as {:?} ({} alerts{}{})",
                input.display(),
                c.id,
                c.out.summary.alerts.len(),
                if c.pcap.is_none() { ", no pcap" } else { "" },
                if c.flows.is_none() { ", no flows" } else { "" },
            );
        }
        captures.push(c);
    }
    let mut server = crate::mcp::Server::new(
        captures,
        Some(feed),
        crate::mcp::ServerOptions {
            allow_write,
            online,
            max_response_bytes,
            playbooks: Some(playbooks),
        },
    );
    if !quiet {
        eprintln!("mcp: serving on stdio (ctrl-d to stop)");
    }
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    crate::mcp::serve(&mut server, stdin.lock(), stdout.lock()).context("MCP transport (stdio)")?;
    drop(work);
    Ok(())
}

/// `ppcap suppress …`.
fn dispatch_suppress(action: SuppressAction) -> anyhow::Result<()> {
    match action {
        SuppressAction::Add {
            summary,
            alerts,
            reason,
            scope,
            author,
            expires_days,
            no_expiry,
            file,
        } => {
            if reason.trim().is_empty() {
                return Err(anyhow!("--reason must say why these alerts are benign"));
            }
            if !no_expiry && expires_days < 1 {
                return Err(anyhow!(
                    "--expires-days must be at least 1 (or pass --no-expiry)"
                ));
            }
            let text = std::fs::read_to_string(&summary)
                .with_context(|| format!("read analysis output {}", summary.display()))?;
            let mut out: ppcap_core::AnalysisOutput = serde_json::from_str(&text)
                .with_context(|| format!("parse analysis output {}", summary.display()))?;
            ppcap_core::refresh_alerts(&mut out.summary);
            let now = unix_now();
            ppcap_core::expire_carried_rules(
                &mut out.summary,
                &ppcap_core::ymd_from_unix_secs(now),
            );
            let meta = ppcap_core::TeachMeta {
                reason: reason.trim().to_string(),
                author,
                created: Some(ppcap_core::ymd_from_unix_secs(now)),
                expires: (!no_expiry)
                    .then(|| ppcap_core::ymd_from_unix_secs(now + expires_days * 86_400)),
            };
            let mut rules = Vec::new();
            for id in &alerts {
                let taught = ppcap_core::rules_for_alert(&out.summary, id, scope.into(), &meta)
                    .map_err(|e| anyhow!("{e}"))?;
                for (idx, why) in &taught.kept {
                    let title = out
                        .summary
                        .findings
                        .get(*idx as usize)
                        .map_or("", |f| f.title.as_str());
                    eprintln!(
                        "suppress: {id}: finding #{idx} \"{title}\" stays visible ({})",
                        why.as_str()
                    );
                }
                rules.extend(taught.rules);
            }
            let mut rule_file = if file.exists() {
                read_suppression_files(std::slice::from_ref(&file))?
                    .pop()
                    .unwrap_or_default()
            } else {
                ppcap_core::SuppressionFile::default()
            };
            let added = ppcap_core::merge_suppression_rules(&mut rule_file, &rules);
            let s = serde_json::to_string_pretty(&rule_file)?;
            std::fs::write(&file, s + "\n")
                .with_context(|| format!("write suppression rules {}", file.display()))?;
            eprintln!(
                "suppress: added {added} rule{} to {} ({} already present)",
                if added == 1 { "" } else { "s" },
                file.display(),
                rules.len() - added,
            );
            Ok(())
        }
        SuppressAction::List { files } => {
            let parsed = read_suppression_files(&files)?;
            let today = ppcap_core::ymd_from_unix_secs(unix_now());
            let loaded = ppcap_core::load_suppression_rules(&parsed, Some(&today));
            let show = |status: &str, r: &ppcap_core::SuppressionRule| {
                eprintln!(
                    "  {status:<8} {}  {} src={} dst={} port={}  expires={}  {}",
                    r.id,
                    r.kind,
                    r.src.as_deref().unwrap_or("any"),
                    r.dst.as_deref().unwrap_or("any"),
                    r.dst_port
                        .map_or_else(|| "any".to_string(), |p| p.to_string()),
                    r.expires.as_deref().unwrap_or("never"),
                    r.reason,
                );
            };
            eprintln!(
                "suppress: {} active, {} expired, {} invalid, {} duplicate",
                loaded.active.len(),
                loaded.expired.len(),
                loaded.invalid.len(),
                loaded.duplicates,
            );
            for r in &loaded.active {
                show("active", r);
            }
            for r in &loaded.expired {
                show("expired", r);
            }
            for (r, why) in &loaded.invalid {
                show("invalid", r);
                eprintln!("           {why}");
            }
            Ok(())
        }
        SuppressAction::Test {
            summary,
            suppress,
            json,
        } => {
            use ppcap_core::model::SuppressionOutcome;
            let text = std::fs::read_to_string(&summary)
                .with_context(|| format!("read analysis output {}", summary.display()))?;
            let mut out: ppcap_core::AnalysisOutput = serde_json::from_str(&text)
                .with_context(|| format!("parse analysis output {}", summary.display()))?;
            out.summary.suppression_rules = Vec::new();
            ppcap_core::refresh_alerts(&mut out.summary);
            let before = out.summary.alerts.len();
            let rules = load_suppression_rules(&suppress, false)?;
            ppcap_core::apply_suppressions(&mut out.summary, rules);
            eprintln!("{}", suppression_summary_line(&out.summary));
            eprintln!(
                "alerts: {before} without rules, {} with rules",
                out.summary.alerts.len()
            );
            for h in &out.summary.suppressions {
                let title = out
                    .summary
                    .findings
                    .get(h.finding_index as usize)
                    .map_or("", |f| f.title.as_str());
                let status = match h.outcome {
                    SuppressionOutcome::Suppressed => "hidden".to_string(),
                    SuppressionOutcome::Blocked(why) => format!("kept ({})", why.as_str()),
                };
                eprintln!("  {status:<22} {}  {title}", h.rule_id);
            }
            if let Some(path) = json.as_deref() {
                let s = serde_json::to_string_pretty(&out.summary.suppressions)?;
                match path {
                    "-" => println!("{s}"),
                    p => std::fs::write(p, &s)
                        .with_context(|| format!("write suppression hits to {p}"))?,
                }
            }
            Ok(())
        }
    }
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
/// The timelines `ppcap timeline` prints: every one, or exactly the requested alert ids (in the
/// order asked). An unknown id is an error naming it, so a typo never prints a silent subset.
/// The built-in playbooks with `files` applied over them in order.
pub fn load_playbooks(files: &[PathBuf]) -> anyhow::Result<ppcap_core::PlaybookSet> {
    let mut set = ppcap_core::builtin_playbooks();
    for path in files {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read playbook file {}", path.display()))?;
        let (file, warnings) = ppcap_core::parse_playbook_file(&text).map_err(|problems| {
            anyhow::anyhow!(
                "playbook file {} has problems:\n  {}",
                path.display(),
                problems.join("\n  ")
            )
        })?;
        for w in warnings {
            eprintln!("playbook: {}: {w}", path.display());
        }
        let origin = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        set.add_file(file, &origin);
    }
    Ok(set)
}

fn dispatch_playbook(action: PlaybookAction) -> anyhow::Result<()> {
    match action {
        PlaybookAction::List { playbooks } => {
            let set = load_playbooks(&playbooks)?;
            for p in &set.playbooks {
                let kinds: Vec<&str> = p.kinds.iter().map(|k| k.as_str()).collect();
                println!(
                    "{:<24} {:<44} {} step(s)  [{}]  {}",
                    p.id,
                    p.title,
                    p.steps.len(),
                    p.origin.as_deref().unwrap_or("built-in"),
                    if kinds.is_empty() {
                        "fallback".to_string()
                    } else {
                        kinds.join(", ")
                    }
                );
            }
            Ok(())
        }
        PlaybookAction::Show {
            summary,
            alerts,
            playbooks,
            format,
            out,
        } => {
            let set = load_playbooks(&playbooks)?;
            let text = std::fs::read_to_string(&summary)
                .with_context(|| format!("read analysis output {}", summary.display()))?;
            let mut analysis: ppcap_core::AnalysisOutput = serde_json::from_str(&text)
                .with_context(|| format!("parse analysis output {}", summary.display()))?;
            ppcap_core::refresh_alerts(&mut analysis.summary);
            let s = &analysis.summary;
            let mut runs = Vec::new();
            if alerts.is_empty() {
                for a in &s.alerts {
                    runs.extend(ppcap_core::runs_for_alert(s, a, &set));
                }
            } else {
                for id in &alerts {
                    runs.extend(ppcap_core::runs_for_alert_id(s, id, &set).ok_or_else(|| {
                        anyhow::anyhow!("no alert {id} in this analysis (see `ppcap alerts`)")
                    })?);
                }
            }
            if runs.is_empty() {
                eprintln!("playbook: no alerts — nothing to hunt");
            }
            let rendered = match format {
                PlaybookFormat::Markdown => ppcap_core::render_playbook_markdown(&runs, None),
                PlaybookFormat::Json => serde_json::to_string_pretty(&runs)? + "\n",
            };
            match out.as_deref() {
                None | Some("-") => print!("{rendered}"),
                Some(p) => {
                    std::fs::write(p, &rendered)
                        .with_context(|| format!("write playbooks to {p}"))?;
                    eprintln!("playbook: {} checklist(s) written to {p}", runs.len());
                }
            }
            Ok(())
        }
        PlaybookAction::Lint { file } => {
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("read playbook file {}", file.display()))?;
            match ppcap_core::parse_playbook_file(&text) {
                Ok((f, warnings)) => {
                    for w in &warnings {
                        println!("warning: {w}");
                    }
                    println!(
                        "{}: ok, {} playbook(s), {} warning(s)",
                        file.display(),
                        f.playbooks.len(),
                        warnings.len()
                    );
                    Ok(())
                }
                Err(problems) => {
                    for p in &problems {
                        println!("problem: {p}");
                    }
                    anyhow::bail!("{}: {} problem(s)", file.display(), problems.len())
                }
            }
        }
        PlaybookAction::Builtin => {
            print!("{}", ppcap_core::builtin_playbooks_json());
            Ok(())
        }
    }
}

fn select_timelines(
    all: &[ppcap_core::AlertTimeline],
    ids: &[String],
) -> anyhow::Result<Vec<ppcap_core::AlertTimeline>> {
    if ids.is_empty() {
        return Ok(all.to_vec());
    }
    ids.iter()
        .map(|id| {
            all.iter()
                .find(|t| &t.alert_id == id)
                .cloned()
                .ok_or_else(|| {
                    anyhow::anyhow!("no alert {id} in this analysis (see `ppcap alerts`)")
                })
        })
        .collect()
}

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
            no_encrypted_analysis,
            no_identity,
            dc,
            forecast_z,
            forecast_min_bins,
            evidence,
            keylog,
            suppress,
            eve,
            zeek,
            zeek_json,
            review_rates,
            yara,
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
                    ppcap_core::IdentityParams {
                        enabled: !no_identity,
                        domain_controllers: dc.clone(),
                        ..Default::default()
                    },
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

            // Key-log decryption: parse up front so a wrong path or an empty/foreign file fails
            // before the (possibly long) analysis pass rather than after it.
            let keylog_path = keylog.clone();
            // SHA-256 + size of the exact key-log bytes parsed below, for the evidence manifest.
            let mut keylog_digest: Option<(String, u64)> = None;
            let keylog = match keylog.as_ref() {
                Some(path) => {
                    let text = std::fs::read_to_string(path)
                        .with_context(|| format!("reading key-log file {}", path.display()))?;
                    keylog_digest =
                        Some((ppcap_core::sha256_hex(text.as_bytes()), text.len() as u64));
                    let parsed = ppcap_core::KeyLog::parse(&text);
                    if parsed.is_empty() {
                        return Err(anyhow!(
                            "key-log file {} has no NSS key-log entries (expected lines like \
                             `CLIENT_RANDOM <hex> <hex>` or `CLIENT_TRAFFIC_SECRET_0 <hex> <hex>`)",
                            path.display()
                        ));
                    }
                    Some(parsed)
                }
                None => None,
            };

            // YARA rules: loaded up front too, so a bad path fails before the pass.
            let yara_rules = crate::yara::load(&yara, quiet)?;
            // Review rates: loaded up front too, with the digest of the exact bytes for the manifest.
            let review_rates = review_rates
                .map(|p| load_review_rates(&p).map(|loaded| (p, loaded)))
                .transpose()?;

            // Derive a stable capture id from the input path (cheap FNV-1a hash) so distinct
            // captures get distinct ids in the Parquet footer; falls back to 0 on empty path.
            let cfg = ppcap_core::PipelineConfig {
                strict_decode: strict,
                hash_source: hash,
                flows_parquet: parquet.clone(),
                threat_feed: threat_feed.clone(),
                carve_dir: carve_dir.clone(),
                yara: yara_rules.as_ref().map(|y| y.rules.clone()),
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
                // Encrypted Traffic Analysis: on by default; `--no-encrypted-analysis` opts out of
                // the detectors AND the entropy sampling that feeds one of them.
                entropy: ppcap_core::entropy::EntropyConfig {
                    enabled: !no_encrypted_analysis,
                    ..Default::default()
                },
                encrypted_unknown: ppcap_core::detect::EncryptedUnknownParams {
                    enabled: !no_encrypted_analysis,
                    ..Default::default()
                },
                missing_sni: ppcap_core::detect::MissingSniParams {
                    enabled: !no_encrypted_analysis,
                    ..Default::default()
                },
                port_mismatch: ppcap_core::detect::PortMismatchParams {
                    enabled: !no_encrypted_analysis,
                    ..Default::default()
                },
                ssh_posture: ppcap_core::detect::SshPostureParams {
                    enabled: !no_encrypted_analysis,
                    ..Default::default()
                },
                // Windows identity attacks: on by default; `--no-identity` opts out, `--dc` adds
                // domain controllers to the inferred set.
                identity: ppcap_core::IdentityParams {
                    enabled: !no_identity,
                    domain_controllers: dc.clone(),
                    ..Default::default()
                },
                keylog,
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

            let mut zeek_logger = zeek
                .as_deref()
                .map(|d| crate::zeek::logger(d, zeek_json))
                .transpose()?;
            let mut out = match zeek_logger.as_mut() {
                Some(l) => ppcap_core::run_observing(&input, &cfg, l, progress)?,
                None => ppcap_core::run(&input, &cfg, progress)?,
            };
            if !quiet {
                // Terminate the in-place progress line.
                let _ = writeln!(std::io::stderr());
            }

            if let (Some(k), false) = (out.keylog.as_ref(), quiet) {
                eprintln!(
                    "keylog: decrypted {} of {} keyed TLS flow{} ({} of {} key-log session{} used{})",
                    k.flows_decrypted,
                    k.flows_keyed,
                    if k.flows_keyed == 1 { "" } else { "s" },
                    k.keylog_sessions_used,
                    k.keylog_sessions,
                    if k.keylog_sessions == 1 { "" } else { "s" },
                    if k.flows_skipped_over_cap > 0 {
                        format!(", {} skipped over the buffer cap", k.flows_skipped_over_cap)
                    } else {
                        String::new()
                    }
                );
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

            if let (Some(r), false) = (out.summary.rarity.as_ref(), quiet) {
                if r.warming_up {
                    eprintln!(
                        "rarity: baseline has {} of {} captures of network history; nothing is called new yet",
                        r.history_captures,
                        ppcap_core::BaselineParams::default().min_env_captures
                    );
                } else if r.baseline_loaded {
                    eprintln!(
                        "rarity: {} indicator{} new to this network (vs {} captures), {} on only one host",
                        r.new_total,
                        if r.new_total == 1 { "" } else { "s" },
                        r.history_captures,
                        r.single_host_total
                    );
                }
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

                // Encrypted Traffic Analysis summary. Spelled out rather than "eta:", which on a
                // CLI reads as estimated-time-remaining.
                let n_eta = out
                    .summary
                    .findings
                    .iter()
                    .filter(|f| {
                        matches!(
                            f.kind,
                            ppcap_core::FindingKind::EncryptedUnknownProtocol
                                | ppcap_core::FindingKind::MissingSni
                                | ppcap_core::FindingKind::PortProtocolMismatch
                                | ppcap_core::FindingKind::SshPosture
                        )
                    })
                    .count();
                if n_eta > 0 {
                    eprintln!(
                        "encrypted-traffic: {n_eta} finding{}",
                        if n_eta == 1 { "" } else { "s" }
                    );
                }
            }

            if !no_identity && !quiet {
                let n = out
                    .summary
                    .findings
                    .iter()
                    .filter(|f| {
                        matches!(
                            f.kind,
                            ppcap_core::FindingKind::Kerberoasting
                                | ppcap_core::FindingKind::AsrepRoasting
                                | ppcap_core::FindingKind::DcSync
                                | ppcap_core::FindingKind::AdRecon
                                | ppcap_core::FindingKind::LegacyAuth
                        )
                    })
                    .count();
                if n > 0 {
                    eprintln!("identity: {n} finding{}", if n == 1 { "" } else { "s" });
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
                let (rf, ctx) = match std::fs::File::open(&input) {
                    Ok(f) => {
                        let len = std::fs::metadata(&input).ok().map(|m| m.len());
                        ppcap_core::apply_rules_with_context(f, len, &parsed.rules)
                    }
                    Err(_) => Default::default(),
                };
                ppcap_core::fold_rule_findings_with_context(&mut out.summary, &rf, &ctx);
                eprintln!(
                    "rules: {} loaded, {} skipped, {} matches",
                    parsed.rules.len(),
                    parsed.skipped.len(),
                    rf.len()
                );
            }

            crate::zeek::fold_eve_files(&mut out.summary, &eve, quiet)?;

            // Teach it once: analyst suppression rules shape the queue last, after every pass
            // that adds findings or moves the cards their guardrails read.
            if !suppress.is_empty() {
                let rules = load_suppression_rules(&suppress, quiet)?;
                ppcap_core::apply_suppressions(&mut out.summary, rules);
                if !quiet {
                    eprintln!("{}", suppression_summary_line(&out.summary));
                }
            }

            // Smart Alerting one-liner — printed after ALL summary-mutating passes (reputation,
            // rules, suppressions) so the counts match the JSON that follows.
            if !quiet && !out.summary.alerts.is_empty() {
                eprintln!("{}", alerts_summary_line(&out.summary));
            }
            if let Some((_, loaded)) = review_rates.as_ref() {
                ppcap_core::apply_review_rates(&mut out.summary, loaded.rates);
            }
            if !quiet {
                if let Some(line) = noise_budget_line(&out.summary) {
                    eprintln!("{line}");
                }
            }

            // notice.log carries every finding, so the logs close after the passes that add them.
            let zeek_report = match (zeek_logger, zeek.as_deref()) {
                (Some(l), Some(dir)) => Some(crate::zeek::finish(l, &out, dir, quiet)?),
                _ => None,
            };

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
                        "updated behavioral baseline ({} hosts, {} captures, {} network-wide indicators) -> {}",
                        updated.hosts.len(),
                        updated.captures_merged,
                        updated.environment.len(),
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
                if no_encrypted_analysis {
                    settings.push("--no-encrypted-analysis".to_string());
                }
                if no_identity {
                    settings.push("--no-identity".to_string());
                }
                if !dc.is_empty() {
                    let ips: Vec<String> = dc.iter().map(|i| i.to_string()).collect();
                    settings.push(format!("--dc {}", ips.join(",")));
                }
                if let (Some(p), Some((sha, _))) = (keylog_path.as_ref(), keylog_digest.as_ref()) {
                    settings.push(format!("--keylog {} (sha256 {sha})", p.display()));
                }
                for p in &eve {
                    settings.push(format!("--eve {}", p.display()));
                }
                if let Some(y) = yara_rules.as_ref() {
                    settings.extend(y.settings());
                }
                if let Some((p, loaded)) = review_rates.as_ref() {
                    settings.push(format!(
                        "--review-rates {} (sha256 {})",
                        p.display(),
                        loaded.sha256
                    ));
                }
                if let Some(d) = zeek.as_ref() {
                    settings.push(format!("--zeek {}", d.display()));
                    if zeek_json {
                        settings.push("--zeek-json".to_string());
                    }
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
                // `verify` resolves relative paths against the manifest's own directory, so record
                // each path relative to it (or absolute when it lives outside that directory).
                let manifest_dir = match evidence_path.parent() {
                    Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
                    _ => PathBuf::from("."),
                };
                let manifest_dir = manifest_dir
                    .canonicalize()
                    .with_context(|| format!("resolve {}", manifest_dir.display()))?;
                let rel = |path: &std::path::Path| -> String {
                    let abs = path
                        .canonicalize()
                        .or_else(|_| std::path::absolute(path))
                        .unwrap_or_else(|_| path.to_path_buf());
                    match abs.strip_prefix(&manifest_dir) {
                        Ok(r) => r.display().to_string(),
                        Err(_) => abs.display().to_string(),
                    }
                };
                let mut artifacts: Vec<ppcap_core::ArtifactRecord> = Vec::new();
                let mut record = |role: &str, path: &std::path::Path| -> anyhow::Result<()> {
                    let (sha256, bytes) = ppcap_core::hash_file(path)
                        .with_context(|| format!("hash artifact {}", path.display()))?;
                    artifacts.push(ppcap_core::ArtifactRecord {
                        role: role.to_string(),
                        path: rel(path),
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
                // Suppression rule files are inputs the alert queue depends on: record them so
                // `verify` notices a rule file edited after the fact.
                for p in &suppress {
                    record("suppression_rules", p)?;
                }
                // Suricata EVE files add findings, so they are inputs like the rule files.
                for p in &eve {
                    record("eve_input", p)?;
                }
                // Every Zeek log this run wrote.
                if let (Some(dir), Some(report)) = (zeek.as_ref(), zeek_report.as_ref()) {
                    for (log, _) in &report.logs {
                        record("zeek_log", &dir.join(format!("{log}.log")))?;
                    }
                }
                // Bodies extracted by --carve-dir are evidence too; one record per file (the
                // uncapped list, not the top-k `carved_files` projection).
                for p in &out.summary.extracted_paths {
                    record("carved_file", std::path::Path::new(p))?;
                }
                // The key-log is an input the output depends on: record it so `verify` checks it,
                // with the digest of the exact bytes the run parsed.
                // YARA rule files add findings: record the digest of the exact bytes parsed.
                for (p, sha256, bytes) in yara_rules.iter().flat_map(|y| y.files.iter()) {
                    artifacts.push(ppcap_core::ArtifactRecord {
                        role: "yara_rules".to_string(),
                        path: rel(p),
                        sha256: sha256.clone(),
                        bytes: *bytes,
                    });
                }
                // Review rates shape the noise budget estimate: the digest of the bytes applied.
                if let Some((p, loaded)) = review_rates.as_ref() {
                    artifacts.push(ppcap_core::ArtifactRecord {
                        role: "review_rates".to_string(),
                        path: rel(p),
                        sha256: loaded.sha256.clone(),
                        bytes: loaded.bytes,
                    });
                }
                if let (Some(p), Some((sha256, bytes))) =
                    (keylog_path.as_ref(), keylog_digest.clone())
                {
                    artifacts.push(ppcap_core::ArtifactRecord {
                        role: "keylog_input".to_string(),
                        path: rel(p),
                        sha256,
                        bytes,
                    });
                }

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let mut manifest = ppcap_core::EvidenceManifest::new(
                    &out.engine_version,
                    now,
                    settings,
                    &rel(&input),
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
        Command::Suppress { action } => dispatch_suppress(action),
        Command::Playbook { action } => dispatch_playbook(action),
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
                eprintln!(
                    "network history: {} indicators from {} captures",
                    profile.environment.len(),
                    profile.env_captures
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
                let mut rarity =
                    ppcap_core::rarity::rarity_report(Some(&base), &prof.environment, &params);
                rarity.truncate_for(&Default::default());
                if rarity.warming_up {
                    eprintln!(
                        "new to this network: baseline has {} of {} captures of history, nothing called new yet",
                        rarity.history_captures, params.min_env_captures
                    );
                } else {
                    eprintln!(
                        "new to this network: {} indicator(s) vs {} captures",
                        rarity.new_total, rarity.history_captures
                    );
                    for r in rarity.new.iter().take(20) {
                        eprintln!(
                            "  {:<20} {}  [{}]",
                            r.kind.phrase(),
                            r.value,
                            r.hosts.join(", ")
                        );
                    }
                }
                if let Some(path) = json.as_deref() {
                    // The deviation report's own keys stay at the top level; the network-wide
                    // view is an added `rarity` key.
                    #[derive(serde::Serialize)]
                    struct DiffJson<'a> {
                        #[serde(flatten)]
                        report: &'a ppcap_core::DeviationReport,
                        rarity: &'a ppcap_core::rarity::RarityReport,
                    }
                    let s = serde_json::to_string_pretty(&DiffJson {
                        report: &report,
                        rarity: &rarity,
                    })?;
                    match path {
                        "-" => println!("{s}"),
                        p => std::fs::write(p, &s)
                            .with_context(|| format!("write deviation report to {p}"))?,
                    }
                }
                Ok(())
            }
        },
        Command::Mcp {
            inputs,
            threat_feed,
            suppress,
            playbooks,
            allow_write,
            online,
            max_response_bytes,
            quiet,
        } => dispatch_mcp(
            &inputs,
            threat_feed,
            &suppress,
            &playbooks,
            allow_write,
            online,
            max_response_bytes,
            quiet,
        ),
        Command::Alerts {
            summary,
            diff,
            json,
            suppress,
        } => {
            let text = std::fs::read_to_string(&summary)
                .with_context(|| format!("read analysis output {}", summary.display()))?;
            let mut out: ppcap_core::AnalysisOutput = serde_json::from_str(&text)
                .with_context(|| format!("parse analysis output {}", summary.display()))?;
            // `--suppress` replaces the rules the analysis carries; without it the carried rules
            // (if any) still apply.
            let rules = if suppress.is_empty() {
                None
            } else {
                Some(load_suppression_rules(&suppress, false)?)
            };
            let today = ppcap_core::ymd_from_unix_secs(unix_now());
            if let Some(r) = rules.as_ref() {
                out.summary.suppression_rules = r.clone();
            }
            // Idempotent pure re-derive over the loaded summary (same fn as the analyze seam).
            ppcap_core::refresh_alerts(&mut out.summary);
            // Rules carried from the original run may have expired since.
            let expired = ppcap_core::expire_carried_rules(&mut out.summary, &today);
            if expired > 0 {
                eprintln!("suppress: {expired} carried rule(s) have expired and no longer apply");
            }
            if !out.summary.suppressions.is_empty() {
                eprintln!("{}", suppression_summary_line(&out.summary));
            }

            // Diff mode: compare against an OLDER analysis, matched by stable alert ids.
            if let Some(old_path) = diff.as_ref() {
                let old_text = std::fs::read_to_string(old_path)
                    .with_context(|| format!("read older analysis {}", old_path.display()))?;
                let mut old: ppcap_core::AnalysisOutput = serde_json::from_str(&old_text)
                    .with_context(|| format!("parse older analysis {}", old_path.display()))?;
                // Re-derive on the old side too, so pre-alerting summaries diff correctly. The
                // same `--suppress` rules apply to both sides, so the diff shows network change
                // rather than rule change.
                if let Some(r) = rules.as_ref() {
                    old.summary.suppression_rules = r.clone();
                }
                ppcap_core::refresh_alerts(&mut old.summary);
                ppcap_core::expire_carried_rules(&mut old.summary, &today);
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
            if out.summary.alerts.is_empty() && !out.summary.suppressions.is_empty() {
                eprintln!("alerts: none — every finding was suppressed by an analyst rule");
            } else if out.summary.alerts.is_empty() {
                eprintln!("alerts: none — no findings rose above informational");
            } else {
                eprintln!("{}", alerts_summary_line(&out.summary));
                if let Some(line) = noise_budget_line(&out.summary) {
                    eprintln!("{line}");
                }
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
        Command::Zeek {
            input,
            out_dir,
            json,
            eve,
            yara,
            summary,
            quiet,
        } => {
            let cfg = ppcap_core::PipelineConfig {
                writer: ppcap_core::columnar::WriterConfig {
                    capture_id: fnv1a64(input.to_string_lossy().as_bytes()),
                    ..Default::default()
                },
                yara: crate::yara::load(&yara, quiet)?.map(|y| y.rules),
                ..Default::default()
            };
            let mut logger = crate::zeek::logger(&out_dir, json)?;
            let mut out = ppcap_core::run_observing(&input, &cfg, &mut logger, |_, _, _| {})?;
            crate::zeek::fold_eve_files(&mut out.summary, &eve, quiet)?;
            crate::zeek::finish(logger, &out, &out_dir, quiet)?;
            if let Some(path) = summary.as_ref() {
                std::fs::write(path, out.to_json_pretty()?)
                    .with_context(|| format!("write JSON output to {}", path.display()))?;
            }
            Ok(())
        }
        Command::Eve {
            summary,
            eve,
            json,
            quiet,
        } => {
            let text = std::fs::read_to_string(&summary)
                .with_context(|| format!("read analysis output {}", summary.display()))?;
            let mut out: ppcap_core::AnalysisOutput = serde_json::from_str(&text)
                .with_context(|| format!("parse analysis output {}", summary.display()))?;
            crate::zeek::fold_eve_files(&mut out.summary, &eve, quiet)?;
            if !quiet && !out.summary.alerts.is_empty() {
                eprintln!("{}", alerts_summary_line(&out.summary));
            }
            let s = out.to_json_pretty()?;
            match json.as_deref() {
                None | Some("-") => println!("{s}"),
                Some(path) => {
                    std::fs::write(path, &s)
                        .with_context(|| format!("write JSON output to {path}"))?;
                }
            }
            Ok(())
        }
        Command::Push {
            summary,
            destinations,
            to,
            min_band,
            alerts,
            suppress,
            dry_run,
            out_dir,
            ledger,
            resend,
            example,
            json,
            quiet,
        } => {
            if example {
                let text = serde_json::to_string_pretty(
                    &ppcap_core::export::push::DestinationFile::example(),
                )?;
                println!("{text}");
                return Ok(());
            }
            let summary = summary.ok_or_else(|| anyhow!("push needs an analysis JSON"))?;
            let text = std::fs::read_to_string(&summary)
                .with_context(|| format!("read analysis output {}", summary.display()))?;
            let mut out: ppcap_core::AnalysisOutput = serde_json::from_str(&text)
                .with_context(|| format!("parse analysis output {}", summary.display()))?;
            if !suppress.is_empty() {
                out.summary.suppression_rules = load_suppression_rules(&suppress, quiet)?;
            }
            ppcap_core::refresh_alerts(&mut out.summary);
            let today = ppcap_core::ymd_from_unix_secs(unix_now());
            ppcap_core::expire_carried_rules(&mut out.summary, &today);

            let dtext = std::fs::read_to_string(&destinations).with_context(|| {
                format!(
                    "read destinations {} (start one with `ppcap push --example`)",
                    destinations.display()
                )
            })?;
            let file = ppcap_core::export::push::DestinationFile::parse(&dtext)
                .map_err(|e| anyhow!(e))
                .with_context(|| format!("parse destinations {}", destinations.display()))?;
            let ledger_path =
                ledger.unwrap_or_else(|| crate::push::default_ledger_path(&destinations));
            let mut book = crate::push::load_ledger(&ledger_path)?;
            let mode = match (dry_run, out_dir) {
                (true, _) => crate::push::Mode::DryRun,
                (false, Some(d)) => crate::push::Mode::OutDir(d),
                (false, None) => crate::push::Mode::Send,
            };
            let opts = crate::push::PushOptions {
                to,
                min_band,
                alerts,
                resend,
                mode,
                quiet,
            };
            let env = |k: &str| std::env::var(k).ok();
            let report = crate::push::run_push(
                &out,
                &file,
                &opts,
                &mut book,
                &crate::push::HttpSender,
                &env,
                unix_now(),
                &mut |l| crate::push::save_ledger(&ledger_path, l),
            )?;
            if let Some(dest) = json.as_deref() {
                let body = serde_json::to_string_pretty(&report)?;
                if dest == "-" {
                    println!("{body}");
                } else {
                    std::fs::write(dest, body + "\n")
                        .with_context(|| format!("write push report to {dest}"))?;
                }
            }
            match report.failed() {
                0 => Ok(()),
                n => Err(anyhow!("push: {n} alert(s) were not delivered")),
            }
        }
        Command::Timeline {
            summary,
            alerts,
            format,
            out,
        } => {
            let text = std::fs::read_to_string(&summary)
                .with_context(|| format!("read analysis output {}", summary.display()))?;
            let mut analysis: ppcap_core::AnalysisOutput = serde_json::from_str(&text)
                .with_context(|| format!("parse analysis output {}", summary.display()))?;
            // Re-derive so a summary written before timelines existed still gets them (its
            // DNS / first-contact rows need the context only a fresh analyze records).
            ppcap_core::refresh_alerts(&mut analysis.summary);
            let timelines = select_timelines(&analysis.summary.timelines, &alerts)?;
            if timelines.is_empty() {
                eprintln!("timeline: no alerts — nothing to tell");
            }
            let rendered = match format {
                TimelineFormat::Markdown => {
                    ppcap_core::timelines_text(&timelines, "markdown").expect("known format")
                }
                TimelineFormat::Csv => {
                    ppcap_core::timelines_text(&timelines, "csv").expect("known format")
                }
                TimelineFormat::Json => serde_json::to_string_pretty(&timelines)?,
            };
            match out.as_deref() {
                None | Some("-") => print!("{rendered}"),
                Some(p) => {
                    std::fs::write(p, &rendered)
                        .with_context(|| format!("write timeline to {p}"))?;
                    eprintln!("timeline: {} alert(s) written to {p}", timelines.len());
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
#[allow(clippy::too_many_arguments)]
fn dispatch_batch(
    dir: &std::path::Path,
    recursive: bool,
    case_out: Option<&std::path::Path>,
    threat_feed: Option<&std::path::Path>,
    hash: bool,
    strict: bool,
    quiet: bool,
    identity: ppcap_core::IdentityParams,
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
        identity,
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
pub(crate) fn fnv1a64(bytes: &[u8]) -> u64 {
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
    fn zeek_and_eve_subcommands_parse() {
        let cli =
            Cli::try_parse_from(["ppcap", "zeek", "x.pcap", "--json", "--eve", "e.json"]).unwrap();
        match cli.command {
            Command::Zeek {
                out_dir, json, eve, ..
            } => {
                assert_eq!(out_dir, PathBuf::from("zeek-logs"));
                assert!(json);
                assert_eq!(eve, vec![PathBuf::from("e.json")]);
            }
            _ => panic!("expected Zeek"),
        }
        let cli = Cli::try_parse_from(["ppcap", "eve", "s.json", "a.json", "b.json"]).unwrap();
        assert!(matches!(cli.command, Command::Eve { ref eve, .. } if eve.len() == 2));
        assert!(Cli::try_parse_from(["ppcap", "eve", "s.json"]).is_err());
        // `--zeek-json` needs `--zeek`.
        assert!(Cli::try_parse_from(["ppcap", "analyze", "x.pcap", "--zeek-json"]).is_err());
        let cli = Cli::try_parse_from(["ppcap", "analyze", "x.pcap", "--zeek", "d", "--eve", "e"])
            .unwrap();
        assert!(
            matches!(cli.command, Command::Analyze { zeek: Some(_), ref eve, .. } if eve.len() == 1)
        );
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
    fn keylog_flag_parses_and_defaults_off() {
        let cli = Cli::try_parse_from(["ppcap", "analyze", "x.pcap"]).unwrap();
        match cli.command {
            Command::Analyze { keylog, .. } => assert!(keylog.is_none()),
            _ => panic!("expected Analyze"),
        }
        let cli =
            Cli::try_parse_from(["ppcap", "analyze", "x.pcap", "--keylog", "keys.log"]).unwrap();
        match cli.command {
            Command::Analyze { keylog, .. } => {
                assert_eq!(keylog.as_deref(), Some(std::path::Path::new("keys.log")))
            }
            _ => panic!("expected Analyze"),
        }
    }

    #[test]
    fn keylog_conflicts_with_batch() {
        assert!(Cli::try_parse_from([
            "ppcap", "analyze", "--batch", "dir", "--keylog", "keys.log"
        ])
        .is_err());
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
    fn analyze_identity_flags_parse() {
        let on = Cli::try_parse_from(["ppcap", "analyze", "x.pcap"]).unwrap();
        match on.command {
            Command::Analyze {
                no_identity, dc, ..
            } => {
                assert!(!no_identity);
                assert!(dc.is_empty());
            }
            _ => panic!("expected Analyze"),
        }
        let off = Cli::try_parse_from([
            "ppcap",
            "analyze",
            "x.pcap",
            "--no-identity",
            "--dc",
            "10.0.0.10,10.0.0.11",
            "--dc",
            "fd00::1",
        ])
        .unwrap();
        match off.command {
            Command::Analyze {
                no_identity, dc, ..
            } => {
                assert!(no_identity);
                let dc: Vec<String> = dc.iter().map(|i| i.to_string()).collect();
                assert_eq!(dc, vec!["10.0.0.10", "10.0.0.11", "fd00::1"]);
            }
            _ => panic!("expected Analyze"),
        }
        assert!(Cli::try_parse_from(["ppcap", "analyze", "x.pcap", "--dc", "nope"]).is_err());
    }

    #[test]
    fn analyze_no_encrypted_analysis_flag_parses() {
        // Default: the encrypted-traffic detectors are on (the flag is absent).
        let on = Cli::try_parse_from(["ppcap", "analyze", "x.pcap"]).unwrap();
        match on.command {
            Command::Analyze {
                no_encrypted_analysis,
                ..
            } => assert!(!no_encrypted_analysis),
            _ => panic!("expected Analyze"),
        }
        // Opt out.
        let off =
            Cli::try_parse_from(["ppcap", "analyze", "x.pcap", "--no-encrypted-analysis"]).unwrap();
        match off.command {
            Command::Analyze {
                no_encrypted_analysis,
                ..
            } => assert!(no_encrypted_analysis),
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
    fn push_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "ppcap",
            "push",
            "out.json",
            "-d",
            "team/destinations.json",
            "--to",
            "jira",
            "--to",
            "soc-slack",
            "--min-band",
            "act-now",
            "--dry-run",
        ])
        .unwrap();
        match cli.command {
            Command::Push {
                summary,
                destinations,
                to,
                min_band,
                dry_run,
                out_dir,
                example,
                ..
            } => {
                assert_eq!(summary, Some(PathBuf::from("out.json")));
                assert_eq!(destinations, PathBuf::from("team/destinations.json"));
                assert_eq!(to, ["jira", "soc-slack"]);
                assert_eq!(min_band, Some(ppcap_core::PriorityBand::ActNow));
                assert!(dry_run && out_dir.is_none() && !example);
            }
            _ => panic!("expected Push"),
        }
        assert!(Cli::try_parse_from(["ppcap", "push", "--example"]).is_ok());
        assert!(
            Cli::try_parse_from(["ppcap", "push"]).is_err(),
            "summary required"
        );
        assert!(
            Cli::try_parse_from(["ppcap", "push", "o.json", "--dry-run", "--out-dir", "x"])
                .is_err()
        );
        assert!(Cli::try_parse_from(["ppcap", "push", "o.json", "--min-band", "urgent"]).is_err());
    }

    #[test]
    fn alerts_subcommand_parses() {
        let cli = Cli::try_parse_from(["ppcap", "alerts", "out.json", "--json", "-"]).unwrap();
        match cli.command {
            Command::Alerts {
                summary,
                diff,
                json,
                suppress,
            } => {
                assert_eq!(summary, std::path::PathBuf::from("out.json"));
                assert_eq!(diff, None);
                assert_eq!(json.as_deref(), Some("-"));
                assert!(suppress.is_empty());
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
                keylog: None,
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
    fn timeline_exports_markdown_csv_json_and_rejects_unknown_ids() {
        let mut summary = ppcap_core::Summary::empty();
        summary.findings = vec![ppcap_core::Finding {
            kind: ppcap_core::FindingKind::Beacon,
            severity: ppcap_core::Severity::High,
            score: 75,
            title: "beacon: 10.0.0.7".to_string(),
            src_ip: "10.0.0.7".to_string(),
            dst_ip: Some("45.77.13.37".to_string()),
            dst_port: Some(443),
            attack: vec!["T1071".to_string()],
            evidence: vec!["every 30s".to_string()],
            interval_ns: None,
            jitter_cv: None,
            contacts: None,
            first_seen_ns: Some(1_700_000_000_000_000_000),
            last_seen_ns: Some(1_700_000_060_000_000_000),
            victims: Vec::new(),
        }];
        // Written without alerts/timelines: the command re-derives them.
        let out = ppcap_core::AnalysisOutput {
            summary,
            ..Default::default()
        };
        let input = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(input.path(), out.to_json_pretty().unwrap()).unwrap();
        let run = |args: &[&str]| -> anyhow::Result<String> {
            let dest = tempfile::NamedTempFile::new().unwrap();
            let mut argv = vec!["ppcap", "timeline", input.path().to_str().unwrap()];
            argv.extend_from_slice(args);
            argv.extend_from_slice(&["--out", dest.path().to_str().unwrap()]);
            dispatch(Cli::try_parse_from(argv).unwrap())?;
            Ok(std::fs::read_to_string(dest.path()).unwrap())
        };
        let md = run(&[]).unwrap();
        assert!(md.contains("| Time (UTC) | Host | Event | What | Severity | Packets |"));
        assert!(md.contains("`host 10.0.0.7 and host 45.77.13.37 and port 443`"));
        let csv = run(&["--format", "csv"]).unwrap();
        assert!(csv.starts_with("alert_id,time_utc,"));
        assert_eq!(csv.lines().count(), 2);
        let json: Vec<ppcap_core::AlertTimeline> =
            serde_json::from_str(&run(&["--format", "json"]).unwrap()).unwrap();
        assert_eq!(json.len(), 1);
        let id = json[0].alert_id.clone();
        let one: Vec<ppcap_core::AlertTimeline> =
            serde_json::from_str(&run(&["--format", "json", "--alert", &id]).unwrap()).unwrap();
        assert_eq!(one[0].alert_id, id);
        let err = run(&["--alert", "alert:nope"]).unwrap_err().to_string();
        assert!(err.contains("alert:nope"), "{err}");
    }

    #[test]
    fn review_rates_file_and_noise_budget_line() {
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("review-rates.json");
        std::fs::write(&good, r#"{"version":1,"minutes_per_story":5}"#).unwrap();
        let loaded = load_review_rates(&good).unwrap();
        let rates = loaded.rates;
        assert_eq!(rates.minutes_per_story, 5.0);
        assert_eq!(loaded.bytes, 35);
        assert_eq!(loaded.sha256.len(), 64);
        let bad = dir.path().join("bad.json");
        std::fs::write(&bad, r#"{"version":1,"minutes_per_finding":-2}"#).unwrap();
        let err = format!("{:#}", load_review_rates(&bad).unwrap_err());
        assert!(err.contains("minutes_per_finding"), "{err}");

        let mut summary = ppcap_core::Summary::empty();
        assert!(noise_budget_line(&summary).is_none());
        summary.total_packets = 12_000;
        summary.total_flows = 3_000;
        ppcap_core::refresh_alerts(&mut summary);
        ppcap_core::apply_review_rates(&mut summary, rates);
        let line = noise_budget_line(&summary).unwrap();
        assert!(
            line.starts_with("noise budget: 12k packets → 3k flows → 0 stories"),
            "{line}"
        );
        assert!(line.contains("(5 min per story)"), "{line}");
    }

    #[test]
    fn playbook_show_lint_and_team_files() {
        let mut summary = ppcap_core::Summary::empty();
        summary.findings = vec![ppcap_core::Finding {
            kind: ppcap_core::FindingKind::Beacon,
            severity: ppcap_core::Severity::High,
            score: 75,
            title: "beacon: 10.0.0.7".to_string(),
            src_ip: "10.0.0.7".to_string(),
            dst_ip: Some("45.77.13.37".to_string()),
            dst_port: Some(443),
            attack: vec!["T1071".to_string()],
            evidence: vec!["every 30s".to_string()],
            interval_ns: None,
            jitter_cv: None,
            contacts: None,
            first_seen_ns: Some(1_700_000_000_000_000_000),
            last_seen_ns: Some(1_700_000_060_000_000_000),
            victims: Vec::new(),
        }];
        let out = ppcap_core::AnalysisOutput {
            summary,
            ..Default::default()
        };
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("a.json");
        std::fs::write(&input, out.to_json_pretty().unwrap()).unwrap();
        let team = dir.path().join("team.json");
        std::fs::write(
            &team,
            r#"{"version":1,"playbooks":[{"id":"ours","title":"Our beacon list","kinds":["beacon"],
               "steps":[{"id":"t","question":"Ticket {actor}","why":"Policy."}]}]}"#,
        )
        .unwrap();
        let dest = dir.path().join("out.md");
        let run = |args: &[&str]| -> anyhow::Result<String> {
            let mut argv = vec!["ppcap", "playbook", "show", input.to_str().unwrap()];
            argv.extend_from_slice(args);
            argv.extend_from_slice(&["--out", dest.to_str().unwrap()]);
            dispatch(Cli::try_parse_from(argv).unwrap())?;
            Ok(std::fs::read_to_string(&dest).unwrap())
        };
        let md = run(&[]).unwrap();
        assert!(md.contains("## Command and control channel"), "{md}");
        assert!(md.contains("dst_ip = '45.77.13.37'"));
        let json: Vec<ppcap_core::PlaybookRun> =
            serde_json::from_str(&run(&["--format", "json"]).unwrap()).unwrap();
        assert_eq!(json[0].playbook_id, "c2-channel");
        let md = run(&["--playbooks", team.to_str().unwrap()]).unwrap();
        assert!(md.contains("## Our beacon list"));
        assert!(md.contains("**Ticket 10.0.0.7**"));
        assert!(md.contains("_Playbook from team.json_"));
        let err = run(&["--alert", "alert:nope"]).unwrap_err().to_string();
        assert!(err.contains("alert:nope"), "{err}");

        let lint = |path: &std::path::Path| {
            dispatch(
                Cli::try_parse_from(["ppcap", "playbook", "lint", path.to_str().unwrap()]).unwrap(),
            )
        };
        lint(&team).unwrap();
        let bad = dir.path().join("bad.json");
        std::fs::write(
            &bad,
            r#"{"version":1,"playbooks":[{"id":"x","title":"X","kinds":["beacon"],
            "steps":[{"id":"s","question":"Who is {attacker}","why":""}]}]}"#,
        )
        .unwrap();
        assert!(lint(&bad).unwrap_err().to_string().contains("1 problem"));
        let err = run(&["--playbooks", bad.to_str().unwrap()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown placeholder {attacker}"), "{err}");
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
            keylog: None,
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
    fn review_rates_fail_before_analysis_and_are_sealed_as_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let p = |n: &str| dir.path().join(n).to_string_lossy().into_owned();
        let parse = |args: &[&str]| Cli::try_parse_from(args).unwrap();
        dispatch(parse(&[
            "ppcap",
            "gen",
            &p("in.pcap"),
            "--scenario",
            "beacon",
            "--packets",
            "500",
        ]))
        .unwrap();
        // A bad rates file stops the run before anything is written.
        std::fs::write(p("bad.json"), r#"{"version":9}"#).unwrap();
        let analyze = |rates: &str, json: &str| {
            parse(&[
                "ppcap",
                "analyze",
                &p("in.pcap"),
                "--json",
                &p(json),
                "--review-rates",
                &p(rates),
                "--evidence",
                &p("case.json"),
                "--quiet",
            ])
        };
        assert!(dispatch(analyze("bad.json", "bad-out.json")).is_err());
        assert!(!dir.path().join("bad-out.json").exists());
        assert!(dispatch(analyze("missing.json", "bad-out.json")).is_err());
        assert!(!dir.path().join("bad-out.json").exists());

        // A good one is applied, listed in the settings and sealed as an input artifact.
        std::fs::write(p("rates.json"), r#"{"version":1,"minutes_per_finding":20}"#).unwrap();
        dispatch(analyze("rates.json", "out.json")).unwrap();
        let out: ppcap_core::AnalysisOutput =
            serde_json::from_str(&std::fs::read_to_string(p("out.json")).unwrap()).unwrap();
        assert_eq!(
            out.summary.noise_budget.unwrap().rates.minutes_per_finding,
            20.0
        );
        let m = ppcap_core::EvidenceManifest::from_json_str(
            &std::fs::read_to_string(p("case.json")).unwrap(),
        )
        .unwrap();
        assert!(m.settings.iter().any(|s| s.starts_with("--review-rates ")));
        assert!(m.artifacts.iter().any(|a| a.role == "review_rates"));
        dispatch(parse(&["ppcap", "verify", &p("case.json")])).unwrap();
        std::fs::write(p("rates.json"), r#"{"version":1,"minutes_per_finding":40}"#).unwrap();
        assert!(dispatch(parse(&["ppcap", "verify", &p("case.json")])).is_err());
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

            // A manifest in a subdirectory, with the input outside it: paths are recorded
            // relative to the manifest (or absolute), so the intact bundle still verifies.
            std::fs::create_dir("results")?;
            let analyze = Cli::try_parse_from([
                "ppcap",
                "analyze",
                "in.pcap",
                "--json",
                "results/out.json",
                "--evidence",
                "results/case.json",
                "--no-encrypted-analysis",
                "--quiet",
            ])
            .unwrap();
            dispatch(analyze)?;
            let m = ppcap_core::EvidenceManifest::from_json_str(&std::fs::read_to_string(
                "results/case.json",
            )?)?;
            assert_eq!(m.artifacts[0].path, "out.json");
            assert!(m.settings.iter().any(|s| s == "--no-encrypted-analysis"));
            let verify = Cli::try_parse_from(["ppcap", "verify", "results/case.json"]).unwrap();
            dispatch(verify)?;

            // A --keylog input is sealed as a file record, so verify notices it going missing.
            let keylog = format!("CLIENT_RANDOM {} {}\n", "ab".repeat(32), "cd".repeat(48));
            std::fs::write("keys.log", &keylog)?;
            let analyze = Cli::try_parse_from([
                "ppcap",
                "analyze",
                "in.pcap",
                "--json",
                "k.json",
                "--keylog",
                "keys.log",
                "--evidence",
                "k.evidence.json",
                "--quiet",
            ])
            .unwrap();
            dispatch(analyze)?;
            let m = ppcap_core::EvidenceManifest::from_json_str(&std::fs::read_to_string(
                "k.evidence.json",
            )?)?;
            let rec = m
                .artifacts
                .iter()
                .find(|a| a.role == "keylog_input")
                .expect("keylog record");
            assert_eq!(rec.sha256, ppcap_core::sha256_hex(keylog.as_bytes()));
            std::fs::remove_file("keys.log")?;
            let verify = Cli::try_parse_from(["ppcap", "verify", "k.evidence.json"]).unwrap();
            assert!(dispatch(verify).is_err());
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
                ..Default::default()
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
        // The network-wide view rides alongside under `rarity` (1 capture of history: warming up).
        assert_eq!(report["rarity"]["baseline_loaded"], true);
        assert_eq!(report["rarity"]["warming_up"], true);

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

    #[test]
    fn analyze_suppress_is_repeatable() {
        let cli = Cli::try_parse_from([
            "ppcap",
            "analyze",
            "x.pcap",
            "--suppress",
            "team.json",
            "--suppress",
            "mine.json",
        ])
        .unwrap();
        match cli.command {
            Command::Analyze { suppress, .. } => assert_eq!(
                suppress,
                vec![PathBuf::from("team.json"), PathBuf::from("mine.json")]
            ),
            _ => panic!("expected Analyze"),
        }
    }

    #[test]
    fn suppress_add_test_and_alerts_round_trip() {
        let mut summary = ppcap_core::Summary::empty();
        summary.findings = vec![ppcap_core::Finding {
            kind: ppcap_core::FindingKind::MissingSni,
            severity: ppcap_core::Severity::Medium,
            score: 45,
            title: "missing SNI: 10.0.0.5".to_string(),
            src_ip: "10.0.0.5".to_string(),
            dst_ip: Some("52.1.1.1".to_string()),
            dst_port: Some(443),
            attack: Vec::new(),
            evidence: Vec::new(),
            interval_ns: None,
            jitter_cv: None,
            contacts: None,
            first_seen_ns: Some(1),
            last_seen_ns: Some(2),
            victims: Vec::new(),
        }];
        ppcap_core::refresh_alerts(&mut summary);
        let alert_id = summary.alerts[0].id.clone();
        let out = ppcap_core::AnalysisOutput {
            summary,
            ..ppcap_core::AnalysisOutput::default()
        };
        let dir = tempfile::tempdir().unwrap();
        let analysis = dir.path().join("a.json");
        std::fs::write(&analysis, out.to_json_pretty().unwrap()).unwrap();
        let rules = dir.path().join("suppressions.json");
        let a = analysis.to_str().unwrap();
        let r = rules.to_str().unwrap();

        // Teach it (twice: the second add dedupes by id).
        for _ in 0..2 {
            let cli = Cli::try_parse_from([
                "ppcap", "suppress", "add", a, "--alert", &alert_id, "--reason", "IoT hub",
                "--author", "john", "--file", r,
            ])
            .unwrap();
            dispatch(cli).unwrap();
        }
        let file: ppcap_core::SuppressionFile =
            serde_json::from_str(&std::fs::read_to_string(&rules).unwrap()).unwrap();
        assert_eq!(file.rules.len(), 1);
        assert_eq!(file.rules[0].src.as_deref(), Some("10.0.0.5"));
        assert!(file.rules[0].expires.is_some());

        // `suppress test` reports the hit.
        let hits = dir.path().join("hits.json");
        let cli = Cli::try_parse_from([
            "ppcap",
            "suppress",
            "test",
            a,
            "--suppress",
            r,
            "--json",
            hits.to_str().unwrap(),
        ])
        .unwrap();
        dispatch(cli).unwrap();
        let hits: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&hits).unwrap()).unwrap();
        assert_eq!(hits[0]["status"], "suppressed");

        // `alerts --suppress` writes an analysis whose queue is empty but whose finding is
        // still accounted for.
        let updated = dir.path().join("b.json");
        let cli = Cli::try_parse_from([
            "ppcap",
            "alerts",
            a,
            "--suppress",
            r,
            "--json",
            updated.to_str().unwrap(),
        ])
        .unwrap();
        dispatch(cli).unwrap();
        let b: ppcap_core::AnalysisOutput =
            serde_json::from_str(&std::fs::read_to_string(&updated).unwrap()).unwrap();
        assert!(b.summary.alerts.is_empty());
        assert_eq!(b.summary.suppressions.len(), 1);
        assert_eq!(b.summary.suppression_rules.len(), 1);

        // An unknown alert id is a hard error, and the rule file is left alone.
        let cli = Cli::try_parse_from([
            "ppcap",
            "suppress",
            "add",
            a,
            "--alert",
            "alert:nope",
            "--reason",
            "x",
            "--file",
            r,
        ])
        .unwrap();
        assert!(dispatch(cli).is_err());
    }
}
