//! The captures an MCP session serves, loaded once at launch.
//!
//! An input is either an `analyze --json` output (read as is, its pcap and flows Parquet found
//! through the paths it records) or a capture, analysed here with default settings into a
//! scratch directory that is removed when the server exits.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};

/// One loaded analysis plus where its packets and flows live.
pub struct Capture {
    /// Short id agents pass as `capture` (the file stem, de-duplicated).
    pub id: String,
    pub out: ppcap_core::AnalysisOutput,
    /// The original capture, when it is on disk (packet tools need it).
    pub pcap: Option<PathBuf>,
    /// The flows Parquet, when it is on disk (flow tools need it).
    pub flows: Option<PathBuf>,
}

/// Settings shared by every input of one session.
pub struct LoadOptions {
    pub threat_feed: Option<PathBuf>,
    /// `Some` when `--suppress` was given: its active rules (already loaded and expiry-filtered,
    /// possibly none), which replace whatever a summary carries. `None` => a summary keeps its
    /// own rules and captures get none.
    pub suppress: Option<Vec<ppcap_core::SuppressionRule>>,
    /// Where analysed captures write their flows Parquet.
    pub work_dir: PathBuf,
    pub quiet: bool,
}

/// A scratch directory deleted on drop.
pub struct WorkDir(pub PathBuf);

impl WorkDir {
    /// A fresh, private directory under the system temp dir. `create_dir` (not `_all`) fails if
    /// the name already exists, so a directory or symlink planted at a guessable name is never
    /// reused: a clash just moves on to the next name.
    pub fn create() -> anyhow::Result<WorkDir> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let seed = crate::cli::fnv1a64(format!("{}:{nanos}", std::process::id()).as_bytes());
        let mut last_err = None;
        for attempt in 0u64..16 {
            let dir = std::env::temp_dir().join(format!(
                "ppcap-mcp-{}-{:016x}",
                std::process::id(),
                seed.wrapping_add(attempt.wrapping_mul(0x9e37_79b9_7f4a_7c15))
            ));
            match std::fs::create_dir(&dir) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt as _;
                        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                            .with_context(|| format!("restrict {}", dir.display()))?;
                    }
                    return Ok(WorkDir(dir));
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last_err = Some(e),
                Err(e) => {
                    return Err(anyhow::Error::new(e))
                        .with_context(|| format!("create scratch directory {}", dir.display()))
                }
            }
        }
        Err(anyhow!(
            "could not create a fresh scratch directory under {}: {}",
            std::env::temp_dir().display(),
            last_err.map(|e| e.to_string()).unwrap_or_default()
        ))
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn looks_like_summary(path: &Path) -> bool {
    if path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("json"))
    {
        return true;
    }
    // Sniff: an analysis JSON starts with `{`; every capture container starts with binary magic.
    use std::io::Read as _;
    let mut head = [0u8; 64];
    let n = std::fs::File::open(path)
        .and_then(|mut f| f.read(&mut head))
        .unwrap_or(0);
    head[..n]
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|b| *b == b'{')
}

/// Where a path recorded in a summary points from here. An absolute path is taken as is. A
/// relative one is tried beside the summary first (the bundle moved whole), then against the
/// working directory (how `analyze` recorded it), so a same-named file elsewhere never wins over
/// the one that travels with the summary.
fn resolve(recorded: &str, base: Option<&Path>) -> Option<PathBuf> {
    if recorded.is_empty() {
        return None;
    }
    let p = PathBuf::from(recorded);
    if p.is_absolute() {
        return p.is_file().then_some(p);
    }
    if let Some(alt) = base.map(|b| b.join(&p)) {
        if alt.is_file() {
            return Some(alt);
        }
    }
    p.is_file().then_some(p)
}

/// A unique short id for `path` among `taken`.
pub fn capture_id(path: &Path, taken: &[String]) -> String {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "capture".into());
    // Strip every capture/summary extension (`a.pcap.gz`, `a.summary.json` -> `a`).
    let mut stem = name.as_str();
    while let Some((head, ext)) = stem.rsplit_once('.') {
        let ext = ext.to_ascii_lowercase();
        if head.is_empty()
            || !matches!(
                ext.as_str(),
                "pcap" | "pcapng" | "cap" | "gz" | "json" | "summary" | "analysis"
            )
        {
            break;
        }
        stem = head;
    }
    let base: String = stem
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let base = if base.is_empty() {
        "capture".into()
    } else {
        base
    };
    let mut id = base.clone();
    let mut n = 2;
    while taken.contains(&id) {
        id = format!("{base}-{n}");
        n += 1;
    }
    id
}

/// Load one input (summary JSON or capture).
pub fn load(path: &Path, opts: &LoadOptions, taken: &[String]) -> anyhow::Result<Capture> {
    if !path.is_file() {
        return Err(anyhow!(
            "input {} does not exist or is not a file",
            path.display()
        ));
    }
    let id = capture_id(path, taken);
    if looks_like_summary(path) {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read analysis output {}", path.display()))?;
        let mut out: ppcap_core::AnalysisOutput = serde_json::from_str(&text)
            .with_context(|| format!("parse analysis output {}", path.display()))?;
        if let Some(rules) = &opts.suppress {
            out.summary.suppression_rules = rules.clone();
        }
        // Same idempotent re-derive `ppcap alerts` runs, so older summaries gain alerts and
        // timelines, and carried rules that have since expired stop applying.
        ppcap_core::refresh_alerts(&mut out.summary);
        let today = ppcap_core::ymd_from_unix_secs(crate::cli::unix_now());
        ppcap_core::expire_carried_rules(&mut out.summary, &today);
        let base = path.parent();
        let pcap = resolve(&out.source_path, base);
        let flows = out
            .flows_parquet_path
            .as_deref()
            .and_then(|p| resolve(p, base));
        return Ok(Capture {
            id,
            out,
            pcap,
            flows,
        });
    }

    let parquet = opts.work_dir.join(format!("{id}.flows.parquet"));
    let cfg = ppcap_core::PipelineConfig {
        flows_parquet: Some(parquet.clone()),
        threat_feed: opts.threat_feed.clone(),
        writer: ppcap_core::columnar::WriterConfig {
            capture_id: crate::cli::fnv1a64(path.to_string_lossy().as_bytes()),
            ..Default::default()
        },
        ..Default::default()
    };
    if !opts.quiet {
        eprintln!("mcp: analysing {} ...", path.display());
    }
    let mut out = ppcap_core::run(path, &cfg, |_, _, _| {})
        .with_context(|| format!("analyse {}", path.display()))?;
    if let Some(rules) = opts.suppress.as_ref().filter(|r| !r.is_empty()) {
        ppcap_core::apply_suppressions(&mut out.summary, rules.clone());
    }
    Ok(Capture {
        id,
        out,
        pcap: Some(path.to_path_buf()),
        flows: parquet.is_file().then_some(parquet),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_paths_prefer_the_summary_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("capture.pcap");
        std::fs::write(&file, b"x").unwrap();
        assert_eq!(
            resolve("capture.pcap", Some(dir.path())),
            Some(file.clone())
        );
        let abs = file.display().to_string();
        assert_eq!(resolve(&abs, Some(Path::new("/elsewhere"))), Some(file));
        assert_eq!(resolve("missing.pcap", Some(dir.path())), None);
        assert_eq!(resolve("", Some(dir.path())), None);
    }

    #[test]
    fn ids_strip_extensions_and_dedupe() {
        let taken = vec!["incident".to_string()];
        assert_eq!(
            capture_id(Path::new("/x/incident.pcap.gz"), &taken),
            "incident-2"
        );
        assert_eq!(
            capture_id(Path::new("/x/web traffic.pcapng"), &[]),
            "web_traffic"
        );
        assert_eq!(capture_id(Path::new("/x/run.summary.json"), &[]), "run");
        assert_eq!(capture_id(Path::new("/x/v1.2.pcap"), &[]), "v1_2");
    }
}
