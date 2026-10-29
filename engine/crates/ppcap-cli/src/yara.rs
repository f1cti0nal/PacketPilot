//! `--yara`: user YARA rule files, matched by the engine over every carved file.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context};
use ppcap_core::YaraRules;

/// The merged rule set, and each file's digest of the exact bytes parsed (for `--evidence`).
pub(crate) struct LoadedYara {
    pub rules: Arc<YaraRules>,
    pub files: Vec<(PathBuf, String, u64)>,
}

/// Load and merge `paths` in order (a rule name seen twice keeps its first definition). Rules the
/// engine can't evaluate are listed on stderr and skipped; a set with no usable rule is an error.
pub(crate) fn load(paths: &[PathBuf], quiet: bool) -> anyhow::Result<Option<LoadedYara>> {
    if paths.is_empty() {
        return Ok(None);
    }
    let mut rules = YaraRules::default();
    let mut files = Vec::new();
    let mut skipped = 0;
    for path in paths {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading YARA rules {}", path.display()))?;
        files.push((
            path.clone(),
            ppcap_core::sha256_hex(text.as_bytes()),
            text.len() as u64,
        ));
        let parsed = YaraRules::parse(&text);
        let mut skips = parsed.skipped;
        skips.extend(rules.extend(parsed.rules));
        skipped += skips.len();
        if !quiet {
            for s in &skips {
                let name = if s.name.is_empty() {
                    "(unnamed)"
                } else {
                    &s.name
                };
                eprintln!("yara: {}: skipped {name}: {}", path.display(), s.reason);
            }
        }
    }
    if rules.is_empty() {
        let names: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
        bail!("no usable YARA rules in {}", names.join(", "));
    }
    if !quiet {
        eprintln!("yara: {} rules loaded, {skipped} skipped", rules.len());
    }
    Ok(Some(LoadedYara {
        rules: Arc::new(rules),
        files,
    }))
}

impl LoadedYara {
    /// `--yara <path> (sha256 …)` lines for the evidence manifest's settings.
    pub(crate) fn settings(&self) -> impl Iterator<Item = String> + '_ {
        self.files
            .iter()
            .map(|(p, sha, _)| format!("--yara {} (sha256 {sha})", p.display()))
    }
}
