//! Zeek logs out (`ppcap zeek`, `analyze --zeek`) and Suricata EVE in (`analyze --eve`,
//! `ppcap eve`): the file-system side of [`ppcap_core::ZeekLogger`] and [`ppcap_core::read_eve`].

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Writes each Zeek log to `<dir>/<path>.log`, creating the directory and files on first use.
pub struct DirSink {
    dir: PathBuf,
    files: BTreeMap<String, BufWriter<File>>,
}

impl DirSink {
    pub fn new(dir: &Path) -> DirSink {
        DirSink {
            dir: dir.to_path_buf(),
            files: BTreeMap::new(),
        }
    }

    /// Flush every log to disk.
    pub fn flush(&mut self) -> std::io::Result<()> {
        for f in self.files.values_mut() {
            f.flush()?;
        }
        Ok(())
    }
}

impl ppcap_core::LogSink for DirSink {
    fn write(&mut self, log: &str, bytes: &[u8]) -> std::io::Result<()> {
        if !self.files.contains_key(log) {
            std::fs::create_dir_all(&self.dir)?;
            let f = File::create(self.dir.join(log))?;
            self.files.insert(log.to_string(), BufWriter::new(f));
        }
        match self.files.get_mut(log) {
            Some(f) => f.write_all(bytes),
            None => Ok(()),
        }
    }
}

pub type DirLogger = ppcap_core::ZeekLogger<DirSink>;

/// A logger writing to `dir`, opened now.
pub fn logger(dir: &Path, json: bool) -> DirLogger {
    let format = if json {
        ppcap_core::ZeekFormat::Json
    } else {
        ppcap_core::ZeekFormat::Tsv
    };
    let open = ppcap_core::zeek_header_time(crate::cli::unix_now());
    ppcap_core::ZeekLogger::new(DirSink::new(dir), format, &open)
}

/// Write the logs that need the finished analysis, close every log, and report on stderr.
pub fn finish(
    logger: DirLogger,
    out: &ppcap_core::AnalysisOutput,
    dir: &Path,
    quiet: bool,
) -> Result<ppcap_core::ZeekReport> {
    let close = ppcap_core::zeek_header_time(crate::cli::unix_now());
    let (mut sink, report) = logger
        .finish(out, &close)
        .with_context(|| format!("write Zeek logs to {}", dir.display()))?;
    sink.flush()
        .with_context(|| format!("write Zeek logs to {}", dir.display()))?;
    if !quiet {
        let parts: Vec<String> = report
            .logs
            .iter()
            .map(|(log, rows)| format!("{log} {rows}"))
            .collect();
        eprintln!(
            "wrote Zeek logs ({}) -> {}",
            if parts.is_empty() {
                "no rows".to_string()
            } else {
                parts.join(", ")
            },
            dir.display()
        );
    }
    Ok(report)
}

/// Fold each EVE file's alerts into the analysis, reporting per file on stderr.
pub fn fold_eve_files(
    summary: &mut ppcap_core::Summary,
    files: &[PathBuf],
    quiet: bool,
) -> Result<()> {
    for path in files {
        let f = File::open(path).with_context(|| format!("open EVE file {}", path.display()))?;
        let imp = ppcap_core::read_eve(BufReader::new(f))
            .with_context(|| format!("read EVE file {}", path.display()))?;
        let added = ppcap_core::fold_eve(summary, &imp);
        if !quiet {
            eprintln!(
                "eve: {} alert{} -> {} finding{} ({added} new) from {}{}",
                imp.alerts,
                if imp.alerts == 1 { "" } else { "s" },
                imp.findings.len(),
                if imp.findings.len() == 1 { "" } else { "s" },
                path.display(),
                if imp.skipped > 0 {
                    format!(", {} line(s) skipped", imp.skipped)
                } else {
                    String::new()
                }
            );
        }
        if imp.lines > 0 && imp.alerts == 0 && imp.other_events == 0 {
            anyhow::bail!(
                "{} has no Suricata EVE events (expected one JSON object per line with an \
                 `event_type`)",
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ppcap_core::LogSink;

    #[test]
    fn dir_sink_creates_the_folder_and_appends() {
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("zeek");
        let mut sink = DirSink::new(&logs);
        sink.write("conn.log", b"a\n").unwrap();
        sink.write("conn.log", b"b\n").unwrap();
        sink.write("dns.log", b"c\n").unwrap();
        sink.flush().unwrap();
        assert_eq!(
            std::fs::read_to_string(logs.join("conn.log")).unwrap(),
            "a\nb\n"
        );
        assert_eq!(
            std::fs::read_to_string(logs.join("dns.log")).unwrap(),
            "c\n"
        );
    }

    #[test]
    fn a_file_without_eve_events_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.json");
        std::fs::write(&p, "{\"a\":1}\n").unwrap();
        let mut s = ppcap_core::Summary::empty();
        assert!(fold_eve_files(&mut s, &[p], true).is_err());
    }
}
