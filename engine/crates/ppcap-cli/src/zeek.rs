//! Zeek logs out (`ppcap zeek`, `analyze --zeek`) and Suricata EVE in (`analyze --eve`,
//! `ppcap eve`): the file-system side of [`ppcap_core::ZeekLogger`] and [`ppcap_core::read_eve`].

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Every log `ZeekLogger` can write; an export clears all of them first, so a reused directory never
/// mixes an earlier export's logs with this one's.
const LOG_FILES: [&str; 7] = [
    "conn.log",
    "dns.log",
    "http.log",
    "ssl.log",
    "ssh.log",
    "files.log",
    "notice.log",
];

/// Remove the Zeek logs an earlier export left in `dir` (other files are left alone).
pub fn clear_logs(dir: &Path) -> Result<()> {
    for name in LOG_FILES {
        let path = dir.join(name);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| format!("remove old Zeek log {}", path.display()))
            }
        }
    }
    Ok(())
}

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

/// A logger writing to `dir`, opened now. Logs from an earlier export in `dir` are removed.
pub fn logger(dir: &Path, json: bool) -> Result<DirLogger> {
    clear_logs(dir)?;
    let format = if json {
        ppcap_core::ZeekFormat::Json
    } else {
        ppcap_core::ZeekFormat::Tsv
    };
    let open = ppcap_core::zeek_header_time(crate::cli::unix_now());
    Ok(ppcap_core::ZeekLogger::new(
        DirSink::new(dir),
        format,
        &open,
    ))
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
    if files.is_empty() {
        return Ok(());
    }
    // One import across every file, so hits of one signature in several files add up.
    let mut imp = ppcap_core::EveImport::default();
    for path in files {
        let f = File::open(path).with_context(|| format!("open EVE file {}", path.display()))?;
        let before = (imp.lines, imp.alerts, imp.other_events);
        imp.read(BufReader::new(f))
            .with_context(|| format!("read EVE file {}", path.display()))?;
        if imp.lines > before.0 && imp.alerts == before.1 && imp.other_events == before.2 {
            anyhow::bail!(
                "{} has no Suricata EVE events (expected one JSON object per line with an \
                 `event_type`)",
                path.display()
            );
        }
    }
    imp.finish();
    let added = ppcap_core::fold_eve(summary, &imp);
    if !quiet {
        eprintln!(
            "eve: {} alert{} -> {} finding{} ({added} new){}",
            imp.alerts,
            if imp.alerts == 1 { "" } else { "s" },
            imp.findings.len(),
            if imp.findings.len() == 1 { "" } else { "s" },
            if imp.skipped > 0 {
                format!(", {} line(s) skipped", imp.skipped)
            } else {
                String::new()
            }
        );
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
    fn an_export_clears_old_logs_but_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("http.log"), "old").unwrap();
        std::fs::write(dir.path().join("notes.txt"), "keep").unwrap();
        let _logger = logger(dir.path(), false).unwrap();
        assert!(!dir.path().join("http.log").exists());
        assert!(dir.path().join("notes.txt").exists());
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
