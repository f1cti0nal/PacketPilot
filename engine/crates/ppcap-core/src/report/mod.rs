//! Self-contained HTML triage report renderer.
//!
//! [`render_html`] turns an [`AnalysisOutput`] into a single, dependency-free HTML5
//! document: inline CSS (dark screen theme + a print-friendly `@media print` override),
//! inline SVG charts (no JavaScript, no network, no external assets), the per-IP threat
//! report-card table, and HTML-escaping of **every** capture-derived string.
//!
//! The function is pure and infallible — it formats into a `String`, which never fails —
//! so the caller supplies the wall-clock "generated at" time as a Unix timestamp to keep
//! this unit-testable. The only fallible part (writing the file) lives in the CLI.
//!
//! ## Escaping discipline
//!
//! The single choke point is [`esc`]. Any value interpolated from `out`/`summary` that is a
//! `String`/`&str` is wrapped in `esc(...)`. Numbers and the closed-enum `as_str()` tokens
//! are the only unescaped interpolations (enum tokens are still wrapped for zero-trust).

use std::fmt::Write as _;

use time::macros::format_description;
use time::OffsetDateTime;

use crate::model::category::Category;
use crate::model::output::AnalysisOutput;
use crate::model::severity::Severity;

// ---------------------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------------------

/// Render a self-contained HTML5 triage report (inline CSS, inline SVG, no JS/network).
///
/// `generated_unix_secs` is the wall-clock "generated at" time (UTC), supplied by the caller
/// so this stays pure and unit-testable. Never fails: formatting into a `String` is
/// infallible and the `fmt::Result` from each `write!` is ignored.
pub fn render_html(out: &AnalysisOutput, generated_unix_secs: i64) -> String {
    let mut s = String::with_capacity(64 * 1024);
    let sum = &out.summary;

    // ---- skeleton + head -------------------------------------------------------------
    s.push_str("<!doctype html>\n");
    s.push_str("<html lang=\"en\"><head>\n");
    s.push_str("<meta charset=\"utf-8\">\n");
    s.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    s.push_str("<title>PacketPilot — Capture Triage Report</title>\n");
    s.push_str("<style>\n");
    s.push_str(STYLE);
    s.push_str("\n</style>\n</head><body>\n<main class=\"report\">\n");

    // ---- Section 1: header card ------------------------------------------------------
    let sha = match out.source_sha256.as_deref() {
        Some(h) if h.chars().count() >= 12 => {
            format!("{}…", h.chars().take(12).collect::<String>())
        }
        Some(h) => h.to_string(),
        None => "n/a".to_string(),
    };
    let range = format!(
        "{} → {}",
        match sum.first_ts_ns {
            Some(ns) => fmt_ns_utc(ns),
            None => "—".to_string(),
        },
        match sum.last_ts_ns {
            Some(ns) => fmt_ns_utc(ns),
            None => "—".to_string(),
        },
    );
    let _ = writeln!(
        s,
        "<section class=\"card\">\
         <h1>PacketPilot — Capture Triage Report</h1>\
         <dl class=\"kv\">\
         <dt>Capture file</dt><dd class=\"mono\">{file}</dd>\
         <dt>SHA-256</dt><dd class=\"mono\">{sha}</dd>\
         <dt>Size</dt><dd>{size}</dd>\
         <dt>Link type</dt><dd class=\"mono\">{link}</dd>\
         <dt>Capture range</dt><dd>{range}</dd>\
         <dt>Duration</dt><dd>{dur}</dd>\
         <dt>Engine</dt><dd class=\"mono\">{engine}</dd>\
         <dt>Analysis elapsed</dt><dd>{elapsed} ms</dd>\
         <dt>Generated</dt><dd>{gen}</dd>\
         </dl>\
         <p class=\"muted\">Print to PDF from any browser (Ctrl/Cmd-P).</p>\
         </section>",
        file = esc(basename(&out.source_path)),
        sha = esc(&sha),
        size = human_bytes(out.source_bytes),
        link = esc(&out.link_type),
        range = esc(&range),
        dur = human_duration_ns(sum.duration_ns),
        engine = esc(&out.engine_version),
        elapsed = out.elapsed_ms,
        gen = esc(&fmt_unix_secs_utc(generated_unix_secs)),
    );

    // ---- Section 2: executive summary ------------------------------------------------
    let crit = sum.severity_counts.critical;
    let high = sum.severity_counts.high;
    let ioc_cards = sum.ip_threats.iter().filter(|t| t.ioc).count();
    let _ = write!(
        s,
        "<section class=\"card\">\
         <h2>Executive summary</h2>\
         <div class=\"tiles\">\
         <div class=\"tile\"><div class=\"v\">{pkts}</div><div class=\"k\">Packets</div></div>\
         <div class=\"tile\"><div class=\"v\">{flows}</div><div class=\"k\">Flows</div></div>\
         <div class=\"tile\"><div class=\"v\">{bytes}</div><div class=\"k\">Bytes</div></div>\
         <div class=\"tile\"><div class=\"v\">{dur}</div><div class=\"k\">Duration</div></div>\
         <div class=\"tile\"><div class=\"v\">{hosts}</div><div class=\"k\">Unique hosts</div></div>\
         </div>",
        pkts = group_thousands(sum.total_packets),
        flows = group_thousands(sum.total_flows),
        bytes = human_bytes(sum.total_bytes),
        dur = human_duration_ns(sum.duration_ns),
        hosts = group_thousands(sum.unique_hosts),
    );
    if crit > 0 || ioc_cards > 0 {
        let _ = write!(
            s,
            "<div class=\"callout danger\">{crit} critical and {high} high-severity flows; \
             {ioc} IP(s) matched the offline IOC feed.</div>",
            crit = crit,
            high = high,
            ioc = ioc_cards,
        );
    } else {
        s.push_str("<div class=\"callout\">No critical or high-severity activity detected.</div>");
    }
    s.push_str("</section>\n");

    // ---- Section 3: severity distribution (inline SVG) -------------------------------
    s.push_str("<section class=\"card\"><h2>Severity distribution</h2>");
    s.push_str(&severity_svg(&sum.severity_counts));
    s.push_str("</section>\n");

    // ---- Section 4: top threats (report-card table) ----------------------------------
    s.push_str("<section class=\"card\"><h2>Top threats</h2><table>");
    s.push_str(
        "<thead><tr><th>IP</th><th>Class</th><th>Severity</th><th>Score</th>\
         <th>IOC</th><th>ATT&amp;CK</th><th>Evidence</th></tr></thead><tbody>",
    );
    if sum.ip_threats.is_empty() {
        s.push_str("<tr><td colspan=\"7\" class=\"muted\">No scored IP threats.</td></tr>");
    } else {
        for t in sum.ip_threats.iter().take(25) {
            let attack = t
                .attack
                .iter()
                .map(|a| esc(a))
                .collect::<Vec<_>>()
                .join(", ");
            let evidence = t
                .evidence
                .iter()
                .map(|e| esc(e))
                .collect::<Vec<_>>()
                .join("; ");
            let ioc_cell = if t.ioc {
                "<span class=\"ioc\">IOC</span>".to_string()
            } else {
                "—".to_string()
            };
            let _ = write!(
                s,
                "<tr><td class=\"mono\">{ip}</td><td>{class}</td>\
                 <td><span class=\"chip\" style=\"background:{color}\">{sev}</span></td>\
                 <td>{score}/100</td><td>{ioc}</td><td>{attack}</td><td>{evidence}</td></tr>",
                ip = esc(&t.ip),
                class = esc(t.ip_class.as_str()),
                color = sev_color(t.severity),
                sev = esc(t.severity.as_str()),
                score = t.score,
                ioc = ioc_cell,
                attack = attack,
                evidence = evidence,
            );
        }
    }
    s.push_str("</tbody></table></section>\n");

    // ---- Section 5: traffic categories (inline SVG) ----------------------------------
    s.push_str("<section class=\"card\"><h2>Traffic categories</h2>");
    s.push_str(&category_svg(&sum.category_breakdown));
    s.push_str("</section>\n");

    // ---- Section 6: top talkers (table) ----------------------------------------------
    s.push_str("<section class=\"card\"><h2>Top talkers</h2><table>");
    s.push_str(
        "<thead><tr><th>IP</th><th>Packets</th><th>Bytes</th><th>Flows</th></tr></thead><tbody>",
    );
    if sum.top_talkers.is_empty() {
        s.push_str("<tr><td colspan=\"4\" class=\"muted\">No talkers recorded.</td></tr>");
    } else {
        for tk in sum.top_talkers.iter().take(15) {
            let _ = write!(
                s,
                "<tr><td class=\"mono\">{ip}</td><td>{pkts}</td><td>{bytes}</td><td>{flows}</td></tr>",
                ip = esc(&tk.ip),
                pkts = group_thousands(tk.pkts),
                bytes = human_bytes(tk.bytes),
                flows = group_thousands(tk.flows),
            );
        }
    }
    s.push_str("</tbody></table></section>\n");

    // ---- Section 7: protocol mix -----------------------------------------------------
    let p = &sum.proto;
    let other_l4 = p.other_tcp + p.other_udp;
    let _ = writeln!(
        s,
        "<section class=\"card\"><h2>Protocol mix</h2><table>\
         <thead><tr><th>Group</th><th>Protocol</th><th>Packets</th></tr></thead><tbody>\
         <tr><td>Transport</td><td>TCP</td><td>{tcp}</td></tr>\
         <tr><td>Transport</td><td>UDP</td><td>{udp}</td></tr>\
         <tr><td>Transport</td><td>Other L4</td><td>{other}</td></tr>\
         <tr><td>Application</td><td>DNS</td><td>{dns}</td></tr>\
         <tr><td>Application</td><td>HTTP</td><td>{http}</td></tr>\
         <tr><td>Application</td><td>TLS</td><td>{tls}</td></tr>\
         </tbody></table>\
         <p class=\"muted\">Truncated frames: {trunc} · Non-IPv4 frames: {nonip}</p>\
         </section>",
        tcp = group_thousands(p.tcp),
        udp = group_thousands(p.udp),
        other = group_thousands(other_l4),
        dns = group_thousands(p.dns),
        http = group_thousands(p.http),
        tls = group_thousands(p.tls),
        trunc = group_thousands(p.truncated),
        nonip = group_thousands(p.non_ipv4),
    );

    // ---- Section 8: activity timeline (inline SVG sparkline) -------------------------
    s.push_str("<section class=\"card\"><h2>Activity timeline</h2>");
    s.push_str(&timeline_svg(&sum.time_histogram));
    s.push_str("</section>\n");

    // ---- Section 9: footer methodology -----------------------------------------------
    let _ = writeln!(
        s,
        "<footer>\
         <p>Severity is the engine score = traffic category + offline IOC reputation + \
         behavioral signals (banded Info/Low/Medium/High/Critical). IOC matching uses a \
         local, offline feed; technique ids follow MITRE ATT&amp;CK.</p>\
         <p>Generated by PacketPilot {engine} — print to PDF from any browser.</p>\
         </footer>",
        engine = esc(&out.engine_version),
    );

    s.push_str("</main>\n</body></html>\n");
    s
}

// ---------------------------------------------------------------------------------------
// HTML escaping (CRITICAL): the single choke point.
// ---------------------------------------------------------------------------------------

/// Escape the 5 HTML-significant chars. Applied to EVERY capture-derived string. Safe inside
/// element text and both double- and single-quoted attributes. Order matters: `&` first.
fn esc(raw: &str) -> String {
    let mut o = String::with_capacity(raw.len() + 8);
    for c in raw.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

// ---------------------------------------------------------------------------------------
// Formatting helpers.
// ---------------------------------------------------------------------------------------

/// Human-readable byte size: `1023 B`, `1.5 KiB`, … up to TiB. 1 decimal for >= KiB.
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut i = 0usize;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", UNITS[i])
}

/// Human-readable duration from nanoseconds: `h:mm:ss` / `Xm Ys` / `X.YYs` / `Xms`; `—` for 0.
fn human_duration_ns(ns: i64) -> String {
    if ns <= 0 {
        return "—".to_string();
    }
    let total_ms = ns / 1_000_000;
    if total_ms < 1000 {
        return format!("{total_ms}ms");
    }
    let total_secs = total_ms as f64 / 1000.0;
    if total_secs < 60.0 {
        return format!("{total_secs:.2}s");
    }
    let whole = ns / 1_000_000_000;
    let h = whole / 3600;
    let m = (whole % 3600) / 60;
    let sec = whole % 60;
    if h > 0 {
        format!("{h}:{m:02}:{sec:02}")
    } else {
        format!("{m}m {sec}s")
    }
}

/// Group a u64 with thousands separators: `123456` -> `123,456`.
fn group_thousands(n: u64) -> String {
    let digits = n.to_string();
    let bytes = digits.as_bytes();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    let len = bytes.len();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

const TS_FMT: &[time::format_description::FormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]:[second] UTC");

/// Format a Unix-seconds timestamp as a UTC string; `—` on overflow.
fn fmt_unix_secs_utc(secs: i64) -> String {
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|dt| dt.format(&TS_FMT).ok())
        .unwrap_or_else(|| "—".to_string())
}

/// Format a Unix-nanoseconds timestamp as a UTC string; `—` on overflow.
fn fmt_ns_utc(ns: i64) -> String {
    OffsetDateTime::from_unix_timestamp_nanos(ns as i128)
        .ok()
        .and_then(|dt| dt.format(&TS_FMT).ok())
        .unwrap_or_else(|| "—".to_string())
}

/// Last path segment after `/` or `\\`; falls back to the whole string.
fn basename(path: &str) -> &str {
    let cut = path.rfind(['/', '\\']).map(|i| i + 1).unwrap_or(0);
    let b = &path[cut..];
    if b.is_empty() {
        path
    } else {
        b
    }
}

/// Severity -> on-screen chart/chip color (matches the app palette).
fn sev_color(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "#f43f5e",
        Severity::High => "#fb923c",
        Severity::Medium => "#fbbf24",
        Severity::Low => "#2dd4bf",
        Severity::Info => "#64748b",
    }
}

/// Category -> a severity-flavored hue ("colored by category severity").
fn cat_color(c: Category) -> &'static str {
    match c {
        Category::C2 | Category::Anomalous => "#f43f5e", // critical red
        Category::Scan => "#fb923c",                     // high orange
        Category::RemoteAccess | Category::TunnelVpn => "#fbbf24", // medium amber
        Category::Voip | Category::IotOt | Category::FileTransfer => "#2dd4bf", // low teal
        Category::Web | Category::Dns | Category::Email | Category::Unknown => "#64748b", // info slate
    }
}

// ---------------------------------------------------------------------------------------
// Inline SVG charts (all coordinates precomputed in Rust; no JS).
// ---------------------------------------------------------------------------------------

/// Severity distribution: 5 fixed horizontal bars (critical..info), always shown.
fn severity_svg(sc: &crate::model::summary::SeverityCounts) -> String {
    let rows: [(Severity, u64); 5] = [
        (Severity::Critical, sc.critical),
        (Severity::High, sc.high),
        (Severity::Medium, sc.medium),
        (Severity::Low, sc.low),
        (Severity::Info, sc.info),
    ];
    let w = 680i32;
    let row_h = 34i32;
    let gap = 8i32;
    let label_w = 90i32;
    let count_w = 70i32;
    let track_x = label_w;
    let track_w = w - label_w - count_w;
    let h = 5 * row_h + 4 * gap + 16;
    let maxv = rows.iter().map(|(_, v)| *v).max().unwrap_or(0).max(1);

    let mut s = String::with_capacity(2048);
    let _ = write!(
        s,
        "<svg viewBox=\"0 0 {w} {h}\" role=\"img\" aria-label=\"Severity distribution\">"
    );
    for (i, (sev, v)) in rows.iter().enumerate() {
        let y = 8 + i as i32 * (row_h + gap);
        let bar_h = row_h - 12;
        let bw = ((track_w as f64) * (*v as f64) / (maxv as f64)).round() as i32;
        let bw = if *v > 0 { bw.max(1) } else { 0 };
        let ty = y + (row_h as f64 * 0.62) as i32;
        let _ = write!(
            s,
            "<text x=\"0\" y=\"{ty}\" fill=\"#94a3b8\" font-size=\"13\">{label}</text>\
             <rect x=\"{track_x}\" y=\"{y}\" width=\"{track_w}\" height=\"{bar_h}\" rx=\"4\" fill=\"#0d131c\"/>\
             <rect x=\"{track_x}\" y=\"{y}\" width=\"{bw}\" height=\"{bar_h}\" rx=\"4\" fill=\"{color}\"/>\
             <text x=\"{w}\" y=\"{ty}\" text-anchor=\"end\" fill=\"#e2e8f0\" font-size=\"13\">{v}</text>",
            label = esc(sev.as_str()),
            color = sev_color(*sev),
        );
    }
    s.push_str("</svg>");
    s
}

/// Traffic categories: horizontal bars per category with flows > 0, desc by flows.
fn category_svg(cats: &[crate::model::summary::CategoryCount]) -> String {
    let mut rows: Vec<(&crate::model::summary::CategoryCount,)> =
        cats.iter().filter(|c| c.flows > 0).map(|c| (c,)).collect();
    rows.sort_by_key(|b| std::cmp::Reverse(b.0.flows));
    if rows.is_empty() {
        return "<p class=\"muted\">No categorized flows.</p>".to_string();
    }
    let w = 680i32;
    let row_h = 30i32;
    let gap = 8i32;
    let label_w = 120i32;
    let count_w = 80i32;
    let track_x = label_w;
    let track_w = w - label_w - count_w;
    let n = rows.len() as i32;
    let h = n * row_h + (n - 1).max(0) * gap + 16;
    let maxv = rows.iter().map(|(c,)| c.flows).max().unwrap_or(0).max(1);

    let mut s = String::with_capacity(2048);
    let _ = write!(
        s,
        "<svg viewBox=\"0 0 {w} {h}\" role=\"img\" aria-label=\"Traffic categories\">"
    );
    for (i, (c,)) in rows.iter().enumerate() {
        let y = 8 + i as i32 * (row_h + gap);
        let bar_h = row_h - 10;
        let bw = (((track_w as f64) * (c.flows as f64) / (maxv as f64)).round() as i32).max(1);
        let ty = y + (row_h as f64 * 0.62) as i32;
        let _ = write!(
            s,
            "<text x=\"0\" y=\"{ty}\" fill=\"#94a3b8\" font-size=\"12\">{label}</text>\
             <rect x=\"{track_x}\" y=\"{y}\" width=\"{track_w}\" height=\"{bar_h}\" rx=\"4\" fill=\"#0d131c\"/>\
             <rect x=\"{track_x}\" y=\"{y}\" width=\"{bw}\" height=\"{bar_h}\" rx=\"4\" fill=\"{color}\"/>\
             <text x=\"{w}\" y=\"{ty}\" text-anchor=\"end\" fill=\"#e2e8f0\" font-size=\"12\">{flows}</text>",
            label = esc(c.category.as_str()),
            color = cat_color(c.category),
            flows = group_thousands(c.flows),
        );
    }
    s.push_str("</svg>");
    s
}

/// Activity timeline: an area sparkline of packets/second, plotted against the real time
/// axis (the histogram omits gap seconds, so index-based plotting would distort).
fn timeline_svg(hist: &[crate::model::summary::TimeBucket]) -> String {
    let w = 680i32;
    let h = 120i32;
    let pad_l = 8i32;
    let pad_r = 8i32;
    let pad_t = 10i32;
    let pad_b = 18i32;
    let plot_w = (w - pad_l - pad_r) as f64;
    let plot_h = (h - pad_t - pad_b) as f64;
    let baseline = (pad_t as f64) + plot_h;

    if hist.len() < 2 {
        let mut s = String::with_capacity(256);
        let _ = write!(
            s,
            "<svg viewBox=\"0 0 {w} {h}\" role=\"img\" aria-label=\"Activity timeline\">\
             <line x1=\"{pad_l}\" y1=\"{baseline:.1}\" x2=\"{x2}\" y2=\"{baseline:.1}\" stroke=\"#1e293b\"/>\
             </svg><p class=\"muted\">Insufficient timeline data.</p>",
            x2 = w - pad_r,
        );
        return s;
    }

    let t0 = hist[0].epoch_sec;
    let t1 = hist[hist.len() - 1].epoch_sec;
    let span = (t1 - t0).max(1) as f64;
    let real_peak = hist.iter().map(|b| b.pkts).max().unwrap_or(0);
    let ymax = real_peak.max(1) as f64;

    let mut points = String::with_capacity(hist.len() * 12);
    for b in hist {
        let x = pad_l as f64 + plot_w * ((b.epoch_sec - t0) as f64) / span;
        let y = pad_t as f64 + plot_h * (1.0 - (b.pkts as f64) / ymax);
        let _ = write!(points, "{x:.1},{y:.1} ");
    }
    let x_last = pad_l as f64 + plot_w; // last point sits at the right edge (epoch == t1)
    let x_first = pad_l as f64;

    let mut s = String::with_capacity(hist.len() * 14 + 1024);
    let _ = write!(
        s,
        "<svg viewBox=\"0 0 {w} {h}\" role=\"img\" aria-label=\"Activity timeline (packets per second)\">\
         <polygon points=\"{pts}{xl:.1},{base:.1} {xf:.1},{base:.1}\" fill=\"rgba(56,189,248,0.18)\"/>\
         <polyline points=\"{pts}\" fill=\"none\" stroke=\"#38bdf8\" stroke-width=\"1.5\"/>\
         <line x1=\"{pad_l}\" y1=\"{base:.1}\" x2=\"{x2}\" y2=\"{base:.1}\" stroke=\"#1e293b\"/>\
         <text x=\"{pad_l}\" y=\"{ty}\" fill=\"#94a3b8\" font-size=\"11\">{lo}</text>\
         <text x=\"{w}\" y=\"{ty}\" text-anchor=\"end\" fill=\"#94a3b8\" font-size=\"11\">{hi}</text>\
         <text x=\"{xmid}\" y=\"{ty}\" text-anchor=\"middle\" fill=\"#94a3b8\" font-size=\"11\">peak {peak} pkts/s</text>\
         </svg>",
        pts = points,
        xl = x_last,
        xf = x_first,
        base = baseline,
        x2 = w - pad_r,
        ty = h - 5,
        xmid = w / 2,
        lo = esc(&hhmmss_utc(t0)),
        hi = esc(&hhmmss_utc(t1)),
        peak = group_thousands(real_peak),
    );
    s
}

/// `HH:MM:SS` (UTC) of a Unix-seconds value; `—` on overflow. For sparkline axis labels.
fn hhmmss_utc(secs: i64) -> String {
    const FMT: &[time::format_description::FormatItem<'static>] =
        format_description!("[hour]:[minute]:[second]");
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|dt| dt.format(&FMT).ok())
        .unwrap_or_else(|| "—".to_string())
}

// ---------------------------------------------------------------------------------------
// Inline stylesheet (dark screen theme + print override).
// ---------------------------------------------------------------------------------------

const STYLE: &str = r#":root{
  --bg:#0a0e14; --surface:#111722; --surface-2:#0d131c; --text:#e2e8f0;
  --muted:#94a3b8; --border:#1e293b; --accent:#38bdf8;
  --crit:#f43f5e; --high:#fb923c; --med:#fbbf24; --low:#2dd4bf; --info:#64748b;
}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--text);
  font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.report{max-width:1100px;margin:0 auto;padding:32px 24px}
.mono{font-family:ui-monospace,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace}
h1{font-size:24px;margin:0 0 4px} h2{font-size:18px;margin:0 0 12px;color:var(--accent)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;
  padding:20px 22px;margin:18px 0}
.tiles{display:flex;flex-wrap:wrap;gap:14px}
.tile{flex:1 1 150px;background:var(--surface-2);border:1px solid var(--border);
  border-radius:10px;padding:14px 16px}
.tile .v{font-size:22px;font-weight:700}
.tile .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.callout{border-left:4px solid var(--accent);padding:12px 16px;border-radius:8px;
  background:var(--surface-2);margin-top:14px}
.callout.danger{border-left-color:var(--crit)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.04em}
.chip{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700;color:#0a0e14}
.ioc{color:var(--crit);font-weight:700}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:4px 18px;margin:0}
.kv dt{color:var(--muted)} .kv dd{margin:0}
.muted{color:var(--muted)} footer{color:var(--muted);font-size:12px;margin-top:24px}
svg{display:block;max-width:100%;height:auto}

@media print{
  :root{ --bg:#ffffff; --surface:#ffffff; --surface-2:#f6f7f9; --text:#0b1220;
         --muted:#475569; --border:#cbd5e1; --accent:#0369a1; }
  body{font-size:11pt}
  .report{max-width:none;padding:0}
  .card,.tile,table,tr,.callout{break-inside:avoid;page-break-inside:avoid}
  a[href]:after{content:""}
}"#;
