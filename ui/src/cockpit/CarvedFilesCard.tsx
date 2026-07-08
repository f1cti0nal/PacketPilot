import { Card } from "./primitives";
import { humanNumber, humanBytes } from "../lib/format";
import type { CarvedFile } from "../types";

/** VirusTotal verdict chip for a carved file's SHA-256 — red w/ threat label when malicious, a
 *  faint check when no engine flagged it, nothing for unknown/not-found (keeps the row uncluttered). */
function RepBadge({ file }: { file: CarvedFile }) {
  const v = file.reputation?.[0];
  if (!v) return null;
  if (v.malicious) {
    const label = (v.tags[0] || "malicious").slice(0, 18);
    return (
      <a
        href={v.link ?? undefined}
        target="_blank"
        rel="noreferrer noopener"
        className="shrink-0 truncate rounded px-1 text-[0.6rem] font-medium uppercase hover:underline"
        style={{ color: "var(--color-sev-critical)" }}
        title={`VirusTotal: ${v.score ?? "?"}% of engines flagged this${v.tags[0] ? ` — ${v.tags[0]}` : ""}`}
      >
        VT ✕ {label}
      </a>
    );
  }
  if (v.status === "clean") {
    return (
      <span
        className="shrink-0 rounded px-1 text-[0.6rem] font-medium uppercase text-[var(--color-text-faint)]"
        title="VirusTotal: no engine detections"
      >
        VT ✓
      </span>
    );
  }
  return null;
}

/**
 * Carved files: cleartext HTTP downloads reassembled in-stream and hashed. Each row is the file's
 * SHA-256 — a ready IOC — with its size and the downloading client ← serving host. A `known-bad`
 * badge flags a hash that matched the embedded known-bad set (a confirmed-malware download, which
 * also raises a Critical finding). Content-signature chips (file type + suspicious markers like a
 * UPX packer or PowerShell cradle, matched in-stream) give triage context; a suspicious match also
 * raises a Malware Signature finding. When file-hash reputation is enabled + consented, a `VT` badge
 * shows the VirusTotal verdict (red w/ threat label when flagged, links to the report). By default no
 * file bytes are retained — only the hash; when opt-in extraction (`--carve-dir`) is enabled, an
 * `extracted` line shows the saved filename. Display-only; hidden when nothing was carved.
 */
export function CarvedFilesCard({ files }: { files: CarvedFile[] }) {
  const rows = files ?? [];
  if (rows.length === 0) return null;

  return (
    <Card
      label="FILES"
      title="Carved files"
      right={
        <span className="font-mono-num t-tag text-[var(--color-text-dim)]">
          {humanNumber(rows.length)} hashed
        </span>
      }
    >
      <ul className="flex flex-col divide-y divide-[var(--color-border)]">
        {rows.slice(0, 12).map((f) => (
          <li key={`${f.sha256}-${f.client}-${f.server}`} className="flex flex-col gap-0.5 py-1.5 text-xs">
            <div className="flex items-baseline gap-2">
              <span
                className="font-mono-num truncate text-[var(--color-text)]"
                title={f.sha256}
              >
                {f.sha256.slice(0, 20)}…
              </span>
              {f.known_bad && (
                <span
                  className="shrink-0 rounded px-1 text-[0.6rem] font-medium uppercase"
                  style={{ color: "var(--color-sev-critical)" }}
                >
                  known-bad
                </span>
              )}
              <RepBadge file={f} />
              <span className="font-mono-num ml-auto shrink-0 text-[0.65rem] text-[var(--color-text-faint)]">
                {humanBytes(f.size)}
              </span>
            </div>
            <div className="flex items-baseline gap-1.5 text-[0.65rem] text-[var(--color-text-dim)]">
              <span className="font-mono-num truncate" title={f.client}>
                {f.client}
              </span>
              <span className="text-[var(--color-text-faint)]">←</span>
              <span className="font-mono-num truncate" title={f.server}>
                {f.server}
              </span>
            </div>
            {(f.signatures?.length ?? 0) > 0 && (
              <div className="flex flex-wrap gap-1 pt-0.5">
                {f.signatures!.slice(0, 6).map((s) => (
                  <span
                    key={s}
                    className="rounded bg-[var(--color-surface-2)] px-1 text-[0.6rem] text-[var(--color-text-dim)]"
                  >
                    {s}
                  </span>
                ))}
              </div>
            )}
            {f.extracted_path && (
              <div
                className="flex items-baseline gap-1 pt-0.5 text-[0.6rem] text-[var(--color-text-faint)]"
                title={f.extracted_path}
              >
                <span className="uppercase tracking-wide">extracted</span>
                <span className="font-mono-num truncate">
                  {f.extracted_path.split(/[/\\]/).pop()}
                </span>
              </div>
            )}
          </li>
        ))}
      </ul>
    </Card>
  );
}

export default CarvedFilesCard;
