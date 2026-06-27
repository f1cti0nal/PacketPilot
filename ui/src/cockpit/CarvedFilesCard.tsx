import { Card } from "./primitives";
import { humanNumber, humanBytes } from "../lib/format";
import type { CarvedFile } from "../types";

/**
 * Carved files: cleartext HTTP downloads reassembled in-stream and hashed. Each row is the file's
 * SHA-256 — a ready IOC to look up externally (VirusTotal, etc.) — with its size and the
 * downloading client ← serving host. A `known-bad` badge flags a hash that matched the embedded
 * known-bad set (a confirmed-malware download, which also raises a Critical finding). No file bytes
 * are retained — only the hash. Display-only; hidden when nothing was carved.
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
          </li>
        ))}
      </ul>
    </Card>
  );
}

export default CarvedFilesCard;
