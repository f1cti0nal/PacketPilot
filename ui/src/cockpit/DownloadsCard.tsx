import { Card } from "./primitives";
import { humanNumber } from "../lib/format";
import type { DownloadEvent } from "../types";

// Risk accent per file class (executables are the loudest). Uses the severity color tokens
// (--color-sev-*, not bare --color-*, which are undefined → invisible — the score-waterfall lesson).
const KIND_ACCENT: Record<string, string> = {
  executable: "var(--color-sev-critical)",
  script: "var(--color-sev-high)",
  installer: "var(--color-sev-medium)",
  archive: "var(--color-sev-low)",
};

/**
 * Downloads overview: notable file classes (executable / script / installer / archive) served over
 * HTTP, attributed client ← server. Inferred from each response's Content-Type / filename (no body
 * bytes are read), so this is *informational triage* — "what risky file types entered the network,
 * and which host received them" — not an alert. Display-only; hidden when none were seen.
 */
export function DownloadsCard({ downloads }: { downloads: DownloadEvent[] }) {
  const rows = downloads ?? [];
  if (rows.length === 0) return null;

  return (
    <Card
      label="FILES"
      title="Downloads"
      right={
        <span className="font-mono-num t-tag text-[var(--color-text-dim)]">
          {humanNumber(rows.length)} seen
        </span>
      }
    >
      <ul className="flex flex-col divide-y divide-[var(--color-border)]">
        {rows.slice(0, 12).map((d) => (
          <li
            key={`${d.client}-${d.server}-${d.kind}`}
            className="flex items-baseline gap-2 py-1.5 text-xs"
          >
            <span
              className="shrink-0 rounded px-1 text-[0.65rem] font-medium uppercase"
              style={{ color: KIND_ACCENT[d.kind] ?? "var(--color-text-dim)" }}
            >
              {d.kind}
            </span>
            <span className="font-mono-num shrink-0 truncate text-[var(--color-text)]" title={d.client}>
              {d.client}
            </span>
            <span className="text-[var(--color-text-faint)]">←</span>
            <span className="font-mono-num truncate text-[var(--color-text-dim)]" title={d.server}>
              {d.server}
            </span>
            {d.count > 1 && (
              <span className="font-mono-num ml-auto shrink-0 text-[0.65rem] text-[var(--color-text-faint)]">
                ×{humanNumber(d.count)}
              </span>
            )}
          </li>
        ))}
      </ul>
    </Card>
  );
}

export default DownloadsCard;
