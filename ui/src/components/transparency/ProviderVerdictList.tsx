import type { ReputationVerdict, RepStatus } from "../../types";

/** Worst-first ordering: malicious is worst; benign/clean are best. */
const STATUS_RANK: Record<RepStatus, number> = {
  malicious: 5, unknown: 3, notfound: 2, unavailable: 1, benign: 0, clean: 0,
};
const STATUS_COLOR: Record<RepStatus, string> = {
  malicious: "var(--color-sev-critical, #ef4444)",
  benign: "var(--color-sev-low, #22c55e)",
  clean: "var(--color-sev-low, #22c55e)",
  unknown: "var(--color-text-faint)",
  notfound: "var(--color-text-faint)",
  unavailable: "var(--color-text-faint)",
};

/** Coarse "as of" age from a unix-seconds timestamp. */
function freshness(fetchedAt: number, now: number): string {
  const secs = Math.max(0, now - fetchedAt);
  if (secs < 90) return "just now";
  const mins = Math.round(secs / 60);
  if (mins < 90) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 36) return `${hrs}h ago`;
  return `${Math.round(hrs / 24)}d ago`;
}

/** Full per-provider reputation breakdown. Renders nothing when there are no verdicts. */
export function ProviderVerdictList({
  verdicts,
  now = Math.floor(Date.now() / 1000),
}: {
  verdicts: ReputationVerdict[];
  now?: number;
}) {
  if (!verdicts || verdicts.length === 0) return null;
  const sorted = [...verdicts].sort((a, b) => STATUS_RANK[b.status] - STATUS_RANK[a.status]);
  return (
    <ul className="flex flex-col gap-1">
      {sorted.map((vd, i) => (
        <li key={`${vd.source}-${i}`} className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs">
          <span className="font-medium text-[var(--color-text)]">{vd.source}</span>
          <span style={{ color: STATUS_COLOR[vd.status] }}>{vd.status}</span>
          <span className="font-mono-num tabular-nums text-[var(--color-text-dim)]">
            {vd.score != null ? `${vd.score}%` : "—"}
          </span>
          {vd.tags.length > 0 && (
            <span className="font-mono-num text-[0.65rem] text-[var(--color-text-faint)]">
              {vd.tags.join(", ")}
            </span>
          )}
          {vd.link && (
            <a
              href={vd.link}
              target="_blank"
              rel="noopener noreferrer"
              className="text-[var(--color-accent)] underline"
            >
              report ↗
            </a>
          )}
          <span className="ml-auto text-[0.65rem] text-[var(--color-text-faint)]">
            {freshness(vd.fetched_at, now)}
          </span>
        </li>
      ))}
    </ul>
  );
}
