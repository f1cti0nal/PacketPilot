import {
  Clock,
  Database,
  FileStack,
  HardDrive,
  Loader2,
  Monitor,
  RefreshCw,
  Trash2,
  Upload,
  Zap,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { RecentEntry, RecentOrigin, Severity } from "../../types";
import { SEVERITY_META, SEVERITY_ORDER } from "../../lib/severity";
import { compactNumber, humanBytes, humanNumber } from "../../lib/format";
import { cn } from "../../lib/cn";

export interface RecentViewProps {
  entries: RecentEntry[];
  /** Id of the capture currently shown on the dashboard (highlighted). */
  activeId?: string | null;
  /** Id of an entry whose re-analysis is in flight (spinner + disabled actions). */
  busyId?: string | null;
  onOpen: (entry: RecentEntry) => void;
  onReanalyze: (entry: RecentEntry) => void;
  onRemove: (entry: RecentEntry) => void;
  onClear: () => void;
  /** Open the load affordance (native dialog on desktop, drop dialog in the browser). */
  onLoadNew: () => void;
}

const ORIGIN_META: Record<
  RecentOrigin,
  { label: string; icon: LucideIcon; title: string }
> = {
  native: { label: "Desktop", icon: Monitor, title: "Analyzed by the native engine" },
  wasm: { label: "In-browser", icon: Zap, title: "Analyzed in-browser (WebAssembly engine)" },
  upload: { label: "Imported", icon: Upload, title: "Imported summary.json / flows.parquet" },
  sample: { label: "Sample", icon: Database, title: "Bundled sample capture" },
};

const STRIP_ORDER = SEVERITY_ORDER as Exclude<Severity, "none">[];

/** Compact relative-time, e.g. "just now", "3m ago", "2h ago", "Apr 5". */
function relativeTime(ts: number): string {
  const diff = Date.now() - ts;
  const sec = Math.round(diff / 1000);
  if (sec < 45) return "just now";
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.round(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.round(hr / 24);
  if (day < 7) return `${day}d ago`;
  return new Date(ts).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
  });
}

/** A thin stacked bar visualizing the severity mix of a cached summary. */
function SeverityBar({ entry }: { entry: RecentEntry }) {
  const counts = entry.summary.summary.severity_counts;
  const total = counts
    ? STRIP_ORDER.reduce((acc, s) => acc + (counts[s] ?? 0), 0)
    : 0;
  if (!counts || total === 0) {
    return (
      <div
        className="h-1.5 w-full rounded-full bg-[var(--color-surface-2)]"
        aria-hidden
      />
    );
  }
  return (
    <div
      className="flex h-1.5 w-full overflow-hidden rounded-full bg-[var(--color-surface-2)]"
      role="img"
      aria-label={STRIP_ORDER.map(
        (s) => `${SEVERITY_META[s].label} ${counts[s] ?? 0}`,
      ).join(", ")}
    >
      {STRIP_ORDER.map((s) => {
        const v = counts[s] ?? 0;
        if (v === 0) return null;
        return (
          <span
            key={s}
            style={{
              width: `${(v / total) * 100}%`,
              background: `var(${SEVERITY_META[s].cssVar})`,
            }}
          />
        );
      })}
    </div>
  );
}

function Stat({ icon: Icon, label, value }: { icon: LucideIcon; label: string; value: string }) {
  return (
    <div className="flex items-center gap-1.5" title={label}>
      <Icon className="h-3.5 w-3.5 text-[var(--color-text-faint)]" aria-hidden />
      <span className="font-mono-num text-xs text-[var(--color-text-dim)]">{value}</span>
    </div>
  );
}

function RecentCard({
  entry,
  active,
  busy,
  onOpen,
  onReanalyze,
  onRemove,
}: {
  entry: RecentEntry;
  active: boolean;
  busy: boolean;
  onOpen: (e: RecentEntry) => void;
  onReanalyze: (e: RecentEntry) => void;
  onRemove: (e: RecentEntry) => void;
}) {
  const origin = ORIGIN_META[entry.origin];
  const OriginIcon = origin.icon;
  const s = entry.summary.summary;

  return (
    <div
      className={cn(
        "group flex flex-col gap-3 rounded-xl border bg-surface p-4 transition-colors",
        active
          ? "border-[var(--color-accent)]"
          : "border-border hover:border-[var(--color-text-faint)]",
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <button
          type="button"
          onClick={() => onOpen(entry)}
          title={entry.path ?? entry.name}
          className="min-w-0 flex-1 text-left"
        >
          <div className="truncate text-sm font-semibold text-[var(--color-text)] group-hover:text-[var(--color-accent)]">
            {entry.name}
          </div>
          <div
            className="mt-0.5 flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-[var(--color-text-faint)]"
            title={origin.title}
          >
            <OriginIcon className="h-3 w-3" aria-hidden />
            {origin.label}
            {active && (
              <span className="rounded-sm bg-[color-mix(in_srgb,var(--color-accent)_18%,transparent)] px-1 py-0.5 text-[9px] text-[var(--color-accent)]">
                Active
              </span>
            )}
          </div>
        </button>
      </div>

      <SeverityBar entry={entry} />

      <div className="grid grid-cols-2 gap-x-3 gap-y-1.5">
        <Stat icon={FileStack} label="Flows" value={`${compactNumber(entry.flowCount)} flows`} />
        <Stat
          icon={Database}
          label="Packets"
          value={`${compactNumber(s.total_packets)} pkts`}
        />
        <Stat icon={HardDrive} label="Capture size" value={humanBytes(entry.sizeBytes)} />
        <Stat icon={Clock} label="Last analyzed" value={relativeTime(entry.analyzedAt)} />
      </div>

      {s.unique_hosts > 0 && (
        <div className="text-[11px] text-[var(--color-text-faint)]">
          {humanNumber(s.unique_hosts)} hosts ·{" "}
          {entry.flowsCached ? "flows cached" : "stats only"}
        </div>
      )}

      <div className="mt-auto flex items-center gap-1.5 pt-1">
        <button
          type="button"
          onClick={() => onOpen(entry)}
          disabled={busy}
          className="flex-1 rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs font-medium text-[var(--color-text)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-accent)] disabled:opacity-50"
        >
          Open
        </button>
        <button
          type="button"
          onClick={() => onReanalyze(entry)}
          disabled={busy}
          title="Re-run the engine on the original file"
          className="inline-flex items-center gap-1 rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs font-medium text-[var(--color-text-dim)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-accent)] disabled:opacity-50"
        >
          {busy ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
          ) : (
            <RefreshCw className="h-3.5 w-3.5" aria-hidden />
          )}
          Re-analyze
        </button>
        <button
          type="button"
          onClick={() => onRemove(entry)}
          disabled={busy}
          aria-label={`Remove ${entry.name}`}
          title="Remove from recent"
          className="rounded-md border border-border bg-surface-2 p-1.5 text-[var(--color-text-faint)] transition-colors hover:border-sev-high hover:text-sev-high disabled:opacity-50"
        >
          <Trash2 className="h-3.5 w-3.5" aria-hidden />
        </button>
      </div>
    </div>
  );
}

/**
 * The "Recent captures" tab: a grid of last-opened captures rendered from their cached
 * stats. Opening a card restores the dashboard instantly (and the flows table when cached);
 * Re-analyze re-runs the engine on the original file.
 */
export function RecentView({
  entries,
  activeId = null,
  busyId = null,
  onOpen,
  onReanalyze,
  onRemove,
  onClear,
  onLoadNew,
}: RecentViewProps) {
  return (
    <div data-component="RecentView" className="flex h-full min-h-0 flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-base font-semibold text-[var(--color-text)]">
            Recent captures
          </h1>
          <p className="text-xs text-[var(--color-text-dim)]">
            Last opened files with their cached stats — open to restore instantly, or
            re-analyze from the original.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onLoadNew}
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface-2 px-3 py-1.5 text-xs font-medium text-[var(--color-text)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-accent)]"
          >
            <Upload className="h-3.5 w-3.5" aria-hidden />
            Load capture
          </button>
          {entries.length > 0 && (
            <button
              type="button"
              onClick={onClear}
              className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface-2 px-3 py-1.5 text-xs font-medium text-[var(--color-text-dim)] transition-colors hover:border-sev-high hover:text-sev-high"
            >
              <Trash2 className="h-3.5 w-3.5" aria-hidden />
              Clear all
            </button>
          )}
        </div>
      </div>

      {entries.length === 0 ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border p-10 text-center">
          <FileStack className="h-8 w-8 text-[var(--color-text-faint)]" aria-hidden />
          <div className="text-sm text-[var(--color-text)]">No recent captures yet</div>
          <p className="max-w-sm text-xs text-[var(--color-text-dim)]">
            Load a <span className="font-mono-num">.pcap</span> /{" "}
            <span className="font-mono-num">.pcapng</span> capture and it will appear here,
            with its stats saved so you can reopen it in one click.
          </p>
          <button
            type="button"
            onClick={onLoadNew}
            className="mt-1 inline-flex items-center gap-1.5 rounded-md border border-border bg-surface-2 px-3 py-1.5 text-xs font-medium text-[var(--color-text)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-accent)]"
          >
            <Upload className="h-3.5 w-3.5" aria-hidden />
            Load capture
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-3 overflow-auto pb-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {entries.map((entry) => (
            <RecentCard
              key={entry.id}
              entry={entry}
              active={entry.id === activeId}
              busy={entry.id === busyId}
              onOpen={onOpen}
              onReanalyze={onReanalyze}
              onRemove={onRemove}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default RecentView;
