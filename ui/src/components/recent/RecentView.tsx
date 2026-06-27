import {
  Clock,
  Database,
  FileStack,
  GitCompare,
  HardDrive,
  Loader2,
  Monitor,
  RefreshCw,
  Trash2,
  Upload,
  Zap,
} from "lucide-react";
import { useState } from "react";
import type { LucideIcon } from "lucide-react";
import type { RecentEntry, RecentOrigin, Severity } from "../../types";
import { SEVERITY_META, SEVERITY_ORDER } from "../../lib/severity";
import { compactNumber, humanBytes, humanNumber, relativeTime } from "../../lib/format";
import { cn } from "../../lib/cn";
import { Panel } from "../../cockpit/primitives";

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
  /** Compare two selected captures (ids ordered older-first by analyzedAt). */
  onCompare?: (beforeId: string, afterId: string) => void;
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

/** A thin stacked bar visualizing the severity mix of a cached summary. */
function SeverityBar({ entry }: { entry: RecentEntry }) {
  const counts = entry.summary.summary.severity_counts;
  const total = counts
    ? STRIP_ORDER.reduce((acc, s) => acc + (counts[s] ?? 0), 0)
    : 0;
  if (!counts || total === 0) {
    return (
      <div
        className="h-1 w-full rounded-full bg-[var(--color-surface-3)]"
        aria-hidden
      />
    );
  }
  return (
    <div
      className="flex h-1 w-full overflow-hidden rounded-full bg-[var(--color-surface-3)]"
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

function RecentRow({
  entry,
  active,
  busy,
  selectable,
  selected,
  onToggleSelect,
  onOpen,
  onReanalyze,
  onRemove,
}: {
  entry: RecentEntry;
  active: boolean;
  busy: boolean;
  selectable: boolean;
  selected: boolean;
  onToggleSelect: (id: string) => void;
  onOpen: (e: RecentEntry) => void;
  onReanalyze: (e: RecentEntry) => void;
  onRemove: (e: RecentEntry) => void;
}) {
  const origin = ORIGIN_META[entry.origin];
  const OriginIcon = origin.icon;
  const s = entry.summary.summary;

  return (
    <tr
      className={cn(
        "border-t border-[var(--color-border)] transition-colors hover:bg-[var(--color-surface-2)]",
        active && "bg-[color-mix(in_srgb,var(--color-accent)_6%,transparent)]",
      )}
    >
      {/* Select checkbox */}
      {selectable && (
        <td className="w-8 px-3 py-2.5 text-center">
          <input
            type="checkbox"
            checked={selected}
            onChange={() => onToggleSelect(entry.id)}
            aria-label={`Select ${entry.name} to compare`}
            className="h-3.5 w-3.5 accent-[var(--color-accent)]"
          />
        </td>
      )}

      {/* Name + origin */}
      <td className="min-w-0 px-3 py-2.5">
        <button
          type="button"
          onClick={() => onOpen(entry)}
          title={entry.path ?? entry.name}
          className="min-w-0 text-left"
        >
          <div
            className={cn(
              "truncate text-sm font-medium text-[var(--color-text)] hover:text-[var(--color-accent)]",
              active && "text-[var(--color-accent)]",
            )}
          >
            {entry.name}
            {active && (
              <span className="ml-2 rounded-sm bg-[color-mix(in_srgb,var(--color-accent)_18%,transparent)] px-1 py-0.5 text-[9px] text-[var(--color-accent)]">
                Active
              </span>
            )}
          </div>
          <div
            className="mt-0.5 flex items-center gap-1 text-[10px] uppercase tracking-wider text-[var(--color-text-faint)]"
            title={origin.title}
          >
            <OriginIcon className="h-3 w-3" aria-hidden />
            {origin.label}
          </div>
        </button>
      </td>

      {/* Severity bar */}
      <td className="w-24 px-3 py-2.5">
        <SeverityBar entry={entry} />
      </td>

      {/* Stats */}
      <td className="hidden px-3 py-2.5 sm:table-cell">
        <div className="flex items-center gap-1.5">
          <FileStack className="h-3.5 w-3.5 text-[var(--color-text-faint)]" aria-hidden />
          <span className="font-mono-num text-xs text-[var(--color-text-dim)]">
            {compactNumber(entry.flowCount)} flows
          </span>
        </div>
      </td>

      <td className="hidden px-3 py-2.5 md:table-cell">
        <div className="flex items-center gap-1.5">
          <Database className="h-3.5 w-3.5 text-[var(--color-text-faint)]" aria-hidden />
          <span className="font-mono-num text-xs text-[var(--color-text-dim)]">
            {compactNumber(s.total_packets)} pkts
          </span>
        </div>
      </td>

      <td className="hidden px-3 py-2.5 lg:table-cell">
        <div className="flex items-center gap-1.5">
          <HardDrive className="h-3.5 w-3.5 text-[var(--color-text-faint)]" aria-hidden />
          <span className="font-mono-num text-xs text-[var(--color-text-dim)]">
            {humanBytes(entry.sizeBytes)}
          </span>
        </div>
      </td>

      <td className="hidden px-3 py-2.5 xl:table-cell">
        <div className="flex items-center gap-1.5">
          <Clock className="h-3.5 w-3.5 text-[var(--color-text-faint)]" aria-hidden />
          <span className="font-mono-num text-xs text-[var(--color-text-dim)]">
            {relativeTime(entry.analyzedAt)}
          </span>
        </div>
      </td>

      {/* Hosts */}
      <td className="hidden px-3 py-2.5 lg:table-cell">
        {s.unique_hosts > 0 && (
          <span className="text-[11px] text-[var(--color-text-faint)]">
            {humanNumber(s.unique_hosts)} hosts
          </span>
        )}
      </td>

      {/* Actions */}
      <td className="px-3 py-2.5">
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => onOpen(entry)}
            disabled={busy}
            className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2.5 py-1 text-xs font-medium text-[var(--color-text)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-accent)] disabled:opacity-50"
          >
            Open
          </button>
          <button
            type="button"
            onClick={() => onReanalyze(entry)}
            disabled={busy}
            title="Re-run the engine on the original file"
            className="inline-flex items-center gap-1 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2.5 py-1 text-xs font-medium text-[var(--color-text-dim)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-accent)] disabled:opacity-50"
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
            className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] p-1.5 text-[var(--color-text-faint)] transition-colors hover:border-[var(--color-sev-high)] hover:text-[var(--color-sev-high)] disabled:opacity-50"
          >
            <Trash2 className="h-3.5 w-3.5" aria-hidden />
          </button>
        </div>
      </td>
    </tr>
  );
}

/**
 * The "Recent captures" tab: a list of last-opened captures rendered from their
 * cached stats as bordered console rows inside a Panel. Opening a row restores the
 * dashboard instantly (and the flows table when cached); Re-analyze re-runs the
 * engine on the original file.
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
  onCompare,
}: RecentViewProps) {
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const toggleSelect = (id: string) =>
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const selectable = !!onCompare && entries.length >= 2;
  const startCompare = () => {
    if (!onCompare || selectedIds.size !== 2) return;
    const [a, b] = entries.filter((e) => selectedIds.has(e.id)).sort((x, y) => x.analyzedAt - y.analyzedAt);
    onCompare(a.id, b.id);
    setSelectedIds(new Set());
  };

  const toolbar = (
    <div className="flex items-center gap-2">
      {selectable && (
        <button
          type="button"
          onClick={startCompare}
          disabled={selectedIds.size !== 2}
          className="inline-flex items-center gap-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-xs font-medium text-[var(--color-text)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-accent)] disabled:opacity-50"
        >
          <GitCompare className="h-3.5 w-3.5" aria-hidden />
          Compare ({selectedIds.size}/2)
        </button>
      )}
      <button
        type="button"
        onClick={onLoadNew}
        className="inline-flex items-center gap-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-xs font-medium text-[var(--color-text)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-accent)]"
      >
        <Upload className="h-3.5 w-3.5" aria-hidden />
        Load capture
      </button>
      {entries.length > 0 && (
        <button
          type="button"
          onClick={onClear}
          className="inline-flex items-center gap-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-dim)] transition-colors hover:border-[var(--color-sev-high)] hover:text-[var(--color-sev-high)]"
        >
          <Trash2 className="h-3.5 w-3.5" aria-hidden />
          Clear all
        </button>
      )}
    </div>
  );

  return (
    <div data-component="RecentView" className="flex h-full min-h-0 flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-base font-medium text-[var(--color-text)]">
            Recent captures
          </h1>
          <p className="text-xs text-[var(--color-text-dim)]">
            Last opened files with their cached stats — open to restore instantly, or
            re-analyze from the original.
          </p>
        </div>
        {toolbar}
      </div>

      {entries.length === 0 ? (
        <Panel className="flex-1">
          <div className="flex h-full flex-col items-center justify-center gap-3 p-10 text-center">
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
              className="mt-1 inline-flex items-center gap-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-xs font-medium text-[var(--color-text)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-accent)]"
            >
              <Upload className="h-3.5 w-3.5" aria-hidden />
              Load capture
            </button>
          </div>
        </Panel>
      ) : (
        <Panel className="overflow-auto">
          <table className="pp-table">
            <thead>
              <tr>
                {selectable && <th className="w-8 px-3 py-2 text-left" />}
                <th className="px-3 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-[var(--color-text-faint)]">Capture</th>
                <th className="w-24 px-3 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-[var(--color-text-faint)]">Severity</th>
                <th className="hidden px-3 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-[var(--color-text-faint)] sm:table-cell">Flows</th>
                <th className="hidden px-3 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-[var(--color-text-faint)] md:table-cell">Packets</th>
                <th className="hidden px-3 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-[var(--color-text-faint)] lg:table-cell">Size</th>
                <th className="hidden px-3 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-[var(--color-text-faint)] xl:table-cell">Analyzed</th>
                <th className="hidden px-3 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-[var(--color-text-faint)] lg:table-cell">Hosts</th>
                <th className="px-3 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-[var(--color-text-faint)]">Actions</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <RecentRow
                  key={entry.id}
                  entry={entry}
                  active={entry.id === activeId}
                  busy={entry.id === busyId}
                  selectable={selectable}
                  selected={selectedIds.has(entry.id)}
                  onToggleSelect={toggleSelect}
                  onOpen={onOpen}
                  onReanalyze={onReanalyze}
                  onRemove={onRemove}
                />
              ))}
            </tbody>
          </table>
        </Panel>
      )}
    </div>
  );
}

export default RecentView;
