import { useState } from "react";
import { ArrowLeftRight } from "lucide-react";
import type { RecentEntry, IpThreat, Incident, Severity } from "../types";
import { diffSummaries } from "../lib/diff";
import type { Changed, DiffResult, FieldDelta } from "../lib/diff";
import { severityColor } from "../lib/palette";
import { Panel, Card, SectionHeader } from "../cockpit/primitives";

/** A signed delta number, colored: increases (worse) red, decreases green. */
function Signed({ n }: { n: number }) {
  if (n === 0) return <span className="text-[var(--color-text-faint)]">0</span>;
  const color = n > 0 ? "var(--color-sev-high)" : "var(--color-sev-low)";
  return <span style={{ color }}>{n > 0 ? "+" : ""}{n}</span>;
}

function DeltaRow({ deltas }: { deltas: FieldDelta[] }) {
  return (
    <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-[var(--color-text-faint)]">
      {deltas.map((d, i) => (
        <span key={i} className="font-mono-num">
          {d.field} <span className="text-[var(--color-text-dim)]">{d.before} → {d.after}</span>
        </span>
      ))}
    </div>
  );
}

function EntityRow({ ipOrHost, severity, kind }: { ipOrHost: string; severity: Severity; kind: "+" | "−" | "~" }) {
  return (
    <div className="flex items-center gap-2 text-xs">
      <span aria-hidden className="w-3 select-none text-center font-mono-num text-[var(--color-text-faint)]">{kind}</span>
      <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: severityColor(severity) }} aria-hidden />
      <span className="font-mono-num truncate text-[var(--color-text)]">{ipOrHost}</span>
    </div>
  );
}

function DiffSection<T extends IpThreat | Incident>({
  title, result, label,
}: { title: string; result: DiffResult<T>; label: (t: T) => string }) {
  const total = result.added.length + result.removed.length + result.changed.length;
  if (total === 0) return null;
  return (
    <Card>
      <SectionHeader
        title={title}
        count={total}
      />
      <div className="flex flex-col gap-3">
        {result.added.length > 0 && (
          <div className="flex flex-col gap-1">
            <div className="text-[10px] uppercase tracking-wider text-[var(--color-sev-high)]">Added · {result.added.length}</div>
            {result.added.map((t, i) => <EntityRow key={i} ipOrHost={label(t)} severity={t.severity} kind="+" />)}
          </div>
        )}
        {result.removed.length > 0 && (
          <div className="flex flex-col gap-1">
            <div className="text-[10px] uppercase tracking-wider text-[var(--color-sev-low)]">Removed · {result.removed.length}</div>
            {result.removed.map((t, i) => <EntityRow key={i} ipOrHost={label(t)} severity={t.severity} kind="−" />)}
          </div>
        )}
        {result.changed.length > 0 && (
          <div className="flex flex-col gap-1.5">
            <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-dim)]">Changed · {result.changed.length}</div>
            {result.changed.map((c: Changed<T>, i) => (
              <div key={i} className="flex flex-col gap-0.5">
                <EntityRow ipOrHost={c.key} severity={c.after.severity} kind="~" />
                <div className="pl-5"><DeltaRow deltas={c.deltas} /></div>
              </div>
            ))}
          </div>
        )}
      </div>
    </Card>
  );
}

export function CompareView({ before, after, onSwap }: { before?: RecentEntry; after?: RecentEntry; onSwap: () => void }) {
  const [bannerDismissed, setBannerDismissed] = useState(false);
  if (!before || !after) {
    return (
      <div data-component="CompareView" className="flex h-full items-center justify-center p-10 text-center">
        <p className="max-w-sm text-sm text-[var(--color-text-dim)]">
          One of the captures is no longer cached. Re-open it from the Recent tab and try comparing again.
        </p>
      </div>
    );
  }
  const diff = diffSummaries(before.summary.summary, after.summary.summary);
  const threatTotal = diff.threats.added.length + diff.threats.removed.length + diff.threats.changed.length;
  const incidentTotal = diff.incidents.added.length + diff.incidents.removed.length + diff.incidents.changed.length;
  const severityChanged = diff.severity.some((b) => b.delta !== 0);
  const noDiff = threatTotal === 0 && incidentTotal === 0 && !severityChanged;
  const bothNonEmpty =
    ((before.summary.summary.ip_threats?.length ?? 0) + (before.summary.summary.incidents?.length ?? 0)) > 0 &&
    ((after.summary.summary.ip_threats?.length ?? 0) + (after.summary.summary.incidents?.length ?? 0)) > 0;
  const unrelated = diff.shared === 0 && bothNonEmpty;

  return (
    <div data-component="CompareView" className="flex h-full min-h-0 flex-col gap-4 overflow-auto">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="text-base font-medium text-[var(--color-text)]">Compare captures</h1>
        <div className="flex items-center gap-2 text-xs text-[var(--color-text-dim)]">
          <span className="font-mono-num truncate">{before.name}</span>
          <span aria-hidden>→</span>
          <span className="font-mono-num truncate">{after.name}</span>
        </div>
        <button
          type="button"
          onClick={onSwap}
          className="ml-auto inline-flex items-center gap-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2.5 py-1.5 text-xs font-medium text-[var(--color-text-dim)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-accent)]"
        >
          <ArrowLeftRight className="h-3.5 w-3.5" aria-hidden /> Swap
        </button>
      </div>

      {/* Unrelated-captures banner */}
      {unrelated && !bannerDismissed && (
        <div className="flex items-start gap-2 rounded-[var(--r-card)] border border-[var(--color-sev-medium)] bg-[color-mix(in_srgb,var(--color-sev-medium)_10%,transparent)] px-3 py-2 text-xs text-[var(--color-text-dim)]">
          <span className="min-w-0 flex-1">These captures share no threat IPs or hosts; they may be unrelated.</span>
          <button
            type="button"
            onClick={() => setBannerDismissed(true)}
            aria-label="Dismiss"
            className="shrink-0 text-[var(--color-text-faint)] hover:text-[var(--color-text)]"
          >
            ✕
          </button>
        </div>
      )}

      {/* Severity delta chips */}
      {diff.severity.length > 0 && (
        <Panel label="Severity delta">
          <div className="flex flex-wrap gap-2 px-3.5 pb-3">
            {diff.severity.map((b) => (
              <div
                key={b.band}
                className="rounded-[var(--r-chip)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-xs"
              >
                <span className="capitalize text-[var(--color-text-dim)]">{b.band}</span>{" "}
                <span className="font-mono-num font-medium"><Signed n={b.delta} /></span>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* Diff content */}
      {noDiff ? (
        <Panel className="flex-1">
          <div className="flex h-full items-center justify-center p-10 text-sm text-[var(--color-text-dim)]">
            No differences between these captures.
          </div>
        </Panel>
      ) : (
        <div className="flex flex-col gap-4">
          <DiffSection title="Threat IPs" result={diff.threats} label={(t: IpThreat) => t.ip} />
          <DiffSection title="Incidents" result={diff.incidents} label={(i: Incident) => i.host} />
        </div>
      )}
    </div>
  );
}
