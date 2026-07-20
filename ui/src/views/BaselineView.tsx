import { useMemo, useRef } from "react";
import { ArrowRight, Download, Gauge, GraduationCap, Radio, Trash2, Upload } from "lucide-react";
import type { AnalysisOutput, BaselineProfile, Finding, HostBaseline } from "../types";
import { humanNumber } from "../lib/format";
import { parseBaseline, serializeBaseline } from "../lib/baseline";
import { downloadText } from "../lib/platform";
import { BTN_OUTLINE, Panel, SeverityChip } from "../cockpit/primitives";
import { cn } from "../lib/cn";

export interface BaselineViewProps {
  /** The current ready analysis (its findings carry any folded deviations); null when none loaded. */
  output: AnalysisOutput | null;
  /** The learned baseline profile from local storage, or null if none yet. */
  baseline: BaselineProfile | null;
  /** Fold the current capture into the baseline (create-or-merge) and persist it. */
  onLearn: () => void;
  /** Drop one host from the baseline (e.g. a host you now believe was compromised). */
  onForgetHost: (host: string) => void;
  /** Delete the whole baseline (a clean reset). */
  onClear: () => void;
  /** Replace the baseline with an imported profile (a portable `.baseline.json`). */
  onImport: (profile: BaselineProfile) => void;
  /** Drill into Flows filtered by a host. */
  onJumpToFlows?: (filter: { ip?: string }) => void;
}

/** An "Import" button that owns its own hidden file input (so it works in both the empty and
 *  populated states without threading a ref through the parent). */
function ImportControl({ onImport }: { onImport: (p: BaselineProfile) => void }) {
  const ref = useRef<HTMLInputElement>(null);
  return (
    <>
      <button type="button" className={BTN_OUTLINE} onClick={() => ref.current?.click()}>
        <Upload className="mr-1.5 h-4 w-4" />
        Import
      </button>
      <input
        ref={ref}
        type="file"
        accept=".json,application/json"
        hidden
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f)
            void f.text().then((t) => {
              const p = parseBaseline(t);
              if (p) onImport(p);
            });
          e.target.value = "";
        }}
      />
    </>
  );
}

const activeHours = (h: HostBaseline): number =>
  (h.hour_of_day ?? []).filter((v) => v > 0).length;

function HourStrip({ host }: { host: HostBaseline }) {
  const hours = host.hour_of_day ?? [];
  if (hours.length === 0) return null;
  return (
    <div className="mt-2 flex gap-px" title="Active hours (UTC)">
      {Array.from({ length: 24 }, (_, i) => (
        <span
          key={i}
          className={cn(
            "h-3 flex-1 rounded-[1px]",
            (hours[i] ?? 0) > 0 ? "bg-sky-400/70" : "bg-white/8",
          )}
        />
      ))}
    </div>
  );
}

function HostCard({
  host,
  onForget,
  onJump,
}: {
  host: HostBaseline;
  onForget: () => void;
  onJump?: () => void;
}) {
  const stat = (label: string, value: string | number) => (
    <div>
      <div className="text-[10px] uppercase tracking-wide text-white/40">{label}</div>
      <div className="tabular-nums text-white/90">{value}</div>
    </div>
  );
  return (
    <div className="rounded-lg border border-white/10 bg-white/[0.02] p-3">
      <div className="flex items-start justify-between gap-2">
        <button
          type="button"
          onClick={onJump}
          className="font-mono text-sm text-white/90 hover:text-sky-300"
          title="View this host's flows"
        >
          {host.host}
        </button>
        <button
          type="button"
          onClick={onForget}
          className="shrink-0 rounded p-1 text-white/40 hover:bg-white/10 hover:text-rose-300"
          title="Forget this host (drop it from the baseline)"
          aria-label={`Forget ${host.host}`}
        >
          <Trash2 className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="mt-2 grid grid-cols-4 gap-2 text-xs">
        {stat("captures", host.captures_seen)}
        {stat("peers", host.peers.length)}
        {stat("ports", host.services.length)}
        {stat("JA3", host.ja3?.length ?? 0)}
        {stat("out ~B", humanNumber(Math.round(host.bytes_out.mean)))}
        {stat("in ~B", humanNumber(Math.round(host.bytes_in.mean)))}
        {stat("flows ~", humanNumber(Math.round(host.flows.mean)))}
        {stat("active h", activeHours(host))}
      </div>
      {(host.beacons?.length ?? 0) > 0 && (
        <div className="mt-2 flex items-center gap-1 text-[11px] text-amber-300/80">
          <Radio className="h-3 w-3" />
          {host.beacons!.length} learned beacon channel{host.beacons!.length === 1 ? "" : "s"}
        </div>
      )}
      <HourStrip host={host} />
    </div>
  );
}

function DeviationCard({ f, onJump }: { f: Finding; onJump?: () => void }) {
  return (
    <div className="rounded-lg border border-white/10 bg-white/[0.02] p-3">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <SeverityChip severity={f.severity} />
          <button
            type="button"
            onClick={onJump}
            className="font-mono text-sm text-white/90 hover:text-sky-300"
          >
            {f.src_ip}
          </button>
          {f.dst_ip && <span className="text-xs text-white/40">→ {f.dst_ip}</span>}
        </div>
        {onJump && (
          <button
            type="button"
            onClick={onJump}
            className="flex items-center gap-1 text-[11px] text-white/50 hover:text-sky-300"
          >
            flows <ArrowRight className="h-3 w-3" />
          </button>
        )}
      </div>
      <div className="mt-1 text-sm text-white/80">{f.title}</div>
      <ul className="mt-2 space-y-0.5">
        {f.evidence.map((e, i) => (
          <li key={i} className="text-xs text-white/55">
            • {e}
          </li>
        ))}
      </ul>
    </div>
  );
}

export function BaselineView({
  output,
  baseline,
  onLearn,
  onForgetHost,
  onClear,
  onImport,
  onJumpToFlows,
}: BaselineViewProps) {
  const deviations = useMemo<Finding[]>(
    () => (output?.summary.findings ?? []).filter((f) => f.kind === "baseline_deviation"),
    [output],
  );
  const hosts = useMemo(
    () => [...(baseline?.hosts ?? [])].sort((a, b) => b.captures_seen - a.captures_seen),
    [baseline],
  );
  const canLearn = !!output?.baseline?.hosts?.length;

  if (!baseline) {
    return (
      <div className="flex h-full min-h-0 flex-col items-center justify-center px-6 py-12 text-center">
        <div className="mb-5 flex h-16 w-16 items-center justify-center rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-1)] text-[var(--color-accent)]">
          <Gauge size={30} aria-hidden />
        </div>
        <h2 className="font-display text-xl font-medium text-[var(--color-text)]">
          No behavioral baseline yet
        </h2>
        <p className="mt-2 max-w-md text-sm text-[var(--color-text-dim)]">
          {canLearn
            ? "Learn this capture as the first observation of your network's normal behavior. After a few captures, PacketPilot flags hosts that deviate — a new external peer, port, JA3, off-hours activity, or a new beacon. The baseline stays on this device — nothing is uploaded."
            : "Analyze a capture in the browser first, then learn it as the baseline. The baseline is stored on this device (local storage) — nothing is uploaded."}
        </p>
        <div className="mt-6 flex items-center gap-2">
          {canLearn && (
            <button type="button" className={BTN_OUTLINE} onClick={onLearn}>
              <GraduationCap className="mr-1.5 h-4 w-4" />
              Learn from this capture
            </button>
          )}
          <ImportControl onImport={onImport} />
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-6xl space-y-4 px-4 py-6">
      <Panel
        label="BASELINE"
        title="Learned behavioral profile"
        right={
          <div className="flex items-center gap-2">
            <span className="text-xs text-white/40">
              {baseline.captures_merged ?? 0} capture
              {(baseline.captures_merged ?? 0) === 1 ? "" : "s"} · {hosts.length} host
              {hosts.length === 1 ? "" : "s"}
            </span>
            <button
              type="button"
              className={BTN_OUTLINE}
              onClick={onLearn}
              disabled={!canLearn}
              title={canLearn ? "Fold the current capture into the baseline" : "No snapshot in the current capture"}
            >
              <GraduationCap className="mr-1.5 h-4 w-4" />
              Learn this capture
            </button>
            <button
              type="button"
              className={BTN_OUTLINE}
              onClick={() =>
                downloadText(
                  serializeBaseline(baseline),
                  "packetpilot-baseline.json",
                  "application/json",
                )
              }
              title="Export the baseline to a portable JSON file"
            >
              <Download className="mr-1.5 h-4 w-4" />
              Export
            </button>
            <ImportControl onImport={onImport} />
            <button
              type="button"
              className={BTN_OUTLINE}
              onClick={onClear}
              title="Delete the baseline (a clean reset)"
            >
              <Trash2 className="mr-1.5 h-4 w-4" />
              Reset
            </button>
          </div>
        }
      >
        {hosts.length === 0 ? (
          <div className="p-4 text-sm text-white/50">The baseline has no hosts yet.</div>
        ) : (
          <div className="grid grid-cols-1 gap-2 p-2 sm:grid-cols-2 lg:grid-cols-3">
            {hosts.map((h) => (
              <HostCard
                key={h.host}
                host={h}
                onForget={() => onForgetHost(h.host)}
                onJump={onJumpToFlows ? () => onJumpToFlows({ ip: h.host }) : undefined}
              />
            ))}
          </div>
        )}
      </Panel>

      <Panel
        label="DEVIATIONS"
        title="This capture vs. the baseline"
        right={
          <span className="text-xs text-white/40">
            {deviations.length} deviation{deviations.length === 1 ? "" : "s"}
          </span>
        }
      >
        {deviations.length === 0 ? (
          <div className="p-4 text-sm text-white/50">
            No deviations — every host in this capture matches its learned baseline (or hasn't reached
            the warm-up threshold yet).
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-2 p-2 lg:grid-cols-2">
            {deviations.map((f, i) => (
              <DeviationCard
                key={i}
                f={f}
                onJump={onJumpToFlows ? () => onJumpToFlows({ ip: f.src_ip }) : undefined}
              />
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
