// Full-tab view: one alert told as a single chronological story across every host it touches —
// first contact, DNS answers, downloads, detections and lateral hops — with each row one click
// from its packets (a carved .pcap of just that host pair and window) or its flows. The analyst
// picks the alert, can narrow to a host, and copies / downloads the story for a ticket.
import { useMemo, useState } from "react";
import { ArrowRightLeft, Copy, Download, Globe, FileDown, Radar, Scissors, Share2, Waypoints } from "lucide-react";
import type { Alert, AlertTimeline, TimelineEvent, TimelineEventKind, TimelineExportFormat } from "../types";
import { Card, MitreTag, SeverityChip, BTN_OUTLINE, BTN_GHOST_ICON } from "../cockpit/primitives";
import { EmptyState } from "../components/state/EmptyState";
import { bandLabel } from "../lib/alerts";
import { nsToDateTime, durationHumanNs } from "../lib/format";
import { sevColor } from "../cockpit/viz";
import { bpfFor, filterByHosts, kindLabel, laneColor, offsetLabel, pickTimeline } from "../lib/timeline";
import { cn } from "../lib/cn";

const KIND_ICON: Record<TimelineEventKind, typeof Radar> = {
  first_contact: ArrowRightLeft,
  dns_answer: Globe,
  pivot: Waypoints,
  file_download: FileDown,
  detection: Radar,
};

export function TimelineView({
  timelines,
  alerts = [],
  focusId = null,
  onFocus,
  canCarve = false,
  onCarve,
  onJumpToFlows,
  onExport,
  onCopy,
  notice,
}: {
  timelines: AlertTimeline[];
  /** The alert queue, for band labels in the picker. */
  alerts?: Alert[];
  /** Alert id whose timeline to show (the Alerts "Open timeline" pivot); else the top alert's. */
  focusId?: string | null;
  onFocus?: (alertId: string) => void;
  /** Packets are retained for this capture (carving is possible). */
  canCarve?: boolean;
  /** Carve a row's packet scope into a .pcap. */
  onCarve?: (event: TimelineEvent) => void;
  /** Open the Flows view filtered to a host. */
  onJumpToFlows?: (ip: string) => void;
  onExport?: (timeline: AlertTimeline, format: TimelineExportFormat) => void;
  onCopy?: (timeline: AlertTimeline, format: TimelineExportFormat) => void;
  /** One-line outcome of the last carve / export (status region). */
  notice?: string | null;
}) {
  const [hostFilter, setHostFilter] = useState<ReadonlySet<string>>(new Set());
  const current = pickTimeline(timelines, focusId);
  const bandById = useMemo(() => new Map(alerts.map((a) => [a.id, a.band])), [alerts]);
  const rows = useMemo(
    () => (current ? filterByHosts(current.events, hostFilter) : []),
    [current, hostFilter],
  );

  if (!current) {
    return (
      <EmptyState
        title="No incident timeline yet"
        hint="A timeline appears for every alert: each one is retold in time order across the hosts it touches. This capture raised no alerts."
      />
    );
  }

  const toggleHost = (h: string) =>
    setHostFilter((prev) => {
      const next = new Set(prev);
      if (next.has(h)) next.delete(h);
      else next.add(h);
      return next;
    });
  const select = (id: string) => {
    setHostFilter(new Set());
    onFocus?.(id);
  };
  const span =
    current.first_ts_ns != null && current.last_ts_ns != null
      ? `${nsToDateTime(current.first_ts_ns)} · ${durationHumanNs(current.last_ts_ns - current.first_ts_ns)}`
      : "untimed";
  const hidden = current.event_count - current.events.length;

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-4 p-4">
      <Card
        label="Incident timeline"
        title={current.title}
        right={
          <div className="flex flex-wrap items-center justify-end gap-1.5">
            {onCopy && (
              <button type="button" className={cn(BTN_OUTLINE, "whitespace-nowrap")} onClick={() => onCopy(current, "markdown")}>
                <Copy className="h-3.5 w-3.5" /> Copy Markdown
              </button>
            )}
            {onExport && (
              <>
                <button type="button" className={BTN_OUTLINE} onClick={() => onExport(current, "markdown")}>
                  <Download className="h-3.5 w-3.5" /> .md
                </button>
                <button type="button" className={BTN_OUTLINE} onClick={() => onExport(current, "csv")}>
                  <Download className="h-3.5 w-3.5" /> .csv
                </button>
              </>
            )}
          </div>
        }
      >
        <div className="flex flex-col gap-3">
          {timelines.length > 1 && (
            <label className="flex flex-wrap items-center gap-2 text-xs text-[var(--color-text-dim)]">
              <span>Alert</span>
              <select
                aria-label="Alert"
                value={current.alert_id}
                onChange={(e) => select(e.target.value)}
                className="min-w-0 max-w-full flex-1 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-1 text-xs text-[var(--color-text)]"
              >
                {timelines.map((t, i) => {
                  const band = bandById.get(t.alert_id);
                  return (
                    <option key={t.alert_id} value={t.alert_id}>
                      {i + 1}. {band ? `[${bandLabel(band)}] ` : ""}
                      {t.title}
                    </option>
                  );
                })}
              </select>
            </label>
          )}

          <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 text-xs text-[var(--color-text-dim)]">
            <span className="font-mono-num">{span}</span>
            <span>
              {current.events.length} event{current.events.length === 1 ? "" : "s"}
              {hidden > 0 && ` (of ${current.event_count}; detections kept first)`}
            </span>
          </div>

          {/* Host lanes: colour key + click to narrow the story to one or more hosts. */}
          <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter by host">
            {current.hosts.map((h) => {
              const on = hostFilter.has(h);
              return (
                <button
                  key={h}
                  type="button"
                  aria-pressed={on}
                  onClick={() => toggleHost(h)}
                  className={cn(
                    "inline-flex items-center gap-1.5 rounded-[var(--r-micro)] border px-2 py-0.5 font-mono-num text-[11px] transition-colors",
                    on
                      ? "border-[var(--color-accent)] text-[var(--color-text)]"
                      : "border-[var(--color-border)] text-[var(--color-text-dim)] hover:border-[var(--color-border-strong)]",
                  )}
                >
                  <span aria-hidden className="h-2 w-2 rounded-full" style={{ background: laneColor(current.hosts, h) }} />
                  {h}
                </button>
              );
            })}
            {hostFilter.size > 0 && (
              <button type="button" className="text-[11px] text-[var(--color-accent)] underline-offset-2 hover:underline" onClick={() => setHostFilter(new Set())}>
                Show all hosts
              </button>
            )}
          </div>

          {notice && (
            <p role="status" className="text-xs text-[var(--color-text-faint)]">
              {notice}
            </p>
          )}

          <ol className="relative flex flex-col" aria-label="Timeline events">
            {rows.map((e, i) => (
              <TimelineRow
                key={`${e.kind}-${e.ts_ns ?? "u"}-${e.host}-${i}`}
                event={e}
                start={current.first_ts_ns}
                hosts={current.hosts}
                last={i === rows.length - 1}
                canCarve={canCarve}
                onCarve={onCarve}
                onJumpToFlows={onJumpToFlows}
              />
            ))}
          </ol>
        </div>
      </Card>
    </div>
  );
}

function TimelineRow({
  event: e,
  start,
  hosts,
  last,
  canCarve,
  onCarve,
  onJumpToFlows,
}: {
  event: TimelineEvent;
  start: number | null;
  hosts: string[];
  last: boolean;
  canCarve: boolean;
  onCarve?: (event: TimelineEvent) => void;
  onJumpToFlows?: (ip: string) => void;
}) {
  const Icon = KIND_ICON[e.kind] ?? Radar;
  const color = sevColor(e.severity);
  const filter = e.packets ? bpfFor(e.packets) : null;
  return (
    <li data-testid="timeline-row" data-kind={e.kind} className="relative flex gap-3 pb-3">
      {/* Rail: severity-coloured node + connector to the next row. */}
      <div className="relative flex w-6 shrink-0 justify-center">
        {!last && <span aria-hidden className="absolute top-6 bottom-0 w-px bg-[var(--color-border)]" />}
        <span
          aria-hidden
          className="relative z-[1] mt-0.5 flex h-6 w-6 items-center justify-center rounded-full border-2 bg-[var(--color-bg)]"
          style={{ borderColor: color, color }}
        >
          <Icon size={12} />
        </span>
      </div>

      <div className="min-w-0 flex-1 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-[var(--color-text-faint)]">
          <span className="font-mono-num text-[var(--color-text-dim)]">
            {e.ts_ns != null ? nsToDateTime(e.ts_ns) : "untimed"}
          </span>
          {e.ts_ns != null && <span className="font-mono-num">{offsetLabel(e.ts_ns, start)}</span>}
          <span className="inline-flex items-center gap-1 font-mono-num" title="Host">
            <span aria-hidden className="h-2 w-2 rounded-full" style={{ background: laneColor(hosts, e.host) }} />
            {e.host}
          </span>
          <span className="rounded-[var(--r-micro)] border border-[var(--color-border)] px-1.5 py-px uppercase tracking-wide">
            {kindLabel(e.kind)}
          </span>
          {e.tactic && <span>{e.tactic}</span>}
          {e.severity !== "info" && <SeverityChip severity={e.severity} />}
        </div>

        <p className="mt-1 break-words text-[13px] text-[var(--color-text)]">{e.title}</p>
        {e.detail && <p className="mt-0.5 break-words text-xs text-[var(--color-text-dim)]">{e.detail}</p>}

        <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
          {(e.attack ?? []).map((id) => (
            <MitreTag key={id} id={id} />
          ))}
          {filter && (
            <code className="min-w-0 truncate rounded-[var(--r-micro)] bg-[var(--color-surface-3)] px-1.5 py-px font-mono-num text-[11px] text-[var(--color-text-faint)]" title="Capture filter (tcpdump / Wireshark)">
              {filter}
            </code>
          )}
          <span className="ml-auto flex items-center gap-1">
            {onCarve && e.packets && (
              <button
                type="button"
                className={BTN_GHOST_ICON}
                disabled={!canCarve}
                aria-label={`Carve packets for ${kindLabel(e.kind)} on ${e.host}`}
                title={canCarve ? "Carve these packets (.pcap)" : "Packets are only available for captures analyzed from a pcap"}
                onClick={() => onCarve(e)}
                style={canCarve ? undefined : { opacity: 0.4, cursor: "not-allowed" }}
              >
                <Scissors size={13} />
              </button>
            )}
            {onJumpToFlows && (
              <button
                type="button"
                className={BTN_GHOST_ICON}
                aria-label={`Open flows for ${e.host}`}
                title="Open this host's flows"
                onClick={() => onJumpToFlows(e.host)}
              >
                <Share2 size={13} />
              </button>
            )}
          </span>
        </div>
      </div>
    </li>
  );
}

export default TimelineView;
