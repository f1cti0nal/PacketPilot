// Ranked alert queue — the analyst's first screen. Renders the engine's Smart Alerting output
// (summary.alerts) as an expandable, worst-first card list: band + priority + confidence up
// front, the joined context bundle, the transparent priority ledger, and the member findings
// each alert covers. The queue arrives ranked by the engine — array order is preserved, never
// re-sorted.
import { useState } from "react";
import { ChevronDown, ChevronRight, Waypoints } from "lucide-react";
import type { Alert, Finding, PriorityBand } from "../types";
import { bandLabel, bandSeverity, formatTerm } from "../lib/alerts";
import { kindLabel } from "../lib/findingKinds";
import { sevColor } from "../cockpit/viz";
import { BTN_OUTLINE, IocDot, MitreTag, ScoreBar, SectionLabel, SeverityChip, Tag, Toolbar } from "../cockpit/primitives";
import { EmptyState } from "../components/state/EmptyState";
import { cn } from "../lib/cn";

export interface AlertsViewProps {
  /** The engine's ranked triage queue (already sorted worst-first — rendered in given order). */
  alerts: Alert[];
  /** The capture's findings, for resolving each alert's member back-references (finding_indices). */
  findings: Finding[];
  /** Pivot into the Chains view for an alert that carries a chain_id back-reference. */
  onOpenChain?: (chainId: string) => void;
}

/** Cap on ATT&CK technique chips shown per card. */
const MAX_ATTACK_TAGS = 6;

/** Band pill, colored via the band→severity mapping so no new palette entries are needed. */
function BandChip({ band }: { band: PriorityBand }) {
  const color = sevColor(bandSeverity(band));
  return (
    <span
      className="inline-flex shrink-0 items-center gap-1.5 rounded-[var(--r-chip)] border px-2 py-0.5 t-tag font-medium uppercase"
      style={{ color, borderColor: color, backgroundColor: "var(--color-surface-2)" }}
    >
      <span aria-hidden className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
      {bandLabel(band)}
    </span>
  );
}

/** "threat_intel" → "threat intel" — the small kind tag on a context entry. */
const kindTag = (kind: string): string => kind.replace(/_/g, " ");

/** Actor identity line: IP plus whatever hostname / vendor / MAC the context join carried. */
function actorIdentity(a: Alert): string {
  const actor = a.context.actor;
  const parts: string[] = [a.actor];
  if (actor.hostname) parts.push(`= ${actor.hostname}`);
  if (actor.vendor) parts.push(`(${actor.vendor})`);
  if (actor.mac) parts.push(`[${actor.mac}]`);
  return parts.join(" ");
}

function AlertCard({
  alert,
  findings,
  expanded,
  onToggle,
  onOpenChain,
}: {
  alert: Alert;
  findings: Finding[];
  expanded: boolean;
  onToggle: () => void;
  onOpenChain?: (chainId: string) => void;
}) {
  const color = sevColor(bandSeverity(alert.band));
  const peers = alert.context.peers ?? [];
  const entries = alert.context.entries ?? [];
  const hasIoc = peers.some((p) => p.ioc);
  const hasRep = peers.some((p) => (p.reputation_malicious ?? 0) > 0);
  const hasCloud = !!alert.context.actor.cloud || peers.some((p) => !!p.cloud);
  const Chevron = expanded ? ChevronDown : ChevronRight;
  // Member findings resolved via back-references; out-of-range indices are guarded out.
  const members = alert.finding_indices
    .map((i) => ({ index: i, finding: findings[i] }))
    .filter((m): m is { index: number; finding: Finding } => m.finding !== undefined);

  return (
    <div
      className="overflow-hidden rounded-[var(--r-card)] border border-[var(--color-border)] bg-[var(--color-surface-1)]"
      style={{ borderLeft: `2px solid ${color}` }}
    >
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={expanded}
        aria-label={`${alert.title}, ${bandLabel(alert.band)}`}
        className="flex w-full flex-col gap-2 px-3.5 py-3 text-left transition-colors hover:bg-[var(--color-surface-2)]"
      >
        <div className="flex flex-wrap items-center gap-2">
          <BandChip band={alert.band} />
          <span className="font-mono-num text-sm font-medium tabular-nums" style={{ color }}>
            {alert.priority}/100
          </span>
          <ScoreBar score={alert.priority} severity={bandSeverity(alert.band)} className="w-16" />
          <span className="font-mono-num t-tag text-[var(--color-text-dim)]">conf {alert.confidence}%</span>
          <span className="ml-auto flex items-center gap-2">
            <span className="font-mono-num t-tag text-[var(--color-text-faint)]">
              covers {alert.finding_count} finding{alert.finding_count === 1 ? "" : "s"}
            </span>
            <Chevron className="h-4 w-4 shrink-0 text-[var(--color-text-faint)]" aria-hidden />
          </span>
        </div>

        <div className="text-sm font-medium text-[var(--color-text)]">{alert.title}</div>

        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="font-mono-num t-tag text-[var(--color-text-dim)]">{actorIdentity(alert)}</span>
          {alert.peer && <span className="font-mono-num t-tag text-[var(--color-text-faint)]">→ {alert.peer}</span>}
        </div>

        {(hasIoc || hasRep || hasCloud || alert.context.actor.new_to_baseline || alert.attack.length > 0) && (
          <div className="flex flex-wrap items-center gap-1.5">
            {hasIoc && (
              <span
                className="inline-flex items-center gap-1.5 rounded-[var(--r-chip)] border px-1.5 py-0.5 t-tag font-medium uppercase"
                style={{
                  color: "var(--color-sev-critical)",
                  borderColor: "var(--color-sev-critical)",
                  backgroundColor: "var(--color-surface-2)",
                }}
              >
                <IocDot />
                IOC
              </span>
            )}
            {hasRep && <Tag>reputation</Tag>}
            {hasCloud && <Tag>cloud</Tag>}
            {alert.context.actor.new_to_baseline && <Tag>new host behavior</Tag>}
            {alert.attack.slice(0, MAX_ATTACK_TAGS).map((t) => (
              <MitreTag key={t} id={t} />
            ))}
          </div>
        )}

        <div className="t-tag text-[var(--color-text-dim)]">
          <span className="uppercase text-[var(--color-text-faint)]">do: </span>
          {alert.action}
        </div>
      </button>

      {expanded && (
        <div className="flex flex-col gap-3 border-t border-[var(--color-border)] px-3.5 py-3">
          <p className="max-w-3xl text-[13px] text-[var(--color-text-dim)]">{alert.narrative}</p>

          {entries.length > 0 && (
            <div>
              <SectionLabel className="mb-1.5">Context</SectionLabel>
              <ul className="space-y-1">
                {entries.map((e, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs text-[var(--color-text-dim)]">
                    <span className="mt-px shrink-0 rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-1.5 py-0.5 t-tag text-[var(--color-text-faint)]">
                      {kindTag(e.kind)}
                    </span>
                    <span className="min-w-0">{e.text}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {peers.length > 0 && (
            <div>
              <SectionLabel className="mb-1.5">Peers</SectionLabel>
              <ul className="space-y-1">
                {peers.map((p) => (
                  <li key={p.ip} className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs">
                    <span className="font-mono-num text-[var(--color-text)]">
                      {p.ip}
                      {p.dst_port != null ? `:${p.dst_port}` : ""}
                    </span>
                    {p.domain && <span className="text-[var(--color-text-dim)]">{p.domain}</span>}
                    {p.cloud && <Tag>{p.cloud}</Tag>}
                    {p.ioc && (
                      <span className="inline-flex items-center gap-1 t-tag font-medium uppercase text-[var(--color-sev-critical)]">
                        <IocDot />
                        IOC
                      </span>
                    )}
                    {(p.reputation_malicious ?? 0) > 0 && (
                      <span className="t-tag text-[var(--color-sev-high)]">
                        rep malicious ×{p.reputation_malicious}
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div>
            <SectionLabel className="mb-1.5">Priority ledger</SectionLabel>
            <ul className="space-y-0.5">
              {alert.priority_terms.map((t, i) => (
                <li key={i} className="font-mono-num text-xs text-[var(--color-text-dim)]">
                  {formatTerm(t)}
                </li>
              ))}
            </ul>
          </div>

          {members.length > 0 && (
            <div>
              <SectionLabel className="mb-1.5">Covered findings</SectionLabel>
              <ul className="space-y-1">
                {members.map(({ index, finding }) => (
                  <li key={index} className="flex flex-wrap items-center gap-2 text-xs">
                    <SeverityChip severity={finding.severity} />
                    <span className="font-medium text-[var(--color-text)]">{kindLabel(finding.kind)}</span>
                    <span className="min-w-0 truncate text-[var(--color-text-dim)]" title={finding.title}>
                      {finding.title}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {alert.chain_id && onOpenChain && (
            <div>
              <button type="button" className={BTN_OUTLINE} onClick={() => onOpenChain(alert.chain_id!)}>
                <Waypoints className="mr-1.5 h-4 w-4" />
                Open chain
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * The ranked alert queue as a full-tab view: a compact verdict strip, then one expandable card
 * per alert with its band, priority ledger, context bundle, and member findings. Cards are real
 * buttons (aria-expanded) so the queue stays keyboard-navigable.
 */
export function AlertsView({ alerts, findings, onOpenChain }: AlertsViewProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (alerts.length === 0) {
    return (
      <EmptyState
        title="No alerts"
        hint="The ranked triage queue appears once a capture is analyzed. Load a capture to get started."
      />
    );
  }

  const findingTotal = alerts.reduce((n, a) => n + a.finding_count, 0);
  const actNow = alerts.filter((a) => a.band === "act_now").length;
  const investigate = alerts.filter((a) => a.band === "investigate").length;

  return (
    <div data-component="AlertsView" className="flex h-full min-h-0 flex-col gap-3">
      <Toolbar className="gap-2">
        <div className={cn("text-[length:var(--fs-body)] text-[var(--color-text-dim)]")}>
          {`${alerts.length} alert${alerts.length === 1 ? "" : "s"} from ${findingTotal} finding${findingTotal === 1 ? "" : "s"} — ${actNow} act now, ${investigate} investigate`}
        </div>
      </Toolbar>

      <div className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden">
        <ul className="mx-auto flex max-w-4xl flex-col gap-3">
          {alerts.map((a) => (
            <li key={a.id}>
              <AlertCard
                alert={a}
                findings={findings}
                expanded={expandedId === a.id}
                onToggle={() => setExpandedId((cur) => (cur === a.id ? null : a.id))}
                onOpenChain={onOpenChain}
              />
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export default AlertsView;
