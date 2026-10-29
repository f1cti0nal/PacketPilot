// Ranked alert queue — the analyst's first screen. Renders the engine's Smart Alerting output
// (summary.alerts) as an expandable, worst-first card list: band + priority + confidence up
// front, the joined context bundle, the transparent priority ledger, and the member findings
// each alert covers. The queue arrives ranked by the engine — array order is preserved, never
// re-sorted. "Teach it once": each card can be marked benign, which becomes a suppression rule
// applied to every later capture; what the rules hid stays listed under Suppressed.
import { useRef, useState, type ReactNode } from "react";
import { ChevronDown, ChevronRight, Download, ShieldCheck, Trash2, Upload, Waypoints } from "lucide-react";
import type {
  Alert,
  Finding,
  PriorityBand,
  SuppressionBlockReason,
  SuppressionHit,
  SuppressionRule,
  TeachScope,
} from "../types";
import { bandLabel, bandSeverity, formatTerm } from "../lib/alerts";
import { kindLabel } from "../lib/findingKinds";
import { sevColor } from "../cockpit/viz";
import { BTN_OUTLINE, BTN_PRIMARY, IocDot, MitreTag, ScoreBar, SectionLabel, SeverityChip, Tag, Toolbar } from "../cockpit/primitives";
import { EmptyState } from "../components/state/EmptyState";
import { cn } from "../lib/cn";

export interface AlertsViewProps {
  /** The engine's ranked triage queue (already sorted worst-first — rendered in given order). */
  alerts: Alert[];
  /** The capture's findings, for resolving each alert's member back-references (finding_indices). */
  findings: Finding[];
  /** Pivot into the Chains view for an alert that carries a chain_id back-reference. */
  onOpenChain?: (chainId: string) => void;
  /** Findings the analyst's suppression rules matched (hidden, or kept by a guardrail). */
  suppressions?: SuppressionHit[];
  /** The rules the engine applied to this capture (normalized; resolves a hit's rule_id). */
  appliedRules?: SuppressionRule[];
  /** The analyst's stored rule file (for the rules manager; may include expired rules). */
  storedRules?: SuppressionRule[];
  /** `YYYY-MM-DD`, for flagging expired rules. */
  today?: string;
  /** Mark an alert benign. Resolves with a one-line outcome for the card. Absent = read-only. */
  onTeach?: (alertId: string, scope: TeachScope, reason: string) => Promise<string>;
  /** Delete a rule (stops suppressing what it matched). */
  onRemoveRule?: (rule: SuppressionRule) => void;
  /** Merge a rule file the user picked into the stored rules. */
  onImportRules?: (file: File) => void;
  /** Download the stored rules as `suppressions.json`. */
  onExportRules?: () => void;
}

/** Scope choices for "Mark benign", in the order shown. */
const SCOPES: { value: TeachScope; label: string; hint: string }[] = [
  { value: "exact", label: "Exact match", hint: "Same source, destination and port" },
  { value: "source", label: "This source host", hint: "This host, to any destination" },
  { value: "destination", label: "This destination", hint: "Any host, to this destination and port (for scans: this port)" },
];

/** Why a guardrail kept a finding visible, in plain words. */
export const BLOCK_REASON_LABEL: Record<SuppressionBlockReason, string> = {
  protected_kind: "this kind of finding can never be suppressed",
  threat_intel: "a host matched the threat-intel feed",
  reputation: "a host has a malicious reputation verdict",
};

/** `src → dst:port`, with "any" for wildcards. */
export function ruleMatchText(r: SuppressionRule): string {
  const port = r.dst_port != null ? `:${r.dst_port}` : "";
  return `${r.src ?? "any"} → ${r.dst ?? "any"}${port}`;
}

/** The inline "Mark benign" form on an expanded card. */
function TeachForm({
  alertId,
  onTeach,
}: {
  alertId: string;
  onTeach: (alertId: string, scope: TeachScope, reason: string) => Promise<string>;
}) {
  const [open, setOpen] = useState(false);
  const [scope, setScope] = useState<TeachScope>("exact");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  if (!open) {
    return (
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" className={BTN_OUTLINE} onClick={() => setOpen(true)}>
          <ShieldCheck className="mr-1.5 h-4 w-4" />
          Mark benign
        </button>
        {notice && <span className="t-tag text-[var(--color-text-dim)]">{notice}</span>}
      </div>
    );
  }

  const submit = async () => {
    if (!reason.trim() || busy) return;
    setBusy(true);
    try {
      setNotice(await onTeach(alertId, scope, reason.trim()));
      setOpen(false);
      setReason("");
    } catch (e) {
      setNotice(e instanceof Error ? e.message : "Could not save the rule");
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      aria-label="Mark benign"
      className="flex flex-col gap-2 rounded-[var(--r-card)] border border-[var(--color-border)] bg-[var(--color-surface-2)] p-3"
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      <SectionLabel>Mark benign</SectionLabel>
      <p className="t-tag text-[var(--color-text-dim)]">
        Saves a rule on this device. Matching findings in this and later captures move to Suppressed.
      </p>
      <fieldset className="flex flex-col gap-1">
        <legend className="sr-only">Scope</legend>
        {SCOPES.map((o) => (
          <label key={o.value} className="flex items-start gap-2 text-xs text-[var(--color-text)]">
            <input
              type="radio"
              name={`scope-${alertId}`}
              value={o.value}
              checked={scope === o.value}
              onChange={() => setScope(o.value)}
              className="mt-0.5"
            />
            <span>
              {o.label} <span className="text-[var(--color-text-faint)]">— {o.hint}</span>
            </span>
          </label>
        ))}
      </fieldset>
      <label className="flex flex-col gap-1 text-xs text-[var(--color-text-dim)]">
        Why is this benign?
        <input
          type="text"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="e.g. Backup agent to vendor, approved in CHG-1234"
          className="rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-1)] px-2 py-1 text-sm text-[var(--color-text)]"
        />
      </label>
      <div className="flex items-center gap-2">
        <button type="submit" className={BTN_PRIMARY} disabled={!reason.trim() || busy}>
          Save rule
        </button>
        <button type="button" className={BTN_OUTLINE} onClick={() => setOpen(false)}>
          Cancel
        </button>
      </div>
    </form>
  );
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
  onTeach,
}: {
  alert: Alert;
  findings: Finding[];
  expanded: boolean;
  onToggle: () => void;
  onOpenChain?: (chainId: string) => void;
  onTeach?: (alertId: string, scope: TeachScope, reason: string) => Promise<string>;
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
          {/* Severity is the judgment axis (copied from the source story); the band chip is the
              rank axis. The two can disagree — the card always shows both. */}
          <SeverityChip severity={alert.severity} />
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

          {onTeach && <TeachForm alertId={alert.id} onTeach={onTeach} />}
        </div>
      )}
    </div>
  );
}

/** Collapsible section header used by the Suppressed list and the rules manager. */
function Disclosure({
  title,
  open,
  onToggle,
  children,
}: {
  title: string;
  open: boolean;
  onToggle: () => void;
  children: ReactNode;
}) {
  const Chevron = open ? ChevronDown : ChevronRight;
  return (
    <div className="rounded-[var(--r-card)] border border-[var(--color-border)] bg-[var(--color-surface-1)]">
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        className="flex w-full items-center gap-2 px-3.5 py-2.5 text-left text-sm font-medium text-[var(--color-text)] hover:bg-[var(--color-surface-2)]"
      >
        <Chevron className="h-4 w-4 shrink-0 text-[var(--color-text-faint)]" aria-hidden />
        {title}
      </button>
      {open && <div className="border-t border-[var(--color-border)] px-3.5 py-3">{children}</div>}
    </div>
  );
}

/** What the analyst's rules hid in this capture, and what a guardrail refused to hide. */
function SuppressedSection({
  hits,
  findings,
  rules,
  onRemoveRule,
}: {
  hits: SuppressionHit[];
  findings: Finding[];
  rules: SuppressionRule[];
  onRemoveRule?: (rule: SuppressionRule) => void;
}) {
  const [open, setOpen] = useState(false);
  const hidden = hits.filter((h) => h.status === "suppressed");
  const kept = hits.filter(
    (h): h is Extract<SuppressionHit, { status: "blocked" }> => h.status === "blocked",
  );
  const ruleOf = (id: string) => rules.find((r) => r.id === id);
  const title =
    `Suppressed (${hidden.length})` + (kept.length > 0 ? ` · ${kept.length} kept by guardrails` : "");

  return (
    <Disclosure title={title} open={open} onToggle={() => setOpen((o) => !o)}>
      <ul className="space-y-2">
        {hits.map((h) => {
          const f = findings[h.finding_index];
          const rule = ruleOf(h.rule_id);
          return (
            <li key={h.finding_index} className="flex flex-col gap-0.5 text-xs">
              <div className="flex flex-wrap items-center gap-2">
                {f && <SeverityChip severity={f.severity} />}
                <span className="font-medium text-[var(--color-text)]">{f ? kindLabel(f.kind) : "finding"}</span>
                <span className="min-w-0 truncate text-[var(--color-text-dim)]" title={f?.title}>
                  {f?.title ?? `#${h.finding_index}`}
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-2 text-[var(--color-text-faint)]">
                {h.status === "blocked" ? (
                  <span className="text-[var(--color-sev-high)]">
                    Still shown: {BLOCK_REASON_LABEL[h.reason] ?? h.reason}
                  </span>
                ) : (
                  <span>
                    Hidden by rule{rule?.reason ? `: “${rule.reason}”` : ""}
                    {rule?.author ? ` (${rule.author})` : ""}
                  </span>
                )}
                {rule && onRemoveRule && h.status === "suppressed" && (
                  <button
                    type="button"
                    className="underline hover:text-[var(--color-text)]"
                    onClick={() => onRemoveRule(rule)}
                  >
                    Stop suppressing
                  </button>
                )}
              </div>
            </li>
          );
        })}
      </ul>
    </Disclosure>
  );
}

/** The stored rule file: list, delete, import, export. */
function RulesManager({
  rules,
  today,
  onRemoveRule,
  onImportRules,
  onExportRules,
}: {
  rules: SuppressionRule[];
  today?: string;
  onRemoveRule?: (rule: SuppressionRule) => void;
  onImportRules?: (file: File) => void;
  onExportRules?: () => void;
}) {
  const [open, setOpen] = useState(false);
  const fileRef = useRef<HTMLInputElement | null>(null);
  return (
    <Disclosure title={`Suppression rules (${rules.length})`} open={open} onToggle={() => setOpen((o) => !o)}>
      <div className="flex flex-col gap-3">
        <p className="t-tag text-[var(--color-text-dim)]">
          Rules live on this device. Export them as <code>suppressions.json</code> to share with your team or use
          with <code>ppcap analyze --suppress</code>.
        </p>
        <div className="flex flex-wrap gap-2">
          {onImportRules && (
            <>
              <input
                ref={fileRef}
                type="file"
                accept=".json,application/json"
                className="hidden"
                aria-label="Import suppression rules"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) onImportRules(f);
                  e.target.value = "";
                }}
              />
              <button type="button" className={BTN_OUTLINE} onClick={() => fileRef.current?.click()}>
                <Upload className="mr-1.5 h-4 w-4" />
                Import
              </button>
            </>
          )}
          {onExportRules && rules.length > 0 && (
            <button type="button" className={BTN_OUTLINE} onClick={onExportRules}>
              <Download className="mr-1.5 h-4 w-4" />
              Export
            </button>
          )}
        </div>
        {rules.length === 0 ? (
          <p className="text-xs text-[var(--color-text-faint)]">No rules yet. Use “Mark benign” on an alert.</p>
        ) : (
          <ul className="space-y-2">
            {rules.map((r, i) => {
              const expired = !!today && !!r.expires && r.expires < today;
              return (
                <li key={r.id || i} className="flex items-start gap-2 text-xs">
                  <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium text-[var(--color-text)]">{kindLabel(r.kind)}</span>
                      <span className="font-mono-num text-[var(--color-text-dim)]">{ruleMatchText(r)}</span>
                      {expired && <Tag>expired</Tag>}
                    </div>
                    <div className="text-[var(--color-text-faint)]">
                      {r.reason || "no reason given"}
                      {r.author ? ` · ${r.author}` : ""}
                      {r.expires ? ` · ${expired ? "expired" : "expires"} ${r.expires}` : " · never expires"}
                    </div>
                  </div>
                  {onRemoveRule && (
                    <button
                      type="button"
                      aria-label={`Delete rule ${kindLabel(r.kind)} ${ruleMatchText(r)}`}
                      className="shrink-0 rounded p-1 text-[var(--color-text-faint)] hover:text-[var(--color-text)]"
                      onClick={() => onRemoveRule(r)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </Disclosure>
  );
}

/**
 * The ranked alert queue as a full-tab view: a compact verdict strip, then one expandable card
 * per alert with its band, priority ledger, context bundle, and member findings. Cards are real
 * buttons (aria-expanded) so the queue stays keyboard-navigable.
 */
export function AlertsView({
  alerts,
  findings,
  onOpenChain,
  suppressions = [],
  appliedRules = [],
  storedRules = [],
  today,
  onTeach,
  onRemoveRule,
  onImportRules,
  onExportRules,
}: AlertsViewProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const hiddenCount = suppressions.filter((h) => h.status === "suppressed").length;
  const showRules = !!(onTeach || onImportRules || storedRules.length > 0);

  if (alerts.length === 0 && suppressions.length === 0) {
    const empty = (
      <EmptyState
        title="No alerts"
        hint="The ranked triage queue appears once a capture is analyzed. Load a capture to get started."
      />
    );
    if (!showRules) return empty;
    // Rules stay manageable (import a team file, delete one) even when this capture is quiet.
    return (
      <div data-component="AlertsView" className="flex h-full min-h-0 flex-col gap-3 overflow-y-auto">
        {empty}
        <div className="mx-auto w-full max-w-4xl">
          <RulesManager
            rules={storedRules}
            today={today}
            onRemoveRule={onRemoveRule}
            onImportRules={onImportRules}
            onExportRules={onExportRules}
          />
        </div>
      </div>
    );
  }

  const findingTotal = alerts.reduce((n, a) => n + a.finding_count, 0);
  const actNow = alerts.filter((a) => a.band === "act_now").length;
  const investigate = alerts.filter((a) => a.band === "investigate").length;

  return (
    <div data-component="AlertsView" className="flex h-full min-h-0 flex-col gap-3">
      <Toolbar className="gap-2">
        <div className={cn("text-[length:var(--fs-body)] text-[var(--color-text-dim)]")}>
          {alerts.length === 0
            ? "No alerts"
            : `${alerts.length} alert${alerts.length === 1 ? "" : "s"} from ${findingTotal} finding${findingTotal === 1 ? "" : "s"} — ${actNow} act now, ${investigate} investigate`}
          {hiddenCount > 0 && ` · ${hiddenCount} finding${hiddenCount === 1 ? "" : "s"} suppressed`}
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
                onTeach={onTeach}
              />
            </li>
          ))}
          {alerts.length === 0 && (
            <li className="text-sm text-[var(--color-text-dim)]">
              No alerts left — every finding was suppressed by your rules.
            </li>
          )}
          {suppressions.length > 0 && (
            <li>
              <SuppressedSection
                hits={suppressions}
                findings={findings}
                rules={appliedRules}
                onRemoveRule={onRemoveRule}
              />
            </li>
          )}
          {showRules && (
            <li>
              <RulesManager
                rules={storedRules}
                today={today}
                onRemoveRule={onRemoveRule}
                onImportRules={onImportRules}
                onExportRules={onExportRules}
              />
            </li>
          )}
        </ul>
      </div>
    </div>
  );
}

export default AlertsView;
