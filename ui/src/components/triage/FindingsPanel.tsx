import {
  Activity,
  ArrowUpFromLine,
  Radar,
  Radio,
  Siren,
  type LucideIcon,
} from "lucide-react";

import type { Finding, FindingKind } from "../../types";
import { SEVERITY_META, SEVERITY_ORDER } from "../../lib/severity";
import { severityColor } from "../../lib/palette";
import { durationHumanNs, humanNumber } from "../../lib/format";

export interface FindingsPanelProps {
  findings: Finding[];
}

/** Per-kind label + glyph. Unknown kinds fall back to a generic activity icon. */
const KIND_META: Record<FindingKind, { label: string; Icon: LucideIcon }> = {
  beacon: { label: "C2 Beacon", Icon: Radio },
  host_sweep: { label: "Host Sweep", Icon: Radar },
  data_exfil: { label: "Data Exfiltration", Icon: ArrowUpFromLine },
};

/** Worst-first: severity desc, then score desc. */
function bySeverityThenScore(a: Finding, b: Finding): number {
  const rank = (s: Finding["severity"]) => SEVERITY_ORDER.indexOf(s);
  return rank(a.severity) - rank(b.severity) || b.score - a.score;
}

/** A single severity-colored chip (mirrors ThreatsPanel). */
function SeverityChip({ severity }: { severity: Finding["severity"] }) {
  const color = severityColor(severity);
  const label = SEVERITY_META[severity]?.label ?? severity;
  return (
    <span
      className="inline-flex shrink-0 items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium"
      style={{
        color,
        borderColor: color,
        backgroundColor: `color-mix(in srgb, ${color} 14%, transparent)`,
      }}
    >
      <span
        aria-hidden
        className="h-1.5 w-1.5 rounded-full"
        style={{ backgroundColor: color }}
      />
      {label}
    </span>
  );
}

/** Structured metric pills (beacon timing); empty for findings without them. */
function findingMetrics(f: Finding): { label: string; value: string }[] {
  const out: { label: string; value: string }[] = [];
  if (f.interval_ns != null)
    out.push({ label: "Interval", value: durationHumanNs(f.interval_ns) });
  if (f.jitter_cv != null)
    out.push({ label: "Jitter", value: `CV ${f.jitter_cv.toFixed(3)}` });
  if (f.contacts != null)
    out.push({ label: "Contacts", value: humanNumber(f.contacts) });
  return out;
}

/** One behavioral finding card. */
function FindingCard({ finding }: { finding: Finding }) {
  const color = severityColor(finding.severity);
  const meta = KIND_META[finding.kind] ?? {
    label: finding.kind,
    Icon: Activity,
  };
  const Icon = meta.Icon;
  const score = Math.max(0, Math.min(100, finding.score));
  const metrics = findingMetrics(finding);
  const route =
    finding.dst_ip != null
      ? `${finding.src_ip} → ${finding.dst_ip}${
          finding.dst_port != null ? `:${finding.dst_port}` : ""
        }`
      : finding.src_ip;

  return (
    <li
      className="flex flex-col gap-2.5 rounded-lg border bg-[var(--color-surface-2)] p-3"
      style={{
        borderColor: `color-mix(in srgb, ${color} 45%, var(--color-border))`,
      }}
    >
      {/* Header: kind badge + severity chip + score */}
      <div className="flex flex-wrap items-center gap-2">
        <span
          className="inline-flex shrink-0 items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold"
          style={{
            color,
            backgroundColor: `color-mix(in srgb, ${color} 16%, transparent)`,
          }}
        >
          <Icon size={13} aria-hidden />
          {meta.label}
        </span>
        <SeverityChip severity={finding.severity} />
        <span
          className="font-mono-num ml-auto text-sm font-semibold tabular-nums"
          style={{ color }}
        >
          {score}
          <span className="text-[var(--color-text-faint)]">/100</span>
        </span>
      </div>

      {/* Route: src -> dst:port */}
      <div className="font-mono-num truncate text-sm font-semibold text-[var(--color-text)]">
        {route}
      </div>

      {/* Structured metrics (beacon timing) */}
      {metrics.length > 0 && (
        <div className="flex flex-wrap gap-x-4 gap-y-1">
          {metrics.map((m) => (
            <span key={m.label} className="text-xs text-[var(--color-text-dim)]">
              {m.label}{" "}
              <span className="font-mono-num text-[var(--color-text)]">
                {m.value}
              </span>
            </span>
          ))}
        </div>
      )}

      {/* ATT&CK techniques */}
      {finding.attack.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {finding.attack.map((t) => (
            <span
              key={t}
              className="font-mono-num rounded border border-[var(--color-border)] bg-[var(--color-surface)] px-1.5 py-0.5 text-[0.65rem] font-medium text-[var(--color-text-dim)]"
              title={`MITRE ATT&CK ${t}`}
            >
              {t}
            </span>
          ))}
        </div>
      )}

      {/* Evidence */}
      {finding.evidence.length > 0 && (
        <ul className="flex flex-col gap-0.5">
          {finding.evidence.map((e, i) => (
            <li
              key={i}
              className="flex gap-1.5 text-xs leading-snug text-[var(--color-text-faint)]"
            >
              <span aria-hidden className="select-none">
                ·
              </span>
              <span className="min-w-0 break-words">{e}</span>
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}

/**
 * "Behavioral detections" panel: the cross-flow findings (beaconing, sweeps, exfil) the engine
 * derived from traffic *behavior* — independent of any IOC feed. Renders nothing when the
 * capture has no findings, so it only appears when there is something to act on.
 */
export function FindingsPanel({ findings }: FindingsPanelProps) {
  if (findings.length === 0) return null;
  const sorted = [...findings].sort(bySeverityThenScore);

  return (
    <section
      data-component="FindingsPanel"
      aria-label="Behavioral detections"
      className="rounded-lg border border-border bg-surface p-4 shadow-sm"
    >
      <div className="mb-3 flex items-baseline justify-between gap-2">
        <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-[var(--color-text-dim)]">
          <Siren size={15} className="text-[var(--color-sev-high)]" />
          Behavioral detections
        </h2>
        <span className="font-mono-num text-xs text-[var(--color-text-faint)]">
          {humanNumber(findings.length)}{" "}
          {findings.length === 1 ? "finding" : "findings"}
        </span>
      </div>

      <ul className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
        {sorted.map((f, i) => (
          <FindingCard key={`${f.kind}-${f.src_ip}-${f.dst_ip ?? ""}-${i}`} finding={f} />
        ))}
      </ul>
    </section>
  );
}

export default FindingsPanel;
