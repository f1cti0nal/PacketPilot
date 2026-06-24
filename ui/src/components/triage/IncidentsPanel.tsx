import { Fragment } from "react";
import {
  Activity,
  ArrowUpFromLine,
  ChevronRight,
  Crosshair,
  Globe,
  KeyRound,
  IdCard,
  Network,
  Radar,
  Radio,
  ShieldAlert,
  ShieldOff,
  Siren,
  Unlock,
  Waypoints,
  type LucideIcon,
} from "lucide-react";

import type { Finding, FindingKind, Incident } from "../../types";
import { SEVERITY_META, SEVERITY_ORDER } from "../../lib/severity";
import { severityColor } from "../../lib/palette";
import { humanNumber } from "../../lib/format";
import { EvidenceList } from "../transparency/EvidenceList";
import { FindingMetrics } from "../transparency/FindingMetrics";

export interface IncidentsPanelProps {
  incidents: Incident[];
}

/** Per-kind label + glyph. */
const KIND_META: Record<FindingKind, { label: string; Icon: LucideIcon }> = {
  beacon: { label: "C2 Beacon", Icon: Radio },
  host_sweep: { label: "Host Sweep", Icon: Radar },
  brute_force: { label: "Brute Force", Icon: KeyRound },
  cleartext_creds: { label: "Cleartext Credentials", Icon: Unlock },
  pii_exposure: { label: "Plaintext PII", Icon: IdCard },
  lateral_movement: { label: "Lateral Movement", Icon: Network },
  data_exfil: { label: "Data Exfiltration", Icon: ArrowUpFromLine },
  dns_tunnel: { label: "DNS Tunnel", Icon: Globe },
  rule_match: { label: "Signature Match", Icon: Crosshair },
  tls_cert_health: { label: "TLS Cert", Icon: ShieldAlert },
  weak_tls: { label: "Weak TLS", Icon: ShieldOff },
  icmp_tunnel: { label: "ICMP Tunnel", Icon: Waypoints },
};

/** Worst-first ordering. */
const worstFirst = (a: { severity: Incident["severity"]; score: number }, b: typeof a) =>
  SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || b.score - a.score;

/** A single severity-colored chip. */
function SeverityChip({ severity }: { severity: Incident["severity"] }) {
  const color = severityColor(severity);
  const label = SEVERITY_META[severity]?.label ?? severity;
  return (
    <span
      className="inline-flex shrink-0 items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-semibold uppercase tracking-wide"
      style={{
        color,
        borderColor: color,
        backgroundColor: `color-mix(in srgb, ${color} 16%, transparent)`,
      }}
    >
      <span aria-hidden className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
      {label}
    </span>
  );
}

/** One contributing finding, rendered compactly inside an incident card. */
function FindingRow({ finding }: { finding: Finding }) {
  const color = severityColor(finding.severity);
  const meta = KIND_META[finding.kind] ?? { label: finding.kind, Icon: Activity };
  const Icon = meta.Icon;

  return (
    <li className="flex flex-col gap-1 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-2">
      <div className="flex flex-wrap items-center gap-2">
        <span
          className="inline-flex shrink-0 items-center gap-1 rounded px-1.5 py-0.5 text-[0.7rem] font-semibold"
          style={{
            color,
            backgroundColor: `color-mix(in srgb, ${color} 16%, transparent)`,
          }}
        >
          <Icon size={12} aria-hidden />
          {meta.label}
        </span>
        <span className="font-mono-num min-w-0 flex-1 truncate text-xs text-[var(--color-text-dim)]">
          {finding.title}
        </span>
      </div>
      <FindingMetrics finding={finding} />
      <EvidenceList evidence={finding.evidence} />
    </li>
  );
}

/** One correlated incident card. */
function IncidentCard({ incident }: { incident: Incident }) {
  const color = severityColor(incident.severity);
  const score = Math.max(0, Math.min(100, incident.score));

  return (
    <li
      className="flex flex-col gap-3 rounded-lg border bg-[var(--color-surface-2)] p-3.5"
      style={{ borderColor: `color-mix(in srgb, ${color} 50%, var(--color-border))` }}
    >
      {/* Header: severity, host, score */}
      <div className="flex flex-wrap items-center gap-2">
        <SeverityChip severity={incident.severity} />
        <span className="font-mono-num truncate text-sm font-semibold text-[var(--color-text)]">
          {incident.host}
        </span>
        <span
          className="font-mono-num ml-auto text-sm font-semibold tabular-nums"
          style={{ color }}
        >
          {score}
          <span className="text-[var(--color-text-faint)]">/100</span>
        </span>
      </div>

      {/* Kill-chain stages */}
      <div className="flex flex-wrap items-center gap-1.5">
        {incident.stages.map((stage, idx) => (
          <Fragment key={stage}>
            {idx > 0 && (
              <ChevronRight
                size={13}
                aria-hidden
                className="text-[var(--color-text-faint)]"
              />
            )}
            <span className="rounded border border-[var(--color-border)] bg-[var(--color-surface)] px-1.5 py-0.5 text-[0.7rem] font-medium text-[var(--color-text-dim)]">
              {stage}
            </span>
          </Fragment>
        ))}
        {incident.attack.length > 0 && (
          <span className="ml-auto flex flex-wrap gap-1">
            {incident.attack.map((t) => (
              <span
                key={t}
                className="font-mono-num rounded border border-[var(--color-border)] bg-[var(--color-surface)] px-1.5 py-0.5 text-[0.65rem] font-medium text-[var(--color-text-dim)]"
                title={`MITRE ATT&CK ${t}`}
              >
                {t}
              </span>
            ))}
          </span>
        )}
      </div>

      {/* Narrative */}
      <p className="text-sm leading-snug text-[var(--color-text-dim)]">{incident.narrative}</p>

      {/* Contributing findings */}
      <ul className="flex flex-col gap-1.5">
        {incident.findings.map((f, i) => (
          <FindingRow key={`${f.kind}-${i}`} finding={f} />
        ))}
      </ul>
    </li>
  );
}

/**
 * "Active incidents" panel: behavioral findings correlated into per-host stories, ordered along
 * the kill chain and escalated for multi-stage chains. The top-level triage unit — renders
 * nothing when the capture has no incidents.
 */
export function IncidentsPanel({ incidents }: IncidentsPanelProps) {
  if (incidents.length === 0) return null;
  const sorted = [...incidents].sort(worstFirst);

  return (
    <section
      data-component="IncidentsPanel"
      aria-label="Active incidents"
      className="rounded-lg border border-border bg-surface p-4 shadow-sm"
    >
      <div className="mb-3 flex items-baseline justify-between gap-2">
        <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-[var(--color-text-dim)]">
          <Siren size={15} className="text-[var(--color-sev-critical)]" />
          Active incidents
        </h2>
        <span className="font-mono-num text-xs text-[var(--color-text-faint)]">
          {humanNumber(incidents.length)}{" "}
          {incidents.length === 1 ? "incident" : "incidents"}
        </span>
      </div>

      <ul className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        {sorted.map((inc, i) => (
          <IncidentCard key={`${inc.host}-${i}`} incident={inc} />
        ))}
      </ul>
    </section>
  );
}

export default IncidentsPanel;
