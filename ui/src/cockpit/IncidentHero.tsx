// Zone 2 — the kill-chain incident hero. The single object the eye lands on
// first. Only the top (critical) incident breathes; secondaries are static.
import {
  ArrowUpFromLine,
  ChevronRight,
  Globe,
  KeyRound,
  Network,
  Radio,
  Radar,
  Unlock,
  Crosshair,
  FileWarning,
  ShieldAlert,
  ShieldOff,
  Shuffle,
  Waypoints,
  type LucideIcon,
} from "lucide-react";
import { cn } from "../lib/cn";
import { durationHumanNs, humanNumber } from "../lib/format";
import type { Finding, FindingKind, Incident } from "../types";
import { sevColor } from "./viz";
import { SeverityChip, MitreTag, SectionLabel } from "./primitives";
import { ScoreRing, BeaconRadar, RadarStat } from "./instruments";

const KIND_META: Record<FindingKind, { label: string; Icon: LucideIcon }> = {
  beacon: { label: "C2 Beacon", Icon: Radio },
  host_sweep: { label: "Host Sweep", Icon: Radar },
  brute_force: { label: "Brute Force", Icon: KeyRound },
  cleartext_creds: { label: "Cleartext Creds", Icon: Unlock },
  pii_exposure: { label: "PII Exposure", Icon: FileWarning },
  lateral_movement: { label: "Lateral Movement", Icon: Network },
  data_exfil: { label: "Data Exfiltration", Icon: ArrowUpFromLine },
  dns_tunnel: { label: "DNS Tunnel", Icon: Globe },
  rule_match: { label: "Signature Match", Icon: Crosshair },
  tls_cert_health: { label: "TLS Cert", Icon: ShieldAlert },
  weak_tls: { label: "Weak TLS", Icon: ShieldOff },
  icmp_tunnel: { label: "ICMP Tunnel", Icon: Waypoints },
  dga: { label: "DGA Domains", Icon: Shuffle },
};

const KIND_STAGE: Record<FindingKind, string> = {
  host_sweep: "Discovery",
  brute_force: "Credential Access",
  cleartext_creds: "Credential Access",
  pii_exposure: "Collection",
  lateral_movement: "Lateral Movement",
  beacon: "Command & Control",
  dns_tunnel: "Command & Control",
  data_exfil: "Exfiltration",
  rule_match: "Detection",
  tls_cert_health: "Command & Control",
  weak_tls: "Collection",
  icmp_tunnel: "Exfiltration",
  dga: "Command & Control",
};

const CONTACT_NOUN: Partial<Record<FindingKind, string>> = {
  beacon: "contacts",
  host_sweep: "hosts",
  brute_force: "attempts",
  lateral_movement: "hosts",
  dns_tunnel: "queries",
  dga: "domains",
  cleartext_creds: "exposures",
};

/** The load-bearing metric for a finding (what makes it real). */
function metric(f: Finding): string {
  const parts: string[] = [];
  if (f.interval_ns != null) parts.push(`every ${durationHumanNs(f.interval_ns)}`);
  if (f.jitter_cv != null) parts.push(`CV ${f.jitter_cv.toFixed(3)}`);
  if (f.contacts != null) parts.push(`${humanNumber(f.contacts)} ${CONTACT_NOUN[f.kind] ?? ""}`.trim());
  if (parts.length === 0 && f.dst_ip) parts.push(`${f.dst_ip}${f.dst_port ? `:${f.dst_port}` : ""}`);
  return parts.join(" · ");
}

/** Interpolate a stage node color along cyan → violet → critical-red. */
function stageColor(i: number, n: number): string {
  const t = n <= 1 ? 1 : i / (n - 1);
  if (t <= 0.5) return `color-mix(in srgb, var(--color-spine-violet) ${Math.round((t / 0.5) * 100)}%, var(--color-accent))`;
  return `color-mix(in srgb, var(--color-sev-critical) ${Math.round(((t - 0.5) / 0.5) * 100)}%, var(--color-spine-violet))`;
}

function KillChainStepper({ stages, findings }: { stages: string[]; findings: Finding[] }) {
  const stageMetric = (stage: string): string => {
    const f = findings.find((x) => KIND_STAGE[x.kind] === stage);
    return f ? metric(f) : "";
  };
  return (
    <div className="relative pl-1">
      {/* spine track + charging fill */}
      <div aria-hidden className="absolute left-[6px] top-1.5 bottom-1.5 w-px bg-[var(--color-border)]" />
      <div
        aria-hidden
        className="kill-spine-fill absolute left-[6px] top-1.5 bottom-1.5 w-px origin-top"
        style={{
          background: "linear-gradient(to bottom, var(--color-accent), var(--color-spine-violet), var(--color-sev-critical))",
          animation: "spine-charge 1.1s cubic-bezier(0.16,1,0.3,1) forwards",
        }}
      />
      <ol className="flex flex-col gap-3">
        {stages.map((stage, i) => {
          const color = stageColor(i, stages.length);
          const m = stageMetric(stage);
          return (
            <li key={stage} className="kill-node relative flex items-start gap-3" style={{ animation: `node-pop 0.4s ease-out ${0.12 + i * 0.16}s both` }}>
              <span className="relative z-10 mt-0.5 h-3 w-3 shrink-0 rounded-full border-2" style={{ borderColor: color, background: "var(--color-bg)", boxShadow: `0 0 8px -1px ${color}` }} />
              <div className="flex min-w-0 flex-col">
                <span className="text-[13px] font-medium text-[var(--color-text)]">{stage}</span>
                {m && <span className="font-mono-num t-tag text-[var(--color-text-faint)]">{m}</span>}
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

export function IncidentHero({
  incident,
  primary = false,
  onPivot,
  onOpen,
}: {
  incident: Incident;
  primary?: boolean;
  onPivot?: (host: string) => void;
  onOpen?: () => void;
}) {
  const color = sevColor(incident.severity);
  const beacon = incident.findings.find((f) => f.kind === "beacon");

  return (
    <article className={cn("card relative p-5", primary ? "glow-critical" : "glow-high")}>
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:gap-4">
        <ScoreRing score={incident.score} severity={incident.severity} size={primary ? 112 : 92} breathing={primary} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
            <SeverityChip severity={incident.severity} />
            <h2 className="font-mono-num t-host break-words text-[var(--color-text)]">{incident.host}</h2>
          </div>
          <p className="t-body mt-1.5 max-w-2xl text-[var(--color-text-dim)]">{incident.narrative}</p>
          <div className="mt-2 flex flex-wrap gap-1">
            {incident.attack.map((t) => (
              <MitreTag key={t} id={t} />
            ))}
          </div>
        </div>
        {onPivot && (
          <button
            type="button"
            onClick={() => onPivot(incident.host)}
            className="hidden shrink-0 items-center gap-1.5 rounded-[var(--r-tile)] border px-3 py-1.5 text-xs font-semibold transition-colors sm:inline-flex"
            style={{ color, borderColor: `color-mix(in srgb, ${color} 50%, var(--color-border))`, background: `color-mix(in srgb, ${color} 10%, transparent)` }}
          >
            <Crosshair size={13} />
            Pivot to host
          </button>
        )}
      </div>

      {/* Kill chain + beacon radar */}
      <div className="mt-5 grid grid-cols-1 gap-6 lg:grid-cols-[1fr_auto]">
        <div>
          <SectionLabel className="mb-2.5">Kill chain</SectionLabel>
          <KillChainStepper stages={incident.stages} findings={incident.findings} />
        </div>

        {beacon && (
          <div className="flex flex-col items-center gap-3 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] p-4">
            <SectionLabel>Beacon lock</SectionLabel>
            <BeaconRadar size={134} />
            <div className="font-mono-num text-center text-xs text-[var(--color-text-dim)]">
              {beacon.dst_ip}:{beacon.dst_port}
            </div>
            <div className="flex items-start gap-5">
              {beacon.interval_ns != null && <RadarStat label="Interval" value={`~${durationHumanNs(beacon.interval_ns)}`} />}
              {beacon.jitter_cv != null && <RadarStat label="Jitter CV" value={beacon.jitter_cv.toFixed(3)} />}
            </div>
          </div>
        )}
      </div>

      {/* Evidence (findings) */}
      <div className="mt-5">
        <SectionLabel className="mb-2">Evidence · {incident.findings.length} findings</SectionLabel>
        <ul className="grid grid-cols-1 gap-1.5 md:grid-cols-2">
          {incident.findings.map((f, i) => {
            const meta = KIND_META[f.kind];
            const Icon = meta.Icon;
            const fc = sevColor(f.severity);
            return (
              <li key={`${f.kind}-${i}`}>
                <button
                  type="button"
                  onClick={onOpen}
                  aria-haspopup="dialog"
                  aria-label={`Open details: ${f.title}`}
                  className="flex w-full items-center gap-2 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-1)] px-2.5 py-2 text-left transition-colors hover:border-[var(--color-border-strong)] hover:bg-[var(--color-surface-2)]"
                >
                  <span className="inline-flex shrink-0 items-center gap-1 rounded-[var(--r-micro)] px-1.5 py-0.5 t-tag font-semibold" style={{ color: fc, background: `color-mix(in srgb, ${fc} 14%, transparent)` }}>
                    <Icon size={11} />
                    {meta.label}
                  </span>
                  <span className="min-w-0 flex-1 truncate text-xs text-[var(--color-text-dim)]">{f.title}</span>
                  <ChevronRight size={13} className="shrink-0 text-[var(--color-text-faint)]" />
                </button>
              </li>
            );
          })}
        </ul>
      </div>
    </article>
  );
}

export default IncidentHero;
