import { ShieldAlert, ShieldOff } from "lucide-react";
import type { IpThreat } from "../../types";
import { SEVERITY_META } from "../../lib/severity";
import { severityColor } from "../../lib/palette";
import { humanBytes, humanNumber } from "../../lib/format";
import { ProviderVerdictList } from "../transparency/ProviderVerdictList";
import { EvidenceList } from "../transparency/EvidenceList";

export interface ThreatsPanelProps {
  threats: IpThreat[];
}

/** How many scored hosts to surface in the panel. */
const TOP_N = 10;

/** A single severity-colored chip. */
function SeverityChip({ severity }: { severity: IpThreat["severity"] }) {
  const color = severityColor(severity);
  const label = SEVERITY_META[severity]?.label ?? severity;
  return (
    <span
      className="inline-flex shrink-0 items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium"
      style={{
        color,
        borderColor: color,
        backgroundColor: "var(--color-surface-2)",
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

/** One scored host report card. */
function ThreatCard({ threat }: { threat: IpThreat }) {
  const color = severityColor(threat.severity);
  const score = Math.max(0, Math.min(100, threat.score));

  return (
    <li
      className="flex flex-col gap-2.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] p-3"
      style={{ borderColor: `color-mix(in srgb, ${color} 35%, var(--color-border))` }}
    >
      {/* Header row: severity, IP, class, IOC */}
      <div className="flex flex-wrap items-center gap-2">
        <SeverityChip severity={threat.severity} />
        <span className="font-mono-num truncate text-sm font-semibold text-[var(--color-text)]">
          {threat.ip}
        </span>
        <span className="shrink-0 rounded bg-[var(--color-surface)] px-1.5 py-0.5 text-xs font-medium text-[var(--color-text-dim)]">
          {threat.ip_class}
        </span>
        {threat.ioc && (
          <span
            className="inline-flex shrink-0 items-center gap-1 rounded px-1.5 py-0.5 text-xs font-semibold"
            style={{
              color: "var(--color-sev-critical)",
              backgroundColor:
                "color-mix(in srgb, var(--color-sev-critical) 16%, transparent)",
            }}
            title="On a known indicator-of-compromise feed"
          >
            <ShieldAlert size={12} />
            IOC
          </span>
        )}
      </div>

      {/* Score + bar */}
      <div className="flex items-center gap-2">
        <span
          className="font-mono-num text-sm font-semibold tabular-nums"
          style={{ color }}
        >
          {score}
          <span className="text-[var(--color-text-faint)]">/100</span>
        </span>
        <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-[var(--color-surface)]">
          <div
            className="h-full rounded-full"
            style={{ width: `${score}%`, backgroundColor: color }}
          />
        </div>
      </div>

      {/* Volume */}
      <div className="flex items-center gap-3 text-xs text-[var(--color-text-dim)]">
        <span>
          <span className="font-mono-num text-[var(--color-text)]">
            {humanNumber(threat.flows)}
          </span>{" "}
          flows
        </span>
        <span>
          <span className="font-mono-num text-[var(--color-text)]">
            {humanBytes(threat.bytes)}
          </span>
        </span>
      </div>

      {/* ATT&CK techniques */}
      {threat.attack.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {threat.attack.map((t) => (
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

      {/* Tags. A `cloud:<provider>` tag is offline hosting attribution — render it as a small
          outlined provenance chip ("☁ AWS") to distinguish it from the plain public/internal/ioc
          tags. */}
      {threat.tags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {threat.tags.map((t) =>
            t.startsWith("cloud:") ? (
              <span
                key={t}
                className="t-tag rounded border border-[var(--color-border)] px-1 text-[var(--color-text-dim)]"
                title="Offline cloud/hosting attribution (coarse hint)"
              >
                ☁ {t.slice("cloud:".length)}
              </span>
            ) : (
              <span key={t} className="t-tag text-[var(--color-text-dim)]">{t}</span>
            ),
          )}
        </div>
      )}

      {/* TLS fingerprint chips (matched-malware subset) */}
      {threat.fingerprints && threat.fingerprints.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {threat.fingerprints.map((fp, i) => (
            <span
              key={i}
              className="inline-flex shrink-0 items-center gap-1 rounded px-1.5 py-0.5 text-xs font-semibold"
              style={{
                color: "var(--color-sev-critical)",
                backgroundColor: "var(--color-surface-2)",
              }}
              title={[fp.ja3 && `JA3: ${fp.ja3}`, fp.ja4 && `JA4: ${fp.ja4}`].filter(Boolean).join("\n")}
            >
              <ShieldAlert size={12} />
              {fp.ja4 ? "JA4" : "JA3"} · {fp.label}
            </span>
          ))}
        </div>
      )}

      {/* Per-provider reputation breakdown */}
      {threat.reputation && threat.reputation.length > 0 && (
        <ProviderVerdictList verdicts={threat.reputation} />
      )}

      {/* Evidence */}
      <EvidenceList evidence={threat.evidence} />
    </li>
  );
}

/** Empty state when no scored threats exist. */
function EmptyThreats() {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-8 text-center">
      <div className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface-2)] p-3">
        <ShieldOff size={20} className="text-[var(--color-text-faint)]" />
      </div>
      <p className="text-sm font-medium text-[var(--color-text-dim)]">
        No scored threats
      </p>
      <p className="max-w-[18rem] text-xs text-[var(--color-text-faint)]">
        The engine did not score any host above the noise floor in this capture.
      </p>
    </div>
  );
}

/**
 * Prominent "Top threats" panel: renders the highest-scoring hosts the engine
 * flagged, already sorted by score descending.
 */
export function ThreatsPanel({ threats }: ThreatsPanelProps) {
  const top = threats.slice(0, TOP_N);

  return (
    <section
      data-component="ThreatsPanel"
      aria-label="Top threats"
      className="rounded-lg border border-border bg-surface p-4 shadow-sm"
    >
      <div className="mb-3 flex items-baseline justify-between gap-2">
        <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-[var(--color-text-dim)]">
          <ShieldAlert size={15} className="text-[var(--color-sev-critical)]" />
          Top threats
        </h2>
        {threats.length > 0 && (
          <span className="font-mono-num text-xs text-[var(--color-text-faint)]">
            {humanNumber(threats.length)} scored
          </span>
        )}
      </div>

      {top.length === 0 ? (
        <EmptyThreats />
      ) : (
        <ul className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
          {top.map((t) => (
            <ThreatCard key={t.ip} threat={t} />
          ))}
        </ul>
      )}
    </section>
  );
}

export default ThreatsPanel;
