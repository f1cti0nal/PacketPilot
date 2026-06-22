import { Globe } from "lucide-react";
import type { DomainThreat } from "../../types";
import { humanBytes, humanNumber } from "../../lib/format";
import { ProviderVerdictList } from "../transparency/ProviderVerdictList";

function DomainCard({ domain }: { domain: DomainThreat }) {
  const malicious = (domain.reputation ?? []).some((v) => v.status === "malicious");
  return (
    <li
      className="flex flex-col gap-2.5 rounded-lg border bg-[var(--color-surface-2)] p-3"
      style={{ borderColor: malicious ? "color-mix(in srgb, var(--color-sev-critical) 50%, var(--color-border))" : "var(--color-border)" }}
    >
      <div className="flex flex-wrap items-center gap-2">
        <Globe size={13} className="shrink-0 text-[var(--color-text-faint)]" aria-hidden />
        <span className="font-mono-num min-w-0 flex-1 truncate text-sm font-semibold text-[var(--color-text)]">{domain.host}</span>
        {malicious && (
          <span className="t-tag font-semibold" style={{ color: "var(--color-sev-critical)" }} aria-label="malicious">⚠</span>
        )}
      </div>
      <div className="flex items-center gap-3 text-xs text-[var(--color-text-dim)]">
        <span><span className="font-mono-num text-[var(--color-text)]">{humanNumber(domain.flows)}</span> flows</span>
        <span><span className="font-mono-num text-[var(--color-text)]">{humanBytes(domain.bytes)}</span></span>
      </div>
      {domain.reputation && domain.reputation.length > 0 && <ProviderVerdictList verdicts={domain.reputation} />}
    </li>
  );
}

/** Top SNI domains by traffic, with VirusTotal reputation when looked up. Hidden when empty. */
export function DomainThreatsPanel({ domains }: { domains: DomainThreat[] }) {
  if (!domains || domains.length === 0) return null;
  const top = domains.slice(0, 12);
  return (
    <section data-component="DomainThreatsPanel" aria-label="Domains" className="rounded-lg border border-border bg-surface p-4 shadow-sm">
      <div className="mb-3 flex items-baseline justify-between gap-2">
        <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-[var(--color-text-dim)]">
          <Globe size={15} className="text-[var(--color-accent)]" /> Domains
        </h2>
        <span className="font-mono-num text-xs text-[var(--color-text-faint)]">{humanNumber(domains.length)} seen</span>
      </div>
      <ul className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
        {top.map((d) => <DomainCard key={d.host} domain={d} />)}
      </ul>
    </section>
  );
}
