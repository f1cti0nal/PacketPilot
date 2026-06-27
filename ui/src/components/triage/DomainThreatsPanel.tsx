import { Globe } from "lucide-react";
import type { DomainThreat } from "../../types";
import { humanBytes, humanNumber } from "../../lib/format";
import { Panel } from "../../cockpit/primitives";
import { ProviderVerdictList } from "../transparency/ProviderVerdictList";

function DomainCard({ domain }: { domain: DomainThreat }) {
  const malicious = (domain.reputation ?? []).some((v) => v.status === "malicious");
  return (
    <li
      className="flex flex-col gap-2.5 rounded-[var(--r-tile)] border bg-[var(--color-surface-2)] p-3"
      style={{ borderColor: malicious ? "color-mix(in srgb, var(--color-sev-critical) 50%, var(--color-border))" : "var(--color-border)" }}
    >
      <div className="flex flex-wrap items-center gap-2">
        <Globe size={13} className="shrink-0 text-[var(--color-text-faint)]" aria-hidden />
        <span className="font-mono-num min-w-0 flex-1 truncate text-sm font-medium text-[var(--color-text)]">{domain.host}</span>
        {malicious && (
          <span className="t-tag font-medium" style={{ color: "var(--color-sev-critical)" }} aria-label="malicious">⚠</span>
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
    <Panel
      label="DNS / SNI"
      title="Domains"
      count={`${humanNumber(domains.length)} seen`}
      icon={<Globe size={14} />}
      bodyClassName="p-3"
    >
      <ul className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
        {top.map((d) => <DomainCard key={d.host} domain={d} />)}
      </ul>
    </Panel>
  );
}
