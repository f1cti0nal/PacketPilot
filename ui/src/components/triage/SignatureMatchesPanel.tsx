import { ShieldAlert } from "lucide-react";
import type { Finding } from "../../types";
import { humanNumber } from "../../lib/format";
import { SeverityChip, MitreTag } from "../../cockpit/primitives";

/** Extract the rule sid from a finding's evidence (defensive; null if absent). */
function sidOf(f: Finding): string | null {
  for (const e of f.evidence) {
    const m = e.match(/sid:(\d+)/);
    if (m) return m[1];
  }
  return null;
}

function MatchCard({ f }: { f: Finding }) {
  const sid = sidOf(f);
  const dst = f.dst_ip ? `${f.dst_ip}${f.dst_port != null ? `:${f.dst_port}` : ""}` : "—";
  return (
    <li className="flex flex-col gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="min-w-0 flex-1 truncate text-sm font-semibold text-[var(--color-text)]" title={f.title}>
          {f.title}
        </span>
        {sid && <span className="t-tag font-mono-num text-[var(--color-text-faint)]">sid {sid}</span>}
        <SeverityChip severity={f.severity} />
      </div>
      <div className="font-mono-num flex items-center gap-1.5 text-xs text-[var(--color-text-dim)]">
        <span className="truncate">{f.src_ip}</span>
        <span className="text-[var(--color-text-faint)]">→</span>
        <span className="truncate">{dst}</span>
      </div>
      {f.attack.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          {f.attack.map((a) => (
            <MitreTag key={a} id={a} />
          ))}
        </div>
      )}
    </li>
  );
}

/** Consolidated read-only list of imported-rule (`rule_match`) findings. Hidden when none. */
export function SignatureMatchesPanel({ findings }: { findings: Finding[] }) {
  const matches = (findings ?? []).filter((f) => f.kind === "rule_match");
  if (matches.length === 0) return null;
  return (
    <section
      data-component="SignatureMatchesPanel"
      aria-label="Signature matches"
      className="rounded-lg border border-border bg-surface p-4 shadow-sm"
    >
      <div className="mb-3 flex items-baseline justify-between gap-2">
        <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-[var(--color-text-dim)]">
          <ShieldAlert size={15} className="text-[var(--color-accent)]" /> Signature matches
        </h2>
        <span className="font-mono-num text-xs text-[var(--color-text-faint)]">{humanNumber(matches.length)} matched</span>
      </div>
      <ul className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
        {matches.slice(0, 50).map((f, i) => (
          <MatchCard key={`${sidOf(f) ?? "nosid"}-${f.src_ip}-${f.dst_ip}-${i}`} f={f} />
        ))}
      </ul>
    </section>
  );
}
