import { ShieldAlert } from "lucide-react";
import type { Finding } from "../../types";
import { humanNumber } from "../../lib/format";
import { dstLabel } from "../../lib/findingTarget";
import { SeverityChip, MitreTag, Panel } from "../../cockpit/primitives";

/** Extract the rule sid from a finding's evidence (defensive; null if absent). */
function sidOf(f: Finding): string | null {
  for (const e of f.evidence) {
    const m = e.match(/sid:(\d+)/);
    if (m) return m[1];
  }
  return null;
}

function MatchCard({ f, onJump }: { f: Finding; onJump?: (ip: string) => void }) {
  const sid = sidOf(f);
  const dst = dstLabel(f);
  const pivot = f.dst_ip ?? f.src_ip;

  const content = (
    <>
      <div className="flex flex-wrap items-center gap-2">
        <span className="min-w-0 flex-1 truncate text-sm font-medium text-[var(--color-text)]" title={f.title}>
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
    </>
  );

  if (onJump) {
    return (
      <li>
        <button
          type="button"
          onClick={() => onJump(pivot)}
          aria-label={`View flows for ${pivot}`}
          className="flex w-full flex-col gap-2 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] p-3 text-left transition-colors hover:border-[var(--color-border-strong)]"
        >
          {content}
        </button>
      </li>
    );
  }

  return (
    <li className="flex flex-col gap-2 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] p-3">
      {content}
    </li>
  );
}

/** Consolidated read-only list of imported-rule (`rule_match`) findings. Hidden when none. */
export function SignatureMatchesPanel({ findings, onJump }: { findings: Finding[]; onJump?: (ip: string) => void }) {
  const matches = (findings ?? []).filter((f) => f.kind === "rule_match");
  if (matches.length === 0) return null;
  return (
    <Panel
      label="DETECTIONS"
      title="Signature matches"
      count={`${humanNumber(matches.length)} matched`}
      icon={<ShieldAlert size={14} />}
      bodyClassName="p-3"
    >
      <ul className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
        {matches.slice(0, 50).map((f, i) => (
          <MatchCard key={`${sidOf(f) ?? "nosid"}-${f.src_ip}-${f.dst_ip}-${i}`} f={f} onJump={onJump} />
        ))}
      </ul>
    </Panel>
  );
}
