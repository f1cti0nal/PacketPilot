// MITRE ATT&CK coverage matrix — the capture's behavioral findings mapped onto the ATT&CK tactics
// (kill-chain columns) and techniques they cover. A Navigator-style at-a-glance "what did the
// adversary do" view. Each technique chip links to its attack.mitre.org page and is coloured by the
// worst severity of the findings citing it. Display-only; hidden when no finding carries a technique.
import { ExternalLink } from "lucide-react";
import type { Finding } from "../types";
import { attackCoverage, attackUrl } from "../lib/attack";
import { Card } from "./primitives";
import { sevColor } from "./viz";

export function AttackMatrixCard({ findings }: { findings: Finding[] }) {
  const cov = attackCoverage(findings);
  if (cov.tacticCount === 0) return null;

  return (
    <Card
      label="ATT&CK"
      title="MITRE ATT&CK coverage"
      right={
        <span className="font-mono-num t-tag text-[var(--color-text-dim)]">
          {cov.techniqueCount} technique{cov.techniqueCount === 1 ? "" : "s"} · {cov.tacticCount}{" "}
          tactic{cov.tacticCount === 1 ? "" : "s"}
        </span>
      }
    >
      {/* Tactics are kill-chain columns; horizontal scroll keeps the matrix shape on narrow cards. */}
      <div className="flex gap-3 overflow-x-auto pb-1">
        {cov.tactics.map((t) => (
          <div key={t.tactic} className="flex min-w-[140px] shrink-0 flex-col gap-1.5">
            <div className="t-label text-[var(--color-text-faint)]">{t.tactic}</div>
            {t.techniques.map((tech) => {
              const color = sevColor(tech.severity);
              return (
                <a
                  key={tech.id}
                  href={attackUrl(tech.id)}
                  target="_blank"
                  rel="noreferrer"
                  title={`${tech.id} · ${tech.name}: open on attack.mitre.org`}
                  className="group flex flex-col gap-0.5 rounded-[var(--r-tile)] border bg-[var(--color-surface-2)] px-2 py-1.5 transition-colors hover:bg-[var(--color-surface-3)]"
                  style={{ borderColor: "var(--color-border)", borderLeftColor: color, borderLeftWidth: 2 }}
                >
                  <span className="flex items-center gap-1.5">
                    <span className="font-mono-num text-[11px] font-medium" style={{ color }}>
                      {tech.id}
                    </span>
                    {tech.count > 1 && (
                      <span className="font-mono-num t-tag text-[var(--color-text-faint)]">
                        ×{tech.count}
                      </span>
                    )}
                    <ExternalLink
                      className="ml-auto h-3 w-3 shrink-0 text-[var(--color-text-faint)] opacity-0 transition-opacity group-hover:opacity-100"
                      aria-hidden
                    />
                  </span>
                  <span className="truncate text-[11px] text-[var(--color-text-dim)]">{tech.name}</span>
                </a>
              );
            })}
          </div>
        ))}
      </div>
    </Card>
  );
}

export default AttackMatrixCard;
