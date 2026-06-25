import { useMemo } from "react";
import { Share2 } from "lucide-react";
import type { Finding, IpThreat } from "../types";
import { buildThreatGraph } from "../lib/threatGraph";
import { severityColor } from "../lib/palette";
import { SEVERITY_META } from "../lib/severity";

/**
 * Threat relationship graph: a deterministic radial node-link view of the hosts implicated by
 * behavioural findings and the `src -> dst` relationships between them. Complements the incident
 * *list* with a spatial map of who is doing what to whom. Nodes are click-to-jump-to-flows. Hidden
 * when there are fewer than two related hosts.
 */
export function ThreatGraph({
  findings,
  threats,
  onJump,
}: {
  findings: Finding[];
  threats: IpThreat[];
  onJump?: (ip: string) => void;
}) {
  const model = useMemo(
    () => buildThreatGraph(findings ?? [], threats ?? []),
    [findings, threats],
  );
  if (model.nodes.length < 2) return null;

  return (
    <section
      data-component="ThreatGraph"
      aria-label="Threat relationship graph"
      className="rounded-lg border border-border bg-surface p-4 shadow-sm"
    >
      <div className="mb-3 flex items-baseline justify-between gap-2">
        <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-[var(--color-text-dim)]">
          <Share2 size={15} className="text-[var(--color-accent)]" /> Threat relationships
        </h2>
        {model.truncated > 0 && (
          <span className="font-mono-num text-xs text-[var(--color-text-faint)]">
            +{model.truncated} more
          </span>
        )}
      </div>

      <svg
        viewBox={`0 0 ${model.width} ${model.height}`}
        className="mx-auto block w-full max-w-[480px]"
        role="group"
        aria-label="Host relationship graph"
      >
        <g>
          {model.edges.map((e) => (
            <path
              key={e.id}
              d={e.path}
              fill="none"
              stroke={severityColor(e.severity)}
              strokeWidth={1.5}
              strokeOpacity={0.5}
            />
          ))}
        </g>
        <g>
          {model.nodes.map((nd) => {
            const color = severityColor(nd.severity);
            return (
              <g
                key={nd.ip}
                className={onJump ? "cursor-pointer" : undefined}
                role={onJump ? "button" : undefined}
                tabIndex={onJump ? 0 : undefined}
                aria-label={onJump ? `View flows for ${nd.ip}` : undefined}
                onClick={onJump ? () => onJump(nd.ip) : undefined}
                onKeyDown={
                  onJump
                    ? (ev) => {
                        if (ev.key === "Enter" || ev.key === " ") {
                          ev.preventDefault();
                          onJump(nd.ip);
                        }
                      }
                    : undefined
                }
              >
                <circle
                  cx={nd.x}
                  cy={nd.y}
                  r={nd.r}
                  fill={color}
                  fillOpacity={0.22}
                  stroke={color}
                  strokeWidth={1.5}
                />
                <text
                  x={nd.labelX}
                  y={nd.labelY}
                  textAnchor={nd.labelAnchor}
                  fontSize={9}
                  fill="var(--color-text-dim)"
                  className="font-mono-num"
                >
                  {nd.ip}
                </text>
              </g>
            );
          })}
        </g>
      </svg>

      <div className="mt-2 flex flex-wrap items-center justify-center gap-x-3 gap-y-1">
        {(["critical", "high", "medium", "low"] as const).map((s) => (
          <span
            key={s}
            className="inline-flex items-center gap-1 text-[0.65rem] text-[var(--color-text-faint)]"
          >
            <span
              aria-hidden
              className="h-2 w-2 rounded-full"
              style={{ backgroundColor: severityColor(s) }}
            />
            {SEVERITY_META[s].label}
          </span>
        ))}
      </div>
    </section>
  );
}

export default ThreatGraph;
