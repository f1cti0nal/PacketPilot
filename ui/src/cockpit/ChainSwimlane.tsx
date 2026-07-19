// Horizontal swimlane for one reconstructed attack chain: one lane per host, each step placed on
// its actor's lane with x scaled by time, and edges drawn as connectors (cross-host pivots stand
// out dashed + critical-coloured). Pure presentational SVG — layout comes from computeChainLayout.
import { computeChainLayout } from "../lib/killChain";
import type { AttackChain } from "../types";
import { kindMeta } from "../lib/findingKinds";
import { sevColor } from "./viz";

const LANE_LABEL_W = 132;

export function ChainSwimlane({
  chain,
  width = 720,
  laneHeight = 60,
  onOpenFinding,
}: {
  chain: AttackChain;
  width?: number;
  laneHeight?: number;
  onOpenFinding?: (findingIndex: number) => void;
}) {
  const layout = computeChainLayout(chain, { width, laneHeight });
  const svgW = width + LANE_LABEL_W;
  const svgH = layout.height + 24; // headroom for the top tactic labels

  return (
    <svg
      role="img"
      aria-label={`Attack chain across ${chain.hosts.length} host(s): ${chain.hosts.join(" to ")}`}
      viewBox={`0 0 ${svgW} ${svgH}`}
      width="100%"
      style={{ maxWidth: "100%", height: "auto", overflow: "visible" }}
    >
      <g transform="translate(0,20)">
        {/* Lanes: a track line per host + the host label. */}
        {layout.lanes.map((lane) => (
          <g key={lane.host}>
            <line
              x1={LANE_LABEL_W}
              y1={lane.y}
              x2={svgW}
              y2={lane.y}
              stroke="var(--color-border)"
              strokeWidth={1}
            />
            <text
              x={LANE_LABEL_W - 10}
              y={lane.y}
              textAnchor="end"
              dominantBaseline="middle"
              className="font-mono-num"
              fontSize={11}
              fill="var(--color-text-dim)"
            >
              {lane.host}
            </text>
          </g>
        ))}

        {/* Edges: progression (subtle) + pivot (dashed, critical). */}
        {layout.arrows.map((a, i) => {
          const isPivot = a.kind === "pivot";
          return (
            <line
              key={`${a.fromOrder}-${a.toOrder}-${i}`}
              data-kind={a.kind}
              className="chain-arrow"
              x1={a.x1 + LANE_LABEL_W}
              y1={a.y1}
              x2={a.x2 + LANE_LABEL_W}
              y2={a.y2}
              stroke={isPivot ? "var(--color-sev-critical)" : "var(--color-border-strong)"}
              strokeWidth={isPivot ? 2 : 1.25}
              strokeDasharray={isPivot ? "5 3" : undefined}
              opacity={isPivot ? 0.9 : 0.6}
            />
          );
        })}

        {/* Nodes: one per step, coloured by severity; the tactic label sits above. */}
        {layout.nodes.map((nd) => {
          const color = sevColor(nd.step.severity);
          const meta = kindMeta(nd.step.kind);
          const clickable = !!onOpenFinding;
          return (
            <g
              key={nd.order}
              data-testid="chain-node"
              transform={`translate(${nd.x + LANE_LABEL_W},${nd.y})`}
              role={clickable ? "button" : undefined}
              tabIndex={clickable ? 0 : undefined}
              aria-label={`${nd.step.tactic}: ${meta.label} on ${nd.step.actor}`}
              onClick={clickable ? () => onOpenFinding(nd.step.finding_index) : undefined}
              onKeyDown={
                clickable
                  ? (e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        onOpenFinding(nd.step.finding_index);
                      }
                    }
                  : undefined
              }
              style={{ cursor: clickable ? "pointer" : "default" }}
            >
              <circle r={7} fill="var(--color-bg)" stroke={color} strokeWidth={2} />
              <text
                x={0}
                y={-13}
                textAnchor="middle"
                fontSize={9.5}
                fill="var(--color-text-faint)"
              >
                {nd.step.tactic}
              </text>
            </g>
          );
        })}
      </g>
    </svg>
  );
}

export default ChainSwimlane;
