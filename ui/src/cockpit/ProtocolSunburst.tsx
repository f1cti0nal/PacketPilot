import { useMemo } from "react";
import { Network } from "lucide-react";
import type { ProtocolHierarchyNode } from "../types";
import { buildSunburst } from "../lib/protocolSunburst";
import { humanBytes } from "../lib/format";
import { cssVar } from "../lib/palette";

/** L4 transport -> theme token (the L7 ring inherits its L4's hue at lower opacity). */
const L4_TOKEN: Record<string, string> = {
  tcp: "--color-accent",
  udp: "--color-sev-low",
  icmp: "--color-sev-medium",
  icmpv6: "--color-sev-medium",
  sctp: "--color-sev-high",
};
const l4Of = (path: string): string => path.split(".")[1] ?? "";
const colorFor = (path: string): string => cssVar(L4_TOKEN[l4Of(path)] ?? "--color-text-faint");

/**
 * Protocol-hierarchy sunburst: the capture's `ip -> L4 -> L7` byte composition as a two-ring radial
 * (the classic Wireshark "protocol hierarchy" view). Built from the engine's `protocol_hierarchy`
 * leaf paths; deterministic layout (see `buildSunburst`). Display-only with per-segment tooltips;
 * hidden when the capture has no protocol breakdown.
 */
export function ProtocolSunburst({ hierarchy }: { hierarchy: ProtocolHierarchyNode[] }) {
  const model = useMemo(() => buildSunburst(hierarchy ?? []), [hierarchy]);
  if (model.arcs.length === 0) return null;

  const cx = model.size / 2;
  const present = [...new Set(model.arcs.map((a) => l4Of(a.path)))].filter(Boolean);

  return (
    <section
      data-component="ProtocolSunburst"
      aria-label="Protocol hierarchy"
      className="rounded-lg border border-border bg-surface p-4 shadow-sm"
    >
      <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-[var(--color-text-dim)]">
        <Network size={15} className="text-[var(--color-accent)]" /> Protocol hierarchy
      </h2>

      <svg
        viewBox={`0 0 ${model.size} ${model.size}`}
        className="mx-auto block w-full max-w-[340px]"
        role="img"
        aria-label="Protocol hierarchy sunburst"
      >
        {model.arcs.map((a) => (
          <path
            key={a.path}
            d={a.d}
            fill={colorFor(a.path)}
            fillOpacity={a.depth === 1 ? 0.85 : 0.5}
            stroke="var(--color-surface)"
            strokeWidth={1}
          >
            <title>{`${a.path} · ${humanBytes(a.bytes)} (${(a.fraction * 100).toFixed(1)}%)`}</title>
          </path>
        ))}
        {model.arcs
          .filter((a) => a.fraction > 0.06)
          .map((a) => (
            <text
              key={`label-${a.path}`}
              x={a.labelX}
              y={a.labelY}
              textAnchor="middle"
              dominantBaseline="middle"
              fontSize={9}
              fill="var(--color-text)"
              pointerEvents="none"
              className="font-mono-num"
            >
              {a.label}
            </text>
          ))}
        <text x={cx} y={cx - 4} textAnchor="middle" fontSize={10} fill="var(--color-text-dim)">
          IP
        </text>
        <text
          x={cx}
          y={cx + 9}
          textAnchor="middle"
          fontSize={9}
          fill="var(--color-text-faint)"
          className="font-mono-num"
        >
          {humanBytes(model.total)}
        </text>
      </svg>

      <div className="mt-2 flex flex-wrap items-center justify-center gap-x-3 gap-y-1">
        {present.map((l4) => (
          <span
            key={l4}
            className="inline-flex items-center gap-1 text-[0.65rem] uppercase text-[var(--color-text-faint)]"
          >
            <span
              aria-hidden
              className="h-2 w-2 rounded-full"
              style={{ backgroundColor: colorFor(`ip.${l4}`) }}
            />
            {l4}
          </span>
        ))}
      </div>
    </section>
  );
}

export default ProtocolSunburst;
