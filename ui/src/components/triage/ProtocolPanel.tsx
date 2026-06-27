import { useMemo } from "react";
import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  Layers,
  Network,
  Globe,
  Lock,
  Send,
  HelpCircle,
  type LucideIcon,
} from "lucide-react";
import type { ProtoCounts, ProtocolHierarchyNode } from "../../types";
import { compactNumber, humanBytes, humanNumber, percent } from "../../lib/format";

export interface ProtocolPanelProps {
  proto: ProtoCounts;
  /**
   * Optional `summary.protocol_hierarchy`. Rendered as a labeled share list
   * when present. Kept optional so the existing `{ proto }` contract is stable.
   */
  protocolHierarchy?: ProtocolHierarchyNode[];
}

interface ProtoTile {
  key: string;
  label: string;
  count: number;
  icon: LucideIcon;
  cssVar: string;
}

/** Pretty leaf name for a `protocol_hierarchy` path like "ip.tcp.https". */
function hierarchyLeaf(path: string): string {
  const parts = path.split(".");
  return parts[parts.length - 1] || path;
}

export function ProtocolPanel({ proto, protocolHierarchy }: ProtocolPanelProps) {
  // ---- L4 transport split (TCP vs UDP) ----
  const l4Total = proto.tcp + proto.udp;
  const l4Tiles = useMemo<ProtoTile[]>(
    () => [
      {
        key: "tcp",
        label: "TCP",
        count: proto.tcp,
        icon: Network,
        cssVar: "--color-accent",
      },
      {
        key: "udp",
        label: "UDP",
        count: proto.udp,
        icon: Network,
        cssVar: "--color-sev-medium",
      },
    ],
    [proto.tcp, proto.udp],
  );

  // ---- L7 application split (DNS / HTTP / TLS / Other) ----
  const l7Other = proto.other_tcp + proto.other_udp;
  const l7Tiles = useMemo<ProtoTile[]>(
    () => [
      {
        key: "dns",
        label: "DNS",
        count: proto.dns,
        icon: Globe,
        cssVar: "--color-sev-info",
      },
      {
        key: "http",
        label: "HTTP",
        count: proto.http,
        icon: Send,
        cssVar: "--color-sev-high",
      },
      {
        key: "tls",
        label: "TLS",
        count: proto.tls,
        icon: Lock,
        cssVar: "--color-sev-medium",
      },
      {
        key: "other",
        label: "Other",
        count: l7Other,
        icon: HelpCircle,
        cssVar: "--color-sev-none",
      },
    ],
    [proto.dns, proto.http, proto.tls, l7Other],
  );

  const l7Total = useMemo(
    () => l7Tiles.reduce((acc, t) => acc + t.count, 0),
    [l7Tiles],
  );

  const chartData = useMemo(
    () => l7Tiles.map((t) => ({ name: t.label, value: t.count, fill: t.cssVar })),
    [l7Tiles],
  );

  const hierarchy = useMemo(() => {
    if (!protocolHierarchy || protocolHierarchy.length === 0) return [];
    const max = protocolHierarchy.reduce((m, n) => Math.max(m, n.pkts), 0) || 1;
    return [...protocolHierarchy]
      .sort((a, b) => b.pkts - a.pkts)
      .map((n) => ({ ...n, frac: n.pkts / max }));
  }, [protocolHierarchy]);

  return (
    <section
      data-component="ProtocolPanel"
      className="flex flex-col gap-4 rounded-lg border border-border bg-surface p-4"
    >
      <header className="flex items-center gap-2">
        <Layers className="h-4 w-4 text-[var(--color-accent)]" aria-hidden />
        <h3 className="text-sm font-medium text-[var(--color-text)]">
          Protocol mix
        </h3>
        <span className="ml-auto text-xs text-[var(--color-text-faint)]">
          {humanNumber(l4Total)} pkts
        </span>
      </header>

      {/* L4 transport */}
      <div>
        <div className="mb-1.5 text-[11px] font-medium uppercase tracking-wide text-[var(--color-text-faint)]">
          Transport (L4)
        </div>
        <div className="grid grid-cols-2 gap-2">
          {l4Tiles.map((t) => (
            <ProtoStat key={t.key} tile={t} total={l4Total} />
          ))}
        </div>
      </div>

      {/* L7 application */}
      <div>
        <div className="mb-1.5 text-[11px] font-medium uppercase tracking-wide text-[var(--color-text-faint)]">
          Application (L7)
        </div>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          {l7Tiles.map((t) => (
            <ProtoStat key={t.key} tile={t} total={l7Total} />
          ))}
        </div>

        {l7Total > 0 && (
          <div className="mt-3 h-28">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={chartData}
                margin={{ top: 4, right: 4, bottom: 0, left: 4 }}
              >
                <XAxis
                  dataKey="name"
                  tick={{ fill: "var(--color-text-dim)", fontSize: 11 }}
                  axisLine={{ stroke: "var(--color-border)" }}
                  tickLine={false}
                />
                <YAxis
                  width={36}
                  tick={{ fill: "var(--color-text-faint)", fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                  tickFormatter={(v: number) => compactNumber(v)}
                />
                <Tooltip
                  cursor={{ fill: "var(--color-surface-2)" }}
                  contentStyle={{
                    background: "var(--color-surface-2)",
                    border: "1px solid var(--color-border)",
                    borderRadius: 6,
                    color: "var(--color-text)",
                    fontSize: 12,
                  }}
                  labelStyle={{ color: "var(--color-text-dim)" }}
                  formatter={(value: number) => [
                    `${humanNumber(value)} pkts`,
                    "Packets",
                  ]}
                />
                <Bar dataKey="value" radius={[3, 3, 0, 0]}>
                  {chartData.map((d) => (
                    <Cell key={d.name} fill={`var(${d.fill})`} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Protocol hierarchy */}
      {hierarchy.length > 0 && (
        <div>
          <div className="mb-1.5 text-[11px] font-medium uppercase tracking-wide text-[var(--color-text-faint)]">
            Protocol hierarchy
          </div>
          <ul className="flex flex-col gap-1.5">
            {hierarchy.map((n) => (
              <li key={n.path} className="flex flex-col gap-1">
                <div className="flex items-baseline justify-between gap-2">
                  <span
                    className="font-mono-num truncate text-xs text-[var(--color-text)]"
                    title={n.path}
                  >
                    <span className="text-[var(--color-text-faint)]">
                      {n.path.slice(0, n.path.length - hierarchyLeaf(n.path).length)}
                    </span>
                    <span className="font-medium">{hierarchyLeaf(n.path)}</span>
                  </span>
                  <span className="font-mono-num shrink-0 text-xs text-[var(--color-text-dim)]">
                    {humanNumber(n.pkts)}{" "}
                    <span className="text-[var(--color-text-faint)]">
                      · {humanBytes(n.bytes)}
                    </span>
                  </span>
                </div>
                <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-2">
                  <div
                    className="h-full rounded-full bg-[var(--color-accent)]"
                    style={{ width: `${Math.max(2, n.frac * 100)}%` }}
                  />
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

interface ProtoStatProps {
  tile: ProtoTile;
  total: number;
}

function ProtoStat({ tile, total }: ProtoStatProps) {
  const { label, count, icon: Icon, cssVar } = tile;
  const frac = total > 0 ? count / total : 0;
  return (
    <div className="flex flex-col gap-1.5 rounded-md border border-border bg-surface-2 px-2.5 py-2">
      <div className="flex items-center gap-1.5">
        <Icon
          className="h-3.5 w-3.5"
          style={{ color: `var(${cssVar})` }}
          aria-hidden
        />
        <span className="text-[11px] font-medium uppercase tracking-wide text-[var(--color-text-dim)]">
          {label}
        </span>
        <span className="font-mono-num ml-auto text-[11px] text-[var(--color-text-faint)]">
          {percent(count, total)}
        </span>
      </div>
      <span className="font-mono-num text-lg font-medium leading-none text-[var(--color-text)]">
        {humanNumber(count)}
      </span>
      <div className="h-1 w-full overflow-hidden rounded-full bg-[var(--color-grid)]">
        <div
          className="h-full rounded-full"
          style={{
            width: `${Math.max(frac > 0 ? 2 : 0, frac * 100)}%`,
            background: `var(${cssVar})`,
          }}
        />
      </div>
    </div>
  );
}

export default ProtocolPanel;
