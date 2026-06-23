import { type ReactNode, useMemo } from "react";
import {
  X,
  ArrowRight,
  ArrowLeft,
  Network,
  Server,
  Clock,
  Hash,
  Layers,
  Activity,
  Info,
  Globe,
  ShieldAlert,
  Binary,
  Scissors,
} from "lucide-react";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
} from "recharts";
import type { ActiveSource, FlowRow } from "../types";
import { packetsAvailable } from "../lib/packets";
import { cn } from "../lib/cn";
import {
  humanBytes,
  humanNumber,
  durationHumanMs,
  msToTime,
  percent,
} from "../lib/format";
import { SEVERITY_META } from "../lib/severity";
import { severityColor, chartPalette } from "../lib/palette";

/**
 * Props for the flow detail side panel.
 *
 * Mirrors the canonical detail-panel contract used across the PacketPilot UI:
 * a nullable selected row plus a close callback. `flow === null` renders the
 * empty state.
 */
export interface FlowDetailProps {
  /** The currently selected flow row, or `null` when nothing is selected. */
  flow: FlowRow | null;
  /** Invoked when the user dismisses the panel. */
  onClose: () => void;
  /** The active capture source — gates whether packets can be extracted for this flow. */
  activeSource: ActiveSource;
  /** Invoked when the user requests the packet inspector for the selected flow. */
  onInspectPackets: () => void;
  /** Invoked when the user requests a carved sub-pcap for the selected flow. */
  onCarvePcap: () => void;
}

/** Human label for a TCP flags bitmask (bits per RFC 793 + ECN/NS). */
function tcpFlagsLabel(flags: number): string {
  if (flags === 0) return "—";
  const bits: Array<[number, string]> = [
    [0x01, "FIN"],
    [0x02, "SYN"],
    [0x04, "RST"],
    [0x08, "PSH"],
    [0x10, "ACK"],
    [0x20, "URG"],
    [0x40, "ECE"],
    [0x80, "CWR"],
  ];
  const names = bits.filter(([m]) => (flags & m) !== 0).map(([, n]) => n);
  return names.length ? names.join(" ") : "—";
}

/** One labeled key/value row. */
function Field({
  icon,
  label,
  children,
  mono = false,
  title,
}: {
  icon?: ReactNode;
  label: string;
  children: ReactNode;
  mono?: boolean;
  title?: string;
}) {
  return (
    <div className="flex items-start justify-between gap-3 py-1.5">
      <dt className="flex shrink-0 items-center gap-1.5 text-xs font-medium uppercase tracking-wide text-[var(--color-text-faint)]">
        {icon}
        {label}
      </dt>
      <dd
        title={title}
        className={cn(
          "min-w-0 break-words text-right text-sm text-[var(--color-text)]",
          mono && "font-mono-num",
        )}
      >
        {children}
      </dd>
    </div>
  );
}

/** Section heading with a divider. */
function Section({
  icon,
  title,
  children,
}: {
  icon: ReactNode;
  title: string;
  children: ReactNode;
}) {
  return (
    <section className="border-t border-[var(--color-border)] px-4 py-3 first:border-t-0">
      <h3 className="mb-1.5 flex items-center gap-1.5 text-[0.7rem] font-semibold uppercase tracking-wider text-[var(--color-text-dim)]">
        {icon}
        {title}
      </h3>
      <dl>{children}</dl>
    </section>
  );
}

/** Category chip colored by derived severity. */
function CategoryChip({ flow }: { flow: FlowRow }) {
  const color = severityColor(flow.severity);
  const sevLabel = SEVERITY_META[flow.severity].label;
  const catLabel = flow.category.replace(/_/g, " ");
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium capitalize"
      style={{
        color,
        borderColor: color,
        backgroundColor: `color-mix(in srgb, ${color} 14%, transparent)`,
      }}
      title={`Severity: ${sevLabel}`}
    >
      <span
        className="h-1.5 w-1.5 rounded-full"
        style={{ backgroundColor: color }}
      />
      {catLabel}
    </span>
  );
}

/** Directional byte / packet breakdown with a split bar + chart. */
function TrafficBreakdown({ flow }: { flow: FlowRow }) {
  const palette = chartPalette();
  const total = flow.bytesTotal;
  const c2sPct = total > 0 ? (flow.bytesC2s / total) * 100 : 0;
  const s2cPct = total > 0 ? (flow.bytesS2c / total) * 100 : 0;

  const data = useMemo(
    () => [
      { name: "C→S", bytes: flow.bytesC2s, fill: palette.accent },
      { name: "S→C", bytes: flow.bytesS2c, fill: palette.sev.medium },
    ],
    [flow.bytesC2s, flow.bytesS2c, palette.accent, palette.sev.medium],
  );

  return (
    <div>
      {/* Split proportion bar */}
      <div className="mb-3 flex h-2.5 w-full overflow-hidden rounded-full bg-[var(--color-surface-2)]">
        <div
          className="h-full"
          style={{ width: `${c2sPct}%`, backgroundColor: palette.accent }}
          title={`Client → Server: ${humanBytes(flow.bytesC2s)} (${percent(
            flow.bytesC2s,
            total,
          )})`}
        />
        <div
          className="h-full"
          style={{ width: `${s2cPct}%`, backgroundColor: palette.sev.medium }}
          title={`Server → Client: ${humanBytes(flow.bytesS2c)} (${percent(
            flow.bytesS2c,
            total,
          )})`}
        />
      </div>

      <dl>
        <Field
          icon={<ArrowRight size={13} style={{ color: palette.accent }} />}
          label="Bytes C→S"
          mono
          title={`${humanNumber(flow.bytesC2s)} bytes`}
        >
          {humanBytes(flow.bytesC2s)}{" "}
          <span className="text-[var(--color-text-faint)]">
            ({percent(flow.bytesC2s, total)})
          </span>
        </Field>
        <Field
          icon={<ArrowLeft size={13} style={{ color: palette.sev.medium }} />}
          label="Bytes S→C"
          mono
          title={`${humanNumber(flow.bytesS2c)} bytes`}
        >
          {humanBytes(flow.bytesS2c)}{" "}
          <span className="text-[var(--color-text-faint)]">
            ({percent(flow.bytesS2c, total)})
          </span>
        </Field>
        <Field
          icon={<Layers size={13} />}
          label="Bytes total"
          mono
          title={`${humanNumber(total)} bytes`}
        >
          {humanBytes(total)}
        </Field>
        <Field icon={<Activity size={13} />} label="Packets" mono>
          {humanNumber(flow.pkts)}
        </Field>
      </dl>

      {/* Small directional chart */}
      <div className="mt-3 h-24 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={data}
            layout="vertical"
            margin={{ top: 0, right: 8, bottom: 0, left: 0 }}
          >
            <XAxis type="number" hide />
            <YAxis
              type="category"
              dataKey="name"
              width={36}
              tick={{ fill: palette.text, fontSize: 11 }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              cursor={{ fill: "color-mix(in srgb, currentColor 6%, transparent)" }}
              contentStyle={{
                background: "var(--color-surface-2)",
                border: "1px solid var(--color-border)",
                borderRadius: 8,
                fontSize: 12,
                color: "var(--color-text)",
              }}
              formatter={(v: number) => [humanBytes(v), "bytes"]}
            />
            <Bar dataKey="bytes" radius={[0, 4, 4, 0]} barSize={16}>
              {data.map((d) => (
                <Cell key={d.name} fill={d.fill} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

/** Empty state shown when no flow is selected. */
function EmptyDetail() {
  return (
    <div
      data-component="FlowDetail"
      className="flex h-full flex-col items-center justify-center gap-3 px-6 text-center"
    >
      <div className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface-2)] p-3">
        <Network size={22} className="text-[var(--color-text-faint)]" />
      </div>
      <p className="text-sm font-medium text-[var(--color-text-dim)]">
        No flow selected
      </p>
      <p className="max-w-[16rem] text-xs text-[var(--color-text-faint)]">
        Select a row from the flows table to inspect its endpoints, traffic
        breakdown, and timing.
      </p>
    </div>
  );
}

/**
 * Slide-in side detail panel for a single selected flow row.
 *
 * Renders every flow field as a labeled key/value, a severity-colored category
 * chip, a directional byte/packet breakdown, and timestamps as readable dates.
 * Shows an empty state when `flow` is `null`.
 */
export function FlowDetail({
  flow,
  onClose,
  activeSource,
  onInspectPackets,
  onCarvePcap,
}: FlowDetailProps) {
  if (!flow) return <EmptyDetail />;

  const canInspect = packetsAvailable(activeSource);

  const startDate = new Date(flow.startMs);
  const endDate = new Date(flow.endMs);

  return (
    <div
      data-component="FlowDetail"
      role="dialog"
      aria-label={`Flow ${flow.flowId} detail`}
      className="flex h-full flex-col overflow-y-auto bg-[var(--color-surface)] text-[var(--color-text)]"
    >
      {/* Header */}
      <div className="sticky top-0 z-10 flex items-center justify-between gap-3 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <CategoryChip flow={flow} />
            <span className="rounded bg-[var(--color-surface-2)] px-1.5 py-0.5 text-xs font-medium text-[var(--color-text-dim)]">
              {flow.protoLabel}
            </span>
          </div>
          <h2 className="mt-1 truncate text-sm font-semibold">
            Flow <span className="font-mono-num">#{flow.flowId}</span>
          </h2>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close flow detail"
          className="shrink-0 rounded-md p-1.5 text-[var(--color-text-dim)] transition-colors hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)] focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
        >
          <X size={18} />
        </button>
      </div>

      {/* Inspect packets + Carve sub-pcap */}
      <div className="border-b border-[var(--color-border)] px-4 py-2 flex gap-2">
        <button
          type="button"
          onClick={onInspectPackets}
          disabled={!canInspect}
          title={
            canInspect
              ? "Inspect this flow's packets"
              : "Packets are only available for captures analyzed from a pcap"
          }
          className={cn(
            "flex flex-1 items-center justify-center gap-2 rounded-md border px-3 py-1.5 text-sm transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]",
            canInspect
              ? "border-[var(--color-border)] text-[var(--color-text)] hover:border-[var(--color-accent)] hover:text-[var(--color-accent)]"
              : "cursor-not-allowed border-[var(--color-border)] text-[var(--color-text-faint)]",
          )}
        >
          <Binary size={14} /> Inspect packets
        </button>
        <button
          type="button"
          onClick={onCarvePcap}
          disabled={!canInspect}
          title={
            canInspect
              ? "Export this flow as a .pcap"
              : "Packets are only available for captures analyzed from a pcap"
          }
          className={cn(
            "flex flex-1 items-center justify-center gap-2 rounded-md border px-3 py-1.5 text-sm transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]",
            canInspect
              ? "border-[var(--color-border)] text-[var(--color-text)] hover:border-[var(--color-accent)] hover:text-[var(--color-accent)]"
              : "cursor-not-allowed border-[var(--color-border)] text-[var(--color-text-faint)]",
          )}
        >
          <Scissors size={14} /> Carve sub-pcap
        </button>
      </div>

      {/* Endpoints */}
      <Section icon={<Network size={13} />} title="Endpoints">
        <Field icon={<Server size={13} />} label="Source" mono>
          {flow.srcIp}
          <span className="text-[var(--color-text-faint)]">
            :{flow.srcPort}
          </span>
        </Field>
        <Field icon={<Server size={13} />} label="Destination" mono>
          {flow.dstIp}
          <span className="text-[var(--color-text-faint)]">
            :{flow.dstPort}
          </span>
        </Field>
        <Field label="Protocol" mono title={`IANA proto ${flow.proto}`}>
          {flow.protoLabel}{" "}
          <span className="text-[var(--color-text-faint)]">({flow.proto})</span>
        </Field>
      </Section>

      {/* Application (L7) */}
      <Section icon={<Globe size={13} />} title="Application (L7)">
        <Field label="App protocol" mono>
          {flow.appProto ?? (
            <span className="text-[var(--color-text-faint)]">—</span>
          )}
        </Field>
        <Field
          label="Derivation"
          title={
            flow.appProtoSrc === "payload"
              ? "Detected by inspecting the packet payload (DPI)"
              : flow.appProtoSrc === "port"
                ? "Inferred from the well-known port"
                : undefined
          }
        >
          {flow.appProtoSrc === "payload" ? (
            <span className="inline-flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-accent)]" />
              <span style={{ color: "var(--color-accent)" }}>payload</span>
            </span>
          ) : flow.appProtoSrc === "port" ? (
            <span className="text-[var(--color-text-dim)]">port</span>
          ) : (
            <span className="text-[var(--color-text-faint)]">—</span>
          )}
        </Field>
        <Field label="TLS SNI" mono title={flow.sni ?? undefined}>
          {flow.sni ?? <span className="text-[var(--color-text-faint)]">—</span>}
        </Field>
        <Field label="TLS JA3" mono title={flow.ja3 ?? undefined}>
          {flow.ja3 ?? <span className="text-[var(--color-text-faint)]">—</span>}
        </Field>
        <Field label="TLS JA4" mono title={flow.ja4 ?? undefined}>
          {flow.ja4 ?? <span className="text-[var(--color-text-faint)]">—</span>}
        </Field>
      </Section>

      {/* Traffic */}
      <Section icon={<Layers size={13} />} title="Traffic breakdown">
        <TrafficBreakdown flow={flow} />
      </Section>

      {/* Timing */}
      <Section icon={<Clock size={13} />} title="Timing">
        <Field label="Start" mono title={startDate.toISOString()}>
          {startDate.toISOString().slice(0, 10)}{" "}
          <span className="text-[var(--color-text-faint)]">
            {msToTime(flow.startMs)}
          </span>
        </Field>
        <Field label="End" mono title={endDate.toISOString()}>
          {endDate.toISOString().slice(0, 10)}{" "}
          <span className="text-[var(--color-text-faint)]">
            {msToTime(flow.endMs)}
          </span>
        </Field>
        <Field label="Duration" mono>
          {durationHumanMs(flow.durationMs)}
        </Field>
      </Section>

      {/* TCP / IP detail */}
      <Section icon={<Activity size={13} />} title="TCP / IP">
        <Field label="TCP flags C→S" mono title={`0x${flow.tcpFlagsC2s.toString(16)}`}>
          {tcpFlagsLabel(flow.tcpFlagsC2s)}
        </Field>
        <Field label="TCP flags S→C" mono title={`0x${flow.tcpFlagsS2c.toString(16)}`}>
          {tcpFlagsLabel(flow.tcpFlagsS2c)}
        </Field>
        <Field label="TTL min C→S" mono>
          {flow.ttlMinC2s === 0 ? (
            <span className="text-[var(--color-text-faint)]">—</span>
          ) : (
            flow.ttlMinC2s
          )}
        </Field>
      </Section>

      {/* Classification */}
      <Section icon={<Info size={13} />} title="Classification">
        <Field label="Category">
          <CategoryChip flow={flow} />
        </Field>
        <Field label="Severity">
          <span style={{ color: severityColor(flow.severity) }}>
            {SEVERITY_META[flow.severity].label}
          </span>
        </Field>
      </Section>

      {/* Threat */}
      <Section icon={<ShieldAlert size={13} />} title="Threat">
        <Field label="Severity">
          <span
            className="inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium"
            style={{
              color: severityColor(flow.severity),
              borderColor: severityColor(flow.severity),
              backgroundColor: `color-mix(in srgb, ${severityColor(
                flow.severity,
              )} 14%, transparent)`,
            }}
          >
            <span
              aria-hidden
              className="h-1.5 w-1.5 rounded-full"
              style={{ backgroundColor: severityColor(flow.severity) }}
            />
            {SEVERITY_META[flow.severity].label}
          </span>
        </Field>
        <Field label="Threat score" mono>
          <div className="flex items-center justify-end gap-2">
            <span style={{ color: severityColor(flow.severity) }}>
              {Math.max(0, Math.min(100, flow.threatScore))}{" "}
              <span className="text-[var(--color-text-faint)]">/ 100</span>
            </span>
            <div className="h-1.5 w-20 overflow-hidden rounded-full bg-[var(--color-surface-2)]">
              <div
                className="h-full rounded-full"
                style={{
                  width: `${Math.max(0, Math.min(100, flow.threatScore))}%`,
                  backgroundColor: severityColor(flow.severity),
                }}
              />
            </div>
          </div>
        </Field>
        <Field label="IOC">
          {flow.ioc ? (
            <span
              className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-semibold"
              style={{
                color: "var(--color-sev-critical)",
                backgroundColor:
                  "color-mix(in srgb, var(--color-sev-critical) 16%, transparent)",
              }}
            >
              Yes
            </span>
          ) : (
            <span className="text-[var(--color-text-faint)]">No</span>
          )}
        </Field>
      </Section>

      {/* Identity */}
      <Section icon={<Hash size={13} />} title="Identity">
        <Field label="Flow ID" mono>
          {flow.flowIdBig.toString()}
        </Field>
        <Field label="Capture ID" mono>
          {humanNumber(flow.captureId)}
        </Field>
      </Section>
    </div>
  );
}

export default FlowDetail;
