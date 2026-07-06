// Pure SVG/geometry + color helpers for the Cockpit widgets. Dependency-free
// except the shared cssVar() resolver (recharts/SVG need literal colors).
import { cssVar } from "../lib/palette";
import type { ProtoCounts, Severity } from "../types";

export const clamp01 = (n: number): number => (n < 0 ? 0 : n > 1 ? 1 : n);

/** Point on a circle. 0deg = 12 o'clock, clockwise-positive. */
export function polarToCartesian(
  cx: number,
  cy: number,
  r: number,
  angleDeg: number,
): { x: number; y: number } {
  const a = ((angleDeg - 90) * Math.PI) / 180;
  return { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) };
}

/** SVG arc path between two angles (degrees) on a circle of radius r. */
export function describeArc(
  cx: number,
  cy: number,
  r: number,
  startDeg: number,
  endDeg: number,
): string {
  const start = polarToCartesian(cx, cy, r, endDeg);
  const end = polarToCartesian(cx, cy, r, startDeg);
  const largeArc = endDeg - startDeg <= 180 ? "0" : "1";
  return `M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArc} 0 ${end.x} ${end.y}`;
}

export interface Spark {
  line: string;
  area: string;
  lastX: number;
  lastY: number;
}

/** Sparkline path builder. Normalizes values into a w×h box (top-padded by `pad`). */
export function sparkline(values: number[], w: number, h: number, pad = 1.5): Spark {
  if (values.length === 0) return { line: "", area: "", lastX: 0, lastY: h };
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min || 1;
  const n = values.length;
  const innerH = h - pad * 2;
  const pts = values.map((v, i): [number, number] => {
    const x = n === 1 ? w / 2 : (i / (n - 1)) * w;
    const y = pad + (1 - (v - min) / span) * innerH;
    return [x, y];
  });
  const line = pts
    .map(([x, y], i) => `${i === 0 ? "M" : "L"}${x.toFixed(2)},${y.toFixed(2)}`)
    .join(" ");
  const [lx, ly] = pts[pts.length - 1];
  const area = `${line} L${w.toFixed(2)},${h} L0,${h} Z`;
  return { line, area, lastX: lx, lastY: ly };
}

/** Circle circumference for stroke-dasharray ring gauges. */
export const circumference = (r: number): number => 2 * Math.PI * r;

/** Resolve a severity token to its literal hex (for SVG/recharts). */
export function sevColor(sev: Severity): string {
  return cssVar(`--color-sev-${sev}`, "#64748b");
}

/** Protocol-mix segment metadata (label + literal color), engine field order. */
export interface ProtoSeg {
  key: keyof ProtoCounts;
  label: string;
  value: number;
  color: string;
}

/**
 * Leaf protocol partition that sums EXACTLY to total_packets. Per the engine
 * invariants (http+tls+other_tcp == tcp, dns+other_udp == udp, tcp+udp+non_ipv4
 * + truncated == packets), tls/http/dns are SUBSETS of tcp/udp — so we must never
 * mix the L4 parents and their L7 children in one denominator (that double-counts).
 * `truncated` (undecoded frames — e.g. snaplen-clipped) are now counted in
 * total_packets, so they get their own segment to keep the donut reconciled.
 */
export function protoSegments(proto: ProtoCounts): ProtoSeg[] {
  const accent = cssVar("--color-accent", "#38bdf8");
  const teal = cssVar("--color-sev-low", "#2dd4bf");
  const amber = cssVar("--color-sev-medium", "#fbbf24");
  const dim = cssVar("--color-text-faint", "#5b6b80");
  const violet = cssVar("--color-spine-violet", "#7c5cff");
  const defs: { key: keyof ProtoCounts; label: string; color: string }[] = [
    { key: "tls", label: "TLS", color: accent },
    { key: "http", label: "HTTP", color: amber },
    { key: "other_tcp", label: "Other TCP", color: cssVar("--color-accent-strong", "#5fd0ff") },
    { key: "dns", label: "DNS", color: teal },
    { key: "other_udp", label: "Other UDP", color: violet },
    { key: "non_ipv4", label: "Non-IPv4", color: dim },
    { key: "truncated", label: "Undecoded", color: cssVar("--color-text-dim", "#8b98a5") },
  ];
  return defs
    .map((d) => ({ ...d, value: proto[d.key] ?? 0 }))
    .filter((d) => d.value > 0);
}
