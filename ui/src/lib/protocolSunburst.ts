import type { ProtocolHierarchyNode } from "../types";

/** One annular sector of the sunburst, pre-computed (geometry + value). */
export interface SunburstArc {
  /** Full dotted path, e.g. `ip.tcp.https`. */
  path: string;
  /** Last segment, e.g. `https`. */
  label: string;
  /** 1 = inner ring (L4: tcp/udp/icmp…), 2 = outer ring (L7: https/dns…). */
  depth: number;
  /** Pre-computed SVG `d` for the annular sector. */
  d: string;
  bytes: number;
  pkts: number;
  /** Share of total bytes (0..1). */
  fraction: number;
  /** `(label x, label y)` at the sector's mid-angle/mid-radius (for labels). */
  labelX: number;
  labelY: number;
}

export interface SunburstModel {
  arcs: SunburstArc[];
  total: number;
  size: number;
  rings: number;
}

interface TreeNode {
  name: string;
  path: string;
  bytes: number;
  pkts: number;
  children: Map<string, TreeNode>;
}

const TAU = Math.PI * 2;

/**
 * Build a deterministic protocol-hierarchy sunburst from the engine's leaf `ip.<l4>.<l7>` paths.
 * Each entry is a leaf (one per packet class), so prefixes are accumulated to form the tree; ring
 * `d` holds the depth-`d` nodes, each child filling its parent's angular span proportional to bytes.
 * Pure and deterministic (no layout simulation) → fully unit-testable.
 */
export function buildSunburst(
  nodes: ProtocolHierarchyNode[],
  opts: { size?: number; maxRings?: number } = {},
): SunburstModel {
  const size = opts.size ?? 320;
  const maxRings = opts.maxRings ?? 2;

  // 1. Accumulate each leaf path's prefixes into a tree.
  const root: TreeNode = { name: "ip", path: "ip", bytes: 0, pkts: 0, children: new Map() };
  for (const n of nodes ?? []) {
    const segs = n.path.split(".").filter(Boolean);
    if (segs.length === 0 || segs[0] !== "ip") continue;
    root.bytes += n.bytes;
    root.pkts += n.pkts;
    let cur = root;
    for (let i = 1; i < segs.length; i++) {
      const p = segs.slice(0, i + 1).join(".");
      let child = cur.children.get(segs[i]);
      if (!child) {
        child = { name: segs[i], path: p, bytes: 0, pkts: 0, children: new Map() };
        cur.children.set(segs[i], child);
      }
      child.bytes += n.bytes;
      child.pkts += n.pkts;
      cur = child;
    }
  }

  const total = root.bytes;
  if (total === 0) return { arcs: [], total: 0, size, rings: maxRings };

  // 2. Radial layout: a centre hole, then `maxRings` equal-width rings.
  const cx = size / 2;
  const cy = size / 2;
  const holeR = size * 0.13;
  const ringW = (size / 2 - holeR - 8) / maxRings;
  const arcs: SunburstArc[] = [];

  const layout = (node: TreeNode, a0: number, a1: number, depth: number) => {
    if (depth >= 1 && depth <= maxRings) {
      const innerR = holeR + (depth - 1) * ringW;
      const outerR = innerR + ringW;
      const mid = (a0 + a1) / 2;
      const midR = (innerR + outerR) / 2;
      arcs.push({
        path: node.path,
        label: node.name,
        depth,
        d: annularSector(cx, cy, innerR, outerR, a0, a1),
        bytes: node.bytes,
        pkts: node.pkts,
        fraction: node.bytes / total,
        labelX: cx + midR * Math.cos(mid),
        labelY: cy + midR * Math.sin(mid),
      });
    }
    if (depth >= maxRings) return;
    // Children fill [a0, a1] proportional to bytes (deterministic: bytes desc, then name).
    const kids = [...node.children.values()].sort(
      (x, y) => y.bytes - x.bytes || (x.name < y.name ? -1 : 1),
    );
    const sum = kids.reduce((s, k) => s + k.bytes, 0) || node.bytes || 1;
    let a = a0;
    for (const k of kids) {
      const a2 = a + (a1 - a0) * (k.bytes / sum);
      layout(k, a, a2, depth + 1);
      a = a2;
    }
  };
  // Start at the top (-90°), sweeping clockwise. Clamp just under a full turn so a single
  // 100%-share child never degenerates to a zero-length arc.
  layout(root, -Math.PI / 2, -Math.PI / 2 + TAU - 1e-4, 0);

  return { arcs, total, size, rings: maxRings };
}

/** SVG path for an annular sector (clockwise outer arc, then back along the inner arc). */
function annularSector(
  cx: number,
  cy: number,
  rInner: number,
  rOuter: number,
  a0: number,
  a1: number,
): string {
  const pt = (r: number, a: number): [number, number] => [
    cx + r * Math.cos(a),
    cy + r * Math.sin(a),
  ];
  const largeArc = a1 - a0 > Math.PI ? 1 : 0;
  const [x0o, y0o] = pt(rOuter, a0);
  const [x1o, y1o] = pt(rOuter, a1);
  const [x1i, y1i] = pt(rInner, a1);
  const [x0i, y0i] = pt(rInner, a0);
  const f = (n: number) => n.toFixed(2);
  return (
    `M${f(x0o)} ${f(y0o)} A${f(rOuter)} ${f(rOuter)} 0 ${largeArc} 1 ${f(x1o)} ${f(y1o)} ` +
    `L${f(x1i)} ${f(y1i)} A${f(rInner)} ${f(rInner)} 0 ${largeArc} 0 ${f(x0i)} ${f(y0i)} Z`
  );
}
