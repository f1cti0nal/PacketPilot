import type { Finding, IpThreat, Severity } from "../types";
import { SEVERITY_ORDER } from "./severity";

/** Rank a severity (lower = worse); `none`/unknown sort last. */
function sevRank(s: Severity): number {
  const i = SEVERITY_ORDER.indexOf(s);
  return i === -1 ? SEVERITY_ORDER.length : i;
}
const worse = (a: Severity, b: Severity): Severity => (sevRank(a) <= sevRank(b) ? a : b);

export interface ThreatNode {
  ip: string;
  x: number;
  y: number;
  /** Node radius, scaled by score. */
  r: number;
  severity: Severity;
  score: number;
  /** Label text anchor + position derived from the node's angle on the ring. */
  labelX: number;
  labelY: number;
  labelAnchor: "start" | "middle" | "end";
}

export interface ThreatEdge {
  id: string;
  from: string;
  to: string;
  /** Pre-computed quadratic-bezier path (`M … Q …`) bowing toward the centre. */
  path: string;
  severity: Severity;
}

export interface ThreatGraphModel {
  nodes: ThreatNode[];
  edges: ThreatEdge[];
  /** Hosts that did not fit `maxNodes` (shown as a "+N more" note). */
  truncated: number;
  width: number;
  height: number;
}

export interface BuildOpts {
  maxNodes?: number;
  width?: number;
  height?: number;
}

/**
 * Build a deterministic radial node-link model of the finding-derived host relationships: nodes are
 * the hosts implicated by behavioural findings (severity/score from the per-IP threat cards when
 * available), placed on a ring ordered by score; edges are the `src -> dst` relationships a finding
 * establishes. Pure and deterministic (no layout simulation), so it is fully unit-testable.
 */
export function buildThreatGraph(
  findings: Finding[],
  threats: IpThreat[],
  opts: BuildOpts = {},
): ThreatGraphModel {
  const width = opts.width ?? 420;
  const height = opts.height ?? 420;
  const maxNodes = opts.maxNodes ?? 14;

  // 1. Aggregate per-IP involvement from the findings.
  const agg = new Map<string, { severity: Severity; score: number }>();
  const bump = (ip: string, sev: Severity, score: number) => {
    const cur = agg.get(ip);
    if (!cur) {
      agg.set(ip, { severity: sev, score });
      return;
    }
    cur.severity = worse(cur.severity, sev);
    cur.score = Math.max(cur.score, score);
  };
  for (const f of findings ?? []) {
    bump(f.src_ip, f.severity, f.score);
    if (f.dst_ip) bump(f.dst_ip, f.severity, f.score);
  }
  // Fold in the authoritative per-IP threat-card severity/score for involved hosts.
  const threatByIp = new Map((threats ?? []).map((t) => [t.ip, t]));
  for (const [ip, v] of agg) {
    const t = threatByIp.get(ip);
    if (t) {
      v.severity = worse(v.severity, t.severity);
      v.score = Math.max(v.score, t.score);
    }
  }

  // 2. Rank by score (then severity, then IP) and cap.
  const ranked = [...agg.entries()].sort(
    (a, b) =>
      b[1].score - a[1].score ||
      sevRank(a[1].severity) - sevRank(b[1].severity) ||
      (a[0] < b[0] ? -1 : 1),
  );
  const kept = ranked.slice(0, maxNodes);
  const truncated = ranked.length - kept.length;
  const keptIps = new Set(kept.map((e) => e[0]));

  // 3. Radial layout.
  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.min(width, height) / 2 - 56; // margin for labels
  const n = kept.length;
  const pos = new Map<string, [number, number]>();
  const nodes: ThreatNode[] = kept.map(([ip, v], i) => {
    const angle = n <= 1 ? -Math.PI / 2 : -Math.PI / 2 + (i * 2 * Math.PI) / n;
    const x = cx + (n <= 1 ? 0 : radius * Math.cos(angle));
    const y = cy + (n <= 1 ? 0 : radius * Math.sin(angle));
    pos.set(ip, [x, y]);
    const r = 7 + Math.round((Math.max(0, Math.min(100, v.score)) / 100) * 9); // 7..16
    const cos = Math.cos(angle);
    const labelAnchor: ThreatNode["labelAnchor"] =
      n <= 1 ? "middle" : cos > 0.3 ? "start" : cos < -0.3 ? "end" : "middle";
    const lx = cx + (n <= 1 ? 0 : (radius + r + 6) * cos);
    const ly = cy + (n <= 1 ? r + 16 : (radius + r + 6) * Math.sin(angle)) + 3;
    return { ip, x, y, r, severity: v.severity, score: v.score, labelX: lx, labelY: ly, labelAnchor };
  });

  // 4. Edges (deduped src->dst keeping the worst severity), both endpoints kept.
  const edgeMap = new Map<string, ThreatEdge>();
  for (const f of findings ?? []) {
    if (!f.dst_ip || f.src_ip === f.dst_ip) continue;
    if (!keptIps.has(f.src_ip) || !keptIps.has(f.dst_ip)) continue;
    const key = `${f.src_ip}->${f.dst_ip}`;
    const existing = edgeMap.get(key);
    if (existing) {
      existing.severity = worse(existing.severity, f.severity);
      continue;
    }
    const [x1, y1] = pos.get(f.src_ip)!;
    const [x2, y2] = pos.get(f.dst_ip)!;
    // Bow the edge toward the centre for a readable chord look.
    const mx = (x1 + x2) / 2;
    const my = (y1 + y2) / 2;
    const ctrlX = mx + (cx - mx) * 0.4;
    const ctrlY = my + (cy - my) * 0.4;
    edgeMap.set(key, {
      id: key,
      from: f.src_ip,
      to: f.dst_ip,
      path: `M${x1.toFixed(1)} ${y1.toFixed(1)} Q${ctrlX.toFixed(1)} ${ctrlY.toFixed(1)} ${x2.toFixed(1)} ${y2.toFixed(1)}`,
      severity: f.severity,
    });
  }
  const edges = [...edgeMap.values()].sort((a, b) => sevRank(b.severity) - sevRank(a.severity));

  return { nodes, edges, truncated, width, height };
}
