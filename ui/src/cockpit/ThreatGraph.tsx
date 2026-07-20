import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Finding, IpThreat, Severity } from "../types";
import { buildThreatGraph } from "../lib/threatGraph";
import { severityColor } from "../lib/palette";
import { SEVERITY_META } from "../lib/severity";
import { Card } from "./primitives";

/** SVG canvas (viewBox) the force layout is fit into. */
const W = 880;
const H = 380;
const MARGIN_X = 84;
const MARGIN_TOP = 26;
const MARGIN_BOTTOM = 42;

/**
 * Force-directed layout (Fruchterman-Reingold repulsion + edge springs) with anisotropic gravity to
 * keep the — often disconnected — incident stars gathered into one landscape-shaped blob, followed
 * by radius-aware overlap resolution so no two host bubbles (or their labels) collide. Pure and
 * deterministic (seeded within the canvas, no randomness) so positions are stable across renders and
 * safe in tests. n is small (<= ~16), so the O(n^2 * iters) cost is trivial.
 */
function computeLayout(
  nodes: { ip: string; r: number }[],
  edges: { from: string; to: string }[],
): Map<string, { x: number; y: number }> {
  const out = new Map<string, { x: number; y: number }>();
  const n = nodes.length;
  const drawW = W - 2 * MARGIN_X;
  const drawH = H - MARGIN_TOP - MARGIN_BOTTOM;
  const cx = W / 2;
  const cy = MARGIN_TOP + drawH / 2;
  if (n === 0) return out;
  if (n === 1) {
    out.set(nodes[0].ip, { x: cx, y: cy });
    return out;
  }

  const idx = new Map(nodes.map((nd, i) => [nd.ip, i]));
  const px = new Float64Array(n);
  const py = new Float64Array(n);
  for (let i = 0; i < n; i++) {
    const a = -Math.PI / 2 + (i * 2 * Math.PI) / n;
    px[i] = cx + Math.cos(a) * drawW * 0.32 + i * 0.001;
    py[i] = cy + Math.sin(a) * drawH * 0.32;
  }
  const links = edges
    .map((e) => [idx.get(e.from), idx.get(e.to)] as const)
    .filter((p): p is [number, number] => p[0] !== undefined && p[1] !== undefined && p[0] !== p[1]);

  const k = 0.62 * Math.sqrt((drawW * drawH) / n); // ideal edge length
  const REP_CUT = 2.0 * k; // localise repulsion so distant components don't fling to the corners
  const GRAV_X = 0.03; // gravity gathers the (often disconnected) incident stars toward the centre
  const GRAV_Y = 0.05; // slightly stronger vertically keeps the blob landscape
  const ITER = 520;
  let temp = Math.max(drawW, drawH) / 9;
  const cool = temp / (ITER + 1);
  const dx = new Float64Array(n);
  const dy = new Float64Array(n);

  for (let it = 0; it < ITER; it++) {
    dx.fill(0);
    dy.fill(0);
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        let ex = px[i] - px[j];
        let ey = py[i] - py[j];
        let d = Math.sqrt(ex * ex + ey * ey);
        if (d < 0.05) {
          ex = 0.1;
          ey = 0.05;
          d = 0.112;
        }
        if (d > REP_CUT) continue;
        const f = (k * k) / d;
        dx[i] += (ex / d) * f;
        dy[i] += (ey / d) * f;
        dx[j] -= (ex / d) * f;
        dy[j] -= (ey / d) * f;
      }
    }
    for (const [a, b] of links) {
      const ex = px[a] - px[b];
      const ey = py[a] - py[b];
      const d = Math.sqrt(ex * ex + ey * ey) || 0.05;
      const f = (d * d) / k;
      dx[a] -= (ex / d) * f;
      dy[a] -= (ey / d) * f;
      dx[b] += (ex / d) * f;
      dy[b] += (ey / d) * f;
    }
    for (let i = 0; i < n; i++) {
      dx[i] += (cx - px[i]) * GRAV_X;
      dy[i] += (cy - py[i]) * GRAV_Y;
      const dl = Math.sqrt(dx[i] * dx[i] + dy[i] * dy[i]) || 0.05;
      px[i] += (dx[i] / dl) * Math.min(dl, temp);
      py[i] += (dy[i] / dl) * Math.min(dl, temp);
    }
    temp = Math.max(temp - cool, 1);
  }

  // Label-aware (box) overlap resolution: each host's footprint is its bubble PLUS the IP label
  // sitting under it, so nodes are separated enough that the always-on labels stay legible. Separate
  // overlapping boxes along whichever axis needs the least movement.
  const halfW = nodes.map((nd) => Math.max(nd.r + 2, (nd.ip.length * 5.7) / 2 + 4));
  const halfH = nodes.map((nd) => nd.r + 16);
  for (let pass = 0; pass < 200; pass++) {
    let any = false;
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        let ex = px[i] - px[j];
        let ey = py[i] - py[j];
        if (Math.abs(ex) < 0.05 && Math.abs(ey) < 0.05) {
          ex = (i - j) * 0.2 + 0.2;
          ey = 0.2;
        }
        const ox = halfW[i] + halfW[j] + 8 - Math.abs(ex); // horizontal box overlap
        const oy = halfH[i] + halfH[j] + 4 - Math.abs(ey); // vertical box overlap
        if (ox > 0 && oy > 0) {
          if (ox < oy) {
            const push = (ox / 2) * (ex >= 0 ? 1 : -1);
            px[i] += push;
            px[j] -= push;
          } else {
            const push = (oy / 2) * (ey >= 0 ? 1 : -1);
            py[i] += push;
            py[j] -= push;
          }
          any = true;
        }
      }
    }
    if (!any) break;
  }

  // Center + scale to fill the drawable area. Scaling positions (not radii) only widens the gaps,
  // so it can't reintroduce overlap; clamped so it neither blows up a tiny graph nor crushes a large
  // one back into collisions.
  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;
  for (let i = 0; i < n; i++) {
    if (px[i] < minX) minX = px[i];
    if (px[i] > maxX) maxX = px[i];
    if (py[i] < minY) minY = py[i];
    if (py[i] > maxY) maxY = py[i];
  }
  const spanX = Math.max(maxX - minX, 1);
  const spanY = Math.max(maxY - minY, 1);
  const maxHalfW = Math.max(...halfW);
  const maxHalfH = Math.max(...halfH);
  const fit = Math.min((drawW - 2 * maxHalfW) / spanX, (drawH - 2 * maxHalfH) / spanY);
  const scale = Math.max(0.82, Math.min(1.6, fit));
  const offX = cx - ((minX + maxX) / 2) * scale;
  const offY = cy - ((minY + maxY) / 2) * scale;
  for (let i = 0; i < n; i++) {
    out.set(nodes[i].ip, { x: px[i] * scale + offX, y: py[i] * scale + offY });
  }
  return out;
}

/**
 * Threat relationship graph: an interactive force-directed node-link view of the hosts implicated by
 * behavioural findings and the directed `src -> dst` relationships between them. Hover a host to
 * highlight it and everything it touches; drag hosts to rearrange; click (or Enter) to jump to its
 * flows. Complements the incident list with a spatial map of who is doing what to whom. Hidden when
 * fewer than two related hosts.
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
    () => buildThreatGraph(findings ?? [], threats ?? [], { maxNodes: 16 }),
    [findings, threats],
  );
  // Stable identity for the topology (which hosts + edges), so the layout only recomputes when the
  // graph actually changes, not on every render.
  const topoKey = useMemo(
    () => model.nodes.map((n) => n.ip).join(",") + "|" + model.edges.map((e) => e.id).join(","),
    [model],
  );
  const layout = useMemo(() => computeLayout(model.nodes, model.edges), [topoKey]); // eslint-disable-line react-hooks/exhaustive-deps

  const [pos, setPos] = useState(layout);
  useEffect(() => setPos(layout), [layout]);

  const [hover, setHover] = useState<string | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const drag = useRef<{ ip: string; moved: boolean } | null>(null);
  const suppressClick = useRef(false);

  // Per-host metadata + adjacency (neighbours in either direction), for sizing + highlighting.
  const meta = useMemo(() => {
    const m = new Map<string, { r: number; severity: Severity; score: number; deg: number }>();
    for (const nd of model.nodes) m.set(nd.ip, { r: nd.r, severity: nd.severity, score: nd.score, deg: 0 });
    const nbr = new Map<string, Set<string>>();
    for (const nd of model.nodes) nbr.set(nd.ip, new Set());
    for (const e of model.edges) {
      nbr.get(e.from)?.add(e.to);
      nbr.get(e.to)?.add(e.from);
    }
    for (const [ip, set] of nbr) {
      const mm = m.get(ip);
      if (mm) mm.deg = set.size;
    }
    return { m, nbr };
  }, [model]);

  const clientToSvg = useCallback((clientX: number, clientY: number) => {
    const svg = svgRef.current;
    if (!svg) return null;
    const rect = svg.getBoundingClientRect();
    if (!rect.width || !rect.height) return null;
    return { x: ((clientX - rect.left) / rect.width) * W, y: ((clientY - rect.top) / rect.height) * H };
  }, []);

  const onNodePointerDown = (ip: string) => (e: React.PointerEvent) => {
    drag.current = { ip, moved: false };
    (e.currentTarget as Element).setPointerCapture?.(e.pointerId);
  };
  const onNodePointerMove = (ip: string) => (e: React.PointerEvent) => {
    if (drag.current?.ip !== ip) return;
    const p = clientToSvg(e.clientX, e.clientY);
    if (!p) return;
    drag.current.moved = true;
    const x = Math.max(MARGIN_X * 0.5, Math.min(W - MARGIN_X * 0.5, p.x));
    const y = Math.max(MARGIN_TOP, Math.min(H - MARGIN_BOTTOM, p.y));
    setPos((prev) => new Map(prev).set(ip, { x, y }));
  };
  const onNodePointerUp = (e: React.PointerEvent) => {
    (e.currentTarget as Element).releasePointerCapture?.(e.pointerId);
    if (drag.current?.moved) suppressClick.current = true; // a drag shouldn't also open flows
    drag.current = null;
  };

  if (model.nodes.length < 2) return null;

  const active = hover;
  const nbrOf = active ? meta.nbr.get(active) : null;
  const nodeLit = (ip: string) => !active || ip === active || !!nbrOf?.has(ip);
  const edgeLit = (e: { from: string; to: string }) => !active || e.from === active || e.to === active;
  const rOf = (ip: string) => meta.m.get(ip)?.r ?? 8;

  const hoverMeta = active ? meta.m.get(active) : null;

  return (
    <section
      data-component="ThreatGraph"
      aria-label="Threat relationship graph"
      className="min-w-0"
    >
      <Card
        label="GRAPH"
        title="Threat relationships"
        right={
          hoverMeta && active ? (
            <span className="flex items-center gap-2 t-tag text-[var(--color-text-dim)]">
              <span aria-hidden className="h-2 w-2 rounded-full" style={{ backgroundColor: severityColor(hoverMeta.severity) }} />
              <span className="font-mono-num text-[var(--color-text)]">{active}</span>
              <span className="text-[var(--color-text-faint)]">
                {SEVERITY_META[hoverMeta.severity].label} · score {hoverMeta.score} · {hoverMeta.deg} link{hoverMeta.deg === 1 ? "" : "s"}
              </span>
            </span>
          ) : (
            <span className="font-mono-num text-xs text-[var(--color-text-faint)]">
              {model.nodes.length} hosts · {model.edges.length} link{model.edges.length === 1 ? "" : "s"}
              {model.truncated > 0 ? ` · +${model.truncated} more` : ""}
            </span>
          )
        }
      >
      <svg
        ref={svgRef}
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="xMidYMid meet"
        className="block h-[340px] w-full touch-none select-none overflow-visible"
        role="group"
        aria-label="Host relationship graph"
        onPointerLeave={() => setHover(null)}
      >
        {/* Edges (directed src -> dst, arrowhead at the target). */}
        <g>
          {model.edges.map((e) => {
            const s = pos.get(e.from);
            const t = pos.get(e.to);
            if (!s || !t) return null;
            let ex = t.x - s.x;
            let ey = t.y - s.y;
            const d = Math.hypot(ex, ey) || 1;
            const ux = ex / d;
            const uy = ey / d;
            const sr = rOf(e.from);
            const tr = rOf(e.to);
            const x1 = s.x + ux * sr;
            const y1 = s.y + uy * sr;
            const tipX = t.x - ux * (tr + 1.5);
            const tipY = t.y - uy * (tr + 1.5);
            const backX = tipX - ux * 8;
            const backY = tipY - uy * 8;
            const perpX = -uy;
            const perpY = ux;
            const lit = edgeLit(e);
            const color = severityColor(e.severity);
            return (
              <g key={e.id} style={{ opacity: lit ? 0.95 : 0.12, transition: "opacity 0.15s" }}>
                <line
                  x1={x1}
                  y1={y1}
                  x2={backX}
                  y2={backY}
                  stroke={color}
                  strokeWidth={lit ? 2 : 1.25}
                  strokeLinecap="round"
                />
                <polygon
                  points={`${tipX},${tipY} ${backX + perpX * 4},${backY + perpY * 4} ${backX - perpX * 4},${backY - perpY * 4}`}
                  fill={color}
                />
              </g>
            );
          })}
        </g>

        {/* Nodes + labels. */}
        <g>
          {model.nodes.map((nd) => {
            const p = pos.get(nd.ip);
            if (!p) return null;
            const color = severityColor(nd.severity);
            const lit = nodeLit(nd.ip);
            const isActive = nd.ip === active;
            return (
              <g
                key={nd.ip}
                style={{ opacity: lit ? 1 : 0.28, transition: "opacity 0.15s" }}
                className={onJump ? "cursor-pointer" : "cursor-grab"}
                role={onJump ? "button" : undefined}
                tabIndex={onJump ? 0 : undefined}
                aria-label={onJump ? `View flows for ${nd.ip}` : undefined}
                onPointerEnter={() => setHover(nd.ip)}
                onPointerDown={onNodePointerDown(nd.ip)}
                onPointerMove={onNodePointerMove(nd.ip)}
                onPointerUp={onNodePointerUp}
                onClick={
                  onJump
                    ? () => {
                        if (suppressClick.current) {
                          suppressClick.current = false;
                          return;
                        }
                        onJump(nd.ip);
                      }
                    : undefined
                }
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
                {isActive && (
                  <circle cx={p.x} cy={p.y} r={nd.r + 5} fill="none" stroke={color} strokeWidth={1} strokeOpacity={0.5} />
                )}
                <circle cx={p.x} cy={p.y} r={nd.r} fill={color} fillOpacity={isActive ? 0.4 : 0.22} stroke={color} strokeWidth={isActive ? 2 : 1.5} />
                {/* Always-on IP labels (the layout is spaced so they don't collide). On hover the
                    non-highlighted labels fade so the traced subgraph stands out. */}
                <text
                  x={p.x}
                  y={p.y + nd.r + 11}
                  textAnchor="middle"
                  fontSize={9.5}
                  fill={isActive ? "var(--color-text)" : "var(--color-text-dim)"}
                  style={{ opacity: active ? (lit ? 1 : 0.1) : 0.88, transition: "opacity 0.15s" }}
                  className="pointer-events-none font-mono-num"
                >
                  {nd.ip}
                </text>
              </g>
            );
          })}
        </g>
      </svg>

      <div className="mt-2 flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
        <span className="t-tag text-[var(--color-text-faint)]">Hover to trace · drag to rearrange{onJump ? " · click to open flows" : ""}</span>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          {(["critical", "high", "medium", "low"] as const).map((s) => (
            <span key={s} className="inline-flex items-center gap-1 t-tag text-[var(--color-text-faint)]">
              <span aria-hidden className="h-2 w-2 rounded-full" style={{ backgroundColor: severityColor(s) }} />
              {SEVERITY_META[s].label}
            </span>
          ))}
        </div>
      </div>
      </Card>
    </section>
  );
}

export default ThreatGraph;
