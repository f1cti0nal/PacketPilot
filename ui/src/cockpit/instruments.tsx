// SVG instruments: the score ring (hero), the per-flow severity ring (KPI
// corner), and the beacon-lock radar (the one allowed flourish — a beacon's
// near-perfect periodicity IS the metronomic sweep, so metaphor = evidence).
import { SEVERITY_ORDER } from "../lib/severity";
import type { Severity, SeverityCounts } from "../types";
import { circumference, clamp01, polarToCartesian, sevColor } from "./viz";

/** Radial score gauge with the score centered. Only the hero ring "breathes". */
export function ScoreRing({
  score,
  severity,
  size = 120,
  breathing = false,
}: {
  score: number;
  severity: Severity;
  size?: number;
  breathing?: boolean;
}) {
  const stroke = Math.max(6, Math.round(size * 0.075));
  const r = (size - stroke) / 2;
  const cx = size / 2;
  const circ = circumference(r);
  const frac = clamp01(score / 100);
  const color = sevColor(severity);

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`Threat score ${score} of 100`}>
      <circle cx={cx} cy={cx} r={r} fill="none" stroke="var(--color-surface-3)" strokeWidth={stroke} />
      <circle
        cx={cx}
        cy={cx}
        r={r}
        fill="none"
        stroke={color}
        strokeWidth={stroke}
        strokeLinecap="round"
        strokeDasharray={circ}
        strokeDashoffset={circ * (1 - frac)}
        transform={`rotate(-90 ${cx} ${cx})`}
        className={breathing ? "score-glow" : undefined}
        style={{ transition: "stroke-dashoffset 900ms cubic-bezier(0.16,1,0.3,1)" }}
      />
      <text
        x={cx}
        y={cx - size * 0.02}
        textAnchor="middle"
        dominantBaseline="central"
        className="font-display"
        style={{ fontWeight: 500, fontSize: size * 0.32, fill: color }}
      >
        {score}
      </text>
      <text
        x={cx}
        y={cx + size * 0.26}
        textAnchor="middle"
        dominantBaseline="central"
        className="font-mono-num"
        style={{ fontSize: size * 0.1, fill: "var(--color-text-faint)", letterSpacing: "0.05em" }}
      >
        / 100
      </text>
    </svg>
  );
}

/** Segmented per-flow severity donut. Deliberately small & calm (context, not verdict). */
export function SeverityRing({ counts, size = 60 }: { counts: SeverityCounts; size?: number }) {
  const stroke = Math.max(5, Math.round(size * 0.12));
  const r = (size - stroke) / 2;
  const cx = size / 2;
  const circ = circumference(r);
  const order = SEVERITY_ORDER; // critical..info
  const total = order.reduce((s, sev) => s + (counts[sev as keyof SeverityCounts] ?? 0), 0) || 1;
  const gap = 1.5;

  let cum = 0;
  const segments = order.map((sev) => {
    const v = counts[sev as keyof SeverityCounts] ?? 0;
    const frac = v / total;
    const startFrac = cum;
    cum += frac;
    return { sev: sev as Severity, frac, startFrac, v };
  });

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label="Per-flow severity mix">
      <circle cx={cx} cy={cx} r={r} fill="none" stroke="var(--color-surface-2)" strokeWidth={stroke} />
      {segments.map((seg) =>
        seg.v === 0 ? null : (
          <circle
            key={seg.sev}
            cx={cx}
            cy={cx}
            r={r}
            fill="none"
            stroke={sevColor(seg.sev)}
            strokeWidth={stroke}
            strokeDasharray={`${Math.max(0, seg.frac * circ - gap)} ${circ}`}
            transform={`rotate(${-90 + seg.startFrac * 360} ${cx} ${cx})`}
          />
        ),
      )}
    </svg>
  );
}

/**
 * Beacon-lock radar scope: concentric rings + crosshair + a slow conic sweep,
 * with a pulsing blip locked on the C2. When `intervalSeconds` (the beacon's
 * observed interval) is provided, the sweep period matches it, clamped to
 * 2-10s so it stays readable; otherwise the sweep runs at a fixed 4.2s.
 */
export function BeaconRadar({ size = 150, intervalSeconds }: { size?: number; intervalSeconds?: number }) {
  const cx = size / 2;
  const rings = [0.94, 0.66, 0.36];
  // Blip locked at a fixed bearing/range (the C2 contact).
  const blip = polarToCartesian(cx, cx, (size / 2) * 0.66, 52);
  const sweepSeconds =
    intervalSeconds != null && Number.isFinite(intervalSeconds)
      ? Math.min(10, Math.max(2, intervalSeconds))
      : 4.2;

  return (
    <div className="relative" style={{ width: size, height: size }}>
      {/* Rotating sweep wedge (masked to the scope circle). */}
      <div
        className="radar-sweep absolute inset-0 rounded-full"
        style={{
          background:
            "conic-gradient(from 0deg, transparent 0deg, color-mix(in srgb, var(--color-accent) 26%, transparent) 38deg, transparent 64deg)",
          animation: `radar-spin ${sweepSeconds}s linear infinite`,
          maskImage: "radial-gradient(circle, #000 70%, transparent 71%)",
          WebkitMaskImage: "radial-gradient(circle, #000 70%, transparent 71%)",
        }}
      />
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="absolute inset-0" aria-hidden>
        {rings.map((f) => (
          <circle key={f} cx={cx} cy={cx} r={(size / 2) * f - 1} fill="none" stroke="var(--color-border)" strokeWidth={1} />
        ))}
        <line x1={cx} y1={4} x2={cx} y2={size - 4} stroke="var(--color-border)" strokeWidth={1} />
        <line x1={4} y1={cx} x2={size - 4} y2={cx} stroke="var(--color-border)" strokeWidth={1} />
        {/* C2 blip */}
        <circle cx={blip.x} cy={blip.y} r={9} fill="none" stroke="var(--color-sev-critical)" strokeWidth={1} opacity={0.4} />
        <circle className="blip" cx={blip.x} cy={blip.y} r={3.4} fill="var(--color-sev-critical)"
          style={{ animation: "blip-pulse 2.6s ease-in-out infinite" }} />
      </svg>
    </div>
  );
}

/** Tiny labelled stat used beside the radar (interval / jitter). */
export function RadarStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="t-label">{label}</span>
      <span className="font-mono-num text-[13px] text-[var(--color-text)]">{value}</span>
    </div>
  );
}
