// Noise budget: how far the engine boiled this capture down — packets to flows to findings to
// the stories an analyst reads — and the review time that saved. The counts are exact; the
// minutes are the engine's estimate from the (team-overridable) review rates, always shown
// with the formula behind them. Display-only over `summary.noise_budget`.
import { useState } from "react";
import { ChevronDown, ChevronRight, Hourglass } from "lucide-react";
import { compactNumber } from "../lib/format";
import type { NoiseBudget } from "../types";
import { SectionLabel } from "./primitives";
import { cn } from "../lib/cn";

/** `about 6 h saved`, `about 25 min saved`, `no review time saved` (mirrors the engine). */
export function savedPhrase(minutes: number): string {
  if (!(minutes >= 1)) return "no review time saved";
  if (minutes < 60) return `about ${Math.round(minutes)} min saved`;
  const h = minutes / 60;
  return `about ${h < 10 ? Math.round(h * 2) / 2 : Math.round(h)} h saved`;
}

const fmtMin = (m: number) => (Number.isInteger(m) ? String(m) : m.toFixed(1));

function Step({ value, label, onClick }: { value: number; label: string; onClick?: () => void }) {
  const body = (
    <>
      <span className="font-mono-num text-base font-semibold text-[var(--color-text)]">{compactNumber(value)}</span>
      <span className="t-tag text-[var(--color-text-dim)]">{label}</span>
    </>
  );
  const cls = "flex items-baseline gap-1.5 rounded-[var(--r-micro)] px-1.5 py-0.5";
  return onClick ? (
    <button type="button" className={cn(cls, "hover:bg-[var(--color-surface-2)]")} onClick={onClick}>
      {body}
    </button>
  ) : (
    <span className={cls}>{body}</span>
  );
}

const Arrow = () => (
  <span aria-hidden className="text-[var(--color-text-faint)]">
    →
  </span>
);

export interface NoiseBudgetMeterProps {
  budget: NoiseBudget;
  /** Open the flow table. */
  onFlows?: () => void;
  /** Open the alert queue. */
  onStories?: () => void;
}

/** One-line funnel plus the time-saved estimate, with its formula one click away. */
export function NoiseBudgetMeter({ budget: b, onFlows, onStories }: NoiseBudgetMeterProps) {
  const [open, setOpen] = useState(false);
  const r = b.rates;
  const Chevron = open ? ChevronDown : ChevronRight;
  return (
    <div
      data-component="NoiseBudgetMeter"
      className="rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2"
    >
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <SectionLabel className="mr-1">Noise budget</SectionLabel>
        <Step value={b.packets} label="packets" />
        <Arrow />
        <Step value={b.flows} label="flows" onClick={onFlows} />
        <Arrow />
        <Step value={b.findings} label={b.findings === 1 ? "finding" : "findings"} />
        <Arrow />
        <Step value={b.stories} label={b.stories === 1 ? "story" : "stories"} onClick={onStories} />
        <span className="ml-auto flex items-center gap-1.5 text-xs text-[var(--color-text)]">
          <Hourglass className="h-3.5 w-3.5 text-[var(--color-accent)]" aria-hidden />
          <span>{savedPhrase(b.saved_minutes)}</span>
          <span className="text-[var(--color-text-faint)]">(estimate)</span>
          <button
            type="button"
            aria-expanded={open}
            className="ml-1 flex items-center gap-0.5 text-[var(--color-text-faint)] hover:text-[var(--color-text)]"
            onClick={() => setOpen((o) => !o)}
          >
            <Chevron className="h-3.5 w-3.5" aria-hidden />
            How is this estimated?
          </button>
        </span>
      </div>
      {open && (
        <div className="mt-1.5 flex flex-col gap-0.5 text-xs text-[var(--color-text-dim)]">
          <p>
            {b.suppressed > 0 && <>{b.suppressed} of the findings were suppressed by analyst rules. </>}
            {b.urgent} {b.urgent === 1 ? "story is" : "stories are"} in the Investigate or Act now band.
          </p>
          <p>
            Without the queue: {fmtMin(b.manual_minutes)} min to skim the flows ({fmtMin(r.minutes_per_1k_flows)} min
            per 1k) and triage each finding on its own ({fmtMin(r.minutes_per_finding)} min each). Reading the queue:{" "}
            {fmtMin(b.queue_minutes)} min ({fmtMin(r.minutes_per_story)} min per story).
          </p>
          <p className="text-[var(--color-text-faint)]">
            Teams set their own rates with a review-rates.json file (ppcap analyze --review-rates).
          </p>
        </div>
      )}
    </div>
  );
}

export default NoiseBudgetMeter;
