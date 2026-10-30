// Guided hunt playbook for one alert: a senior analyst's checklist per alert type, with every
// pivot already filled in from the alert (flow filter, SQL over the flow table, the packets, the
// timeline). The engine renders the playbooks (built-ins plus an optional team file) and answers
// the steps it already holds evidence for; this panel tracks the analyst's ticks and notes and
// hands each pivot to the app. Display-only for the engine output — nothing here re-derives it.
import { useEffect, useState } from "react";
import {
  ChartGantt,
  Check,
  ChevronDown,
  ChevronRight,
  Copy,
  Database,
  Download,
  FileDown,
  ListFilter,
} from "lucide-react";
import type { Alert, PivotTarget, PlaybookProgress, PlaybookRun, PlaybookStep, RenderedPivot } from "../types";
import { BTN_OUTLINE, SectionLabel, Tag } from "./primitives";
import { setNote, stepKey, toggleDone } from "../lib/playbooks";
import { cn } from "../lib/cn";

const PIVOT_ICON: Record<PivotTarget, typeof Database> = {
  flows: ListFilter,
  sql: Database,
  packets: FileDown,
  timeline: ChartGantt,
};

const PIVOT_ACTION: Record<PivotTarget, string> = {
  flows: "Filter flows",
  sql: "Run in Query",
  packets: "Get packets",
  timeline: "Open timeline",
};

export interface HuntPanelProps {
  alert: Alert;
  /** Render the alert's playbooks (the engine call). */
  loadRuns: (alert: Alert) => Promise<PlaybookRun[]>;
  /** The analyst's saved progress for this alert. */
  initialProgress: PlaybookProgress;
  /** Persist progress after every tick or note. */
  onProgress: (progress: PlaybookProgress) => void;
  /** Follow a pivot. Absent = pivots are copy-only. */
  onPivot?: (pivot: RenderedPivot, alert: Alert) => void;
  /** Export the checklist (with ticks and notes) as Markdown. */
  onExport?: (runs: PlaybookRun[], progress: PlaybookProgress) => void;
}

function PivotRow({ pivot, onFollow }: { pivot: RenderedPivot; onFollow?: () => void }) {
  const Icon = PIVOT_ICON[pivot.target];
  const [copied, setCopied] = useState(false);
  const value = pivot.value ?? "";
  return (
    <li className="flex flex-col gap-1">
      <div className="flex flex-wrap items-center gap-2">
        <Icon className="h-3.5 w-3.5 shrink-0 text-[var(--color-text-faint)]" aria-hidden />
        <span className="text-xs text-[var(--color-text)]">{pivot.label}</span>
        <span className="ml-auto flex items-center gap-1">
          {value && (
            <button
              type="button"
              className="rounded p-1 text-[var(--color-text-faint)] hover:text-[var(--color-text)]"
              aria-label={`Copy ${pivot.label}`}
              onClick={() => {
                void navigator.clipboard?.writeText(value);
                setCopied(true);
              }}
            >
              {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
            </button>
          )}
          {onFollow && (
            <button type="button" className={cn(BTN_OUTLINE, "h-7 px-2 text-xs")} onClick={onFollow}>
              {pivot.target === "packets" && !pivot.scope ? "Copy filter" : PIVOT_ACTION[pivot.target]}
            </button>
          )}
        </span>
      </div>
      {value && pivot.target !== "flows" && (
        <code className="font-mono-num block max-h-24 overflow-auto whitespace-pre-wrap break-all rounded-[var(--r-micro)] bg-[var(--color-surface-2)] px-2 py-1 text-[11px] text-[var(--color-text-dim)]">
          {value}
        </code>
      )}
    </li>
  );
}

function StepRow({
  run,
  step,
  alert,
  progress,
  onProgress,
  onPivot,
}: {
  run: PlaybookRun;
  step: PlaybookStep;
  alert: Alert;
  progress: PlaybookProgress;
  onProgress: (p: PlaybookProgress) => void;
  onPivot?: (pivot: RenderedPivot, alert: Alert) => void;
}) {
  const key = stepKey(run, step);
  const done = progress.done.includes(key);
  const [open, setOpen] = useState(false);
  const Chevron = open ? ChevronDown : ChevronRight;
  const note = progress.notes[key] ?? "";
  return (
    <li className="py-1.5">
      <div className="flex items-start gap-2">
        <input
          type="checkbox"
          className="mt-0.5 h-4 w-4 shrink-0 accent-[var(--color-accent)]"
          checked={done}
          aria-label={`Done: ${step.question}`}
          onChange={() => onProgress(toggleDone(progress, key))}
        />
        <button
          type="button"
          aria-expanded={open}
          onClick={() => setOpen((o) => !o)}
          className="flex min-w-0 flex-1 items-start gap-1.5 text-left"
        >
          <Chevron className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--color-text-faint)]" aria-hidden />
          <span
            className={cn(
              "min-w-0 flex-1 text-xs font-medium",
              done ? "text-[var(--color-text-faint)] line-through" : "text-[var(--color-text)]",
            )}
          >
            {step.question}
          </span>
          {step.auto?.found && <Tag tone="accent">engine found</Tag>}
          {note && <Tag>note</Tag>}
        </button>
      </div>
      {open && (
        <div className="mt-1.5 flex flex-col gap-2 pl-6 text-xs text-[var(--color-text-dim)]">
          <p>{step.why}</p>
          {(step.normal || step.bad) && (
            <dl className="grid grid-cols-[auto_1fr] gap-x-2 gap-y-0.5">
              {step.normal && (
                <>
                  <dt className="t-tag uppercase text-[var(--color-text-faint)]">normal</dt>
                  <dd>{step.normal}</dd>
                </>
              )}
              {step.bad && (
                <>
                  <dt className="t-tag uppercase text-[var(--color-sev-high)]">bad</dt>
                  <dd>{step.bad}</dd>
                </>
              )}
            </dl>
          )}
          {step.auto && (
            <div>
              <div className="t-tag uppercase text-[var(--color-text-faint)]">Engine found</div>
              {step.auto.found ? (
                <ul className="list-disc space-y-0.5 pl-4">
                  {step.auto.evidence.map((e, i) => (
                    <li key={i}>{e}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-[var(--color-text-faint)]">Nothing in this capture. That is not proof it is clean.</p>
              )}
            </div>
          )}
          {step.pivots.length > 0 && (
            <ul className="flex flex-col gap-2">
              {step.pivots.map((p, i) => (
                <PivotRow key={i} pivot={p} onFollow={onPivot ? () => onPivot(p, alert) : undefined} />
              ))}
            </ul>
          )}
          <textarea
            className="min-h-[2.5rem] w-full rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-1 text-xs text-[var(--color-text)]"
            placeholder="What you found"
            aria-label={`Note: ${step.question}`}
            value={note}
            onChange={(e) => onProgress(setNote(progress, key, e.target.value))}
          />
        </div>
      )}
    </li>
  );
}

/** The alert's playbooks as a checklist; hidden while loading and when there are none. */
export function HuntPanel({ alert, loadRuns, initialProgress, onProgress, onPivot, onExport }: HuntPanelProps) {
  const [runs, setRuns] = useState<PlaybookRun[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<PlaybookProgress>(initialProgress);

  useEffect(() => {
    let live = true;
    setRuns(null);
    setError(null);
    loadRuns(alert).then(
      (r) => live && setRuns(r),
      (e: unknown) => live && setError(e instanceof Error ? e.message : String(e)),
    );
    return () => {
      live = false;
    };
  }, [alert, loadRuns]);

  const update = (p: PlaybookProgress) => {
    setProgress(p);
    onProgress(p);
  };

  if (error) {
    return (
      <div>
        <SectionLabel className="mb-1.5">Hunt playbook</SectionLabel>
        <p className="text-xs text-[var(--color-sev-high)]">Could not load the playbook: {error}</p>
      </div>
    );
  }
  if (!runs || runs.length === 0) return null;

  const total = runs.reduce((n, r) => n + r.steps.length, 0);
  const done = runs.reduce((n, r) => n + r.steps.filter((s) => progress.done.includes(stepKey(r, s))).length, 0);

  return (
    <div data-component="HuntPanel">
      <div className="mb-1.5 flex items-center gap-2">
        <SectionLabel>Hunt playbook</SectionLabel>
        <span className="font-mono-num t-tag text-[var(--color-text-faint)]">
          {done}/{total} done
        </span>
        {onExport && (
          <button
            type="button"
            className={cn(BTN_OUTLINE, "ml-auto h-7 px-2 text-xs")}
            onClick={() => onExport(runs, progress)}
          >
            <Download className="mr-1 h-3.5 w-3.5" />
            Export checklist
          </button>
        )}
      </div>
      <div className="flex flex-col gap-3">
        {runs.map((run) => (
          <div key={run.playbook_id}>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-semibold text-[var(--color-text)]">{run.title}</span>
              {run.origin !== "built-in" && <Tag>{run.origin}</Tag>}
            </div>
            {run.summary && <p className="mt-0.5 text-xs text-[var(--color-text-faint)]">{run.summary}</p>}
            <ul className="mt-1 divide-y divide-[var(--color-border)]">
              {run.steps.map((s) => (
                <StepRow
                  key={s.id}
                  run={run}
                  step={s}
                  alert={alert}
                  progress={progress}
                  onProgress={update}
                  onPivot={onPivot}
                />
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}

export default HuntPanel;
