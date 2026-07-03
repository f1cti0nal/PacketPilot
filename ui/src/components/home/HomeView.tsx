// The Home surface shown whenever no capture is active. First-time visitors (empty Recent
// list) get an upload-first hero; returning visitors get a workspace overview — rollup KPIs,
// resume-recent, severity trend, and recurring threats — instead of the raw dashboard. Every
// number is derived from the cached Recent summaries (offline; no engine re-run).
import {
  AlertTriangle,
  ArrowRight,
  Database,
  FileStack,
  GitCompare,
  Radar,
  Upload,
} from "lucide-react";
import type { RecentEntry } from "../../types";
import {
  captureVerdict,
  reviewStatus,
  workspaceRollup,
  type ReviewStatus,
} from "../../lib/workspace";
import { compactNumber, humanBytes, humanNumber, relativeTime } from "../../lib/format";
import { kindMeta } from "../../lib/findingKinds";
import { captureKey } from "../../lib/ai/cache";
import { annotationsForCapture } from "../../lib/annotations";
import { StatTile, Sparkline } from "../../cockpit/primitives";
import { VerdictChip } from "../VerdictChip";
import { cn } from "../../lib/cn";

export interface HomeViewProps {
  /** The persisted recent-captures list (newest first). Empty => first-run hero. */
  recent: RecentEntry[];
  /** Id of the capture currently active, if any (highlights its row). */
  activeId?: string | null;
  /** Open a recent capture (restores its cached dashboard instantly). */
  onOpen: (entry: RecentEntry) => void;
  /** Open the load affordance (native picker on desktop, drop dialog in the browser). */
  onLoadNew: () => void;
  /** Load the bundled sample capture as an opt-in preview. */
  onLoadSample?: () => void;
  /** Compare two captures (ids ordered older-first by analyzedAt). */
  onCompare?: (beforeId: string, afterId: string) => void;
  /** Jump to the full Recent list (shown as "View all" when the overview truncates it). */
  onViewAll?: () => void;
  /** Whether the bundled sample can be loaded (browser only — desktop has no bundled assets). */
  sampleAvailable?: boolean;
}

const PRIMARY_BTN =
  "inline-flex items-center gap-2 rounded-full bg-[var(--color-accent-deep)] px-5 py-2 text-sm font-medium text-[var(--color-on-accent)] transition-opacity hover:opacity-90";
const SECONDARY_BTN =
  "inline-flex items-center gap-2 rounded-full border border-[var(--color-border-strong)] bg-[var(--color-surface-1)] px-5 py-2 text-sm font-medium text-[var(--color-text)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-accent)]";

export function HomeView({
  recent,
  activeId = null,
  onOpen,
  onLoadNew,
  onLoadSample,
  onCompare,
  onViewAll,
  sampleAvailable = false,
}: HomeViewProps) {
  if (recent.length === 0) {
    return (
      <FirstRun
        onLoadNew={onLoadNew}
        onLoadSample={onLoadSample}
        sampleAvailable={sampleAvailable}
      />
    );
  }
  return (
    <Overview
      recent={recent}
      activeId={activeId}
      onOpen={onOpen}
      onLoadNew={onLoadNew}
      onCompare={onCompare}
      onViewAll={onViewAll}
    />
  );
}

// ---------------------------------------------------------------------------
// First run — upload-first hero
// ---------------------------------------------------------------------------

function FirstRun({
  onLoadNew,
  onLoadSample,
  sampleAvailable,
}: {
  onLoadNew: () => void;
  onLoadSample?: () => void;
  sampleAvailable: boolean;
}) {
  return (
    <div
      data-component="HomeFirstRun"
      className="app-bg flex h-full min-h-0 flex-col items-center justify-center px-6 py-12 text-center"
    >
      <div className="mb-5 flex h-16 w-16 items-center justify-center rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-1)] text-[var(--color-accent)]">
        <Radar size={30} aria-hidden />
      </div>
      <h2 className="font-display text-xl font-medium text-[var(--color-text)]">
        Analyze your first capture
      </h2>
      <p className="mt-2 max-w-md text-sm text-[var(--color-text-dim)]">
        Drop a <span className="font-mono-num">.pcap</span> or{" "}
        <span className="font-mono-num">.pcapng</span> file to triage it for threats. Analysis
        runs entirely in your browser — nothing is uploaded.
      </p>

      <div className="mt-6 flex flex-wrap items-center justify-center gap-2.5">
        <button type="button" onClick={onLoadNew} className={PRIMARY_BTN}>
          <Upload size={16} aria-hidden />
          Upload capture
        </button>
        {sampleAvailable && onLoadSample && (
          <button type="button" onClick={onLoadSample} className={SECONDARY_BTN}>
            <Database size={16} aria-hidden />
            Explore sample capture
          </button>
        )}
      </div>

      <ol className="mt-10 grid w-full max-w-xl grid-cols-1 gap-3 text-left sm:grid-cols-3">
        <Step n={1} title="Upload" desc="Drop a pcap or pick a file." />
        <Step n={2} title="Review" desc="Findings, incidents, and threats surface automatically." />
        <Step n={3} title="Export" desc="Share an HTML report, STIX, MISP, or CEF." />
      </ol>

      <p className="mt-6 text-[11px] text-[var(--color-text-faint)]">
        Supports <span className="font-mono-num">.pcap</span>,{" "}
        <span className="font-mono-num">.pcapng</span>,{" "}
        <span className="font-mono-num">.cap</span>, and{" "}
        <span className="font-mono-num">.gz</span>
      </p>
    </div>
  );
}

function Step({ n, title, desc }: { n: number; title: string; desc: string }) {
  return (
    <li className="rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-1)] p-3">
      <div className="flex items-center gap-2">
        <span className="flex h-5 w-5 items-center justify-center rounded-full bg-[var(--color-surface-3)] font-mono-num text-[11px] text-[var(--color-text-dim)]">
          {n}
        </span>
        <span className="text-sm font-medium text-[var(--color-text)]">{title}</span>
      </div>
      <p className="mt-1.5 text-xs text-[var(--color-text-dim)]">{desc}</p>
    </li>
  );
}

// ---------------------------------------------------------------------------
// Returning user — workspace overview
// ---------------------------------------------------------------------------

function Overview({
  recent,
  activeId,
  onOpen,
  onLoadNew,
  onCompare,
  onViewAll,
}: {
  recent: RecentEntry[];
  activeId: string | null;
  onOpen: (entry: RecentEntry) => void;
  onLoadNew: () => void;
  onCompare?: (beforeId: string, afterId: string) => void;
  onViewAll?: () => void;
}) {
  const roll = workspaceRollup(recent);
  const review = reviewStatus(
    recent,
    (e) => new Set(Object.keys(annotationsForCapture(captureKey(e.summary)))),
  );
  const top = recent.slice(0, 5);
  const canCompare = !!onCompare && recent.length >= 2;

  return (
    <div
      data-component="HomeOverview"
      className="mx-auto flex h-full min-h-0 w-full max-w-6xl flex-col gap-5 p-4 sm:p-6"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="font-display text-xl font-medium text-[var(--color-text)]">
            Welcome back
          </h1>
          <p className="mt-0.5 text-xs text-[var(--color-text-dim)]">
            {humanNumber(roll.captures)} capture{roll.captures === 1 ? "" : "s"} in this workspace
            {roll.lastAnalyzed !== null && ` · last analyzed ${relativeTime(roll.lastAnalyzed)}`} · all
            analysis runs locally
          </p>
        </div>
        <div className="flex items-center gap-2">
          {canCompare && (
            <button
              type="button"
              onClick={() => onCompare!(recent[1].id, recent[0].id)}
              className={SECONDARY_BTN}
            >
              <GitCompare size={16} aria-hidden />
              Compare
            </button>
          )}
          <button type="button" onClick={onLoadNew} className={PRIMARY_BTN}>
            <Upload size={16} aria-hidden />
            Upload capture
          </button>
        </div>
      </div>

      {review.capturesNeedingReview > 0 && <ReviewBanner review={review} onOpen={onOpen} />}

      <div className="grid grid-cols-2 gap-[var(--density-gap-sm)] sm:grid-cols-3 lg:grid-cols-6">
        <StatTile label="Captures" value={humanNumber(roll.captures)} />
        <StatTile label="Total flows" value={compactNumber(roll.totalFlows)} />
        <StatTile label="Total bytes" value={humanBytes(roll.totalBytes)} />
        <StatTile label="Distinct hosts" value={humanNumber(roll.distinctHosts)} />
        <StatTile label="Findings" value={humanNumber(roll.totalFindings)} />
        <CriticalHighTile value={roll.criticalHigh} />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1.5fr_1fr]">
        <section className="min-w-0">
          <div className="mb-2 flex items-center justify-between gap-2">
            <h2 className="t-label text-[var(--color-text-dim)]">Continue analysis</h2>
            {onViewAll && recent.length > top.length && (
              <button
                type="button"
                onClick={onViewAll}
                className="inline-flex items-center gap-1 text-[11px] font-medium text-[var(--color-accent)] transition-opacity hover:opacity-80"
              >
                View all {recent.length}
                <ArrowRight className="h-3 w-3" aria-hidden />
              </button>
            )}
          </div>
          <div className="overflow-hidden rounded-[var(--r-card)] border border-[var(--color-border)] bg-[var(--color-panel)]">
            {top.map((entry) => (
              <RecentLine
                key={entry.id}
                entry={entry}
                active={entry.id === activeId}
                onOpen={onOpen}
              />
            ))}
          </div>
        </section>

        <div className="flex flex-col gap-4">
          <TrendCard trend={roll.trend} rising={roll.trendRising} />
          <RecurringCard recurring={roll.recurring} />
        </div>
      </div>
    </div>
  );
}

function ReviewBanner({
  review,
  onOpen,
}: {
  review: ReviewStatus;
  onOpen: (entry: RecentEntry) => void;
}) {
  const { capturesNeedingReview: c, untriagedHosts: h, topCapture } = review;
  return (
    <section
      data-component="ReviewBanner"
      className="flex items-center gap-3 rounded-[var(--r-card)] border border-[var(--color-border)] bg-[var(--color-panel)] px-4 py-3"
      style={{ borderLeft: "2px solid var(--color-sev-high)", borderRadius: "0 var(--r-card) var(--r-card) 0" }}
    >
      <AlertTriangle className="h-4 w-4 shrink-0" style={{ color: "var(--color-sev-high)" }} aria-hidden />
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium text-[var(--color-text)]">
          {c} capture{c === 1 ? "" : "s"} need{c === 1 ? "s" : ""} review
        </div>
        <div className="mt-0.5 text-xs text-[var(--color-text-dim)]">
          {humanNumber(h)} untriaged critical/high host{h === 1 ? "" : "s"} across your workspace
        </div>
      </div>
      {topCapture && (
        <button
          type="button"
          onClick={() => onOpen(topCapture)}
          className="shrink-0 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2.5 py-1 text-xs font-medium text-[var(--color-text)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-accent)]"
        >
          Review
        </button>
      )}
    </section>
  );
}

function CriticalHighTile({ value }: { value: number }) {
  const hot = value > 0;
  return (
    <div
      className="rounded-[var(--r-tile)] px-3 py-2.5"
      style={
        hot
          ? {
              background: "color-mix(in srgb, var(--color-sev-critical) 6%, var(--color-bg))",
              boxShadow: "inset 2px 0 0 var(--color-sev-critical)",
            }
          : { background: "var(--color-surface-2)" }
      }
    >
      <div className="t-label text-[var(--color-text-dim)]">Critical / high</div>
      <div
        className="mt-0.5 font-mono-num text-[var(--fs-display)] font-medium leading-none"
        style={{ color: hot ? "var(--color-sev-critical)" : "var(--color-text)" }}
      >
        {humanNumber(value)}
      </div>
    </div>
  );
}

function RecentLine({
  entry,
  active,
  onOpen,
}: {
  entry: RecentEntry;
  active: boolean;
  onOpen: (entry: RecentEntry) => void;
}) {
  const verdict = captureVerdict(entry.summary);
  return (
    <div
      className={cn(
        "flex items-center gap-3 border-b border-[var(--color-border)] px-3.5 py-2.5 last:border-b-0 transition-colors hover:bg-[var(--color-surface-2)]",
        active && "bg-[color-mix(in_srgb,var(--color-accent)_6%,transparent)]",
      )}
    >
      <FileStack className="h-4 w-4 shrink-0 text-[var(--color-text-faint)]" aria-hidden />
      <button
        type="button"
        onClick={() => onOpen(entry)}
        title={entry.path ?? entry.name}
        className="min-w-0 flex-1 text-left"
      >
        <div
          className={cn(
            "truncate text-sm font-medium text-[var(--color-text)] hover:text-[var(--color-accent)]",
            active && "text-[var(--color-accent)]",
          )}
        >
          {entry.name}
        </div>
        <div className="mt-0.5 text-[11px] text-[var(--color-text-faint)]">
          {relativeTime(entry.analyzedAt)} · {compactNumber(entry.flowCount)} flows
        </div>
      </button>
      <VerdictChip verdict={verdict} />
      <button
        type="button"
        onClick={() => onOpen(entry)}
        className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2.5 py-1 text-xs font-medium text-[var(--color-text)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-accent)]"
      >
        Open
      </button>
    </div>
  );
}

function TrendCard({ trend, rising }: { trend: number[]; rising: boolean }) {
  return (
    <section className="rounded-[var(--r-card)] border border-[var(--color-border)] bg-[var(--color-panel)] p-3.5">
      <div className="t-label text-[var(--color-text-dim)]">Severity trend</div>
      {trend.length >= 2 ? (
        <>
          <div className="mt-2">
            <Sparkline
              values={trend}
              width={220}
              height={42}
              color={rising ? "var(--color-sev-high)" : "var(--color-accent)"}
            />
          </div>
          <div className="mt-1.5 t-tag text-[var(--color-text-faint)]">
            Last {trend.length} captures · {rising ? "rising" : "steady"}
          </div>
        </>
      ) : (
        <p className="mt-2 text-xs text-[var(--color-text-dim)]">
          Analyze a few captures to see the trend.
        </p>
      )}
    </section>
  );
}

function RecurringCard({
  recurring,
}: {
  recurring: { kind: string; label: string; captures: number }[];
}) {
  return (
    <section className="rounded-[var(--r-card)] border border-[var(--color-border)] bg-[var(--color-panel)] p-3.5">
      <div className="t-label text-[var(--color-text-dim)]">Recurring threats</div>
      {recurring.length > 0 ? (
        <ul className="mt-2 flex flex-col gap-2">
          {recurring.map((r) => {
            const { Icon } = kindMeta(r.kind);
            return (
              <li key={r.kind} className="flex items-center gap-2 text-sm">
                <Icon className="h-3.5 w-3.5 shrink-0 text-[var(--color-text-faint)]" aria-hidden />
                <span className="min-w-0 flex-1 truncate text-[var(--color-text-dim)]">
                  {r.label}
                </span>
                <span className="font-mono-num t-tag text-[var(--color-text-faint)]">
                  {r.captures} cap{r.captures === 1 ? "" : "s"}
                </span>
              </li>
            );
          })}
        </ul>
      ) : (
        <p className="mt-2 text-xs text-[var(--color-text-dim)]">
          No behavioral findings across your captures yet.
        </p>
      )}
    </section>
  );
}

export default HomeView;
