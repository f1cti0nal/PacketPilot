import { useMemo } from "react";

import type { AnalysisOutput, Severity, SeverityCounts } from "../types";
import { cn } from "../lib/cn";

import { SeverityStrip } from "./triage/SeverityStrip";
import { IncidentsPanel } from "./triage/IncidentsPanel";
import { ThreatsPanel } from "./triage/ThreatsPanel";
import { SummaryCard } from "./triage/SummaryCard";
import { CategoryChart } from "./triage/CategoryChart";
import { TimelineChart } from "./triage/TimelineChart";
import { ProtocolPanel } from "./triage/ProtocolPanel";
import { TopTalkers } from "./TopTalkers";

/**
 * Navigation request raised from the dashboard when the analyst drills into a
 * slice of the capture (a severity band, a traffic category, or a host). The
 * parent decides how to honor it — typically by switching to the Flows tab with
 * the matching filter applied.
 */
export interface DashboardDrilldown {
  severity?: Severity;
  category?: string;
  ip?: string;
}

export interface DashboardProps {
  /** The engine's AnalysisOutput (parsed from summary.json). */
  output: AnalysisOutput;
  /** Optional drill-down handler; wired to the Flows view by the shell. */
  onJumpToFlows?: (filter: DashboardDrilldown) => void;
}

/**
 * Summary-first landing view: the one-click triage screen. A full-width
 * severity strip sits on top, followed by a responsive grid of the at-a-glance
 * panels. Pure composition over `output` — no data fetching happens here.
 */
export function Dashboard({ output, onJumpToFlows }: DashboardProps) {
  const { summary } = output;

  // Source descriptor for the SummaryCard, narrowed to exactly what it needs.
  const source = useMemo(
    () => ({
      source_path: output.source_path,
      source_bytes: output.source_bytes,
      link_type: output.link_type,
    }),
    [output.source_path, output.source_bytes, output.link_type],
  );

  // Engine severity histogram; fall back to a zeroed bucket set if absent.
  const severityCounts: SeverityCounts = summary.severity_counts ?? {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  return (
    <div
      data-component="Dashboard"
      className="flex flex-col gap-4 p-4 sm:p-6"
    >
      {/* Severity triage strip — full width, top of the fold. */}
      <SeverityStrip
        counts={severityCounts}
        onSelect={
          onJumpToFlows
            ? (severity) => onJumpToFlows({ severity })
            : undefined
        }
      />

      {/* Correlated incidents — the highest-signal surface; only shown when present. */}
      <IncidentsPanel incidents={summary.incidents ?? []} />

      {/* Top threats — full width, directly under the severity strip. */}
      <ThreatsPanel threats={summary.ip_threats ?? []} />

      {/* Responsive summary grid. TimelineChart spans the full width. */}
      <div
        className={cn(
          "grid grid-cols-1 gap-4",
          "lg:grid-cols-2 xl:grid-cols-3",
        )}
      >
        <DashboardCell title="Capture overview">
          <SummaryCard summary={summary} source={source} />
        </DashboardCell>

        <DashboardCell title="Traffic by category">
          <CategoryChart
            breakdown={summary.category_breakdown}
            metric="flows"
            onBarClick={
              onJumpToFlows
                ? (category) => onJumpToFlows({ category })
                : undefined
            }
          />
        </DashboardCell>

        <DashboardCell title="Protocols">
          <ProtocolPanel proto={summary.proto} />
        </DashboardCell>

        {/* Timeline spans every column at all breakpoints. */}
        <DashboardCell
          title="Timeline"
          className="lg:col-span-2 xl:col-span-3"
        >
          <TimelineChart histogram={summary.time_histogram} metric="pkts" />
        </DashboardCell>

        {/* Top talkers fills the remaining width below the timeline. */}
        <DashboardCell
          title="Top talkers"
          className="lg:col-span-2 xl:col-span-3"
        >
          <TopTalkers
            talkers={summary.top_talkers}
            onSelect={
              onJumpToFlows ? (ip) => onJumpToFlows({ ip }) : undefined
            }
          />
        </DashboardCell>
      </div>
    </div>
  );
}

interface DashboardCellProps {
  title: string;
  className?: string;
  children: React.ReactNode;
}

/**
 * Lightweight surface wrapper around each panel. Keeps the dashboard's grid
 * concerns (span, surface chrome) out of the individual triage components.
 */
function DashboardCell({ title, className, children }: DashboardCellProps) {
  return (
    <section
      className={cn(
        "min-w-0 rounded-lg border border-border bg-surface p-4 shadow-sm",
        className,
      )}
      aria-label={title}
    >
      {children}
    </section>
  );
}

export default Dashboard;
