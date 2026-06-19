import { useCallback, useEffect, useState } from "react";
import type {
  AnalysisOutput,
  FlowRow,
  Severity,
  SummaryState,
  FlowsState,
  TabId,
} from "./types";
import { loadSummary, loadFlows } from "./lib/data";
import { AppShell } from "./components/layout/AppShell";
import { LoadingState } from "./components/state/LoadingState";
import { ErrorState } from "./components/state/ErrorState";
import { Dashboard } from "./components/Dashboard";
import { FlowsView } from "./views/FlowsView";
import {
  isTauri,
  openCaptureDialog,
  analyzeViaTauri,
  exportReport,
} from "./lib/platform";
import { EmptyState } from "./components/state/EmptyState";

export interface FlowsInitialFilter {
  severity?: Severity;
  category?: string;
  proto?: number;
}

const SUMMARY_URL = "/sample/summary.json";
const FLOWS_URL = "/sample/flows.parquet";

const IS_TAURI = isTauri();

export function App() {
  const [tab, setTab] = useState<TabId>("dashboard");
  const [flowsFilter, setFlowsFilter] = useState<FlowsInitialFilter | undefined>(
    undefined,
  );

  // App owns both datasets so the AppShell upload affordance can replace them.
  const [summary, setSummary] = useState<SummaryState>({ status: "idle" });
  const [flows, setFlows] = useState<FlowsState>({ status: "idle", rows: [] });

  // Eagerly load the bundled sample capture on mount.
  useEffect(() => {
    if (IS_TAURI) return; // desktop shows empty state until a capture is opened
    let cancelled = false;

    setSummary({ status: "loading" });
    loadSummary(SUMMARY_URL)
      .then((data) => {
        if (!cancelled) setSummary({ status: "ready", data });
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setSummary({
            status: "error",
            error: String((err as Error)?.message ?? err),
          });
      });

    setFlows({ status: "loading", rows: [] });
    loadFlows(FLOWS_URL)
      .then((rows) => {
        if (!cancelled) setFlows({ status: "ready", rows });
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setFlows({
            status: "error",
            rows: [],
            error: String((err as Error)?.message ?? err),
          });
      });

    return () => {
      cancelled = true;
    };
  }, []);

  // Replace the active capture with a user-provided summary.json + flows.parquet
  // (either may be supplied; the other is left untouched).
  const handleReplaceData = useCallback(
    (next: { summary?: AnalysisOutput; flows?: FlowRow[] }) => {
      if (next.summary) setSummary({ status: "ready", data: next.summary });
      if (next.flows) setFlows({ status: "ready", rows: next.flows });
    },
    [],
  );

  const handleNativeLoad = useCallback(async () => {
    const path = await openCaptureDialog();
    if (!path) return;
    setSummary({ status: "loading" });
    setFlows({ status: "loading", rows: [] });
    try {
      const { summary: nextSummary, rows } = await analyzeViaTauri(path);
      handleReplaceData({ summary: nextSummary, flows: rows });
    } catch (err: unknown) {
      const message = String((err as Error)?.message ?? err);
      setSummary({ status: "error", error: message });
      setFlows({ status: "error", rows: [], error: message });
    }
  }, [handleReplaceData]);

  const handleExport = useCallback(async () => {
    if (summary.status !== "ready" || !summary.data) return undefined;
    return exportReport(summary.data);
  }, [summary]);

  const jumpToFlows = useCallback(
    (filter: { severity?: Severity; category?: string; ip?: string }) => {
      setFlowsFilter({
        severity: filter.severity,
        category: filter.category,
      });
      setTab("flows");
    },
    [],
  );

  return (
    <AppShell
      activeTab={tab}
      onTabChange={setTab}
      summary={summary}
      onReplaceData={handleReplaceData}
      onNativeLoad={IS_TAURI ? () => void handleNativeLoad() : undefined}
      onExport={handleExport}
    >
      {tab === "dashboard" ? (
        summary.status === "idle" ? (
          IS_TAURI ? (
            <EmptyState title="No capture loaded" />
          ) : (
            <LoadingState label="Loading summary…" />
          )
        ) : summary.status === "loading" ? (
          <LoadingState label="Loading summary…" />
        ) : summary.status === "error" ? (
          <ErrorState message={summary.error ?? "Failed to load summary"} />
        ) : (
          <Dashboard output={summary.data!} onJumpToFlows={jumpToFlows} />
        )
      ) : (
        <FlowsView state={flows} initialFilter={flowsFilter} />
      )}
    </AppShell>
  );
}

export default App;
