import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  AlertTriangle,
  CheckCircle2,
  FileDown,
  FileUp,
  Loader2,
  Radar,
  Upload,
} from "lucide-react";
import type { AnalysisOutput, FlowRow, SummaryState, TabId } from "../../types";
import type { ExportResult } from "../../lib/platform";
import { basename } from "../../lib/format";
import { cn } from "../../lib/cn";
import { LoadCaptureDialog } from "./LoadCaptureDialog";

// The shell derives the capture filename from the App-owned summary state and
// provides a self-contained "load capture" affordance (drag-drop / file picker)
// that parses dropped summary.json + flows.parquet locally via lib helpers, then
// lifts the result up to the App via onReplaceData so it replaces the active
// dataset everywhere.
export interface AppShellProps {
  activeTab: TabId;
  onTabChange: (t: TabId) => void;
  /** App-owned summary load state, used for the header capture label. */
  summary: SummaryState;
  /** Number of recent captures, shown as a badge on the Recent tab. */
  recentCount?: number;
  /** Lift a user-provided capture up to App state, replacing the active data. */
  onReplaceData: (next: { summary?: AnalysisOutput; flows?: FlowRow[] }) => void;
  /** Analyze a dropped/picked raw .pcap/.pcapng in-browser (WebAssembly engine). */
  onAnalyzePcap: (file: File) => Promise<void>;
  /** Invoked by the "Load capture" button — App routes it to the native dialog
   *  (desktop) or opens the in-app drop dialog (browser). */
  onRequestLoad: () => void;
  /** Controlled open-state of the in-app drop dialog (lifted so the Recent tab can open it). */
  loadDialogOpen: boolean;
  onLoadDialogOpenChange: (open: boolean) => void;
  /** Export the active analysis (HTML report on desktop, JSON in the browser).
   *  Resolves to a result the shell can surface, or undefined if nothing to export. */
  onExport: () => Promise<ExportResult | undefined>;
  children: ReactNode;
}

const TABS: ReadonlyArray<{ id: TabId; label: string }> = [
  { id: "dashboard", label: "Dashboard" },
  { id: "flows", label: "Flows" },
  { id: "recent", label: "Recent" },
];

export function AppShell({
  activeTab,
  onTabChange,
  summary,
  recentCount = 0,
  onReplaceData,
  onAnalyzePcap,
  onRequestLoad,
  loadDialogOpen,
  onLoadDialogOpenChange,
  onExport,
  children,
}: AppShellProps) {
  const [exportHint, setExportHint] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

  const canExport = summary.status === "ready" && !!summary.data;

  // Auto-dismiss the transient export hint.
  useEffect(() => {
    if (!exportHint) return;
    const t = window.setTimeout(() => setExportHint(null), 2500);
    return () => window.clearTimeout(t);
  }, [exportHint]);

  const handleExportClick = useCallback(async () => {
    if (!canExport || exporting) return;
    setExporting(true);
    try {
      const res = await onExport();
      if (res?.ok) setExportHint(res.message);
    } catch (err: unknown) {
      setExportHint(`Export failed: ${String((err as Error)?.message ?? err)}`);
    } finally {
      setExporting(false);
    }
  }, [canExport, exporting, onExport]);

  // Capture filename: derived from the App-owned summary state.
  const captureName = useMemo(() => {
    if (summary.status === "ready" && summary.data)
      return basename(summary.data.source_path);
    return null;
  }, [summary]);

  return (
    <div
      data-component="AppShell"
      className="flex h-full min-h-0 flex-col bg-bg text-[var(--color-text)]"
    >
      <header className="flex h-14 shrink-0 items-center gap-4 border-b border-border bg-surface px-4">
        <div className="flex items-center gap-2.5">
          <span
            className="flex h-8 w-8 items-center justify-center rounded-md"
            style={{ background: "color-mix(in srgb, var(--color-accent) 18%, transparent)" }}
          >
            <Radar
              className="h-5 w-5"
              style={{ color: "var(--color-accent)" }}
              aria-hidden
            />
          </span>
          <div className="leading-tight">
            <div className="text-sm font-semibold tracking-tight">PacketPilot</div>
            <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-faint)]">
              Packet triage
            </div>
          </div>
        </div>

        <TabSwitcher
          activeTab={activeTab}
          onTabChange={onTabChange}
          recentCount={recentCount}
        />

        <div className="ml-auto flex items-center gap-3">
          <CaptureLabel
            name={captureName}
            loading={summary.status === "loading" || summary.status === "idle"}
            error={summary.status === "error" ? summary.error : undefined}
          />
          <button
            type="button"
            onClick={onRequestLoad}
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface-2 px-3 py-1.5 text-xs font-medium text-[var(--color-text)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-accent)]"
          >
            <Upload className="h-3.5 w-3.5" aria-hidden />
            Load capture
          </button>
          <button
            type="button"
            onClick={() => void handleExportClick()}
            disabled={!canExport || exporting}
            title={canExport ? "Export report" : "Load a capture to export"}
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface-2 px-3 py-1.5 text-xs font-medium text-[var(--color-text)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-accent)] disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:border-border disabled:hover:text-[var(--color-text)]"
          >
            {exporting ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
            ) : (
              <FileDown className="h-3.5 w-3.5" aria-hidden />
            )}
            Export report
          </button>
          {exportHint && (
            <span
              className="inline-flex items-center gap-1.5 text-xs text-sev-info"
              aria-live="polite"
            >
              <CheckCircle2 className="h-3.5 w-3.5" aria-hidden />
              {exportHint}
            </span>
          )}
        </div>
      </header>

      <main className="min-h-0 flex-1 overflow-auto">{children}</main>

      {loadDialogOpen && (
        <LoadCaptureDialog
          onReplaceData={onReplaceData}
          onAnalyzePcap={onAnalyzePcap}
          onClose={() => onLoadDialogOpenChange(false)}
        />
      )}
    </div>
  );
}

function TabSwitcher({
  activeTab,
  onTabChange,
  recentCount = 0,
}: Pick<AppShellProps, "activeTab" | "onTabChange"> & { recentCount?: number }) {
  return (
    <nav
      role="tablist"
      aria-label="Views"
      className="flex items-center gap-0.5 rounded-lg border border-border bg-surface-2 p-0.5"
    >
      {TABS.map((tab) => {
        const active = tab.id === activeTab;
        const badge = tab.id === "recent" && recentCount > 0 ? recentCount : null;
        return (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onTabChange(tab.id)}
            className={cn(
              "inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
              active
                ? "bg-bg text-[var(--color-text)] shadow-sm"
                : "text-[var(--color-text-dim)] hover:text-[var(--color-text)]",
            )}
          >
            {tab.label}
            {badge !== null && (
              <span className="inline-flex min-w-[1.1rem] items-center justify-center rounded-full bg-[color-mix(in_srgb,var(--color-accent)_18%,transparent)] px-1 text-[10px] font-semibold text-[var(--color-accent)]">
                {badge}
              </span>
            )}
          </button>
        );
      })}
    </nav>
  );
}

function CaptureLabel({
  name,
  loading,
  error,
}: {
  name: string | null;
  loading: boolean;
  error?: string;
}) {
  if (error) {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs text-sev-high">
        <AlertTriangle className="h-3.5 w-3.5" aria-hidden />
        No capture
      </span>
    );
  }
  if (loading && !name) {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs text-[var(--color-text-dim)]">
        <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
        Loading…
      </span>
    );
  }
  if (!name) return null;
  return (
    <span className="hidden items-center gap-1.5 sm:inline-flex" title={name}>
      <FileUp className="h-3.5 w-3.5 text-[var(--color-text-faint)]" aria-hidden />
      <span className="font-mono-num max-w-[16rem] truncate text-xs text-[var(--color-text-dim)]">
        {name}
      </span>
    </span>
  );
}

export default AppShell;
