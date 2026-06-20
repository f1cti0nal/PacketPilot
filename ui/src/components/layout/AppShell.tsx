import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type DragEvent,
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
  X,
} from "lucide-react";
import type { AnalysisOutput, FlowRow, SummaryState, TabId } from "../../types";
import type { ExportResult } from "../../lib/platform";
import { loadFlows } from "../../lib/data";
import { isCaptureFile } from "../../lib/wasmEngine";
import { basename, compactNumber, humanBytes } from "../../lib/format";
import { cn } from "../../lib/cn";

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

type LoadStatus =
  | { phase: "idle" }
  | { phase: "loading"; note: string }
  | {
      phase: "ready";
      summary?: AnalysisOutput;
      flows?: FlowRow[];
      fileNames: string[];
    }
  | { phase: "error"; message: string };

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
  const [load, setLoad] = useState<LoadStatus>({ phase: "idle" });
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

  // Capture filename: prefer a freshly dropped capture, else the auto-loaded one.
  const captureName = useMemo(() => {
    if (load.phase === "ready") {
      if (load.summary) return basename(load.summary.source_path);
      const json = load.fileNames.find((n) => n.endsWith(".json"));
      if (json) return json;
      if (load.fileNames[0]) return load.fileNames[0];
    }
    if (summary.status === "ready" && summary.data)
      return basename(summary.data.source_path);
    return null;
  }, [load, summary]);

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
          status={load}
          onStatusChange={setLoad}
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

function LoadCaptureDialog({
  status,
  onStatusChange,
  onReplaceData,
  onAnalyzePcap,
  onClose,
}: {
  status: LoadStatus;
  onStatusChange: (s: LoadStatus) => void;
  onReplaceData: (next: { summary?: AnalysisOutput; flows?: FlowRow[] }) => void;
  onAnalyzePcap: (file: File) => Promise<void>;
  onClose: () => void;
}) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const titleId = useId();

  const handleFiles = useCallback(
    async (files: FileList | null) => {
      if (!files || files.length === 0) return;
      const list = Array.from(files);

      // A raw capture takes priority: analyze it in-browser via the wasm engine, then close.
      const captureFile = list.find((f) => isCaptureFile(f.name));
      if (captureFile) {
        onStatusChange({
          phase: "loading",
          note: `Analyzing ${captureFile.name}…`,
        });
        try {
          await onAnalyzePcap(captureFile);
          onClose();
        } catch (err: unknown) {
          onStatusChange({
            phase: "error",
            message: String((err as Error)?.message ?? err),
          });
        }
        return;
      }

      const summaryFile = list.find((f) => f.name.toLowerCase().endsWith(".json"));
      const flowsFile = list.find((f) =>
        f.name.toLowerCase().endsWith(".parquet"),
      );
      if (!summaryFile && !flowsFile) {
        onStatusChange({
          phase: "error",
          message:
            "Drop a .pcap/.pcapng capture, or a summary.json and/or flows.parquet.",
        });
        return;
      }
      onStatusChange({ phase: "loading", note: "Parsing capture…" });
      try {
        let summary: AnalysisOutput | undefined;
        let flows: FlowRow[] | undefined;
        if (summaryFile) {
          summary = JSON.parse(await summaryFile.text()) as AnalysisOutput;
        }
        if (flowsFile) {
          const buf = await flowsFile.arrayBuffer();
          flows = await loadFlows(buf);
        }
        // Lift the parsed capture up to App state, replacing the active dataset.
        onReplaceData({ summary, flows });
        onStatusChange({
          phase: "ready",
          summary,
          flows,
          fileNames: list.map((f) => f.name),
        });
      } catch (err: unknown) {
        onStatusChange({
          phase: "error",
          message: String((err as Error)?.message ?? err),
        });
      }
    },
    [onStatusChange, onReplaceData, onAnalyzePcap, onClose],
  );

  const onDrop = useCallback(
    (e: DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      setDragging(false);
      void handleFiles(e.dataTransfer.files);
    },
    [handleFiles],
  );

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      onClick={onClose}
    >
      <div
        className="w-full max-w-md rounded-xl border border-border bg-surface shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <h2 id={titleId} className="text-sm font-semibold">
            Load capture
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="rounded-md p-1 text-[var(--color-text-dim)] transition-colors hover:bg-surface-2 hover:text-[var(--color-text)]"
          >
            <X className="h-4 w-4" aria-hidden />
          </button>
        </div>

        <div className="p-4">
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
            onClick={() => inputRef.current?.click()}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") inputRef.current?.click();
            }}
            className={cn(
              "flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed px-6 py-10 text-center transition-colors",
              dragging
                ? "border-[var(--color-accent)] bg-surface-2"
                : "border-border hover:border-[var(--color-text-faint)]",
            )}
          >
            <Upload
              className="h-7 w-7 text-[var(--color-text-faint)]"
              aria-hidden
            />
            <div className="text-sm text-[var(--color-text)]">
              Drag &amp; drop, or click to browse
            </div>
            <div className="text-xs text-[var(--color-text-dim)]">
              <span className="font-mono-num">.pcap</span> /{" "}
              <span className="font-mono-num">.pcapng</span> — analyzed in your browser
            </div>
            <div className="text-[11px] text-[var(--color-text-faint)]">
              or a <span className="font-mono-num">summary.json</span> +{" "}
              <span className="font-mono-num">flows.parquet</span> export
            </div>
            <input
              ref={inputRef}
              type="file"
              multiple
              accept=".pcap,.pcapng,.cap,.json,.parquet,application/json"
              className="hidden"
              onChange={(e) => void handleFiles(e.target.files)}
            />
          </div>

          <div className="mt-3 min-h-[1.25rem] text-xs" aria-live="polite">
            {status.phase === "loading" && (
              <span className="inline-flex items-center gap-1.5 text-[var(--color-text-dim)]">
                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
                {status.note}
              </span>
            )}
            {status.phase === "error" && (
              <span className="inline-flex items-center gap-1.5 text-sev-critical">
                <AlertTriangle className="h-3.5 w-3.5" aria-hidden />
                {status.message}
              </span>
            )}
            {status.phase === "ready" && (
              <span className="inline-flex items-center gap-1.5 text-sev-info">
                <CheckCircle2 className="h-3.5 w-3.5" aria-hidden />
                Loaded {loadedSummaryLabel(status)}
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function loadedSummaryLabel(s: Extract<LoadStatus, { phase: "ready" }>): string {
  const parts: string[] = [];
  if (s.summary) {
    parts.push(
      `${compactNumber(s.summary.summary.total_packets)} pkts`,
      humanBytes(s.summary.summary.total_bytes),
    );
  }
  if (s.flows) parts.push(`${compactNumber(s.flows.length)} flows`);
  return parts.length ? parts.join(" · ") : s.fileNames.join(", ");
}

export default AppShell;
