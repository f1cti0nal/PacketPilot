import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import type { AnalysisOutput, FlowRow, IpThreat, SummaryState, TabId } from "../../types";
import type { ExportResult } from "../../lib/platform";
import { basename } from "../../lib/format";
import { LoadCaptureDialog } from "./LoadCaptureDialog";
import { CommandBar } from "../../cockpit/CommandBar";
import { ThreatRail } from "../../cockpit/ThreatRail";
import { CommandPalette } from "../../cockpit/CommandPalette";
import type { PaletteAction } from "../../cockpit/CommandPalette";

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
  /** Threat rail data from the active capture. */
  threats: IpThreat[];
  /** Currently active/focused IP in the threat rail. */
  activeIp: string | null;
  /** Called when the user clicks a threat in the rail. */
  onSelectThreat: (ip: string) => void;
  /** Whether the threat rail is collapsed to 64px. */
  collapsed: boolean;
  /** Toggle the collapse state. */
  onToggleCollapse: () => void;
  /** Open the ⌘K command palette. */
  onOpenPalette: () => void;
  /** Controlled open-state of the ⌘K command palette. */
  paletteOpen?: boolean;
  /** Called to change the palette open state. */
  onPaletteOpenChange?: (open: boolean) => void;
  children: ReactNode;
}


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
  threats,
  activeIp,
  onSelectThreat,
  collapsed,
  onToggleCollapse,
  onOpenPalette,
  paletteOpen = false,
  onPaletteOpenChange,
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

  // Global ⌘K / Ctrl+K shortcut to open the command palette.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K")) {
        e.preventDefault();
        if (!paletteOpen && !loadDialogOpen) onPaletteOpenChange?.(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [paletteOpen, loadDialogOpen, onPaletteOpenChange]);

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

  const tabs = [
    { id: "dashboard" as const, label: "Dashboard" },
    { id: "flows" as const, label: "Flows" },
    { id: "recent" as const, label: "Recent", badge: recentCount || undefined },
  ];
  const captureStatus =
    summary.status === "ready" ? "ready" :
    summary.status === "loading" ? "loading" :
    summary.status === "error" ? "error" : "idle";

  const paletteActions: PaletteAction[] = [
    { id: "go-dashboard", label: "Go to Dashboard", hint: "view", run: () => onTabChange("dashboard") },
    { id: "go-flows", label: "Go to Flows", hint: "view", run: () => onTabChange("flows") },
    { id: "go-recent", label: "Go to Recent", hint: "view", run: () => onTabChange("recent") },
    { id: "load", label: "Load capture", hint: "action", run: onRequestLoad },
    { id: "toggle-rail", label: collapsed ? "Expand sidebar" : "Collapse sidebar", hint: "action", run: onToggleCollapse },
    ...(canExport ? [{ id: "export", label: "Export report", hint: "action", run: () => void handleExportClick() }] : []),
  ];

  return (
    <div data-component="AppShell" className="flex h-full min-h-0 flex-col bg-bg text-[var(--color-text)]">
      <CommandBar
        captureName={captureName ?? ""}
        sha256={summary.status === "ready" ? summary.data?.source_sha256 ?? undefined : undefined}
        activeTab={activeTab}
        onTab={onTabChange}
        tabs={tabs}
        captureStatus={captureStatus}
        captureError={summary.status === "error" ? summary.error : undefined}
        onRequestLoad={onRequestLoad}
        onExport={canExport ? () => void handleExportClick() : undefined}
        exporting={exporting}
        exportHint={exportHint ?? undefined}
        onOpenPalette={onOpenPalette}
        collapsed={collapsed}
        onToggleCollapse={onToggleCollapse}
      />
      <div className="flex min-h-0 flex-1">
        <ThreatRail
          threats={threats}
          collapsed={collapsed}
          activeIp={activeIp}
          onSelect={onSelectThreat}
        />
        <main className="min-h-0 flex-1 overflow-auto">{children}</main>
      </div>
      {loadDialogOpen && (
        <LoadCaptureDialog onReplaceData={onReplaceData} onAnalyzePcap={onAnalyzePcap} onClose={() => onLoadDialogOpenChange(false)} />
      )}
      <CommandPalette
        open={paletteOpen}
        onClose={() => onPaletteOpenChange?.(false)}
        actions={paletteActions}
        threats={threats}
        onSelectHost={onSelectThreat}
      />
    </div>
  );
}

export default AppShell;
