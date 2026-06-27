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
import { useIsMobile, BottomTabBar, MobileThreatDrawer } from "./MobileNav";
import { ShortcutsOverlay } from "../../cockpit/ShortcutsOverlay";

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
  onExportCsv?: () => Promise<ExportResult | undefined>;
  onExportStix?: () => Promise<ExportResult | undefined>;
  onCopyCsv?: () => Promise<ExportResult | undefined>;
  onCopyStix?: () => Promise<ExportResult | undefined>;
  onExportMisp?: () => Promise<ExportResult | undefined>;
  onCopyMisp?: () => Promise<ExportResult | undefined>;
  onExportCef?: () => Promise<ExportResult | undefined>;
  onCopyCef?: () => Promise<ExportResult | undefined>;
  onExportSigma?: () => Promise<ExportResult | undefined>;
  onCopySigma?: () => Promise<ExportResult | undefined>;
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
  paletteOpen: boolean;
  /** Called to change the palette open state. */
  onPaletteOpenChange: (open: boolean) => void;
  /** Open the reputation settings dialog. */
  onOpenSettings?: () => void;
  /** Open the AI chat panel. Only provided when a capture is ready. */
  onOpenAiChat?: () => void;
  /** Trigger the "Load detection rules" file picker. Only provided when packets are available. */
  onLoadRules?: () => void;
  /** Slot rendered in the CommandBar in place of the old ShieldAlert button (e.g. RuleSetsMenu). */
  rulesMenu?: ReactNode;
  /** Whether a capture comparison is active (shows the Compare tab). */
  compareActive?: boolean;
  /** Return to the Home overview (unloads the active capture). Wires the clickable wordmark + palette action. */
  onGoHome?: () => void;
  children: ReactNode;
}

/** True when focus is in a text-entry control, so global single-key shortcuts must stay inert. */
function isEditableTarget(el: Element | null): boolean {
  if (!(el instanceof HTMLElement)) return false;
  const tag = el.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || el.isContentEditable) return true;
  const role = el.getAttribute("role");
  return role === "textbox" || role === "searchbox" || role === "combobox" || role === "spinbutton";
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
  onExportCsv,
  onExportStix,
  onCopyCsv,
  onCopyStix,
  onExportMisp,
  onCopyMisp,
  onExportCef,
  onCopyCef,
  onExportSigma,
  onCopySigma,
  threats,
  activeIp,
  onSelectThreat,
  collapsed,
  onToggleCollapse,
  onOpenPalette,
  paletteOpen,
  onPaletteOpenChange,
  onOpenSettings,
  onOpenAiChat,
  onLoadRules,
  rulesMenu,
  compareActive = false,
  onGoHome,
  children,
}: AppShellProps) {
  const [exportHint, setExportHint] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

  // Mobile-first shell: under `md` the rail becomes a drawer and tabs move to a bottom bar.
  const isMobile = useIsMobile();
  const [threatDrawerOpen, setThreatDrawerOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);

  const tabs = useMemo(
    () => [
      { id: "dashboard" as const, label: "Dashboard" },
      { id: "flows" as const, label: "Flows" },
      { id: "findings" as const, label: "Findings" },
      { id: "recent" as const, label: "Recent", badge: recentCount || undefined },
      ...(compareActive ? [{ id: "compare" as const, label: "Compare" }] : []),
    ],
    [recentCount, compareActive],
  );

  // Never strand an open drawer on the desktop layout (e.g. on rotate/resize).
  useEffect(() => {
    if (!isMobile) setThreatDrawerOpen(false);
  }, [isMobile]);

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
        if (!paletteOpen && !loadDialogOpen) onPaletteOpenChange(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [paletteOpen, loadDialogOpen, onPaletteOpenChange]);

  // `?` opens the shortcut help; digit keys jump between tabs. Both are inert while the
  // user is typing or any modal dialog (palette, drawer, settings, consents…) is open.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      // Escape closes the shortcuts overlay regardless of focus position — when it is opened
      // by keyboard ("?") focus may not have moved into the dialog yet, so its own Escape
      // handler (which needs focus inside) can't be relied on.
      if (e.key === "Escape") {
        if (shortcutsOpen) setShortcutsOpen(false);
        return;
      }
      if (isEditableTarget(document.activeElement)) return;
      // Inert while a modal is up: gate on the state we own (synchronous, no render race)
      // plus a DOM check for App-level dialogs (settings, consents) AppShell doesn't track.
      if (paletteOpen || loadDialogOpen || shortcutsOpen || document.querySelector('[role="dialog"][aria-modal="true"]')) return;
      // `?` matches the character (layout-robust via e.key); the ⌘K palette also offers a
      // "Keyboard shortcuts" action as a pointer / layout-independent fallback.
      if (e.key === "?") {
        e.preventDefault();
        setShortcutsOpen(true);
        return;
      }
      const idx = ["1", "2", "3", "4"].indexOf(e.key);
      if (idx >= 0 && idx < tabs.length) {
        e.preventDefault();
        onTabChange(tabs[idx].id);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [paletteOpen, loadDialogOpen, shortcutsOpen, onTabChange, tabs]);

  const runExport = useCallback(
    async (fn?: () => Promise<ExportResult | undefined>) => {
      if (!fn || !canExport || exporting) return;
      setExporting(true);
      try {
        const res = await fn();
        if (res?.ok) setExportHint(res.message);
      } catch (err: unknown) {
        setExportHint(`Export failed: ${String((err as Error)?.message ?? err)}`);
      } finally {
        setExporting(false);
      }
    },
    [canExport, exporting],
  );

  const exportActions = useMemo(
    () => [
      { id: "report", label: "HTML report", run: () => void runExport(onExport) },
      { id: "csv", label: "CSV — download", run: () => void runExport(onExportCsv) },
      { id: "csv-copy", label: "CSV — copy", run: () => void runExport(onCopyCsv) },
      { id: "stix", label: "STIX bundle — download", run: () => void runExport(onExportStix) },
      { id: "stix-copy", label: "STIX bundle — copy", run: () => void runExport(onCopyStix) },
      { id: "misp", label: "MISP event — download", run: () => void runExport(onExportMisp) },
      { id: "misp-copy", label: "MISP event — copy", run: () => void runExport(onCopyMisp) },
      { id: "cef", label: "CEF — download", run: () => void runExport(onExportCef) },
      { id: "cef-copy", label: "CEF — copy", run: () => void runExport(onCopyCef) },
      { id: "sigma", label: "Sigma rules — download", run: () => void runExport(onExportSigma) },
      { id: "sigma-copy", label: "Sigma rules — copy", run: () => void runExport(onCopySigma) },
    ],
    [runExport, onExport, onExportCsv, onCopyCsv, onExportStix, onCopyStix, onExportMisp, onCopyMisp, onExportCef, onCopyCef, onExportSigma, onCopySigma],
  );

  // Capture filename: derived from the App-owned summary state.
  const captureName = useMemo(() => {
    if (summary.status === "ready" && summary.data)
      return basename(summary.data.source_path);
    return null;
  }, [summary]);

  const captureStatus =
    summary.status === "ready" ? "ready" :
    summary.status === "loading" ? "loading" :
    summary.status === "error" ? "error" : "idle";

  const paletteActions = useMemo<PaletteAction[]>(() => [
    ...(onGoHome ? [{ id: "go-home", label: "Go to overview", hint: "view", run: onGoHome }] : []),
    { id: "go-dashboard", label: "Go to Dashboard", hint: "view", run: () => onTabChange("dashboard") },
    { id: "go-flows", label: "Go to Flows", hint: "view", run: () => onTabChange("flows") },
    { id: "go-findings", label: "Go to Findings", hint: "view", run: () => onTabChange("findings") },
    { id: "go-recent", label: "Go to Recent", hint: "view", run: () => onTabChange("recent") },
    { id: "go-compare", label: "Compare captures", hint: "view", run: () => onTabChange("recent") },
    { id: "load", label: "Load capture", hint: "action", run: onRequestLoad },
    { id: "toggle-rail", label: collapsed ? "Expand sidebar" : "Collapse sidebar", hint: "action", run: onToggleCollapse },
    { id: "shortcuts", label: "Keyboard shortcuts", hint: "help", run: () => setShortcutsOpen(true) },
    ...(onLoadRules ? [
      { id: "load-rules", label: "Load detection rules…", hint: "action", run: onLoadRules },
    ] : []),
    ...(canExport ? [
      { id: "export", label: "Export report", hint: "action", run: () => void runExport(onExport) },
      { id: "export-csv", label: "Export CSV", hint: "action", run: () => void runExport(onExportCsv) },
      { id: "export-csv-copy", label: "Copy CSV", hint: "action", run: () => void runExport(onCopyCsv) },
      { id: "export-stix", label: "Export STIX bundle", hint: "action", run: () => void runExport(onExportStix) },
      { id: "export-stix-copy", label: "Copy STIX bundle", hint: "action", run: () => void runExport(onCopyStix) },
      { id: "export-misp", label: "Export MISP event", hint: "action", run: () => void runExport(onExportMisp) },
      { id: "export-misp-copy", label: "Copy MISP event", hint: "action", run: () => void runExport(onCopyMisp) },
      { id: "export-cef", label: "Export CEF", hint: "action", run: () => void runExport(onExportCef) },
      { id: "export-cef-copy", label: "Copy CEF", hint: "action", run: () => void runExport(onCopyCef) },
      { id: "export-sigma", label: "Export Sigma rules", hint: "action", run: () => void runExport(onExportSigma) },
      { id: "export-sigma-copy", label: "Copy Sigma rules", hint: "action", run: () => void runExport(onCopySigma) },
    ] : []),
  ], [onGoHome, onTabChange, onRequestLoad, onToggleCollapse, collapsed, onLoadRules, canExport, runExport, onExport, onExportCsv, onCopyCsv, onExportStix, onCopyStix, onExportMisp, onCopyMisp, onExportCef, onCopyCef, onExportSigma, onCopySigma]);

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
        onGoHome={onGoHome}
        onRequestLoad={onRequestLoad}
        exportActions={canExport ? exportActions : []}
        exporting={exporting}
        exportHint={exportHint ?? undefined}
        onOpenPalette={onOpenPalette}
        collapsed={collapsed}
        onToggleCollapse={onToggleCollapse}
        onOpenSettings={onOpenSettings}
        onOpenAiChat={onOpenAiChat}
        rulesMenu={rulesMenu}
        showTabs={!isMobile}
      />
      <div className="flex min-h-0 flex-1">
        {!isMobile && (
          <ThreatRail
            threats={threats}
            collapsed={collapsed}
            activeIp={activeIp}
            onSelect={onSelectThreat}
          />
        )}
        {/* overflow-x-hidden clips sub-pixel rounding overflow (e.g. the heatmap's
            many flex-1 gap-px cells at the ~768px boundary) so the shell never grows
            a horizontal scrollbar; views that need real horizontal scroll (FlowsTable)
            carry their own overflow-auto container. */}
        <main className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden">{children}</main>
      </div>
      {isMobile && (
        <BottomTabBar
          tabs={tabs}
          activeTab={activeTab}
          onTab={onTabChange}
          threatCount={threats.length}
          onOpenThreats={() => setThreatDrawerOpen(true)}
        />
      )}
      <MobileThreatDrawer
        open={isMobile && threatDrawerOpen}
        onClose={() => setThreatDrawerOpen(false)}
        threats={threats}
        activeIp={activeIp}
        onSelect={onSelectThreat}
      />
      {loadDialogOpen && (
        <LoadCaptureDialog onReplaceData={onReplaceData} onAnalyzePcap={onAnalyzePcap} onClose={() => onLoadDialogOpenChange(false)} />
      )}
      <CommandPalette
        open={paletteOpen}
        onClose={() => onPaletteOpenChange(false)}
        actions={paletteActions}
        threats={threats}
        onSelectHost={onSelectThreat}
      />
      <ShortcutsOverlay
        open={shortcutsOpen}
        onClose={() => setShortcutsOpen(false)}
        tabs={tabs}
      />
    </div>
  );
}

export default AppShell;
