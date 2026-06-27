// Fixed 56px glass command bar: wordmark + collapse, capture identity + live
// status pill, view switcher and capture actions.
import type { ReactNode } from "react";
import {
  Radar,
  PanelLeftClose,
  PanelLeft,
  Upload,
  Loader2,
  Command as CommandIcon,
  CheckCircle2,
  Settings,
  Sparkles,
} from "lucide-react";
import { cn } from "../lib/cn";
import { shortHash } from "../lib/format";
import type { TabId } from "../types";
import { ExportMenu } from "./ExportMenu";
import type { ExportAction } from "./ExportMenu";
import { ThemeToggle } from "./ThemeToggle";
import { DensityToggle } from "./DensityToggle";

const DEFAULT_TABS: ReadonlyArray<{ id: TabId; label: string; badge?: number }> = [
  { id: "dashboard", label: "Dashboard" },
  { id: "flows", label: "Flows" },
];

export function CommandBar({
  captureName,
  sha256,
  activeTab,
  onTab,
  collapsed,
  onToggleCollapse,
  onGoHome,
  tabs = DEFAULT_TABS,
  captureStatus = "ready",
  captureError,
  onRequestLoad,
  exportActions,
  exporting = false,
  exportHint,
  onOpenPalette,
  onOpenSettings,
  onOpenAiChat,
  rulesMenu,
  showTabs = true,
}: {
  captureName: string;
  sha256?: string;
  activeTab: TabId;
  onTab: (t: TabId) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
  /** Return to the Home overview (unloads the active capture). Makes the wordmark clickable. */
  onGoHome?: () => void;
  tabs?: ReadonlyArray<{ id: TabId; label: string; badge?: number }>;
  /** Render the inline Views switcher. Off on mobile, where the bottom tab bar replaces it. */
  showTabs?: boolean;
  captureStatus?: "idle" | "loading" | "ready" | "error";
  captureError?: string;
  onRequestLoad?: () => void;
  exportActions?: ExportAction[];
  exporting?: boolean;
  exportHint?: string;
  onOpenPalette?: () => void;
  onOpenSettings?: () => void;
  onOpenAiChat?: () => void;
  /** Slot for the RuleSetsMenu dropdown (or any rules affordance). */
  rulesMenu?: ReactNode;
}) {
  return (
    <header className="relative z-30 flex h-14 shrink-0 items-center gap-3 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-3">
      {/* Wordmark + collapse */}
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={onToggleCollapse}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          className="rounded-[var(--r-tile)] p-1.5 text-[var(--color-text-dim)] transition-colors hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]"
        >
          {collapsed ? <PanelLeft size={16} /> : <PanelLeftClose size={16} />}
        </button>
        {onGoHome ? (
          <button
            type="button"
            onClick={onGoHome}
            aria-label="Go to overview"
            className="flex items-center gap-2 rounded-[var(--r-tile)] transition-opacity hover:opacity-80"
          >
            <BrandMark />
          </button>
        ) : (
          <BrandMark />
        )}
      </div>

      {/* Capture identity (center). Deferred to lg: at the 768px md boundary the
          capture identity + Views switcher + action cluster together overflowed
          the bar by ~36px (horizontal scrollbar). The capture name/status is
          secondary — the dashboard already shows the capture context. */}
      <div className="ml-3 hidden min-w-0 items-center gap-2.5 lg:flex">
        {captureStatus === "loading" && (
          <>
            <Loader2 size={13} className="animate-spin text-[var(--color-text-faint)]" aria-hidden />
            <span className="font-mono-num truncate text-xs text-[var(--color-text-dim)]">Loading…</span>
          </>
        )}
        {captureStatus === "ready" && (
          <>
            <span className="font-mono-num truncate text-xs text-[var(--color-text-dim)]" title={captureName}>
              {captureName}
            </span>
            {sha256 && (
              <span className="font-mono-num hidden text-xs text-[var(--color-text-faint)] lg:inline" title={sha256}>
                {shortHash(sha256, 8, 6)}
              </span>
            )}
            <span className="inline-flex items-center gap-1.5 rounded-full border border-[color:color-mix(in_srgb,var(--color-accent)_40%,transparent)] bg-[color:color-mix(in_srgb,var(--color-accent)_10%,transparent)] px-2 py-0.5">
              <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-accent)]" />
              <span className="t-tag font-medium uppercase text-[var(--color-accent)]">Analyzed</span>
            </span>
          </>
        )}
        {captureStatus === "error" && (
          <span className="font-mono-num truncate text-xs text-[var(--color-text-faint)]">
            {captureError ?? "Error loading capture"}
          </span>
        )}
        {captureStatus === "idle" && (
          <span className="font-mono-num truncate text-xs text-[var(--color-text-faint)]">No capture</span>
        )}
      </div>

      {/* Right: view switcher + actions */}
      <div className="ml-auto flex items-center gap-2">
        {showTabs && (
        <nav aria-label="Views" className="flex items-center gap-0.5 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] p-0.5">
          {tabs.map((tab) => {
            const active = tab.id === activeTab;
            return (
              <button
                key={tab.id}
                type="button"
                aria-current={active ? "page" : undefined}
                onClick={() => onTab(tab.id)}
                className={cn(
                  "rounded-[var(--r-chip)] px-3 py-1 text-xs font-medium transition-colors",
                  active
                    ? "bg-[var(--color-bg)] text-[var(--color-text)] shadow-sm"
                    : "text-[var(--color-text-dim)] hover:text-[var(--color-text)]",
                )}
              >
                {tab.label}
                {tab.badge ? (
                  <span className="ml-1.5 inline-flex min-w-[1.1rem] items-center justify-center rounded-full bg-[color:color-mix(in_srgb,var(--color-accent)_18%,transparent)] px-1 text-[10px] font-medium text-[var(--color-accent)]">
                    {tab.badge}
                  </span>
                ) : null}
              </button>
            );
          })}
        </nav>
        )}

        <ActionButton
          icon={<Upload size={14} />}
          label="Load capture"
          onClick={onRequestLoad}
          disabled={!onRequestLoad}
        />
        <ExportMenu actions={exportActions ?? []} disabled={(exportActions?.length ?? 0) === 0} busy={exporting} />
        {/* Always-present polite live region so export success/failure is announced on
            every viewport (SR-only below lg, visible chip at lg+). Conditionally rendering
            it would miss the announcement, and `hidden` made a failed export silent. */}
        <span
          role="status"
          aria-live="polite"
          className="sr-only items-center gap-1 text-xs text-[var(--color-text-dim)] lg:not-sr-only lg:inline-flex"
        >
          {exportHint ? (
            <>
              <CheckCircle2 size={12} aria-hidden className="hidden text-[var(--color-accent)] lg:inline-block" />
              {exportHint}
            </>
          ) : null}
        </span>
        <button
          type="button"
          aria-label="Command palette"
          onClick={onOpenPalette}
          disabled={!onOpenPalette}
          className="hidden items-center gap-1.5 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-transparent px-2 py-1.5 text-[var(--color-text-faint)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text-dim)] disabled:cursor-default disabled:opacity-50 lg:inline-flex"
        >
          <CommandIcon size={13} />
          <span className="t-tag">K</span>
        </button>
        {/* Density is a dashboard power-tweak — hide it (and Rules below) on phones
            so the action cluster fits; both return at md+. */}
        <span className="hidden md:contents"><DensityToggle /></span>
        <ThemeToggle />
        {onOpenSettings && (
          <button
            type="button"
            aria-label="Settings"
            onClick={onOpenSettings}
            className="inline-flex items-center justify-center rounded-[var(--r-tile)] border border-[var(--color-border)] bg-transparent p-1.5 text-[var(--color-text-faint)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text-dim)]"
          >
            <Settings size={14} />
          </button>
        )}
        {onOpenAiChat && (
          <button
            type="button"
            aria-label="Ask AI"
            onClick={onOpenAiChat}
            className="inline-flex items-center justify-center rounded-[var(--r-tile)] border border-[var(--color-border)] bg-transparent p-1.5 text-[var(--color-text-faint)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text-dim)]"
          >
            <Sparkles size={14} />
          </button>
        )}
        {rulesMenu && <span className="hidden md:contents">{rulesMenu}</span>}
      </div>
    </header>
  );
}

/** The glyph + wordmark lockup, shared by the static and clickable (go-home) brand. */
function BrandMark() {
  return (
    <>
      <span
        className="flex h-7 w-7 items-center justify-center rounded-[var(--r-tile)]"
        style={{ background: "color-mix(in srgb, var(--color-accent) 16%, transparent)" }}
      >
        <Radar size={17} style={{ color: "var(--color-accent)" }} aria-hidden />
      </span>
      <span className="hidden font-display text-[15px] font-medium tracking-tight sm:inline">PacketPilot</span>
    </>
  );
}

function ActionButton({
  icon,
  label,
  onClick,
  disabled,
}: {
  icon: React.ReactNode;
  label: string;
  onClick?: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-label={label}
      className="inline-flex items-center gap-1.5 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-transparent px-2.5 py-1.5 text-xs font-medium text-[var(--color-text-dim)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)] disabled:cursor-default disabled:opacity-50"
    >
      {icon}
      <span className="hidden lg:inline">{label}</span>
    </button>
  );
}

export default CommandBar;
