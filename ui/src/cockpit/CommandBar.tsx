// Fixed 56px glass command bar: wordmark + collapse, capture identity + live
// status pill, view switcher and capture actions.
import {
  Radar,
  PanelLeftClose,
  PanelLeft,
  Upload,
  FileDown,
  Command as CommandIcon,
} from "lucide-react";
import { cn } from "../lib/cn";
import { shortHash } from "../lib/format";
import type { TabId } from "../types";

const TABS: ReadonlyArray<{ id: TabId; label: string }> = [
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
}: {
  captureName: string;
  sha256?: string;
  activeTab: TabId;
  onTab: (t: TabId) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
}) {
  return (
    <header className="glass-band relative z-30 flex h-14 shrink-0 items-center gap-3 border-b border-[var(--color-border)] px-3">
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
        <span
          className="flex h-7 w-7 items-center justify-center rounded-[var(--r-tile)]"
          style={{ background: "color-mix(in srgb, var(--color-accent) 16%, transparent)" }}
        >
          <Radar size={17} style={{ color: "var(--color-accent)" }} aria-hidden />
        </span>
        <span className="font-display text-[15px] font-semibold tracking-tight">PacketPilot</span>
      </div>

      {/* Capture identity (center) */}
      <div className="ml-3 hidden min-w-0 items-center gap-2.5 md:flex">
        <span className="font-mono-num truncate text-xs text-[var(--color-text-dim)]" title={captureName}>
          {captureName}
        </span>
        {sha256 && (
          <span className="font-mono-num hidden text-xs text-[var(--color-text-faint)] lg:inline" title={sha256}>
            {shortHash(sha256, 8, 6)}
          </span>
        )}
        <span className="glow-live inline-flex items-center gap-1.5 rounded-full border border-[color:color-mix(in_srgb,var(--color-accent)_40%,transparent)] bg-[color:color-mix(in_srgb,var(--color-accent)_10%,transparent)] px-2 py-0.5">
          <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-accent)]" style={{ boxShadow: "0 0 6px var(--color-accent)" }} />
          <span className="t-tag font-semibold uppercase text-[var(--color-accent)]">Analyzed</span>
        </span>
      </div>

      {/* Right: view switcher + actions */}
      <div className="ml-auto flex items-center gap-2">
        <nav aria-label="Views" className="flex items-center gap-0.5 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] p-0.5">
          {TABS.map((tab) => {
            const active = tab.id === activeTab;
            return (
              <button
                key={tab.id}
                type="button"
                aria-pressed={active}
                onClick={() => onTab(tab.id)}
                className={cn(
                  "rounded-[var(--r-chip)] px-3 py-1 text-xs font-medium transition-colors",
                  active
                    ? "bg-[var(--color-bg)] text-[var(--color-text)] shadow-sm"
                    : "text-[var(--color-text-dim)] hover:text-[var(--color-text)]",
                )}
              >
                {tab.label}
              </button>
            );
          })}
        </nav>

        <ActionButton icon={<Upload size={14} />} label="Load capture" />
        <ActionButton icon={<FileDown size={14} />} label="Export" />
        <button
          type="button"
          aria-label="Command palette"
          className="hidden items-center gap-1.5 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-1.5 text-[var(--color-text-faint)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text-dim)] sm:inline-flex"
        >
          <CommandIcon size={13} />
          <span className="t-tag">K</span>
        </button>
      </div>
    </header>
  );
}

function ActionButton({ icon, label }: { icon: React.ReactNode; label: string }) {
  return (
    <button
      type="button"
      className="inline-flex items-center gap-1.5 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2.5 py-1.5 text-xs font-medium text-[var(--color-text-dim)] transition-colors hover:border-[color:color-mix(in_srgb,var(--color-accent)_50%,var(--color-border))] hover:text-[var(--color-text)]"
    >
      {icon}
      <span className="hidden lg:inline">{label}</span>
    </button>
  );
}

export default CommandBar;
