// Persistent left navigation rail for the app. Holds the brand (click → overview),
// the primary view switcher (Dashboard / Flows / Findings / Threats / Recent, plus
// Compare when a comparison is active), and a collapse toggle. Mirrors the admin
// console's Sidebar house pattern so the two shells feel like one product. On mobile
// this is dropped for the BottomTabBar (see MobileNav) — exactly one nav set is ever
// mounted, driven by `useIsMobile` in AppShell.
import { ChevronsLeft, ChevronsRight, Radar } from "lucide-react";
import { cn } from "../../lib/cn";
import type { TabId } from "../../types";
import { TAB_ICON } from "./MobileNav";

export function SideNav({
  tabs,
  activeTab,
  onTab,
  collapsed,
  onToggleCollapse,
  onGoHome,
}: {
  tabs: ReadonlyArray<{ id: TabId; label: string; badge?: number }>;
  activeTab: TabId;
  onTab: (t: TabId) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
  /** Return to the Home overview (unloads the active capture). Makes the brand clickable. */
  onGoHome?: () => void;
}) {
  return (
    <aside
      className={cn(
        "z-20 flex shrink-0 flex-col border-r border-[var(--color-border)] bg-[var(--color-surface)] transition-[width] duration-200",
        collapsed ? "w-16" : "w-60",
      )}
    >
      {/* Brand */}
      <div className={cn("flex h-14 items-center gap-2.5 px-3", collapsed && "justify-center px-0")}>
        {onGoHome ? (
          <button
            type="button"
            onClick={onGoHome}
            aria-label="Go to overview"
            className="flex min-w-0 items-center gap-2.5 rounded-[var(--r-tile)] transition-opacity hover:opacity-80"
          >
            <BrandMark collapsed={collapsed} />
          </button>
        ) : (
          <BrandMark collapsed={collapsed} />
        )}
      </div>

      {/* Primary navigation */}
      <nav aria-label="Views" className="flex min-h-0 flex-1 flex-col gap-1 overflow-y-auto px-2 py-2">
        {tabs.map((tab) => {
          const Icon = TAB_ICON[tab.id];
          const active = tab.id === activeTab;
          return (
            <button
              key={tab.id}
              type="button"
              aria-label={tab.label}
              aria-current={active ? "page" : undefined}
              title={collapsed ? tab.label : undefined}
              onClick={() => onTab(tab.id)}
              className={cn(
                "group relative flex items-center gap-3 rounded-[var(--r-tile)] px-2.5 py-2 text-sm font-medium transition-colors",
                collapsed && "justify-center px-0",
                active
                  ? "bg-[var(--color-surface-2)] text-[var(--color-accent)]"
                  : "text-[var(--color-text-dim)] hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]",
              )}
            >
              <span
                aria-hidden
                className={cn(
                  "absolute inset-y-1 left-0 w-0.5 rounded-full bg-[var(--color-accent)] transition-opacity",
                  active ? "opacity-100" : "opacity-0",
                )}
              />
              <Icon size={18} aria-hidden className="shrink-0" />
              {!collapsed && <span className="min-w-0 flex-1 truncate text-left">{tab.label}</span>}
              {!collapsed && tab.badge ? (
                <span
                  aria-hidden
                  className="inline-flex min-w-[1.1rem] items-center justify-center rounded-full bg-[color:color-mix(in_srgb,var(--color-accent)_18%,transparent)] px-1 text-[10px] font-medium text-[var(--color-accent-badge)]"
                >
                  {tab.badge}
                </span>
              ) : null}
            </button>
          );
        })}
      </nav>

      {/* Collapse toggle */}
      <button
        type="button"
        onClick={onToggleCollapse}
        aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        className={cn(
          "m-2 inline-flex items-center gap-2 rounded-[var(--r-tile)] px-2.5 py-2 text-xs font-medium text-[var(--color-text-faint)] transition-colors hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text-dim)]",
          collapsed && "justify-center px-0",
        )}
      >
        {collapsed ? <ChevronsRight size={16} aria-hidden /> : <ChevronsLeft size={16} aria-hidden />}
        {!collapsed && <span>Collapse</span>}
      </button>
    </aside>
  );
}

/** Radar glyph + wordmark lockup, matching the top bar's brand on mobile. */
function BrandMark({ collapsed }: { collapsed: boolean }) {
  return (
    <>
      <span
        className="flex h-8 w-8 shrink-0 items-center justify-center rounded-[var(--r-tile)]"
        style={{ background: "color-mix(in srgb, var(--color-accent) 16%, transparent)" }}
      >
        <Radar size={18} style={{ color: "var(--color-accent)" }} aria-hidden />
      </span>
      {!collapsed && (
        <span className="min-w-0">
          <span className="block truncate font-display text-[15px] font-medium leading-tight tracking-tight text-[var(--color-text)]">
            PacketPilot
          </span>
          <span className="block truncate text-[10px] font-medium uppercase tracking-wider text-[var(--color-text-faint)]">
            Network forensics
          </span>
        </span>
      )}
    </>
  );
}

export default SideNav;
