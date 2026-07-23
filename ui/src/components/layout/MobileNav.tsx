// Mobile-first shell pieces. Under `md` (768px) the left SideNav and the top bar's
// action cluster don't fit a thumb, so primary navigation moves to a bottom tab bar
// (thumb-reachable). The choice of layout is driven by `useIsMobile` (a JS media query,
// not CSS show/hide) so exactly one nav set is ever in the DOM — desktop tests render the
// desktop shell unchanged, and there are never two same-named tab buttons to make queries
// ambiguous. Threat Watch is a first-class view (a "Threats" tab), so it rides the same
// tab bar as every other view rather than living behind a bespoke drawer.
import { useEffect, useState, type ReactNode } from "react";
import {
  LayoutDashboard,
  BellRing,
  Share2,
  Terminal,
  ListChecks,
  History,
  GitCompare,
  ShieldAlert,
  Waypoints,
  Gauge,
  type LucideIcon,
} from "lucide-react";
import { cn } from "../../lib/cn";
import type { TabId } from "../../types";

/** `true` while the viewport is narrower than the `md` breakpoint (768px). */
export function useIsMobile(query = "(max-width: 767px)"): boolean {
  const [isMobile, setIsMobile] = useState<boolean>(() => {
    try {
      return window.matchMedia?.(query).matches ?? false;
    } catch {
      return false;
    }
  });

  useEffect(() => {
    let mql: MediaQueryList | undefined;
    try {
      mql = window.matchMedia?.(query);
    } catch {
      mql = undefined;
    }
    if (!mql) return;
    const onChange = () => setIsMobile(mql!.matches);
    onChange();
    mql.addEventListener?.("change", onChange);
    return () => mql?.removeEventListener?.("change", onChange);
  }, [query]);

  return isMobile;
}

/** Icon per tab — shared by the desktop SideNav and the mobile BottomTabBar. */
export const TAB_ICON: Record<TabId, LucideIcon> = {
  dashboard: LayoutDashboard,
  alerts: BellRing,
  flows: Share2,
  query: Terminal,
  findings: ListChecks,
  threats: ShieldAlert,
  attackchain: Waypoints,
  baseline: Gauge,
  recent: History,
  compare: GitCompare,
};

/**
 * Deliberately NOT the shared COUNT_BADGE tint recipe: this badge overlaps the tab icon's
 * corner, and COUNT_BADGE's translucent 18%-accent background would let the icon strokes
 * bleed through behind the tiny digits, killing legibility. A filled disc keeps the count
 * readable over any icon in both themes.
 */
function Badge({ children, tone = "accent" }: { children: ReactNode; tone?: "accent" | "critical" }) {
  return (
    <span
      aria-hidden
      className="absolute -right-2 -top-1.5 inline-flex min-w-[1rem] items-center justify-center rounded-full px-1 text-[10px] font-medium leading-tight text-[var(--color-bg)]"
      style={{ background: tone === "critical" ? "var(--color-sev-critical)" : "var(--color-accent)" }}
    >
      {children}
    </span>
  );
}

/** Bottom navigation bar: the capture views (including Threats) as thumb-reachable tabs. */
export function BottomTabBar({
  tabs,
  activeTab,
  onTab,
}: {
  tabs: ReadonlyArray<{ id: TabId; label: string; badge?: number }>;
  activeTab: TabId;
  onTab: (t: TabId) => void;
}) {
  return (
    <nav
      aria-label="Primary"
      className="z-20 flex shrink-0 items-stretch justify-around border-t border-[var(--color-border)] bg-[var(--color-surface)] pb-[env(safe-area-inset-bottom)]"
    >
      {tabs.map((tab) => {
        const Icon = TAB_ICON[tab.id];
        const active = tab.id === activeTab;
        return (
          <button
            key={tab.id}
            type="button"
            onClick={() => onTab(tab.id)}
            aria-current={active ? "page" : undefined}
            className={cn(
              "relative flex flex-1 flex-col items-center gap-1 py-2 text-[11px] font-medium transition-colors",
              active ? "text-[var(--color-accent)]" : "text-[var(--color-text-dim)]",
            )}
          >
            <span className="relative">
              <Icon size={20} aria-hidden />
              {tab.badge ? <Badge>{tab.badge}</Badge> : null}
            </span>
            <span>{tab.label}</span>
          </button>
        );
      })}
    </nav>
  );
}
