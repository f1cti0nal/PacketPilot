// Mobile-first shell pieces (Phase 2 of the UI design brief). Under `md` (768px) the
// always-on left ThreatRail and the top Views switcher don't fit a thumb, so:
//   • primary navigation moves to a bottom tab bar (thumb-reachable), and
//   • the ThreatRail becomes a slide-in drawer behind a "Threats" tab.
// The choice of layout is driven by `useIsMobile` (a JS media query, not CSS show/hide)
// so exactly one nav set is ever in the DOM — desktop tests render the desktop shell
// unchanged, and there are never two same-named tab buttons to make queries ambiguous.
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import {
  LayoutDashboard,
  Share2,
  ListChecks,
  History,
  GitCompare,
  ShieldAlert,
  X,
  type LucideIcon,
} from "lucide-react";
import { cn } from "../../lib/cn";
import type { TabId, IpThreat } from "../../types";
import { ThreatRail } from "../../cockpit/ThreatRail";

const TAB_ICON: Record<TabId, LucideIcon> = {
  dashboard: LayoutDashboard,
  flows: Share2,
  findings: ListChecks,
  recent: History,
  compare: GitCompare,
};

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

/** Bottom navigation bar: the capture views plus a button that opens the threat drawer. */
export function BottomTabBar({
  tabs,
  activeTab,
  onTab,
  threatCount,
  onOpenThreats,
}: {
  tabs: ReadonlyArray<{ id: TabId; label: string; badge?: number }>;
  activeTab: TabId;
  onTab: (t: TabId) => void;
  threatCount: number;
  onOpenThreats: () => void;
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
      <button
        type="button"
        onClick={onOpenThreats}
        aria-label={`Threat watchlist, ${threatCount} ${threatCount === 1 ? "host" : "hosts"}`}
        className="relative flex flex-1 flex-col items-center gap-1 py-2 text-[11px] font-medium text-[var(--color-text-dim)] transition-colors"
      >
        <span className="relative">
          <ShieldAlert size={20} aria-hidden />
          {threatCount > 0 ? <Badge tone="critical">{threatCount}</Badge> : null}
        </span>
        <span>Threats</span>
      </button>
    </nav>
  );
}

/** Slide-in left drawer that hosts the full ThreatRail on mobile. */
export function MobileThreatDrawer({
  open,
  onClose,
  threats,
  activeIp,
  onSelect,
}: {
  open: boolean;
  onClose: () => void;
  threats: IpThreat[];
  activeIp: string | null;
  onSelect: (ip: string) => void;
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const labelId = useId();

  // Focus the close button on open; restore focus to the opener on close.
  useEffect(() => {
    if (!open) return;
    const opener = document.activeElement as HTMLElement | null;
    const id = window.setTimeout(() => closeRef.current?.focus(), 0);
    return () => {
      window.clearTimeout(id);
      opener?.focus?.();
    };
  }, [open]);

  if (!open) return null;

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      onClose();
      return;
    }
    if (e.key === "Tab" && panelRef.current) {
      const focusable = panelRef.current.querySelectorAll<HTMLElement>(
        'button, [href], [tabindex]:not([tabindex="-1"])',
      );
      if (focusable.length > 0) {
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    }
  };

  const select = (ip: string) => {
    onSelect(ip);
    onClose();
  };

  return (
    <div
      className="fixed inset-0 z-40 md:hidden"
      role="dialog"
      aria-modal="true"
      aria-labelledby={labelId}
      onKeyDown={onKeyDown}
    >
      <div className="absolute inset-0 bg-black/50" onClick={onClose} aria-hidden />
      <div
        ref={panelRef}
        className="absolute inset-y-0 left-0 flex w-[280px] max-w-[85vw] flex-col bg-[var(--color-surface)]"
        style={{ boxShadow: "var(--sh-float)" }}
      >
        <div className="flex items-center justify-between border-b border-r border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2.5">
          <span id={labelId} className="font-display text-sm font-medium text-[var(--color-text)]">
            Threats
          </span>
          <button
            ref={closeRef}
            type="button"
            onClick={onClose}
            aria-label="Close threat watchlist"
            className="rounded-[var(--r-tile)] p-1 text-[var(--color-text-dim)] transition-colors hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]"
          >
            <X size={16} aria-hidden />
          </button>
        </div>
        <div className="min-h-0 flex-1 overflow-hidden [&>aside]:h-full [&>aside]:w-full">
          <ThreatRail threats={threats} collapsed={false} activeIp={activeIp} onSelect={select} />
        </div>
      </div>
    </div>
  );
}
