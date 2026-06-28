import { PanelLeftClose, PanelLeft, ShieldCheck } from "lucide-react";
import { cn } from "../lib/cn";
import { ADMIN_SECTIONS, type AdminSectionId } from "./sections";

export function Sidebar({
  active,
  onSelect,
  collapsed,
  onToggleCollapse,
}: {
  active: AdminSectionId;
  onSelect: (id: AdminSectionId) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
}) {
  return (
    <aside
      className={cn(
        "flex shrink-0 flex-col border-r border-[var(--color-border)] bg-[var(--color-surface-1)] transition-[width]",
        collapsed ? "w-16" : "w-56",
      )}
    >
      <div className="flex h-12 items-center gap-2 px-3">
        <ShieldCheck size={18} className="shrink-0 text-[var(--color-accent)]" aria-hidden />
        {!collapsed && <span className="t-title text-[var(--color-text)]">Admin</span>}
      </div>
      <nav aria-label="Admin sections" className="flex flex-1 flex-col gap-0.5 px-2 py-2">
        {ADMIN_SECTIONS.map((s) => {
          const Icon = s.icon;
          const isActive = s.id === active;
          return (
            <button
              key={s.id}
              type="button"
              aria-label={s.label}
              aria-current={isActive ? "page" : undefined}
              title={collapsed ? s.label : undefined}
              onClick={() => onSelect(s.id as AdminSectionId)}
              className={cn(
                "flex items-center gap-2.5 rounded-[var(--r-tile)] px-2.5 py-2 text-sm transition-colors",
                isActive
                  ? "bg-[var(--color-surface-2)] text-[var(--color-text)]"
                  : "text-[var(--color-text-dim)] hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]",
              )}
            >
              <Icon size={16} aria-hidden className="shrink-0" />
              {!collapsed && <span className="truncate">{s.label}</span>}
            </button>
          );
        })}
      </nav>
      <button
        type="button"
        onClick={onToggleCollapse}
        aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        className="m-2 inline-flex items-center justify-center rounded-[var(--r-tile)] border border-[var(--color-border)] p-1.5 text-[var(--color-text-faint)] hover:text-[var(--color-text-dim)]"
      >
        {collapsed ? <PanelLeft size={14} aria-hidden /> : <PanelLeftClose size={14} aria-hidden />}
      </button>
    </aside>
  );
}

export default Sidebar;
