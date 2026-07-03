import { useEffect, useRef, useState } from "react";
import { ChevronsLeft, ChevronsRight, LogOut, ShieldCheck } from "lucide-react";
import { cn } from "../lib/cn";
import { ADMIN_GROUPS, ADMIN_SECTIONS, type AdminSectionId } from "./sections";
import { Avatar } from "./ui/kit";

export function Sidebar({
  active,
  onSelect,
  collapsed,
  onToggleCollapse,
  email,
  name,
  onSignOut,
}: {
  active: AdminSectionId;
  onSelect: (id: AdminSectionId) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
  email: string;
  name: string | null;
  onSignOut: () => Promise<void>;
}) {
  return (
    <aside
      className={cn(
        "flex shrink-0 flex-col border-r border-[var(--color-border)] bg-[var(--color-surface-1)] transition-[width] duration-200",
        collapsed ? "w-[4.5rem]" : "w-64",
      )}
    >
      {/* Brand */}
      <div className={cn("flex h-16 items-center gap-2.5 px-4", collapsed && "justify-center px-0")}>
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--color-accent-deep)] text-[var(--color-on-accent)]">
          <ShieldCheck size={19} aria-hidden />
        </span>
        {!collapsed && (
          <span className="min-w-0">
            <span className="block truncate font-display text-[17px] font-semibold leading-tight text-[var(--color-text)]">
              PacketPilot
            </span>
            <span className="block truncate text-[11px] font-medium uppercase tracking-wider text-[var(--color-text-faint)]">
              Admin Console
            </span>
          </span>
        )}
      </div>

      {/* Grouped navigation */}
      <nav aria-label="Admin sections" className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-3 py-3">
        {ADMIN_GROUPS.map((group) => (
          <div key={group} className="flex flex-col gap-1">
            {!collapsed && (
              <div className="px-2.5 pb-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-faint)]">
                {group}
              </div>
            )}
            {ADMIN_SECTIONS.filter((s) => s.group === group).map((s) => {
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
                    "flex items-center gap-3 rounded-xl px-2.5 py-2 text-sm font-medium transition-colors",
                    collapsed && "justify-center",
                    isActive
                      ? "bg-[color-mix(in_srgb,var(--color-accent)_13%,transparent)] text-[var(--color-accent-strong)]"
                      : "text-[var(--color-text-dim)] hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]",
                  )}
                >
                  <Icon size={18} aria-hidden className="shrink-0" />
                  {!collapsed && <span className="truncate">{s.label}</span>}
                </button>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Collapse toggle */}
      <button
        type="button"
        onClick={onToggleCollapse}
        aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        className={cn(
          "mx-3 mb-1 inline-flex items-center gap-2 rounded-xl px-2.5 py-2 text-xs font-medium text-[var(--color-text-faint)] transition-colors hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text-dim)]",
          collapsed && "justify-center",
        )}
      >
        {collapsed ? <ChevronsRight size={16} aria-hidden /> : <ChevronsLeft size={16} aria-hidden />}
        {!collapsed && <span>Collapse</span>}
      </button>

      {/* Profile card + account menu */}
      <ProfileCard email={email} name={name} collapsed={collapsed} onSignOut={onSignOut} />
    </aside>
  );
}

function ProfileCard({
  email,
  name,
  collapsed,
  onSignOut,
}: {
  email: string;
  name: string | null;
  collapsed: boolean;
  onSignOut: () => Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const display = (name && name.trim()) || email.split("@")[0];

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div ref={ref} className="relative border-t border-[var(--color-border)] p-3">
      <button
        type="button"
        aria-label="Account menu"
        aria-haspopup="true"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className={cn(
          "flex w-full items-center gap-2.5 rounded-xl px-1.5 py-1.5 text-left transition-colors hover:bg-[var(--color-surface-2)]",
          collapsed && "justify-center px-0",
        )}
        title={collapsed ? `${display} · ${email}` : undefined}
      >
        <Avatar name={name} email={email} size={collapsed ? 34 : 32} />
        {!collapsed && (
          <span className="min-w-0 flex-1">
            <span className="block truncate text-sm font-medium text-[var(--color-text)]">{display}</span>
            <span className="block truncate text-xs text-[var(--color-text-dim)]">{email}</span>
          </span>
        )}
      </button>
      {open && (
        <div className="admin-menu absolute bottom-full left-3 right-3 mb-1 overflow-hidden rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-1">
          {collapsed && (
            <div className="truncate px-3 py-1.5 text-xs text-[var(--color-text-dim)]" aria-hidden>
              {email}
            </div>
          )}
          <button
            type="button"
            onClick={() => void onSignOut()}
            className="flex w-full items-center gap-2 rounded-lg px-3 py-1.5 text-left text-sm text-[var(--color-text-dim)] transition-colors hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]"
          >
            <LogOut size={14} aria-hidden />
            Sign out
          </button>
        </div>
      )}
    </div>
  );
}

export default Sidebar;
