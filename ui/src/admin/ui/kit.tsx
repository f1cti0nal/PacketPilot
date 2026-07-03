// Shared admin UI kit — the Cemdash-style building blocks (soft cards, KPI stat
// cards, trend pills, progress bars, avatars, pill buttons, status chips, a
// table-card shell, and an accessible dropdown menu). Every admin surface
// composes these so the console stays visually coherent. All colors come from
// the shared semantic tokens, so light/dark + density keep working.
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { ArrowDownRight, ArrowUpRight, MoreHorizontal, Search, type LucideIcon } from "lucide-react";
import { cn } from "../../lib/cn";
import { avatarColor, initials, type Delta } from "./helpers";

/* ------------------------------------------------------------------ Card --- */

export function AdminCard({
  title,
  subtitle,
  right,
  className,
  bodyClassName,
  as: As = "section",
  children,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  right?: ReactNode;
  className?: string;
  bodyClassName?: string;
  as?: "section" | "div";
  children: ReactNode;
}) {
  return (
    <As className={cn("admin-card flex min-w-0 flex-col", className)}>
      {(title || subtitle || right) && (
        <header className="flex items-start justify-between gap-3 px-5 pt-4 pb-3">
          <div className="min-w-0">
            {title && <h3 className="font-display text-[15px] font-semibold text-[var(--color-text)]">{title}</h3>}
            {subtitle && <p className="mt-0.5 text-xs text-[var(--color-text-dim)]">{subtitle}</p>}
          </div>
          {right && <div className="flex shrink-0 items-center gap-2">{right}</div>}
        </header>
      )}
      <div className={cn("min-w-0 flex-1 px-5 pb-5", !(title || subtitle || right) && "pt-5", bodyClassName)}>
        {children}
      </div>
    </As>
  );
}

/** Card that holds a data grid: header + a horizontally-scrollable table region. */
export function TableCard({
  title,
  count,
  right,
  footer,
  className,
  children,
}: {
  title?: ReactNode;
  count?: ReactNode;
  right?: ReactNode;
  footer?: ReactNode;
  className?: string;
  children: ReactNode;
}) {
  return (
    <section className={cn("admin-card flex min-w-0 flex-col overflow-hidden", className)}>
      {(title || right || count !== undefined) && (
        <header className="flex flex-wrap items-center gap-3 px-5 py-4">
          {title && (
            <h3 className="font-display text-[15px] font-semibold text-[var(--color-text)]">
              {title}
              {count !== undefined && (
                <span className="ml-2 rounded-full bg-[var(--color-surface-2)] px-2 py-0.5 text-xs font-normal text-[var(--color-text-dim)]">
                  {count}
                </span>
              )}
            </h3>
          )}
          {right && <div className="ml-auto flex flex-wrap items-center gap-2">{right}</div>}
        </header>
      )}
      <div className="min-w-0 overflow-x-auto border-t border-[var(--color-border)]">{children}</div>
      {footer && <div className="border-t border-[var(--color-border)] px-5 py-3 text-xs text-[var(--color-text-dim)]">{footer}</div>}
    </section>
  );
}

/* ---------------------------------------------------------------- Buttons --- */

type BtnVariant = "primary" | "secondary" | "ghost" | "danger";

const BTN_BASE =
  "inline-flex items-center justify-center gap-1.5 rounded-full text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-55 whitespace-nowrap";
const BTN_VARIANTS: Record<BtnVariant, string> = {
  primary: "bg-[var(--color-accent-deep)] text-[var(--color-on-accent)] hover:brightness-110",
  secondary:
    "border border-[var(--color-border)] bg-[var(--color-surface-1)] text-[var(--color-text)] hover:border-[var(--color-border-strong)] hover:bg-[var(--color-surface-2)]",
  ghost: "text-[var(--color-text-dim)] hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]",
  danger:
    "border border-[color-mix(in_srgb,var(--color-sev-critical)_40%,transparent)] text-[var(--color-sev-critical)] hover:bg-[color-mix(in_srgb,var(--color-sev-critical)_10%,transparent)]",
};

export function PillButton({
  variant = "secondary",
  icon: Icon,
  size = "md",
  className,
  children,
  ...rest
}: {
  variant?: BtnVariant;
  icon?: LucideIcon;
  size?: "sm" | "md";
} & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      type="button"
      className={cn(BTN_BASE, BTN_VARIANTS[variant], size === "sm" ? "px-2.5 py-1 text-xs" : "px-3.5 py-1.5", className)}
      {...rest}
    >
      {Icon && <Icon size={size === "sm" ? 13 : 15} aria-hidden />}
      {children}
    </button>
  );
}

export function IconButton({
  icon: Icon,
  className,
  ...rest
}: { icon: LucideIcon } & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      type="button"
      className={cn(
        "inline-flex h-8 w-8 items-center justify-center rounded-full border border-[var(--color-border)] bg-[var(--color-surface-1)] text-[var(--color-text-dim)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]",
        className,
      )}
      {...rest}
    >
      <Icon size={15} aria-hidden />
    </button>
  );
}

/* ------------------------------------------------------------------ Search --- */

export function SearchInput({
  className,
  ...rest
}: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <div className={cn("relative", className)}>
      <Search
        size={15}
        aria-hidden
        className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[var(--color-text-faint)]"
      />
      <input
        type="search"
        className="w-full rounded-full border border-[var(--color-border)] bg-[var(--color-surface-1)] py-2 pl-9 pr-3 text-sm text-[var(--color-text)] outline-none transition-colors placeholder:text-[var(--color-text-faint)] focus:border-[var(--color-accent)]"
        {...rest}
      />
    </div>
  );
}

/* ------------------------------------------------------------------ Avatar --- */

export function Avatar({
  name,
  email,
  size = 32,
}: {
  name?: string | null;
  email?: string | null;
  size?: number;
}) {
  const bg = avatarColor(email || name || "");
  return (
    <span
      aria-hidden
      className="inline-flex shrink-0 items-center justify-center rounded-full font-semibold text-white"
      style={{ width: size, height: size, background: bg, fontSize: Math.round(size * 0.4) }}
    >
      {initials(name, email)}
    </span>
  );
}

/* -------------------------------------------------------------- Trend pill --- */

export function TrendPill({ delta, suffix = "%" }: { delta: Delta; suffix?: string }) {
  const { pct, dir } = delta;
  const color = dir === "up" ? "var(--admin-up)" : dir === "down" ? "var(--admin-down)" : "var(--color-text-faint)";
  const label = pct == null ? (dir === "up" ? "New" : "—") : `${pct > 0 ? "+" : ""}${pct}${suffix}`;
  const Arrow = dir === "down" ? ArrowDownRight : ArrowUpRight;
  // Outlined chip on a solid surface (not a transparent hue tint) so the colored
  // text keeps its full contrast on any backdrop — see index.css:38 / SeverityChip.
  return (
    <span
      className="inline-flex items-center gap-0.5 rounded-full border px-1.5 py-0.5 text-xs font-semibold"
      style={{ color, borderColor: color, background: "var(--color-surface-2)" }}
      title="Change vs the previous 7 days"
    >
      {dir !== "flat" && <Arrow size={12} aria-hidden />}
      {label}
    </span>
  );
}

/* -------------------------------------------------------------- Stat card --- */

export function StatCard({
  label,
  value,
  icon: Icon,
  delta,
  caption,
  menu,
}: {
  label: string;
  value: ReactNode;
  icon?: LucideIcon;
  delta?: Delta;
  caption?: ReactNode;
  menu?: ReactNode;
}) {
  return (
    <div className="admin-card flex flex-col gap-3 px-4 py-4">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-[var(--color-text-dim)]">
          {Icon && (
            <span className="flex h-7 w-7 items-center justify-center rounded-full bg-[color-mix(in_srgb,var(--color-accent)_13%,transparent)] text-[var(--color-accent)]">
              <Icon size={15} aria-hidden />
            </span>
          )}
          <span className="text-[13px] font-medium">{label}</span>
        </div>
        {menu}
      </div>
      <div className="flex items-end justify-between gap-2">
        <span className="font-display text-[26px] font-semibold leading-none tracking-tight text-[var(--color-text)]">
          {value}
        </span>
        {delta && <TrendPill delta={delta} />}
      </div>
      {caption && <div className="text-xs text-[var(--color-text-dim)]">{caption}</div>}
    </div>
  );
}

/**
 * Compact stat tile. The label is a DIRECT child of the tile (with the value in a
 * sibling row) so `getByText(label).parentElement` contains the value — a shape
 * some view tests rely on. Use `StatCard` for the richer dashboard KPIs.
 */
export function MiniStat({
  label,
  value,
  delta,
}: {
  label: string;
  value: ReactNode;
  delta?: Delta;
}) {
  return (
    <div className="admin-card flex min-w-[8rem] flex-1 flex-col gap-1.5 px-4 py-3.5">
      <span className="text-[13px] font-medium text-[var(--color-text-dim)]">{label}</span>
      <span className="flex items-center justify-between gap-2">
        <span className="font-display text-[22px] font-semibold leading-none tracking-tight text-[var(--color-text)]">
          {value}
        </span>
        {delta && <TrendPill delta={delta} />}
      </span>
    </div>
  );
}

/* ----------------------------------------------------------- Progress stat --- */

export function ProgressStat({
  label,
  value,
  pct,
  color = "var(--color-accent)",
  caption,
}: {
  label: ReactNode;
  value: ReactNode;
  pct: number;
  color?: string;
  caption?: ReactNode;
}) {
  const w = Math.max(0, Math.min(100, pct));
  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-[13px] font-medium text-[var(--color-text)]">{label}</span>
        <span className="font-mono-num text-sm text-[var(--color-text-dim)]">{value}</span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded-full bg-[var(--color-surface-3)]">
        <div className="h-full rounded-full transition-[width]" style={{ width: `${w}%`, background: color }} />
      </div>
      {caption && <span className="text-xs text-[var(--color-text-faint)]">{caption}</span>}
    </div>
  );
}

/* ------------------------------------------------------------- Status pill --- */

export function StatusPill({ label, color }: { label: string; color: string }) {
  // Outlined on a solid surface (see index.css:38): the colored text sits on an
  // opaque backdrop, so contrast holds even when a hovered table row shifts behind it.
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium capitalize"
      style={{ color, borderColor: color, background: "var(--color-surface-2)" }}
    >
      <span aria-hidden className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
      {label}
    </span>
  );
}

/** Neutral/accent tag chip (e.g. a plan badge). */
export function Badge({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "accent" }) {
  const accent = tone === "accent";
  return (
    <span
      className="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium capitalize"
      style={{
        color: accent ? "var(--color-accent-strong)" : "var(--color-text-dim)",
        background: accent
          ? "color-mix(in srgb, var(--color-accent) 13%, transparent)"
          : "var(--color-surface-2)",
      }}
    >
      {children}
    </span>
  );
}

/* --------------------------------------------------------------- Section --- */

export function SectionTitle({ title, subtitle }: { title: ReactNode; subtitle?: ReactNode }) {
  return (
    <div className="min-w-0">
      <h2 className="font-display text-lg font-semibold text-[var(--color-text)]">{title}</h2>
      {subtitle && <p className="mt-0.5 text-sm text-[var(--color-text-dim)]">{subtitle}</p>}
    </div>
  );
}

/* ----------------------------------------------------------- Dropdown menu --- */

export interface MenuItem {
  label: string;
  onSelect: () => void;
  danger?: boolean;
}

/**
 * A "···" trigger that opens an accessible popover menu. Closes on outside click,
 * Escape, or item selection. `label` names the trigger for assistive tech.
 */
export function MenuButton({ label = "Options", items }: { label?: string; items: MenuItem[] }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const menuId = useId();

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
    <div ref={ref} className="relative">
      <button
        type="button"
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => setOpen((o) => !o)}
        className="inline-flex h-7 w-7 items-center justify-center rounded-full text-[var(--color-text-faint)] transition-colors hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]"
      >
        <MoreHorizontal size={16} aria-hidden />
      </button>
      {open && (
        <div
          id={menuId}
          role="menu"
          className="admin-menu absolute right-0 z-20 mt-1 min-w-[9rem] overflow-hidden rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-1"
        >
          {items.map((it) => (
            <button
              key={it.label}
              type="button"
              role="menuitem"
              onClick={() => {
                setOpen(false);
                it.onSelect();
              }}
              className={cn(
                "block w-full rounded-lg px-3 py-1.5 text-left text-sm transition-colors hover:bg-[var(--color-surface-2)]",
                it.danger ? "text-[var(--color-sev-critical)]" : "text-[var(--color-text-dim)] hover:text-[var(--color-text)]",
              )}
            >
              {it.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
