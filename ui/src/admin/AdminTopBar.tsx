import { useState, type FormEvent } from "react";
import { ThemeToggle } from "../cockpit/ThemeToggle";
import { DensityToggle } from "../cockpit/DensityToggle";
import { SearchInput } from "./ui/kit";
import { ADMIN_SECTIONS, type AdminSectionId } from "./sections";

export function AdminTopBar({
  title,
  subtitle,
  onJump,
}: {
  title: string;
  subtitle?: string;
  onJump: (id: AdminSectionId) => void;
}) {
  const [query, setQuery] = useState("");

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const q = query.trim().toLowerCase();
    if (!q) return;
    const hit = ADMIN_SECTIONS.find((s) => s.label.toLowerCase().includes(q) || s.id.includes(q));
    if (hit) {
      onJump(hit.id as AdminSectionId);
      setQuery("");
    }
  };

  return (
    <header className="flex h-16 shrink-0 items-center gap-4 border-b border-[var(--color-border)] bg-[var(--color-surface-1)] px-[var(--admin-gutter)]">
      <div className="min-w-0">
        <h1 className="font-display text-xl font-semibold leading-tight text-[var(--color-text)]">{title}</h1>
        {subtitle && <p className="truncate text-sm text-[var(--color-text-dim)]">{subtitle}</p>}
      </div>
      <form onSubmit={submit} className="ml-auto hidden min-w-0 max-w-xs flex-1 md:block">
        <SearchInput
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Jump to a section…"
          aria-label="Jump to a section"
        />
      </form>
      <div className="ml-auto flex items-center gap-2 md:ml-0">
        <ThemeToggle />
        <DensityToggle />
      </div>
    </header>
  );
}

export default AdminTopBar;
