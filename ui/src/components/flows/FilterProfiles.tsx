import { useEffect, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { BookmarkPlus, ChevronDown, Download, Upload, X } from "lucide-react";
import {
  listProfiles,
  saveProfile,
  removeProfile,
  serializeProfiles,
  importProfiles,
  type FilterProfile,
  type FlowFilter,
} from "../../lib/filterProfiles";
import { downloadText } from "../../lib/platform";
import { useMenuKeyboard } from "../../lib/useMenuKeyboard";
import { BTN_OUTLINE, MENU_PANEL } from "../../cockpit/primitives";
import { cn } from "../../lib/cn";

export interface FilterProfilesProps {
  current: FlowFilter;
  hasActiveFilters: boolean;
  onApply: (f: FlowFilter) => void;
  onNotice?: (msg: string) => void;
}

/**
 * A "Profiles" dropdown for saving/restoring named filter sets.
 * Mirrors the ExportMenu open + outside-click + menu-keyboard pattern exactly.
 */
export function FilterProfiles({
  current,
  hasActiveFilters,
  onApply,
  onNotice,
}: FilterProfilesProps) {
  const [open, setOpen] = useState(false);
  const [profiles, setProfiles] = useState<FilterProfile[]>(listProfiles);
  const [name, setName] = useState("");
  const ref = useRef<HTMLDivElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const onMenuKeyDown = useMenuKeyboard(menuRef, open, () => setOpen(false), triggerRef);

  // The profile-name input keeps its native cursor keys (Home/End/arrows);
  // roving menu focus applies everywhere else. Escape always closes.
  const handleMenuKeyDown = (e: ReactKeyboardEvent) => {
    if (e.target instanceof HTMLInputElement && e.key !== "Escape") return;
    onMenuKeyDown(e);
  };

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  function handleSave() {
    if (!hasActiveFilters || name.trim() === "") return;
    setProfiles(saveProfile(name.trim(), current));
    setName("");
  }

  function handleRemove(id: string) {
    setProfiles(removeProfile(id));
  }

  function handleExport() {
    downloadText(serializeProfiles(), "packetpilot-filters.json", "application/json");
  }

  function handleImportFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target?.result;
      if (typeof text !== "string") return;
      const res = importProfiles(text);
      setProfiles(listProfiles());
      onNotice?.(res.message);
    };
    reader.readAsText(file);
    // Reset input so the same file can be re-imported
    e.target.value = "";
  }

  return (
    <div ref={ref} className="relative inline-flex">
      <button
        ref={triggerRef}
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-haspopup="menu"
        className={BTN_OUTLINE}
      >
        <BookmarkPlus size={14} />
        Profiles
        <ChevronDown size={14} aria-hidden />
      </button>

      {open && (
        <div
          ref={menuRef}
          onKeyDown={handleMenuKeyDown}
          role="menu"
          aria-label="Filter profiles"
          className={cn(MENU_PANEL, "absolute right-0 top-full z-30 mt-1 w-64 overflow-hidden")}
        >
          {/* Saved profiles list */}
          {profiles.length === 0 ? (
            <p className="px-3 py-2 text-xs text-[var(--color-text-faint)] italic">
              No saved profiles yet.
            </p>
          ) : (
            <div className="max-h-40 overflow-y-auto">
              {profiles.map((p) => (
                <div
                  key={p.id}
                  className="flex items-center gap-1 px-1 py-0.5 hover:bg-[var(--color-surface)]"
                >
                  <button
                    type="button"
                    role="menuitem"
                    tabIndex={-1}
                    onClick={() => { onApply(p.filter); setOpen(false); }}
                    className="flex-1 truncate px-2 py-1 text-left text-xs text-[var(--color-text-dim)] hover:text-[var(--color-accent)]"
                  >
                    {p.name}
                  </button>
                  <button
                    type="button"
                    role="menuitem"
                    tabIndex={-1}
                    onClick={() => handleRemove(p.id)}
                    aria-label={`Delete profile ${p.name}`}
                    className="shrink-0 p-1 text-[var(--color-text-faint)] hover:text-[var(--color-text)]"
                  >
                    <X size={12} />
                  </button>
                </div>
              ))}
            </div>
          )}

          {/* Divider */}
          <div className="my-1 border-t border-[var(--color-border)]" />

          {/* Save current filters */}
          <div className="flex items-center gap-1 px-2 py-1">
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") handleSave(); }}
              placeholder="Profile name…"
              aria-label="Profile name"
              className="min-w-0 flex-1 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface)] px-1.5 py-0.5 text-xs text-[var(--color-text)] placeholder:text-[var(--color-text-faint)] focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)]"
            />
            <button
              type="button"
              role="menuitem"
              tabIndex={-1}
              onClick={handleSave}
              disabled={!hasActiveFilters || name.trim() === ""}
              className="shrink-0 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-1.5 py-0.5 text-xs text-[var(--color-text-dim)] hover:border-[var(--color-accent)] hover:text-[var(--color-accent)] disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Save current
            </button>
          </div>

          {/* Divider */}
          <div className="my-1 border-t border-[var(--color-border)]" />

          {/* Export / Import */}
          <button
            type="button"
            role="menuitem"
            tabIndex={-1}
            onClick={handleExport}
            className="flex w-full items-center gap-1.5 px-3 py-1.5 text-xs text-[var(--color-text-dim)] hover:bg-[var(--color-surface)] hover:text-[var(--color-accent)]"
          >
            <Download size={12} />
            Export JSON
          </button>
          <button
            type="button"
            role="menuitem"
            tabIndex={-1}
            onClick={() => fileRef.current?.click()}
            className="flex w-full items-center gap-1.5 px-3 py-1.5 text-xs text-[var(--color-text-dim)] hover:bg-[var(--color-surface)] hover:text-[var(--color-accent)]"
          >
            <Upload size={12} />
            Import JSON
          </button>
          <input
            ref={fileRef}
            type="file"
            accept=".json,application/json"
            className="hidden"
            onChange={handleImportFile}
          />
        </div>
      )}
    </div>
  );
}
