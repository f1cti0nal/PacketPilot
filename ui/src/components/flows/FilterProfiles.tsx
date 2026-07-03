import { useEffect, useRef, useState } from "react";
import { BookmarkPlus, Download, Upload, X } from "lucide-react";
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

export interface FilterProfilesProps {
  current: FlowFilter;
  hasActiveFilters: boolean;
  onApply: (f: FlowFilter) => void;
  onNotice?: (msg: string) => void;
}

/**
 * A "Profiles ▾" dropdown for saving/restoring named filter sets.
 * Mirrors the ExportMenu open + outside-click pattern exactly.
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
  const fileRef = useRef<HTMLInputElement>(null);

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
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-haspopup="menu"
        className="inline-flex items-center gap-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2.5 py-1.5 text-xs font-medium text-[var(--color-text)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-accent)]"
      >
        <BookmarkPlus size={14} />
        Profiles
      </button>

      {open && (
        <div className="absolute right-0 top-full z-30 mt-1 w-64 overflow-hidden rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] py-1">
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
                    onClick={() => { onApply(p.filter); setOpen(false); }}
                    className="flex-1 truncate px-2 py-1 text-left text-xs text-[var(--color-text-dim)] hover:text-[var(--color-accent)]"
                  >
                    {p.name}
                  </button>
                  <button
                    type="button"
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
              className="min-w-0 flex-1 rounded border border-[var(--color-border)] bg-[var(--color-surface)] px-1.5 py-0.5 text-xs text-[var(--color-text)] placeholder:text-[var(--color-text-faint)] focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)]"
            />
            <button
              type="button"
              onClick={handleSave}
              disabled={!hasActiveFilters || name.trim() === ""}
              className="shrink-0 rounded border border-[var(--color-border)] bg-[var(--color-surface-2)] px-1.5 py-0.5 text-xs text-[var(--color-text-dim)] hover:border-[var(--color-accent)] hover:text-[var(--color-accent)] disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Save current
            </button>
          </div>

          {/* Divider */}
          <div className="my-1 border-t border-[var(--color-border)]" />

          {/* Export / Import */}
          <button
            type="button"
            onClick={handleExport}
            className="flex w-full items-center gap-1.5 px-3 py-1.5 text-xs text-[var(--color-text-dim)] hover:bg-[var(--color-surface)] hover:text-[var(--color-accent)]"
          >
            <Download size={12} />
            Export JSON
          </button>
          <button
            type="button"
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
