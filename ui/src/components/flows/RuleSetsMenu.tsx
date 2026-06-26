import { useEffect, useRef, useState } from "react";
import { listRuleSets, removeRuleSet, type RuleSet } from "../../lib/ruleSets";
import { useMenuKeyboard } from "../../lib/useMenuKeyboard";

export interface RuleSetsMenuProps {
  onLoadFile: () => void;
  onApply: (rs: RuleSet) => void;
  disabled: boolean;
  onNotice?: (msg: string) => void;
}

/**
 * A "Rules ▾" dropdown for loading and applying saved Suricata/Snort rule sets.
 * Mirrors the FilterProfiles open + outside-click pattern exactly.
 */
export function RuleSetsMenu({ onLoadFile, onApply, disabled, onNotice: _onNotice }: RuleSetsMenuProps) {
  const [open, setOpen] = useState(false);
  const [sets, setSets] = useState<RuleSet[]>(listRuleSets);
  const ref = useRef<HTMLDivElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const onMenuKeyDown = useMenuKeyboard(menuRef, open, () => setOpen(false), triggerRef);

  useEffect(() => {
    if (!open) return;
    // Re-read on open: a rule set saved by the file-load path (App.loadRules → saveRuleSet)
    // is written outside this component, so the lazy-initialized list would otherwise be
    // stale and not show the set the user just loaded until a remount.
    setSets(listRuleSets());
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  return (
    <div ref={ref} className="relative inline-flex">
      <button
        ref={triggerRef}
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-haspopup="menu"
        className="inline-flex items-center gap-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2.5 py-1.5 text-xs font-medium text-[var(--color-text)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-accent)]"
      >
        Rules ▾
      </button>

      {open && (
        <div ref={menuRef} onKeyDown={onMenuKeyDown} role="menu" aria-label="Rule sets" className="absolute right-0 top-full z-30 mt-1 w-64 overflow-hidden rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] py-1 shadow-lg">
          {/* Load .rules file row */}
          <button
            type="button"
            role="menuitem"
            tabIndex={-1}
            disabled={disabled}
            title={disabled ? "Available for captures analyzed from a pcap" : undefined}
            onClick={() => { setOpen(false); onLoadFile(); }}
            className="flex w-full items-center gap-1.5 px-3 py-1.5 text-xs text-[var(--color-text-dim)] hover:bg-[var(--color-surface)] hover:text-[var(--color-accent)] disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Load .rules file…
          </button>

          {/* Divider */}
          <div className="my-1 border-t border-[var(--color-border)]" />

          {/* Saved rule sets list */}
          {sets.length === 0 ? (
            <p className="px-3 py-2 text-xs text-[var(--color-text-faint)] italic">
              No saved rule sets yet.
            </p>
          ) : (
            <div className="max-h-40 overflow-y-auto">
              {sets.map((rs) => (
                <div
                  key={rs.id}
                  className="flex items-center gap-1 px-1 py-0.5 hover:bg-[var(--color-surface)]"
                >
                  <button
                    type="button"
                    role="menuitem"
                    tabIndex={-1}
                    disabled={disabled}
                    title={disabled ? "Available for captures analyzed from a pcap" : undefined}
                    onClick={() => { setOpen(false); onApply(rs); }}
                    className="flex-1 truncate px-2 py-1 text-left text-xs text-[var(--color-text-dim)] hover:text-[var(--color-accent)] disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    {rs.name}
                  </button>
                  <button
                    type="button"
                    role="menuitem"
                    tabIndex={-1}
                    onClick={() => setSets(removeRuleSet(rs.id))}
                    aria-label={`Delete rule set ${rs.name}`}
                    className="shrink-0 p-1 text-[var(--color-text-faint)] hover:text-[var(--color-text)]"
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
