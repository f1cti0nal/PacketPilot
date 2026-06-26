// ui/src/cockpit/CommandPalette.tsx
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { CornerDownLeft, Search } from "lucide-react";
import type { IpThreat } from "../types";
import { humanNumber } from "../lib/format";
import { SEVERITY_META } from "../lib/severity";
import { sevColor } from "./viz";
import { fuzzyScore } from "./match";

export interface PaletteAction {
  id: string;
  label: string;
  hint?: string;
  run: () => void;
}

type Item =
  | { kind: "action"; action: PaletteAction; score: number }
  | { kind: "host"; threat: IpThreat; score: number };

export function CommandPalette({
  open,
  onClose,
  actions,
  threats,
  onSelectHost,
}: {
  open: boolean;
  onClose: () => void;
  actions: PaletteAction[];
  threats: IpThreat[];
  onSelectHost: (ip: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const labelId = useId();
  const listId = useId();
  const optionId = (i: number) => `${listId}-opt-${i}`;

  // Reset + focus on open; capture opener so we can restore focus on close.
  useEffect(() => {
    if (!open) return;
    const opener = document.activeElement as HTMLElement | null;
    setQuery("");
    setActive(0);
    const id = window.setTimeout(() => inputRef.current?.focus(), 0);
    return () => {
      window.clearTimeout(id);
      opener?.focus?.();
    };
  }, [open]);

  const items = useMemo<Item[]>(() => {
    const acts: Item[] = [];
    for (const a of actions) {
      const score = fuzzyScore(query, a.label);
      if (score !== null) acts.push({ kind: "action", action: a, score });
    }
    acts.sort((a, b) => b.score - a.score);
    const hosts: Item[] = [];
    for (const t of threats) {
      const score = fuzzyScore(query, `${t.ip} ${t.tags.join(" ")} ${t.attack.join(" ")}`);
      if (score !== null) hosts.push({ kind: "host", threat: t, score });
    }
    hosts.sort((a, b) => b.score - a.score);
    return [...acts, ...hosts.slice(0, 8)];
  }, [query, actions, threats]);

  // Keep the highlighted index in range as the list shrinks.
  useEffect(() => {
    setActive((a) => Math.min(a, Math.max(0, items.length - 1)));
  }, [items.length]);

  if (!open) return null;

  const run = (it: Item) => {
    if (it.kind === "action") it.action.run();
    else onSelectHost(it.threat.ip);
    onClose();
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") onClose();
    else if (e.key === "Tab" && panelRef.current) {
      const focusable = panelRef.current.querySelectorAll<HTMLElement>(
        'input, button, [href], [tabindex]:not([tabindex="-1"])',
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
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, items.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const it = items[active];
      if (it) run(it);
    }
  };

  return (
    <div className="fixed inset-0 z-[60] flex items-start justify-center px-4 pt-[12vh]" role="dialog" aria-modal="true" aria-labelledby={labelId}>
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      <div
        ref={panelRef}
        className="glass-panel relative w-full max-w-lg rounded-[var(--r-card)] border border-[var(--color-border)]"
        style={{ boxShadow: "var(--sh-float)" }}
        onKeyDown={onKeyDown}
      >
        <span id={labelId} className="sr-only">Command palette</span>
        <div className="flex items-center gap-2 border-b border-[var(--color-border)] px-3">
          <Search size={16} className="shrink-0 text-[var(--color-text-faint)]" aria-hidden />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => { setQuery(e.target.value); setActive(0); }}
            placeholder="Jump to a host, or run a command…"
            aria-label="Command palette query"
            role="combobox"
            aria-expanded={items.length > 0}
            aria-controls={listId}
            aria-autocomplete="list"
            aria-activedescendant={items.length > 0 ? optionId(active) : undefined}
            className="font-mono-num w-full bg-transparent py-3 text-sm text-[var(--color-text)] outline-none placeholder:font-sans placeholder:text-[var(--color-text-faint)]"
          />
          <kbd className="t-tag shrink-0 rounded border border-[var(--color-border)] px-1.5 py-0.5 text-[var(--color-text-faint)]">ESC</kbd>
        </div>
        <ul id={listId} role="listbox" aria-label="Results" className="max-h-[50vh] overflow-y-auto p-1.5">
          {items.length === 0 && threats.length === 0 && query.trim() !== "" && (
            <li className="px-3 py-2 t-label">load a capture to search hosts</li>
          )}
          {items.length === 0 && !(threats.length === 0 && query.trim() !== "") && (
            <li className="px-3 py-6 text-center text-sm text-[var(--color-text-faint)]">No matches</li>
          )}
          {items.map((it, i) => (
            <PaletteRow
              key={it.kind === "action" ? `a:${it.action.id}` : `h:${it.threat.ip}`}
              id={optionId(i)}
              item={it}
              active={i === active}
              onMouseEnter={() => setActive(i)}
              onClick={() => run(it)}
            />
          ))}
        </ul>
      </div>
    </div>
  );
}

function PaletteRow({ id, item, active, onMouseEnter, onClick }: { id: string; item: Item; active: boolean; onMouseEnter: () => void; onClick: () => void }) {
  return (
    <li
      id={id}
      role="option"
      aria-selected={active}
      onMouseEnter={onMouseEnter}
      onClick={onClick}
      className={
        "flex w-full cursor-pointer items-center gap-2.5 rounded-[var(--r-tile)] px-2.5 py-2 text-left " +
        (active ? "bg-[var(--color-surface-2)]" : "")
      }
    >
      {item.kind === "action" ? (
          <>
            <span className="min-w-0 flex-1 truncate text-sm text-[var(--color-text)]">{item.action.label}</span>
            {item.action.hint && <span className="t-tag text-[var(--color-text-faint)]">{item.action.hint}</span>}
          </>
        ) : (
          <>
            <span aria-hidden className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: sevColor(item.threat.severity) }} />
            <span className="font-mono-num min-w-0 flex-1 truncate text-sm text-[var(--color-text)]">{item.threat.ip}</span>
            <span className="t-tag uppercase text-[var(--color-text-faint)]">{SEVERITY_META[item.threat.severity].label}</span>
            <span className="font-mono-num text-xs font-semibold" style={{ color: sevColor(item.threat.severity) }}>{item.threat.score}</span>
            <span className="font-mono-num t-tag text-[var(--color-text-faint)]">{humanNumber(item.threat.flows)} fl</span>
          </>
        )}
        {active && <CornerDownLeft size={13} className="shrink-0 text-[var(--color-text-faint)]" aria-hidden />}
    </li>
  );
}

export default CommandPalette;
