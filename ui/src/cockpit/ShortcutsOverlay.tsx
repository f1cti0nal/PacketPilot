import { useId } from "react";
import { useDialogA11y } from "../lib/useDialogA11y";

// The command-palette / per-flow shortcuts are bound to Cmd on macOS, Ctrl elsewhere.
const isMac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);
const MOD = isMac ? "⌘" : "Ctrl";

interface ShortcutTab {
  id: string;
  label: string;
}

/** A modal cheat-sheet of the app's keyboard shortcuts, opened with `?`. */
export function ShortcutsOverlay({
  open,
  onClose,
  tabs,
}: {
  open: boolean;
  onClose: () => void;
  tabs: ReadonlyArray<ShortcutTab>;
}) {
  const { ref, onKeyDown } = useDialogA11y<HTMLDivElement>(onClose);
  const labelId = useId();
  if (!open) return null;

  const groups: { title: string; items: { keys: string[]; label: string }[] }[] = [
    {
      title: "Navigation",
      items: [
        ...tabs.map((t, i) => ({ keys: [String(i + 1)], label: `Go to ${t.label}` })),
        { keys: [MOD, "K"], label: "Open command palette" },
      ],
    },
    {
      title: "Menus & lists",
      items: [
        { keys: ["↑", "↓"], label: "Move selection" },
        { keys: ["Home", "End"], label: "First / last item" },
        { keys: ["Enter"], label: "Activate" },
      ],
    },
    {
      title: "General",
      items: [
        { keys: ["Esc"], label: "Close dialog or menu" },
        { keys: ["Tab"], label: "Move focus" },
        { keys: ["?"], label: "Show this help" },
      ],
    },
  ];

  return (
    <div
      ref={ref}
      onKeyDown={onKeyDown}
      role="dialog"
      aria-modal="true"
      aria-labelledby={labelId}
      className="fixed inset-0 z-[60] flex items-start justify-center px-4 pt-[12vh]"
    >
      <div className="absolute inset-0 bg-black/40" onClick={onClose} aria-hidden />
      <div
        className="glass-band relative w-full max-w-md rounded-[var(--r-card)] border border-[var(--color-border)]"
        style={{ boxShadow: "var(--sh-float)" }}
      >
        <div className="flex items-center justify-between border-b border-[var(--color-border)] px-4 py-3">
          <h2 id={labelId} className="font-display text-sm font-medium text-[var(--color-text)]">
            Keyboard shortcuts
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close keyboard shortcuts"
            className="rounded-[var(--r-tile)] px-1.5 py-0.5 text-[var(--color-text-dim)] transition-colors hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]"
          >
            <kbd className="t-tag">ESC</kbd>
          </button>
        </div>
        {/* tabIndex makes the scroll region keyboard-operable (WCAG 2.1.1 / axe
            scrollable-region-focusable) since its contents (kbd/spans) are not focusable. */}
        <div tabIndex={0} aria-label="Keyboard shortcuts list" className="max-h-[60vh] overflow-y-auto p-4">
          {groups.map((g) => (
            <section key={g.title} className="mb-4 last:mb-0">
              <h3 className="t-label mb-2">{g.title}</h3>
              <ul className="flex flex-col gap-1.5">
                {g.items.map((it) => (
                  <li key={it.label} className="flex items-center justify-between gap-3">
                    <span className="text-sm text-[var(--color-text-dim)]">{it.label}</span>
                    <span className="flex shrink-0 items-center gap-1">
                      {it.keys.map((k) => (
                        <kbd
                          key={k}
                          className="font-mono-num rounded border border-[var(--color-border)] bg-[var(--color-surface-2)] px-1.5 py-0.5 text-[11px] text-[var(--color-text)]"
                        >
                          {k}
                        </kbd>
                      ))}
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}

export default ShortcutsOverlay;
