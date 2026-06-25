import { useEffect, useRef, type KeyboardEvent as ReactKeyboardEvent, type RefObject } from "react";

export const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Shared modal-dialog a11y wiring for the cockpit's overlays. On mount it moves focus into the
 * dialog and restores it to the opener on unmount; the returned `onKeyDown` closes on Escape and
 * traps Tab within the dialog. Spread `ref` + `onKeyDown` on the `role="dialog"` root and add
 * `aria-modal="true"`. The cockpit's overlays mount only while open, so this gives them open/close
 * focus behaviour without an `open` prop. Mirrors the hand-rolled CommandPalette implementation.
 */
export function useDialogA11y<T extends HTMLElement = HTMLDivElement>(
  onClose: () => void,
): { ref: RefObject<T>; onKeyDown: (e: ReactKeyboardEvent) => void } {
  const ref = useRef<T>(null);

  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    const focusables = ref.current?.querySelectorAll<HTMLElement>(FOCUSABLE);
    const first = focusables && focusables.length > 0 ? focusables[0] : ref.current;
    const id = window.setTimeout(() => first?.focus?.(), 0);
    return () => {
      window.clearTimeout(id);
      opener?.focus?.();
    };
  }, []);

  const onKeyDown = (e: ReactKeyboardEvent) => {
    if (e.key === "Escape") {
      e.stopPropagation();
      onClose();
      return;
    }
    if (e.key === "Tab" && ref.current) {
      const f = ref.current.querySelectorAll<HTMLElement>(FOCUSABLE);
      if (f.length > 0) {
        const first = f[0];
        const last = f[f.length - 1];
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

  return { ref, onKeyDown };
}
