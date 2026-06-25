import { useEffect, type KeyboardEvent as ReactKeyboardEvent, type RefObject } from "react";

const MENUITEM = '[role="menuitem"]:not([disabled])';

/**
 * WAI-ARIA keyboard support for the cockpit's `role="menu"` dropdowns (ExportMenu,
 * RuleSetsMenu). On open it moves focus to the first item; the returned `onKeyDown`
 * (spread on the menu container) gives Arrow Up/Down (wrapping), Home/End, Escape
 * (close + restore focus to the trigger), and Tab (close). Items use roving focus —
 * mark each `tabIndex={-1}` so only the focused item is in the tab order.
 */
export function useMenuKeyboard(
  menuRef: RefObject<HTMLElement>,
  open: boolean,
  onClose: () => void,
  triggerRef?: RefObject<HTMLElement>,
): (e: ReactKeyboardEvent) => void {
  useEffect(() => {
    if (!open) return;
    const id = window.setTimeout(() => {
      menuRef.current?.querySelector<HTMLElement>(MENUITEM)?.focus();
    }, 0);
    return () => window.clearTimeout(id);
  }, [open, menuRef]);

  return (e: ReactKeyboardEvent) => {
    const menu = menuRef.current;
    if (!menu) return;

    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      onClose();
      triggerRef?.current?.focus();
      return;
    }
    if (e.key === "Tab") {
      // Standard menu behaviour: Tab dismisses the menu and lets focus move on.
      onClose();
      return;
    }

    const items = Array.from(menu.querySelectorAll<HTMLElement>(MENUITEM));
    if (items.length === 0) return;
    const i = items.indexOf(document.activeElement as HTMLElement);

    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        items[i < 0 ? 0 : (i + 1) % items.length].focus();
        break;
      case "ArrowUp":
        e.preventDefault();
        items[i <= 0 ? items.length - 1 : i - 1].focus();
        break;
      case "Home":
        e.preventDefault();
        items[0].focus();
        break;
      case "End":
        e.preventDefault();
        items[items.length - 1].focus();
        break;
    }
  };
}
