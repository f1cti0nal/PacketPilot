import { describe, it, expect, vi } from "vitest";
import { useRef } from "react";
import { render, screen, fireEvent, act } from "../test/render";
import { useMenuKeyboard } from "./useMenuKeyboard";

function Menu({ onClose }: { onClose: () => void }) {
  const menuRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const onKeyDown = useMenuKeyboard(menuRef, true, onClose, triggerRef);
  return (
    <div>
      <button ref={triggerRef}>trigger</button>
      <div role="menu" ref={menuRef} onKeyDown={onKeyDown} aria-label="t">
        <button role="menuitem" tabIndex={-1}>one</button>
        <button role="menuitem" tabIndex={-1}>two</button>
        <button role="menuitem" tabIndex={-1}>three</button>
      </div>
    </div>
  );
}

const menu = () => screen.getByRole("menu");
const item = (name: string) => screen.getByRole("menuitem", { name });

describe("useMenuKeyboard", () => {
  it("focuses the first item when the menu opens", () => {
    vi.useFakeTimers();
    try {
      render(<Menu onClose={vi.fn()} />);
      act(() => vi.runAllTimers());
      expect(document.activeElement).toBe(item("one"));
    } finally {
      vi.useRealTimers();
    }
  });

  it("ArrowDown advances and wraps; ArrowUp wraps backwards", () => {
    render(<Menu onClose={vi.fn()} />);
    item("one").focus();
    fireEvent.keyDown(menu(), { key: "ArrowDown" });
    expect(document.activeElement).toBe(item("two"));
    item("three").focus();
    fireEvent.keyDown(menu(), { key: "ArrowDown" });
    expect(document.activeElement).toBe(item("one"));
    fireEvent.keyDown(menu(), { key: "ArrowUp" });
    expect(document.activeElement).toBe(item("three"));
  });

  it("Home/End jump to the first/last item", () => {
    render(<Menu onClose={vi.fn()} />);
    item("two").focus();
    fireEvent.keyDown(menu(), { key: "End" });
    expect(document.activeElement).toBe(item("three"));
    fireEvent.keyDown(menu(), { key: "Home" });
    expect(document.activeElement).toBe(item("one"));
  });

  it("Escape closes and restores focus to the trigger", () => {
    const onClose = vi.fn();
    render(<Menu onClose={onClose} />);
    item("one").focus();
    fireEvent.keyDown(menu(), { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "trigger" }));
  });

  it("Tab closes the menu", () => {
    const onClose = vi.fn();
    render(<Menu onClose={onClose} />);
    fireEvent.keyDown(menu(), { key: "Tab" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
