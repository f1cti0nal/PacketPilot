import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, act } from "../test/render";
import { useDialogA11y } from "./useDialogA11y";

function Dialog({ onClose }: { onClose: () => void }) {
  const { ref, onKeyDown } = useDialogA11y<HTMLDivElement>(onClose);
  return (
    <div role="dialog" ref={ref} onKeyDown={onKeyDown} aria-label="test">
      <button>first</button>
      <button>last</button>
    </div>
  );
}

describe("useDialogA11y", () => {
  it("closes on Escape", () => {
    const onClose = vi.fn();
    render(<Dialog onClose={onClose} />);
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("traps Tab from the last element back to the first", () => {
    render(<Dialog onClose={vi.fn()} />);
    const first = screen.getByRole("button", { name: "first" });
    screen.getByRole("button", { name: "last" }).focus();
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Tab" });
    expect(document.activeElement).toBe(first);
  });

  it("traps Shift+Tab from the first element back to the last", () => {
    render(<Dialog onClose={vi.fn()} />);
    const last = screen.getByRole("button", { name: "last" });
    screen.getByRole("button", { name: "first" }).focus();
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(last);
  });

  it("moves focus into the dialog on mount and restores it to the opener on unmount", () => {
    vi.useFakeTimers();
    try {
      const opener = document.createElement("button");
      document.body.appendChild(opener);
      opener.focus();

      const { unmount } = render(<Dialog onClose={vi.fn()} />);
      act(() => vi.runAllTimers());
      expect(document.activeElement).toBe(screen.getByRole("button", { name: "first" }));

      unmount();
      expect(document.activeElement).toBe(opener);
      opener.remove();
    } finally {
      vi.useRealTimers();
    }
  });
});
