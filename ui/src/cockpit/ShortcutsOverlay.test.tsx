import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "../test/render";
import { ShortcutsOverlay } from "./ShortcutsOverlay";

const tabs = [
  { id: "dashboard", label: "Dashboard" },
  { id: "flows", label: "Flows" },
  { id: "recent", label: "Recent" },
];

describe("ShortcutsOverlay", () => {
  it("renders nothing when closed", () => {
    const { container } = render(<ShortcutsOverlay open={false} onClose={vi.fn()} tabs={tabs} />);
    expect(container.querySelector('[role="dialog"]')).toBeNull();
  });

  it("lists per-tab navigation plus general shortcuts when open", () => {
    render(<ShortcutsOverlay open onClose={vi.fn()} tabs={tabs} />);
    expect(screen.getByRole("dialog", { name: "Keyboard shortcuts" })).toBeInTheDocument();
    expect(screen.getByText("Go to Dashboard")).toBeInTheDocument();
    expect(screen.getByText("Go to Recent")).toBeInTheDocument();
    expect(screen.getByText("Open command palette")).toBeInTheDocument();
    expect(screen.getByText("Show this help")).toBeInTheDocument();
  });

  it("closes on Escape, the close button, and the backdrop", () => {
    const onClose = vi.fn();
    const { container } = render(<ShortcutsOverlay open onClose={onClose} tabs={tabs} />);
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: "Close keyboard shortcuts" }));
    expect(onClose).toHaveBeenCalledTimes(2);
    fireEvent.click(container.querySelector(".bg-black\\/40")!);
    expect(onClose).toHaveBeenCalledTimes(3);
  });
});
