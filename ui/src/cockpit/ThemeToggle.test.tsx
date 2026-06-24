import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, fireEvent, act } from "../test/render";
import { ThemeToggle } from "./ThemeToggle";
import { setTheme } from "../lib/theme";

beforeEach(() => {
  localStorage.clear();
  delete document.documentElement.dataset.theme;
  document.documentElement.classList.remove("dark");
});

describe("ThemeToggle", () => {
  it("starts dark and toggles to light on click", () => {
    render(<ThemeToggle />);
    const btn = screen.getByRole("button", { name: "Switch to light theme" });
    expect(btn).toHaveAttribute("aria-pressed", "false");
    expect(document.documentElement.dataset.theme).toBe("dark");

    fireEvent.click(btn);

    expect(screen.getByRole("button", { name: "Switch to dark theme" })).toHaveAttribute("aria-pressed", "true");
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(localStorage.getItem("packetpilot.theme.v1")).toBe("light");
  });

  it("toggles back to dark on a second click", () => {
    render(<ThemeToggle />);
    fireEvent.click(screen.getByRole("button", { name: "Switch to light theme" }));
    fireEvent.click(screen.getByRole("button", { name: "Switch to dark theme" }));
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(localStorage.getItem("packetpilot.theme.v1")).toBe("dark");
  });

  it("reflects a theme change made elsewhere (event-synced)", () => {
    render(<ThemeToggle />);
    expect(screen.getByRole("button", { name: "Switch to light theme" })).toBeInTheDocument();

    act(() => setTheme("light"));

    expect(screen.getByRole("button", { name: "Switch to dark theme" })).toBeInTheDocument();
  });
});
