import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, fireEvent, act } from "../test/render";
import { DensityToggle } from "./DensityToggle";
import { setDensity } from "../lib/density";

beforeEach(() => {
  localStorage.clear();
  delete document.documentElement.dataset.density;
});

describe("DensityToggle", () => {
  it("starts comfortable and toggles to compact on click", () => {
    render(<DensityToggle />);
    const btn = screen.getByRole("button", { name: "Switch to compact density" });
    expect(btn).toHaveAttribute("aria-pressed", "false");
    expect(document.documentElement.dataset.density).toBe("comfortable");

    fireEvent.click(btn);

    expect(screen.getByRole("button", { name: "Switch to comfortable density" })).toHaveAttribute("aria-pressed", "true");
    expect(document.documentElement.dataset.density).toBe("compact");
    expect(localStorage.getItem("packetpilot.density.v1")).toBe("compact");
  });

  it("toggles back to comfortable on a second click", () => {
    render(<DensityToggle />);
    fireEvent.click(screen.getByRole("button", { name: "Switch to compact density" }));
    fireEvent.click(screen.getByRole("button", { name: "Switch to comfortable density" }));
    expect(document.documentElement.dataset.density).toBe("comfortable");
    expect(localStorage.getItem("packetpilot.density.v1")).toBe("comfortable");
  });

  it("reflects a density change made elsewhere (event-synced)", () => {
    render(<DensityToggle />);
    expect(screen.getByRole("button", { name: "Switch to compact density" })).toBeInTheDocument();

    act(() => setDensity("compact"));

    expect(screen.getByRole("button", { name: "Switch to comfortable density" })).toBeInTheDocument();
  });
});
