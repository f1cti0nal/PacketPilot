import { describe, it, expect, vi } from "vitest";
import { render, screen, userEvent } from "../test/render";
import { CategoryMatrix } from "./CategoryMatrix";
import { makeOutput } from "../test/fixtures";

describe("CategoryMatrix", () => {
  const breakdown = makeOutput().summary.category_breakdown;

  it("renders c2 row before web row (severity-first ordering)", () => {
    render(<CategoryMatrix breakdown={breakdown} />);
    // Both labels rendered; c2 ("C2") must appear before "Web"
    const items = screen.getAllByRole("listitem");
    const labels = items.map((li) => li.textContent ?? "");
    const c2Index = labels.findIndex((t) => t.includes("C2"));
    const webIndex = labels.findIndex((t) => t.includes("Web"));
    expect(c2Index).toBeGreaterThanOrEqual(0);
    expect(webIndex).toBeGreaterThanOrEqual(0);
    expect(c2Index).toBeLessThan(webIndex);
  });

  it("calls onJump with the category token when a row button is clicked", async () => {
    const u = userEvent.setup();
    const onJump = vi.fn();
    render(<CategoryMatrix breakdown={breakdown} onJump={onJump} />);
    // Click the c2 row button (aria-label contains "C2, critical, …")
    const c2Button = screen.getByRole("button", { name: /c2/i });
    await u.click(c2Button);
    expect(onJump).toHaveBeenCalledWith("c2");
  });

  it("renders empty state when no categorized flows", () => {
    render(<CategoryMatrix breakdown={[]} />);
    expect(screen.getByText(/No categorized traffic/i)).toBeInTheDocument();
  });
});
