import { describe, it, expect, vi } from "vitest";
import { render, screen, userEvent } from "../test/render";
import { ThreatRail } from "./ThreatRail";
import { makeOutput } from "../test/fixtures";

describe("ThreatRail", () => {
  it("worst-first order + row click", async () => {
    const u = userEvent.setup(); const onSelect = vi.fn();
    render(<ThreatRail threats={makeOutput().summary.ip_threats!} collapsed={false} activeIp={null} onSelect={onSelect} />);
    const labels = screen.getAllByRole("button").map((b) => b.getAttribute("aria-label") || "");
    expect(labels[0]).toContain("10.13.37.7"); // critical first
    await u.click(screen.getByRole("button", { name: /^10\.13\.37\.7/ }));
    expect(onSelect).toHaveBeenCalledWith("10.13.37.7");
  });

  it("collapsed mode hides IP text but keeps row buttons", () => {
    render(<ThreatRail threats={makeOutput().summary.ip_threats!} collapsed={true} activeIp={null} onSelect={vi.fn()} />);
    // Buttons still exist (one per threat)
    const buttons = screen.getAllByRole("button");
    expect(buttons).toHaveLength(2);
    // IP text should not be visible as text content (collapsed shows dots only)
    expect(screen.queryByText("10.13.37.7")).toBeNull();
    expect(screen.queryByText("45.77.13.37")).toBeNull();
  });

  it("activeIp sets aria-current on the matching row", () => {
    render(<ThreatRail threats={makeOutput().summary.ip_threats!} collapsed={false} activeIp="10.13.37.7" onSelect={vi.fn()} />);
    const activeBtn = screen.getByRole("button", { name: /^10\.13\.37\.7/ });
    expect(activeBtn).toHaveAttribute("aria-current", "true");
    // The other button should not have aria-current
    const otherBtn = screen.getByRole("button", { name: /^45\.77\.13\.37/ });
    expect(otherBtn).not.toHaveAttribute("aria-current");
  });
});
