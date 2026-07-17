import { describe, it, expect, vi } from "vitest";
import { render, screen, userEvent } from "../test/render";
import { ThreatsView } from "./ThreatsView";
import { makeOutput } from "../test/fixtures";

const threats = makeOutput().summary.ip_threats ?? [];

describe("ThreatsView", () => {
  it("renders a card per host", () => {
    render(<ThreatsView threats={threats} activeIp={null} onSelect={vi.fn()} />);
    expect(screen.getByRole("button", { name: /^10\.13\.37\.7/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^45\.77\.13\.37/ })).toBeInTheDocument();
  });

  it("shows an empty state when there are no threats", () => {
    render(<ThreatsView threats={[]} activeIp={null} onSelect={vi.fn()} />);
    expect(screen.getByText("No threats to watch")).toBeInTheDocument();
  });

  it("clicking a host card calls onSelect", async () => {
    const u = userEvent.setup();
    const onSelect = vi.fn();
    render(<ThreatsView threats={threats} activeIp={null} onSelect={onSelect} />);
    await u.click(screen.getByRole("button", { name: /^45\.77\.13\.37/ }));
    expect(onSelect).toHaveBeenCalledWith("45.77.13.37");
  });

  it("marks the active host with aria-current", () => {
    render(<ThreatsView threats={threats} activeIp="10.13.37.7" onSelect={vi.fn()} />);
    expect(screen.getByRole("button", { name: /^10\.13\.37\.7/ })).toHaveAttribute("aria-current", "true");
  });

  it("pluralizes the flow count (1 flow, n flows)", () => {
    const one = { ...threats[0], flows: 1 };
    render(<ThreatsView threats={[one]} activeIp={null} onSelect={vi.fn()} />);
    expect(screen.getByText("1 flow")).toBeInTheDocument();
    expect(screen.queryByText("1 flows")).toBeNull();
  });

  it("filters the watchlist by host", async () => {
    const u = userEvent.setup();
    render(<ThreatsView threats={threats} activeIp={null} onSelect={vi.fn()} />);
    await u.type(screen.getByLabelText("Filter threats"), "45.77");
    expect(screen.getByRole("button", { name: /^45\.77\.13\.37/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^10\.13\.37\.7/ })).toBeNull();
  });

  it("shows an explicit 'not checked' affordance for an external host with no verdicts", () => {
    // 45.77.13.37 is public and carries no reputation in the fixture; offline (unconfigured).
    render(<ThreatsView threats={threats} activeIp={null} onSelect={vi.fn()} reputationConfigured={false} />);
    expect(screen.getByText(/reputation not checked/i)).toBeInTheDocument();
  });

  it("does not show the 'not checked' affordance for an internal host", () => {
    const internal = threats.filter((t) => t.ip_class !== "public" && t.ip_class !== "cgnat");
    render(<ThreatsView threats={internal} activeIp={null} onSelect={vi.fn()} />);
    expect(screen.queryByText(/reputation not (checked|looked up)/i)).toBeNull();
  });
});
