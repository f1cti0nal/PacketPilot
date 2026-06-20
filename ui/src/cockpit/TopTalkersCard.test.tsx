import { describe, it, expect, vi } from "vitest";
import { render, screen, userEvent } from "../test/render";
import { TopTalkersCard } from "./TopTalkersCard";
import { makeOutput } from "../test/fixtures";

describe("TopTalkersCard", () => {
  const talkers = makeOutput().summary.top_talkers;

  it("renders rows for all talker IPs", () => {
    render(<TopTalkersCard talkers={talkers} />);
    expect(screen.getByText("10.13.37.7")).toBeInTheDocument();
    expect(screen.getByText("45.77.13.37")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.9")).toBeInTheDocument();
  });

  it("flags the known-bad host (45.77.13.37) with a critical marker dot", () => {
    render(<TopTalkersCard talkers={talkers} />);
    // The flagged dot is an aria-hidden span with class rounded-full, rendered only
    // when flaggedSet.has(t.ip). The bar span shares aria-hidden but not rounded-full.
    const ip = screen.getByText("45.77.13.37");
    const li = ip.closest("li")!;
    expect(li.querySelector("[aria-hidden].rounded-full")).not.toBeNull();
  });

  it("omits the critical marker dot when host is not flagged", () => {
    // Render with no flagged IPs — the dot span should not appear for any host
    render(<TopTalkersCard talkers={talkers} flagged={[]} />);
    const ip = screen.getByText("45.77.13.37");
    const li = ip.closest("li")!;
    expect(li.querySelector("[aria-hidden].rounded-full")).toBeNull();
  });

  it("calls onSelect with the IP when a row button is clicked", async () => {
    const u = userEvent.setup();
    const onSelect = vi.fn();
    render(<TopTalkersCard talkers={talkers} onSelect={onSelect} />);
    const btn = screen.getByRole("button", { name: /10\.13\.37\.7/ });
    await u.click(btn);
    expect(onSelect).toHaveBeenCalledWith("10.13.37.7");
  });

  it("renders empty state when no talkers", () => {
    render(<TopTalkersCard talkers={[]} />);
    expect(screen.getByText(/No host activity/i)).toBeInTheDocument();
  });
});
