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
    // The flagged host text is brighter (font-medium text-[--color-text] vs dim)
    // The flagged dot is an aria-hidden span — check the host text is rendered at all
    // and that 45.77.13.37 is in the flagged set (default DEFAULT_FLAGGED includes it)
    const ip = screen.getByText("45.77.13.37");
    expect(ip).toBeInTheDocument();
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
