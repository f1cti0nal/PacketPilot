import { describe, it, expect, vi } from "vitest";
import { fireEvent, render, screen } from "../test/render";
import { NoiseBudgetMeter, savedPhrase } from "./NoiseBudgetMeter";
import type { NoiseBudget } from "../types";

const budget: NoiseBudget = {
  packets: 4_200_000,
  flows: 61_000,
  findings: 40,
  suppressed: 3,
  stories: 9,
  urgent: 2,
  manual_minutes: 705,
  queue_minutes: 135,
  saved_minutes: 570,
  rates: { version: 1, minutes_per_1k_flows: 5, minutes_per_finding: 10, minutes_per_story: 15 },
};

describe("NoiseBudgetMeter", () => {
  it("shows the funnel and the estimate, with the formula on demand", () => {
    render(<NoiseBudgetMeter budget={budget} />);
    expect(screen.getByText("4.2M")).toBeInTheDocument();
    expect(screen.getByText("61K")).toBeInTheDocument();
    expect(screen.getByText("stories")).toBeInTheDocument();
    expect(screen.getByText("about 9.5 h saved")).toBeInTheDocument();
    expect(screen.queryByText(/Without the queue/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /How is this estimated/ }));
    expect(screen.getByText(/Without the queue: 705 min/)).toBeInTheDocument();
    expect(screen.getByText(/3 of the findings were suppressed/)).toBeInTheDocument();
  });

  it("makes flows and stories clickable when handlers are given", () => {
    const onFlows = vi.fn();
    const onStories = vi.fn();
    render(<NoiseBudgetMeter budget={budget} onFlows={onFlows} onStories={onStories} />);
    fireEvent.click(screen.getByRole("button", { name: /flows/ }));
    fireEvent.click(screen.getByRole("button", { name: /stories/ }));
    expect(onFlows).toHaveBeenCalledOnce();
    expect(onStories).toHaveBeenCalledOnce();
  });

  it("phrases the saving like the engine", () => {
    expect(savedPhrase(0.4)).toBe("no review time saved");
    expect(savedPhrase(25.2)).toBe("about 25 min saved");
    expect(savedPhrase(100)).toBe("about 1.5 h saved");
    expect(savedPhrase(900)).toBe("about 15 h saved");
  });
});
