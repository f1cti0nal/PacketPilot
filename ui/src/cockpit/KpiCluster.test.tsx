import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { KpiCluster } from "./KpiCluster";
import { makeOutput } from "../test/fixtures";

describe("KpiCluster", () => {
  it("renders a smoke test without throwing", () => {
    expect(() => render(<KpiCluster output={makeOutput()} />)).not.toThrow();
  });

  it("shows incident count 1 and CRITICAL marker", () => {
    render(<KpiCluster output={makeOutput()} />);
    // The incidents cell shows the count "1"
    // The fixture has 1 critical incident
    expect(screen.getByText("1")).toBeInTheDocument();
    // The critical sub-label is rendered for criticalIncidents > 0
    expect(screen.getByText(/1 critical/i)).toBeInTheDocument();
  });

  it("does not show the critical marker when worst incident is high", () => {
    const base = makeOutput();
    const output = makeOutput({
      summary: {
        ...base.summary,
        incidents: [
          {
            ...base.summary.incidents![0],
            severity: "high",
          },
        ],
      },
    });
    render(<KpiCluster output={output} />);
    // "1 critical" should NOT appear because worst incident is high
    expect(screen.queryByText(/1 critical/i)).toBeNull();
  });
});
