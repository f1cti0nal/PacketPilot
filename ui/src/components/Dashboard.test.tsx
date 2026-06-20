import { describe, it, expect, vi } from "vitest";
import { render, screen } from "../test/render";
import { Dashboard } from "./Dashboard";
import { makeOutput } from "../test/fixtures";

describe("Dashboard", () => {
  it("smoke: renders hero host, threat watchlist, activity heatmap, and category matrix", () => {
    render(
      <Dashboard
        output={makeOutput()}
        selectedIncident={null}
        onSelectIncident={vi.fn()}
      />,
    );
    // Hero host appears at least once (may appear in hero + watchlist + talkers)
    expect(screen.getAllByText("10.13.37.7").length).toBeGreaterThan(0);
    // Threat watchlist card
    expect(screen.getByText("Threat watchlist")).toBeInTheDocument();
    // CategoryMatrix renders its card
    expect(screen.getByText(/Category threat matrix/i)).toBeInTheDocument();
  });

  it("renders incident flyout dialog when selectedIncident is set", () => {
    const incident = makeOutput().summary.incidents![0];
    render(
      <Dashboard
        output={makeOutput()}
        selectedIncident={incident}
        onSelectIncident={vi.fn()}
      />,
    );
    expect(
      screen.getByRole("dialog", {
        name: /Incident detail for 10\.13\.37\.7/i,
      }),
    ).toBeInTheDocument();
  });

  it("flyout is absent when selectedIncident is null", () => {
    render(
      <Dashboard
        output={makeOutput()}
        selectedIncident={null}
        onSelectIncident={vi.fn()}
      />,
    );
    expect(
      screen.queryByRole("dialog", { name: /Incident detail/i }),
    ).toBeNull();
  });
});
