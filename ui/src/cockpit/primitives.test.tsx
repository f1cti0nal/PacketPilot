import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { Panel } from "./primitives";

describe("Panel", () => {
  it("renders a titled console panel with a count and severity accent", () => {
    const { container } = render(
      <Panel title="Threat watchlist" count={50} accent="critical">
        <div>rows</div>
      </Panel>,
    );
    expect(screen.getByText("Threat watchlist")).toBeInTheDocument();
    expect(screen.getByText("50")).toBeInTheDocument();
    expect(screen.getByText("rows")).toBeInTheDocument();
    // severity accent applies the critical token as a left border color
    expect(container.querySelector("section")?.getAttribute("style") || "").toMatch(/--color-sev-critical|border-left/);
  });
});
