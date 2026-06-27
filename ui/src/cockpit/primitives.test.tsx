import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { Panel, StatTile, ProvenanceChip, Toolbar, SectionHeader } from "./primitives";

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

describe("StatTile + chips", () => {
  it("renders a KPI tile with label and value", () => {
    render(<StatTile label="Flows" value="99,993" />);
    expect(screen.getByText("Flows")).toBeInTheDocument();
    expect(screen.getByText("99,993")).toBeInTheDocument();
  });
  it("renders a cloud provenance chip with the provider", () => {
    render(<ProvenanceChip provider="AWS" />);
    expect(screen.getByText(/AWS/)).toBeInTheDocument();
  });
});

describe("Toolbar + SectionHeader", () => {
  it("renders a section header with title and count", () => {
    render(<SectionHeader title="Flows" count="1,024" />);
    expect(screen.getByText("Flows")).toBeInTheDocument();
    expect(screen.getByText("1,024")).toBeInTheDocument();
  });
  it("renders toolbar children", () => {
    render(<Toolbar><button>Filter</button></Toolbar>);
    expect(screen.getByRole("button", { name: "Filter" })).toBeInTheDocument();
  });
});
