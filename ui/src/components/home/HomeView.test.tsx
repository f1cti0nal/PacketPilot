import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { HomeView } from "./HomeView";
import { makeOutput } from "../../test/fixtures";
import type { AnalysisOutput, RecentEntry } from "../../types";

function entry(id: string, name: string, summary: AnalysisOutput, analyzedAt = 1000): RecentEntry {
  return {
    id,
    name,
    sizeBytes: 1000,
    analyzedAt,
    engineVersion: "0.1.0",
    origin: "wasm",
    flowCount: 100,
    flowsCached: false,
    summary,
  };
}

const cleanOutput: AnalysisOutput = (() => {
  const base = makeOutput();
  return { ...base, summary: { ...base.summary, findings: [], incidents: [] } };
})();

describe("HomeView — first run (no recent captures)", () => {
  it("shows the upload-first hero instead of any dashboard data", () => {
    render(<HomeView recent={[]} onOpen={vi.fn()} onLoadNew={vi.fn()} />);
    expect(screen.getByText("Analyze your first capture")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /upload capture/i })).toBeInTheDocument();
  });

  it("offers the opt-in sample only when it is available", () => {
    const onLoadSample = vi.fn();
    const { rerender } = render(
      <HomeView recent={[]} onOpen={vi.fn()} onLoadNew={vi.fn()} onLoadSample={onLoadSample} sampleAvailable />,
    );
    const sample = screen.getByRole("button", { name: /explore sample capture/i });
    fireEvent.click(sample);
    expect(onLoadSample).toHaveBeenCalledTimes(1);

    rerender(
      <HomeView recent={[]} onOpen={vi.fn()} onLoadNew={vi.fn()} onLoadSample={onLoadSample} sampleAvailable={false} />,
    );
    expect(screen.queryByRole("button", { name: /explore sample capture/i })).toBeNull();
  });

  it("routes the upload CTA to onLoadNew", () => {
    const onLoadNew = vi.fn();
    render(<HomeView recent={[]} onOpen={vi.fn()} onLoadNew={onLoadNew} />);
    fireEvent.click(screen.getByRole("button", { name: /upload capture/i }));
    expect(onLoadNew).toHaveBeenCalledTimes(1);
  });
});

describe("HomeView — returning user (workspace overview)", () => {
  const recent = [
    entry("a", "alpha.pcap", makeOutput(), 2000), // critical incident in fixture
    entry("b", "beta.pcap", cleanOutput, 1000),
  ];

  it("renders the overview, not the first-run hero", () => {
    render(<HomeView recent={recent} onOpen={vi.fn()} onLoadNew={vi.fn()} />);
    expect(screen.getByText("Welcome back")).toBeInTheDocument();
    expect(screen.queryByText("Analyze your first capture")).toBeNull();
  });

  it("lists recent captures with a per-capture verdict chip", () => {
    render(<HomeView recent={recent} onOpen={vi.fn()} onLoadNew={vi.fn()} />);
    expect(screen.getByText("alpha.pcap")).toBeInTheDocument();
    expect(screen.getByText("beta.pcap")).toBeInTheDocument();
    expect(screen.getByText("1 Critical")).toBeInTheDocument(); // alpha's worst severity + count
    expect(screen.getByText("Clean")).toBeInTheDocument(); // beta has no findings
  });

  it("shows the workspace rollup KPI tiles", () => {
    render(<HomeView recent={recent} onOpen={vi.fn()} onLoadNew={vi.fn()} />);
    expect(screen.getByText("Captures")).toBeInTheDocument();
    expect(screen.getByText("Total flows")).toBeInTheDocument();
    expect(screen.getByText("Total bytes")).toBeInTheDocument();
    expect(screen.getByText("Distinct hosts")).toBeInTheDocument();
    expect(screen.getByText("Findings")).toBeInTheDocument();
    expect(screen.getByText("Critical / high")).toBeInTheDocument();
  });

  it("opens a capture when its row is activated", () => {
    const onOpen = vi.fn();
    render(<HomeView recent={recent} onOpen={onOpen} onLoadNew={vi.fn()} />);
    fireEvent.click(screen.getAllByRole("button", { name: "Open" })[0]);
    expect(onOpen).toHaveBeenCalledWith(recent[0]);
  });

  it("hides 'View all' when every capture already fits in the overview", () => {
    render(<HomeView recent={recent} onOpen={vi.fn()} onLoadNew={vi.fn()} onViewAll={vi.fn()} />);
    expect(screen.queryByRole("button", { name: /view all/i })).toBeNull();
  });

  it("shows 'View all' and routes to Recent when captures exceed the shown rows", () => {
    const onViewAll = vi.fn();
    const many = Array.from({ length: 7 }, (_, i) => entry(`id${i}`, `cap${i}.pcap`, cleanOutput, 1000 + i));
    render(<HomeView recent={many} onOpen={vi.fn()} onLoadNew={vi.fn()} onViewAll={onViewAll} />);
    const link = screen.getByRole("button", { name: /view all 7/i });
    fireEvent.click(link);
    expect(onViewAll).toHaveBeenCalledTimes(1);
  });

  it("offers Compare only when at least two captures and a handler exist", () => {
    const onCompare = vi.fn();
    const { rerender } = render(
      <HomeView recent={recent} onOpen={vi.fn()} onLoadNew={vi.fn()} onCompare={onCompare} />,
    );
    fireEvent.click(screen.getByRole("button", { name: /compare/i }));
    expect(onCompare).toHaveBeenCalledWith("b", "a"); // older id first

    rerender(<HomeView recent={[recent[0]]} onOpen={vi.fn()} onLoadNew={vi.fn()} onCompare={onCompare} />);
    expect(screen.queryByRole("button", { name: /compare/i })).toBeNull();
  });
});
