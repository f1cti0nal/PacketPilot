import { describe, it, expect } from "vitest";
import { act } from "react";
import { render, screen, userEvent, sizeScrollElement } from "../test/render";
import { FlowsView } from "./FlowsView";
import { makeFlows } from "../test/fixtures";

describe("FlowsView", () => {
  it("renders rows: the filter bar is visible and the table grid exists", () => {
    const rows = makeFlows(20);
    const { container } = render(
      <FlowsView state={{ status: "ready", rows }} />,
    );
    // Filter bar is always present when rows exist
    expect(screen.getByLabelText("Filter flows")).toBeInTheDocument();
    // The grid element is rendered
    const grid = container.querySelector('[role="grid"]')!;
    expect(grid).toBeInTheDocument();
    // Size the scroll element so TanStack Virtual renders row cells, then
    // force a synchronous re-render so the virtualizer picks up the new dims.
    act(() => { sizeScrollElement(grid as HTMLElement); });
    // Flow count shown in the bar (filtered / total — both show 20 when no filter)
    // Both the filtered-count and the total-count slots in the bar render "20"
    const twenties = screen.getAllByText("20");
    expect(twenties.length).toBeGreaterThanOrEqual(2);
    // Default sort is bytes-desc; row 0 has bytesTotal=1_200_500 → "1.14 MB"
    expect(screen.getByText("1.14 MB")).toBeInTheDocument();
  });

  it("typing in 'Filter flows' narrows the rows", async () => {
    const u = userEvent.setup();
    const rows = makeFlows(5);
    const { container } = render(<FlowsView state={{ status: "ready", rows }} />);

    // Size the scroll element so the virtualizer renders row cells
    const grid = container.querySelector('[role="grid"]') as HTMLElement;
    act(() => { sizeScrollElement(grid); });

    const filter = screen.getByLabelText("Filter flows");
    // Filter to the specific dst IP of row 0
    await u.type(filter, "185.220.101.5");
    // Only row 0 matches dstIp "185.220.101.5"; others have "10.0.0.2"
    // The count should show 1 / 5 flows
    expect(screen.getAllByText("1").length).toBeGreaterThan(0);
  });

  it("shows loading state when status is loading", () => {
    render(<FlowsView state={{ status: "loading", rows: [] }} />);
    expect(screen.getByText(/Loading flows/i)).toBeInTheDocument();
  });

  it("shows error state when status is error", () => {
    render(
      <FlowsView
        state={{ status: "error", rows: [], error: "network failure" }}
      />,
    );
    expect(screen.getByText(/network failure/i)).toBeInTheDocument();
  });

  it("shows empty state when rows is empty", () => {
    render(<FlowsView state={{ status: "ready", rows: [] }} />);
    expect(screen.getByText(/No flows in this capture/i)).toBeInTheDocument();
  });

  it("initialFilter pre-fills the filter input with the ip", () => {
    render(
      <FlowsView
        state={{ status: "ready", rows: makeFlows(5) }}
        initialFilter={{ ip: "10.0.0.1" }}
      />,
    );
    const filter = screen.getByLabelText("Filter flows");
    expect((filter as HTMLInputElement).value).toBe("10.0.0.1");
  });

  it("mounts without throwing", () => {
    // Ensure the component doesn't require unexpected props
    expect(
      () =>
        render(
          <FlowsView state={{ status: "ready", rows: makeFlows(3) }} />,
        ).unmount(),
    ).not.toThrow();
  });

  it("clearFilters button appears and resets the text filter when clicked", async () => {
    const u = userEvent.setup();
    const rows = makeFlows(5);
    render(<FlowsView state={{ status: "ready", rows }} />);

    const filter = screen.getByLabelText("Filter flows");
    // Type something to activate filters
    await u.type(filter, "185");
    // "Clear filters" button should now appear
    const clearBtn = screen.getByRole("button", { name: /Clear filters/i });
    expect(clearBtn).toBeInTheDocument();
    // Click it — the filter should reset
    await u.click(clearBtn);
    expect((screen.getByLabelText("Filter flows") as HTMLInputElement).value).toBe("");
  });

  it("shows 'No flows match the current filters' when filter excludes everything", async () => {
    const u = userEvent.setup();
    const rows = makeFlows(5);
    render(<FlowsView state={{ status: "ready", rows }} />);
    const filter = screen.getByLabelText("Filter flows");
    await u.type(filter, "zzz-no-match-xyz");
    expect(screen.getByText(/No flows match the current filters/i)).toBeInTheDocument();
  });
});
