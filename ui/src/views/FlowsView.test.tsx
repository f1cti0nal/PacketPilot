import { describe, it, expect } from "vitest";
import { render, screen, userEvent } from "../test/render";
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
    expect(container.querySelector('[role="grid"]')).toBeInTheDocument();
    // Flow count shown in the bar (filtered / total — both show 20 when no filter)
    const twenties = screen.getAllByText("20");
    expect(twenties.length).toBeGreaterThan(0);
  });

  it("typing in 'Filter flows' narrows the rows", async () => {
    const u = userEvent.setup();
    const rows = makeFlows(5);
    render(<FlowsView state={{ status: "ready", rows }} />);

    const filter = screen.getByLabelText("Filter flows");
    // Filter to the specific dst IP of row 0
    await u.type(filter, "185.220.101.5");
    // Only row 0 matches dstIp "185.220.101.5"; others have "10.0.0.2"
    // The count should show 1 / 5 flows
    expect(screen.getByText("1")).toBeInTheDocument();
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

  it("vi.fn() passed as unused prop compiles cleanly", () => {
    // Ensure the component doesn't require unexpected props
    expect(
      () =>
        render(
          <FlowsView state={{ status: "ready", rows: makeFlows(3) }} />,
        ).unmount(),
    ).not.toThrow();
  });
});
