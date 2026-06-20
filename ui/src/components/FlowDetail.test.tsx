import { describe, it, expect, vi } from "vitest";
import type { ReactNode } from "react";
import { render, screen, userEvent } from "../test/render";
import { FlowDetail } from "./FlowDetail";
import { makeFlows } from "../test/fixtures";

// Recharts ResponsiveContainer relies on ResizeObserver.contentRect which jsdom
// does not populate. Stub it out so the chart section renders without crashing.
vi.mock("recharts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("recharts")>();
  return {
    ...actual,
    ResponsiveContainer: ({ children }: { children: ReactNode }) => (
      <div data-testid="recharts-stub">{children}</div>
    ),
  };
});

const flow = makeFlows(1)[0];

describe("FlowDetail", () => {
  it("renders empty state when flow is null", () => {
    render(<FlowDetail flow={null} onClose={vi.fn()} />);
    expect(screen.getByText(/No flow selected/i)).toBeInTheDocument();
  });

  it("renders the flow detail dialog with flow id in the aria-label", () => {
    render(<FlowDetail flow={flow} onClose={vi.fn()} />);
    expect(
      screen.getByRole("dialog", { name: /Flow 0 detail/i }),
    ).toBeInTheDocument();
  });

  it("shows source and destination IPs", () => {
    render(<FlowDetail flow={flow} onClose={vi.fn()} />);
    expect(screen.getByText("10.0.0.1")).toBeInTheDocument();
    expect(screen.getAllByText(/185\.220\.101\.5/)[0]).toBeInTheDocument();
  });

  it("shows protocol label", () => {
    render(<FlowDetail flow={flow} onClose={vi.fn()} />);
    // Protocol label appears in both the chip badge and the field
    const tcpElements = screen.getAllByText("TCP");
    expect(tcpElements.length).toBeGreaterThanOrEqual(1);
  });

  it("calls onClose when the close button is clicked", async () => {
    const u = userEvent.setup();
    const onClose = vi.fn();
    render(<FlowDetail flow={flow} onClose={onClose} />);
    await u.click(screen.getByRole("button", { name: /Close flow detail/i }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("renders the Endpoints section", () => {
    render(<FlowDetail flow={flow} onClose={vi.fn()} />);
    expect(screen.getByText("Endpoints")).toBeInTheDocument();
  });

  it("renders the Traffic breakdown section", () => {
    render(<FlowDetail flow={flow} onClose={vi.fn()} />);
    expect(screen.getByText("Traffic breakdown")).toBeInTheDocument();
  });

  it("renders the Timing section", () => {
    render(<FlowDetail flow={flow} onClose={vi.fn()} />);
    expect(screen.getByText("Timing")).toBeInTheDocument();
  });

  it("renders the Classification section", () => {
    render(<FlowDetail flow={flow} onClose={vi.fn()} />);
    expect(screen.getByText("Classification")).toBeInTheDocument();
  });

  it("renders IOC as No for a non-IOC flow", () => {
    render(<FlowDetail flow={{ ...flow, ioc: false }} onClose={vi.fn()} />);
    expect(screen.getByText("No")).toBeInTheDocument();
  });

  it("renders IOC as Yes for a flagged flow", () => {
    render(<FlowDetail flow={{ ...flow, ioc: true }} onClose={vi.fn()} />);
    expect(screen.getByText("Yes")).toBeInTheDocument();
  });

  it("shows the app protocol", () => {
    render(<FlowDetail flow={{ ...flow, appProto: "TLS" }} onClose={vi.fn()} />);
    // "TLS" appears in the app-protocol field
    expect(screen.getAllByText("TLS").length).toBeGreaterThanOrEqual(1);
  });

  it("renders flow identity section header", () => {
    render(<FlowDetail flow={flow} onClose={vi.fn()} />);
    expect(screen.getByText("Identity")).toBeInTheDocument();
    // The h2 reads "Flow #0" but is split: "Flow " + <span>"#" + "0"</span>
    // so we query the heading by its accessible role and pin its text content
    expect(screen.getByRole("heading", { level: 2 })).toHaveTextContent(/Flow/i);
  });
});
