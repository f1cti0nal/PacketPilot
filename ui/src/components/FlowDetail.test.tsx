import { describe, it, expect, vi } from "vitest";
import type { ReactNode } from "react";
import { render, screen, userEvent } from "../test/render";
import { FlowDetail } from "./FlowDetail";
import { makeFlows } from "../test/fixtures";
import type { ActiveSource } from "../types";

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

// Default no-op packet props for the tests that don't exercise the inspect button.
const noSource: ActiveSource = null;
const bytesSource: ActiveSource = { kind: "bytes", bytes: new ArrayBuffer(8) };

describe("FlowDetail", () => {
  it("renders empty state when flow is null", () => {
    render(
      <FlowDetail
        flow={null}
        onClose={vi.fn()}
        activeSource={noSource}
        onInspectPackets={vi.fn()}
        onCarvePcap={vi.fn()}
      />,
    );
    expect(screen.getByText(/No flow selected/i)).toBeInTheDocument();
  });

  it("renders the flow detail dialog with flow id in the aria-label", () => {
    render(
      <FlowDetail
        flow={flow}
        onClose={vi.fn()}
        activeSource={noSource}
        onInspectPackets={vi.fn()}
        onCarvePcap={vi.fn()}
      />,
    );
    expect(
      screen.getByRole("dialog", { name: /Flow 0 detail/i }),
    ).toBeInTheDocument();
  });

  it("shows source and destination IPs", () => {
    render(
      <FlowDetail
        flow={flow}
        onClose={vi.fn()}
        activeSource={noSource}
        onInspectPackets={vi.fn()}
        onCarvePcap={vi.fn()}
      />,
    );
    expect(screen.getByText("10.0.0.1")).toBeInTheDocument();
    expect(screen.getAllByText(/185\.220\.101\.5/)[0]).toBeInTheDocument();
  });

  it("shows protocol label", () => {
    render(
      <FlowDetail
        flow={flow}
        onClose={vi.fn()}
        activeSource={noSource}
        onInspectPackets={vi.fn()}
        onCarvePcap={vi.fn()}
      />,
    );
    // Protocol label appears in both the chip badge and the field
    const tcpElements = screen.getAllByText("TCP");
    expect(tcpElements.length).toBeGreaterThanOrEqual(1);
  });

  it("calls onClose when the close button is clicked", async () => {
    const u = userEvent.setup();
    const onClose = vi.fn();
    render(
      <FlowDetail
        flow={flow}
        onClose={onClose}
        activeSource={noSource}
        onInspectPackets={vi.fn()}
        onCarvePcap={vi.fn()}
      />,
    );
    await u.click(screen.getByRole("button", { name: /Close flow detail/i }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("renders the Endpoints section", () => {
    render(
      <FlowDetail
        flow={flow}
        onClose={vi.fn()}
        activeSource={noSource}
        onInspectPackets={vi.fn()}
        onCarvePcap={vi.fn()}
      />,
    );
    expect(screen.getByText("Endpoints")).toBeInTheDocument();
  });

  it("renders the Traffic breakdown section", () => {
    render(
      <FlowDetail
        flow={flow}
        onClose={vi.fn()}
        activeSource={noSource}
        onInspectPackets={vi.fn()}
        onCarvePcap={vi.fn()}
      />,
    );
    expect(screen.getByText("Traffic breakdown")).toBeInTheDocument();
  });

  it("renders the Timing section", () => {
    render(
      <FlowDetail
        flow={flow}
        onClose={vi.fn()}
        activeSource={noSource}
        onInspectPackets={vi.fn()}
        onCarvePcap={vi.fn()}
      />,
    );
    expect(screen.getByText("Timing")).toBeInTheDocument();
  });

  it("renders the Classification section", () => {
    render(
      <FlowDetail
        flow={flow}
        onClose={vi.fn()}
        activeSource={noSource}
        onInspectPackets={vi.fn()}
        onCarvePcap={vi.fn()}
      />,
    );
    expect(screen.getByText("Classification")).toBeInTheDocument();
  });

  it("renders IOC as No for a non-IOC flow", () => {
    render(
      <FlowDetail
        flow={{ ...flow, ioc: false }}
        onClose={vi.fn()}
        activeSource={noSource}
        onInspectPackets={vi.fn()}
        onCarvePcap={vi.fn()}
      />,
    );
    expect(screen.getByText("No")).toBeInTheDocument();
  });

  it("renders IOC as Yes for a flagged flow", () => {
    render(
      <FlowDetail
        flow={{ ...flow, ioc: true }}
        onClose={vi.fn()}
        activeSource={noSource}
        onInspectPackets={vi.fn()}
        onCarvePcap={vi.fn()}
      />,
    );
    expect(screen.getByText("Yes")).toBeInTheDocument();
  });

  it("shows the app protocol", () => {
    render(
      <FlowDetail
        flow={{ ...flow, appProto: "TLS" }}
        onClose={vi.fn()}
        activeSource={noSource}
        onInspectPackets={vi.fn()}
        onCarvePcap={vi.fn()}
      />,
    );
    // "TLS" appears in the app-protocol field
    expect(screen.getAllByText("TLS").length).toBeGreaterThanOrEqual(1);
  });

  it("renders flow identity section header", () => {
    render(
      <FlowDetail
        flow={flow}
        onClose={vi.fn()}
        activeSource={noSource}
        onInspectPackets={vi.fn()}
        onCarvePcap={vi.fn()}
      />,
    );
    expect(screen.getByText("Identity")).toBeInTheDocument();
    // The h2 reads "Flow #0" but is split: "Flow " + <span>"#" + "0"</span>
    // so we query the heading by its accessible role and pin its text content
    expect(screen.getByRole("heading", { level: 2 })).toHaveTextContent(/Flow/i);
  });

  it("disables the Inspect packets button when there is no active source", () => {
    render(
      <FlowDetail
        flow={flow}
        onClose={vi.fn()}
        activeSource={noSource}
        onInspectPackets={vi.fn()}
        onCarvePcap={vi.fn()}
      />,
    );
    const btn = screen.getByRole("button", { name: /Inspect packets/i });
    expect(btn).toBeDisabled();
    expect(btn).toHaveAttribute(
      "title",
      "Packets are only available for captures analyzed from a pcap",
    );
  });

  it("enables Inspect packets and calls onInspectPackets when a source is present", async () => {
    const u = userEvent.setup();
    const onInspectPackets = vi.fn();
    render(
      <FlowDetail
        flow={flow}
        onClose={vi.fn()}
        activeSource={bytesSource}
        onInspectPackets={onInspectPackets}
        onCarvePcap={vi.fn()}
      />,
    );
    const btn = screen.getByRole("button", { name: /Inspect packets/i });
    expect(btn).toBeEnabled();
    await u.click(btn);
    expect(onInspectPackets).toHaveBeenCalledTimes(1);
  });

  it("renders the Carve sub-pcap button", () => {
    render(
      <FlowDetail
        flow={flow}
        onClose={vi.fn()}
        activeSource={noSource}
        onInspectPackets={vi.fn()}
        onCarvePcap={vi.fn()}
      />,
    );
    expect(screen.getByRole("button", { name: /Carve sub-pcap/i })).toBeInTheDocument();
  });

  it("disables Carve sub-pcap when there is no active source", () => {
    render(
      <FlowDetail
        flow={flow}
        onClose={vi.fn()}
        activeSource={noSource}
        onInspectPackets={vi.fn()}
        onCarvePcap={vi.fn()}
      />,
    );
    const btn = screen.getByRole("button", { name: /Carve sub-pcap/i });
    expect(btn).toBeDisabled();
    expect(btn).toHaveAttribute(
      "title",
      "Packets are only available for captures analyzed from a pcap",
    );
  });

  it("enables Carve sub-pcap and calls onCarvePcap when a source is present", async () => {
    const u = userEvent.setup();
    const onCarvePcap = vi.fn();
    render(
      <FlowDetail
        flow={flow}
        onClose={vi.fn()}
        activeSource={bytesSource}
        onInspectPackets={vi.fn()}
        onCarvePcap={onCarvePcap}
      />,
    );
    const btn = screen.getByRole("button", { name: /Carve sub-pcap/i });
    expect(btn).toBeEnabled();
    await u.click(btn);
    expect(onCarvePcap).toHaveBeenCalledTimes(1);
  });
});
