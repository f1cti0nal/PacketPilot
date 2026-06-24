import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { ProtocolSunburst } from "./ProtocolSunburst";
import type { ProtocolHierarchyNode } from "../types";

const hier: ProtocolHierarchyNode[] = [
  { path: "ip.tcp.https", bytes: 800, pkts: 8 },
  { path: "ip.udp.dns", bytes: 200, pkts: 4 },
];

describe("ProtocolSunburst", () => {
  it("renders a labelled sunburst with one arc per node and an L4 legend", () => {
    const { container } = render(<ProtocolSunburst hierarchy={hier} />);
    expect(screen.getByLabelText("Protocol hierarchy")).toBeInTheDocument();
    // one arc per (tcp, udp, https, dns) — scope to the sunburst svg (the header icon has paths too).
    const svg = container.querySelector('svg[aria-label="Protocol hierarchy sunburst"]')!;
    expect(svg.querySelectorAll("path").length).toBe(4);
    // the L7 segments are labelled (unique text); tcp/udp also appear in the legend.
    expect(screen.getByText("https")).toBeInTheDocument();
    expect(screen.getByText("dns")).toBeInTheDocument();
    expect(screen.getAllByText("tcp").length).toBeGreaterThanOrEqual(1);
  });

  it("renders nothing when the capture has no protocol breakdown", () => {
    const { container } = render(<ProtocolSunburst hierarchy={[]} />);
    expect(container.querySelector('[data-component="ProtocolSunburst"]')).toBeNull();
  });
});
