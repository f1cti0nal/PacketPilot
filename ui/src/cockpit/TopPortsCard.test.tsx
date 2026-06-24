import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { TopPortsCard } from "./TopPortsCard";
import type { PortHistogramEntry } from "../types";

const ports: PortHistogramEntry[] = [
  { port: 53, transport: "UDP", pkts: 300, bytes: 40000 },
  { port: 443, transport: "TCP", pkts: 1000, bytes: 900000 },
  { port: 4444, transport: "TCP", pkts: 120, bytes: 60000 },
];

describe("TopPortsCard", () => {
  it("renders the busiest ports with service names and flags non-standard ports", () => {
    render(<TopPortsCard ports={ports} />);
    expect(screen.getByText("Top ports")).toBeInTheDocument();
    expect(screen.getByText("443")).toBeInTheDocument();
    expect(screen.getByText("HTTPS")).toBeInTheDocument();
    expect(screen.getByText("DNS")).toBeInTheDocument();
    // a non-standard port is flagged rather than left blank.
    expect(screen.getByText("4444")).toBeInTheDocument();
    expect(screen.getByText("non-standard")).toBeInTheDocument();
  });

  it("renders nothing when no ports were seen", () => {
    render(<TopPortsCard ports={[]} />);
    expect(screen.queryByText("Top ports")).toBeNull();
  });
});
