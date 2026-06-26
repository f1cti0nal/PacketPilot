import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { PacketDistributionsCard } from "./PacketDistributionsCard";

describe("PacketDistributionsCard", () => {
  it("renders size buckets and TTL rows with OS hints", () => {
    render(
      <PacketDistributionsCard
        sizes={[
          { label: "0–63", min: 0, max: 63, pkts: 40 },
          { label: "1024–1517", min: 1024, max: 1517, pkts: 10 },
        ]}
        ttls={[
          { ttl: 64, pkts: 30 },
          { ttl: 128, pkts: 20 },
        ]}
      />,
    );
    expect(screen.getByText("Packet size & TTL")).toBeInTheDocument();
    expect(screen.getByText("0–63")).toBeInTheDocument();
    expect(screen.getByText("1024–1517")).toBeInTheDocument();
    // TTL hints: 64 -> Linux/macOS, 128 -> Windows.
    expect(screen.getByText("Linux/macOS")).toBeInTheDocument();
    expect(screen.getByText("Windows")).toBeInTheDocument();
  });

  it("renders nothing when both distributions are empty (older summaries)", () => {
    render(<PacketDistributionsCard sizes={[]} ttls={[]} />);
    expect(screen.queryByText("Packet size & TTL")).toBeNull();
  });

  it("hides when size buckets are all zero and there are no TTL rows", () => {
    render(
      <PacketDistributionsCard
        sizes={[{ label: "0–63", min: 0, max: 63, pkts: 0 }]}
        ttls={[]}
      />,
    );
    expect(screen.queryByText("Packet size & TTL")).toBeNull();
  });
});
