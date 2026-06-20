import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { ProtocolMix } from "./ProtocolMix";
import { makeOutput } from "../test/fixtures";
import { percent } from "../lib/format";

describe("ProtocolMix", () => {
  it("renders the legend with percent values", () => {
    const proto = makeOutput().summary.proto;
    render(<ProtocolMix proto={proto} />);
    // The leaf total is the sum of leaf segments (same as total_packets for the fixture)
    // TLS = 15836, total leaf sum = 40000
    const tlsPct = percent(15836, 40000);
    expect(screen.getByText(tlsPct)).toBeInTheDocument();
  });

  it("renders the TLS-heavy caption when TLS dominates", () => {
    const proto = makeOutput().summary.proto;
    render(<ProtocolMix proto={proto} />);
    expect(screen.getByText(/TLS-heavy/i)).toBeInTheDocument();
  });

  it("renders TLS and HTTP legend labels", () => {
    const proto = makeOutput().summary.proto;
    render(<ProtocolMix proto={proto} />);
    expect(screen.getByText("TLS")).toBeInTheDocument();
    expect(screen.getByText("HTTP")).toBeInTheDocument();
  });

  it("renders an empty state when all proto counts are zero", () => {
    render(
      <ProtocolMix
        proto={{
          tcp: 0, udp: 0, dns: 0, http: 0, tls: 0,
          other_tcp: 0, other_udp: 0, truncated: 0, non_ipv4: 0,
        }}
      />,
    );
    expect(screen.getByText(/No protocol traffic/i)).toBeInTheDocument();
  });
});
