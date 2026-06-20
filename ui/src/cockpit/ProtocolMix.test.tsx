import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { ProtocolMix } from "./ProtocolMix";
import { makeOutput } from "../test/fixtures";

describe("ProtocolMix", () => {
  it("renders the legend with percent values", () => {
    const proto = makeOutput().summary.proto;
    render(<ProtocolMix proto={proto} />);
    // TLS = 15836 out of 40000 total leaf packets → 39.6%
    // Hardcoded so a regression in percent() is caught independently
    expect(screen.getByText("39.6%")).toBeInTheDocument();
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
