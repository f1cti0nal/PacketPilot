import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { ProtocolMix } from "./ProtocolMix";
import { makeOutput } from "../test/fixtures";

describe("ProtocolMix", () => {
  it("renders the legend with percent values", () => {
    const proto = makeOutput().summary.proto;
    render(<ProtocolMix proto={proto} />);
    // Leaf segments (total = dns+http+tls+other_tcp = 40000):
    //   TLS       15836 / 40000 → 39.6%
    //   DNS       12162 / 40000 → 30.4%
    //   HTTP      11922 / 40000 → 29.8%
    //   other_tcp    80 / 40000 →  0.2%
    // Hardcoded so a regression in percent() is caught independently for each protocol.
    expect(screen.getByText("39.6%")).toBeInTheDocument();
    expect(screen.getByText("30.4%")).toBeInTheDocument();
    expect(screen.getByText("29.8%")).toBeInTheDocument();
    expect(screen.getByText("0.2%")).toBeInTheDocument();
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
