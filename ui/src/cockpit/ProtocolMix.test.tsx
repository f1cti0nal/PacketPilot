import { describe, it, expect, vi } from "vitest";
import { render, screen, userEvent } from "../test/render";
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

  it("renders a neutral TLS-heavy caption when TLS dominates (no beacon claim by default)", () => {
    const proto = makeOutput().summary.proto;
    render(<ProtocolMix proto={proto} />);
    expect(screen.getByText("TLS-heavy traffic mix")).toBeInTheDocument();
    expect(screen.queryByText(/C2 beacon/i)).toBeNull();
  });

  it("mentions the C2 beacon profile only when a beacon incident is confirmed", () => {
    const proto = makeOutput().summary.proto;
    render(<ProtocolMix proto={proto} beaconIncident />);
    expect(
      screen.getByText("TLS-heavy, consistent with the C2 beacon profile"),
    ).toBeInTheDocument();
  });

  it("renders TLS and HTTP legend labels", () => {
    const proto = makeOutput().summary.proto;
    render(<ProtocolMix proto={proto} />);
    expect(screen.getByText("TLS")).toBeInTheDocument();
    expect(screen.getByText("HTTP")).toBeInTheDocument();
  });

  it("calls onSelect with the protocol key for a filterable legend item", async () => {
    const onSelect = vi.fn();
    render(<ProtocolMix proto={makeOutput().summary.proto} onSelect={onSelect} />);
    await userEvent.setup().click(screen.getByRole("button", { name: /TLS/ }));
    expect(onSelect).toHaveBeenCalledWith("tls");
  });

  it("leaves non-filterable segments static (Other TCP is not a button)", () => {
    render(<ProtocolMix proto={makeOutput().summary.proto} onSelect={vi.fn()} />);
    expect(screen.queryByRole("button", { name: /Other TCP/ })).toBeNull();
  });

  it("renders an empty state when all proto counts are zero", () => {
    render(
      <ProtocolMix
        proto={{
          tcp: 0, udp: 0, dns: 0, http: 0, tls: 0, quic: 0,
          other_tcp: 0, other_udp: 0, truncated: 0, non_ipv4: 0,
        }}
      />,
    );
    expect(screen.getByText(/No protocol traffic/i)).toBeInTheDocument();
  });
});
