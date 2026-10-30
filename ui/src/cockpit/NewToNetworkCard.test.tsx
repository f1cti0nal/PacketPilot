import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { NewToNetworkCard } from "./NewToNetworkCard";

describe("NewToNetworkCard", () => {
  it("lists new indicators and the single-host list", () => {
    render(
      <NewToNetworkCard
        rarity={{
          baseline_loaded: true,
          history_captures: 12,
          new_total: 2,
          new: [
            { kind: "user_agent", value: "EvilAgent/1.0", hosts: ["10.0.0.9"], count: 1 },
            {
              kind: "cert",
              value: "ab".repeat(32),
              label: "c2.badsite.net",
              hosts: ["10.0.0.9"],
              count: 1,
            },
          ],
          single_host_total: 1,
          single_host: [
            {
              kind: "domain",
              value: "badsite.net",
              label: "cdn.badsite.net",
              hosts: ["10.0.0.9"],
              count: 3,
            },
          ],
        }}
      />,
    );
    expect(screen.getByText("New to this network")).toBeInTheDocument();
    expect(screen.getByText("2 new · vs 12 captures")).toBeInTheDocument();
    expect(screen.getByText("EvilAgent/1.0")).toBeInTheDocument();
    // A certificate shows its CN, with the hash underneath.
    expect(screen.getByText("c2.badsite.net")).toBeInTheDocument();
    expect(screen.getByText(/^sha256 abab/)).toBeInTheDocument();
    expect(screen.getByText("Only one host")).toBeInTheDocument();
    expect(screen.getByText("badsite.net")).toBeInTheDocument();
    expect(screen.getByText("cdn.badsite.net")).toBeInTheDocument();
  });

  it("explains warm-up instead of calling everything new", () => {
    render(<NewToNetworkCard rarity={{ baseline_loaded: true, warming_up: true, history_captures: 1 }} />);
    expect(screen.getByText(/1 capture of network/)).toBeInTheDocument();
  });

  it("renders nothing when there is nothing to say", () => {
    render(<NewToNetworkCard rarity={{ baseline_loaded: false, new: [], single_host: [] }} />);
    expect(screen.queryByText("New to this network")).toBeNull();
    render(<NewToNetworkCard />);
    expect(screen.queryByText("New to this network")).toBeNull();
  });
});
