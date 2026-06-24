import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { HttpOverviewCard } from "./HttpOverviewCard";

describe("HttpOverviewCard", () => {
  it("renders ranked HTTP hosts and user-agents", () => {
    render(
      <HttpOverviewCard
        hosts={[
          { host: "a.example", flows: 5 },
          { host: "b.example", flows: 2 },
        ]}
        userAgents={[{ user_agent: "curl/8.4", flows: 3 }]}
      />,
    );
    expect(screen.getByText("HTTP overview")).toBeInTheDocument();
    expect(screen.getByText("a.example")).toBeInTheDocument();
    expect(screen.getByText("b.example")).toBeInTheDocument();
    expect(screen.getByText("curl/8.4")).toBeInTheDocument();
  });

  it("renders nothing when no HTTP requests were seen", () => {
    render(<HttpOverviewCard hosts={[]} userAgents={[]} />);
    expect(screen.queryByText("HTTP overview")).toBeNull();
  });
});
