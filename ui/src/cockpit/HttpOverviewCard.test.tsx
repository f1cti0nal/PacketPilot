import { describe, it, expect, vi } from "vitest";
import { render, screen, userEvent } from "../test/render";
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

  it("calls onSelect with the host or user-agent when a row is clicked", async () => {
    const onSelect = vi.fn();
    const u = userEvent.setup();
    render(
      <HttpOverviewCard
        hosts={[{ host: "a.example", flows: 5 }]}
        userAgents={[{ user_agent: "curl/8.4", flows: 3 }]}
        onSelect={onSelect}
      />,
    );
    await u.click(screen.getByRole("button", { name: /a\.example/ }));
    expect(onSelect).toHaveBeenCalledWith("a.example");
    await u.click(screen.getByRole("button", { name: /curl/ }));
    expect(onSelect).toHaveBeenCalledWith("curl/8.4");
  });
});
