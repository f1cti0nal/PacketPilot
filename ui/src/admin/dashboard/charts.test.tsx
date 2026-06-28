import { describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { render, screen } from "@testing-library/react";

// recharts' ResponsiveContainer reads container dimensions jsdom doesn't populate;
// stub it so tests assert the data-component container + empty-state, not chart internals.
vi.mock("recharts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("recharts")>();
  return {
    ...actual,
    ResponsiveContainer: ({ children }: { children: ReactNode }) => (
      <div data-testid="recharts-stub">{children}</div>
    ),
  };
});

import { SignupsAreaChart } from "./SignupsAreaChart";
import { SubscriptionsBarChart } from "./SubscriptionsBarChart";

const data = [
  { day: "2026-06-26", count: 2 },
  { day: "2026-06-27", count: 3 },
];

describe("dashboard charts", () => {
  it("area chart renders its container with data", () => {
    const { container } = render(<SignupsAreaChart data={data} />);
    expect(container.querySelector('[data-component="SignupsAreaChart"]')).toBeInTheDocument();
  });
  it("bar chart renders its container with data", () => {
    const { container } = render(<SubscriptionsBarChart data={data} />);
    expect(container.querySelector('[data-component="SubscriptionsBarChart"]')).toBeInTheDocument();
  });
  it("show an empty-state message when there is no data", () => {
    render(<SignupsAreaChart data={[]} />);
    expect(screen.getByText(/no data/i)).toBeInTheDocument();
  });
});
