import { describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { render, screen } from "@testing-library/react";

const mockState = vi.fn();
vi.mock("../useAdminDashboard", () => ({ useAdminDashboard: () => mockState() }));

// recharts' ResponsiveContainer reads container dimensions jsdom doesn't populate.
vi.mock("recharts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("recharts")>();
  return {
    ...actual,
    ResponsiveContainer: ({ children }: { children: ReactNode }) => (
      <div data-testid="recharts-stub">{children}</div>
    ),
  };
});

import AdminDashboard from "./AdminDashboard";

const ready = {
  status: "ready",
  data: {
    stats: { total_users: 5, paid_users: 3, free_users: 2, active_today: 108, mrr_cents: 5700, signups_7d: 3 },
    recentUsers: [{ email: "a@b.com", full_name: "A", plan: "pro", status: "active", created_at: "2026-06-25T00:00:00Z" }],
    signups: [{ day: "2026-06-27", count: 5 }],
    subscriptions: [{ day: "2026-06-27", count: 3 }],
  },
};

describe("AdminDashboard", () => {
  it("shows the loading state while loading", () => {
    mockState.mockReturnValue({ status: "loading" });
    render(<AdminDashboard />);
    expect(screen.getByRole("status")).toBeInTheDocument();
  });
  it("shows the error message on error", () => {
    mockState.mockReturnValue({ status: "error", error: "boom" });
    render(<AdminDashboard />);
    expect(screen.getByText(/boom/i)).toBeInTheDocument();
  });
  it("renders KPIs, both chart cards, and the table when ready", () => {
    mockState.mockReturnValue(ready);
    render(<AdminDashboard />);
    expect(screen.getByText("Total Users")).toBeInTheDocument();
    expect(screen.getByText("Daily New Users")).toBeInTheDocument();
    expect(screen.getByText("New Subscriptions")).toBeInTheDocument();
    expect(screen.getByText("Recent Users")).toBeInTheDocument();
    expect(screen.getByText("Operational")).toBeInTheDocument();
  });
});
