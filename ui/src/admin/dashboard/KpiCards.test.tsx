import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { KpiCards, SystemHealthCard } from "./KpiCards";

const stats = { total_users: 5, paid_users: 3, free_users: 2, active_today: 108, mrr_cents: 5700, signups_7d: 3 };

describe("KpiCards", () => {
  it("renders the six KPIs with formatted values", () => {
    render(<KpiCards stats={stats} healthy={true} />);
    expect(screen.getByText("Total Users")).toBeInTheDocument();
    expect(screen.getByText("Revenue (MRR)")).toBeInTheDocument();
    expect(screen.getByText("$57")).toBeInTheDocument();
    expect(screen.getByText("108")).toBeInTheDocument();
  });
  it("System Health reflects the healthy flag", () => {
    const { rerender } = render(<SystemHealthCard healthy={true} />);
    expect(screen.getByText("Operational")).toBeInTheDocument();
    rerender(<SystemHealthCard healthy={false} />);
    expect(screen.getByText("Degraded")).toBeInTheDocument();
  });
});
