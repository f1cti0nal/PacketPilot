import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { render, screen, within } from "@testing-library/react";

const hookState = vi.fn();
vi.mock("./useAdminTraffic", () => ({ useAdminTraffic: () => ({ state: hookState(), reload: vi.fn() }) }));
vi.mock("recharts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("recharts")>();
  return { ...actual, ResponsiveContainer: ({ children }: { children: ReactNode }) => <div>{children}</div> };
});

import { TrafficView } from "./TrafficView";

const ready = {
  status: "ready",
  data: {
    stats: { active_today: 3, pageviews_today: 9, authed_today: 1, anon_today: 2 },
    byDay: [{ day: "2026-06-27", count: 5 }],
    topPaths: [{ path: "/app#flows", count: 7 }],
    recent: [{ path: "/admin#users", signedIn: true, created_at: "2026-06-28T00:01:00Z" }],
  },
};

beforeEach(() => hookState.mockReturnValue(ready));

describe("TrafficView", () => {
  it("renders the KPI strip, top paths, and recent activity", () => {
    render(<TrafficView />);
    expect(screen.getByText("Active users today").parentElement).toHaveTextContent("3");
    const tables = screen.getAllByRole("table");
    expect(within(tables[0]).getByText("/app#flows")).toBeInTheDocument();
    expect(within(tables[1]).getByText("/admin#users")).toBeInTheDocument();
    expect(within(tables[1]).getByText(/yes/i)).toBeInTheDocument();
  });

  it("shows the loading and error states", () => {
    hookState.mockReturnValue({ status: "loading" });
    const { rerender } = render(<TrafficView />);
    expect(screen.getByRole("status")).toBeInTheDocument();
    hookState.mockReturnValue({ status: "error", error: "denied" });
    rerender(<TrafficView />);
    expect(screen.getByText(/denied/i)).toBeInTheDocument();
  });

  it("renders empty states when there is no traffic", () => {
    hookState.mockReturnValue({ status: "ready", data: { stats: { active_today: 0, pageviews_today: 0, authed_today: 0, anon_today: 0 }, byDay: [], topPaths: [], recent: [] } });
    render(<TrafficView />);
    expect(screen.getByText(/no traffic yet/i)).toBeInTheDocument();
  });
});
