import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { RecentUsersTable } from "./RecentUsersTable";

const users = [
  { email: "alice@x.com", full_name: "Alice", plan: "pro", status: "active", created_at: "2026-06-25T00:00:00Z" },
  { email: "bob@x.com", full_name: null, plan: "free", status: "suspended", created_at: "2026-06-20T00:00:00Z" },
];

describe("RecentUsersTable", () => {
  it("renders a row per user with name/email/plan/status/joined", () => {
    render(<RecentUsersTable users={users} />);
    const table = screen.getByRole("table");
    expect(within(table).getByText("Alice")).toBeInTheDocument();
    expect(within(table).getByText("bob")).toBeInTheDocument(); // falls back to email local-part
    expect(within(table).getByText("alice@x.com")).toBeInTheDocument();
    expect(within(table).getByText("2026-06-25")).toBeInTheDocument();
    expect(within(table).getAllByRole("row")).toHaveLength(3); // header + 2
  });
  it("shows an empty state when there are no users", () => {
    render(<RecentUsersTable users={[]} />);
    expect(screen.getByText(/no users yet/i)).toBeInTheDocument();
  });
});
