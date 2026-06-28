import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const hookState = vi.fn();
const reload = vi.fn();
const setPlan = vi.fn();
const setRole = vi.fn();
const setStatus = vi.fn();
vi.mock("./useAdminUsers", () => ({
  useAdminUsers: () => ({ state: hookState(), reload }),
  setPlan: (...a: unknown[]) => setPlan(...a),
  setRole: (...a: unknown[]) => setRole(...a),
  setStatus: (...a: unknown[]) => setStatus(...a),
}));

import { UsersView } from "./UsersView";

const USERS = [
  { id: "u1", email: "alice@x.com", full_name: "Alice", plan: "free", role: "user", status: "active", created_at: "2026-06-20T00:00:00Z" },
  { id: "me", email: "admin@x.com", full_name: "Admin", plan: "pro", role: "admin", status: "active", created_at: "2026-06-21T00:00:00Z" },
];

beforeEach(() => {
  hookState.mockReturnValue({ status: "ready", users: USERS });
  reload.mockClear(); setPlan.mockReset(); setRole.mockReset(); setStatus.mockReset();
  setPlan.mockResolvedValue({ ok: true });
  setRole.mockResolvedValue({ ok: true });
  setStatus.mockResolvedValue({ ok: true });
});

describe("UsersView", () => {
  it("renders a row per user", () => {
    render(<UsersView adminEmail="admin@x.com" />);
    const table = screen.getByRole("table");
    expect(within(table).getByText("alice@x.com")).toBeInTheDocument();
    expect(within(table).getByText("admin@x.com")).toBeInTheDocument();
  });

  it("changing a user's plan calls setPlan then reloads", async () => {
    render(<UsersView adminEmail="admin@x.com" />);
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Plan for alice@x.com" }), "pro");
    expect(setPlan).toHaveBeenCalledWith("u1", "pro");
    await waitFor(() => expect(reload).toHaveBeenCalled());
  });

  it("disables the Role select on the admin's own row", () => {
    render(<UsersView adminEmail="admin@x.com" />);
    expect(screen.getByRole("combobox", { name: "Role for admin@x.com" })).toBeDisabled();
    expect(screen.getByRole("combobox", { name: "Role for alice@x.com" })).toBeEnabled();
  });

  it("shows an alert when a mutation fails", async () => {
    setPlan.mockResolvedValue({ ok: false, error: "denied" });
    render(<UsersView adminEmail="admin@x.com" />);
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Plan for alice@x.com" }), "pro");
    expect(await screen.findByRole("alert")).toHaveTextContent("denied");
  });

  it("renders the empty state when no users match", () => {
    hookState.mockReturnValue({ status: "ready", users: [] });
    render(<UsersView adminEmail="admin@x.com" />);
    expect(screen.getByText(/no users match/i)).toBeInTheDocument();
  });

  it("renders the error state", () => {
    hookState.mockReturnValue({ status: "error", error: "backend down" });
    render(<UsersView adminEmail="admin@x.com" />);
    expect(screen.getByText(/backend down/i)).toBeInTheDocument();
  });
});
