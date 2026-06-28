import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AdminShell } from "./AdminShell";

afterEach(() => {
  window.location.hash = "";
});

describe("AdminShell", () => {
  it("renders all seven nav items and defaults to the dashboard", () => {
    render(<AdminShell email="a@b.com" onSignOut={vi.fn()} />);
    const nav = screen.getByRole("navigation");
    for (const label of ["Dashboard", "Users", "Payments", "Live Traffic", "App Features", "Settings", "Environment"]) {
      expect(within(nav).getByRole("button", { name: label })).toBeInTheDocument();
    }
    expect(screen.getByText(/overview metrics arrive in phase 4/i)).toBeInTheDocument();
  });

  it("switches content when a nav item is clicked and reflects it in the hash", async () => {
    render(<AdminShell email="a@b.com" onSignOut={vi.fn()} />);
    await userEvent.click(within(screen.getByRole("navigation")).getByRole("button", { name: "Users" }));
    expect(screen.getByText(/coming in phase 5/i)).toBeInTheDocument();
    expect(window.location.hash).toBe("#users");
  });

  it("signs out from the profile menu", async () => {
    const onSignOut = vi.fn().mockResolvedValue(undefined);
    render(<AdminShell email="a@b.com" onSignOut={onSignOut} />);
    await userEvent.click(screen.getByRole("button", { name: /account menu/i }));
    await userEvent.click(screen.getByRole("button", { name: /sign out/i }));
    expect(onSignOut).toHaveBeenCalled();
  });
});
