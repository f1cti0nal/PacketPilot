import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AdminLogin } from "./AdminLogin";

describe("AdminLogin", () => {
  it("starts Auth0 login on Sign in", async () => {
    const login = vi.fn().mockResolvedValue(undefined);
    render(<AdminLogin session={{ status: "anon", login }} />);
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(login).toHaveBeenCalled();
  });

  it("forbidden variant shows a not-admin message and a sign-out button", async () => {
    const signOut = vi.fn().mockResolvedValue(undefined);
    render(<AdminLogin session={{ status: "forbidden", email: "u@b.com", signOut }} />);
    expect(screen.getByText(/not an administrator/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /sign out/i }));
    expect(signOut).toHaveBeenCalled();
  });

  it("unconfigured variant shows a configuration notice", () => {
    render(<AdminLogin session={{ status: "unconfigured" }} />);
    expect(screen.getByText(/not configured/i)).toBeInTheDocument();
  });
});
