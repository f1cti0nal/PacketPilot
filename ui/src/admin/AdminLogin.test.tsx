import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AdminLogin } from "./AdminLogin";

describe("AdminLogin", () => {
  it("signs in with the entered email and password on submit", async () => {
    const signIn = vi.fn().mockResolvedValue({ ok: true });
    render(<AdminLogin session={{ status: "anon", signIn }} />);
    await userEvent.type(screen.getByLabelText(/email/i), "u@b.com");
    await userEvent.type(screen.getByLabelText(/password/i), "s3cret");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(signIn).toHaveBeenCalledWith("u@b.com", "s3cret");
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
    expect(screen.getByText(/VITE_SUPABASE_URL/)).toBeInTheDocument();
    expect(screen.getByText(/VITE_SUPABASE_ANON_KEY/)).toBeInTheDocument();
  });
});
