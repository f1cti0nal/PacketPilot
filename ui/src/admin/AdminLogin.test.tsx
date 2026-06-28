import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AdminLogin } from "./AdminLogin";

describe("AdminLogin", () => {
  it("submits entered credentials via session.signIn", async () => {
    const signIn = vi.fn().mockResolvedValue({ ok: true });
    render(<AdminLogin session={{ status: "anon", signIn }} />);
    await userEvent.type(screen.getByLabelText(/email/i), "a@b.com");
    await userEvent.type(screen.getByLabelText(/password/i), "secret");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(signIn).toHaveBeenCalledWith("a@b.com", "secret");
  });

  it("shows the error returned by signIn", async () => {
    const signIn = vi.fn().mockResolvedValue({ ok: false, error: "Invalid login credentials" });
    render(<AdminLogin session={{ status: "anon", signIn }} />);
    await userEvent.type(screen.getByLabelText(/email/i), "a@b.com");
    await userEvent.type(screen.getByLabelText(/password/i), "bad");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(await screen.findByText(/invalid login credentials/i)).toBeInTheDocument();
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
