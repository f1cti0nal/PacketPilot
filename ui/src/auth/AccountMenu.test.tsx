import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AccountMenu } from "./AccountMenu";

describe("AccountMenu", () => {
  it("anon shows Sign in and calls onOpenAuth", async () => {
    const onOpenAuth = vi.fn();
    render(<AccountMenu session={{ status: "anon", signIn: vi.fn(), signUp: vi.fn() }} onOpenAuth={onOpenAuth} />);
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(onOpenAuth).toHaveBeenCalled();
  });

  it("authed shows the email, plan, and signs out", async () => {
    const signOut = vi.fn().mockResolvedValue(undefined);
    render(
      <AccountMenu
        session={{ status: "authed", email: "a@b.com", profile: { email: "a@b.com", full_name: "A", plan: "pro" }, signOut }}
        onOpenAuth={vi.fn()}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: /account menu/i }));
    expect(screen.getByText("pro")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /sign out/i }));
    expect(signOut).toHaveBeenCalled();
  });
});
