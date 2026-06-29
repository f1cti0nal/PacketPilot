import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AccountMenu } from "./AccountMenu";

const billing = { startCheckout: vi.fn().mockResolvedValue({ ok: true }), openPortal: vi.fn().mockResolvedValue({ ok: true }) };
vi.mock("./billing", () => ({ startCheckout: () => billing.startCheckout(), openPortal: () => billing.openPortal() }));

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
        session={{ status: "authed", email: "a@b.com", profile: { email: "a@b.com", full_name: "A", plan: "pro", hasBilling: true }, signOut }}
        onOpenAuth={vi.fn()}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: /account menu/i }));
    expect(screen.getByText("pro")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /sign out/i }));
    expect(signOut).toHaveBeenCalled();
  });

  it("authed menu links to the /account page", async () => {
    render(
      <AccountMenu
        session={{ status: "authed", email: "a@b.com", profile: { email: "a@b.com", full_name: "A", plan: "free", hasBilling: false }, signOut: vi.fn() }}
        onOpenAuth={vi.fn()}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: /account menu/i }));
    const link = screen.getByRole("link", { name: /profile & account/i });
    expect(link).toHaveAttribute("href", "/account");
  });

  it("anon menu has no Profile & account link", () => {
    render(<AccountMenu session={{ status: "anon", signIn: vi.fn(), signUp: vi.fn() }} onOpenAuth={vi.fn()} />);
    expect(screen.queryByRole("link", { name: /profile & account/i })).not.toBeInTheDocument();
  });

  it("free authed user sees an Upgrade link to /pricing", async () => {
    render(
      <AccountMenu
        session={{ status: "authed", email: "a@b.com", profile: { email: "a@b.com", full_name: "A", plan: "free", hasBilling: false }, signOut: vi.fn() }}
        onOpenAuth={vi.fn()}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: /account menu/i }));
    expect(screen.getByRole("link", { name: /upgrade to pro/i })).toHaveAttribute("href", "/pricing");
  });

  it("pro authed user can manage billing", async () => {
    render(
      <AccountMenu
        session={{ status: "authed", email: "a@b.com", profile: { email: "a@b.com", full_name: "A", plan: "pro", hasBilling: true }, signOut: vi.fn() }}
        onOpenAuth={vi.fn()}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: /account menu/i }));
    await userEvent.click(screen.getByRole("button", { name: /manage billing/i }));
    expect(billing.openPortal).toHaveBeenCalled();
  });

  it("comped Pro (no Stripe customer) shows no Manage billing button", async () => {
    render(
      <AccountMenu
        session={{ status: "authed", email: "a@b.com", profile: { email: "a@b.com", full_name: "A", plan: "pro", hasBilling: false }, signOut: vi.fn() }}
        onOpenAuth={vi.fn()}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: /account menu/i }));
    expect(screen.queryByRole("button", { name: /manage billing/i })).not.toBeInTheDocument();
    expect(screen.getByText(/managed by your administrator/i)).toBeInTheDocument();
  });

  it("surfaces a billing error when Manage billing fails", async () => {
    billing.openPortal.mockResolvedValueOnce({ ok: false, error: "No billing account yet" });
    render(
      <AccountMenu
        session={{ status: "authed", email: "a@b.com", profile: { email: "a@b.com", full_name: "A", plan: "pro", hasBilling: true }, signOut: vi.fn() }}
        onOpenAuth={vi.fn()}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: /account menu/i }));
    await userEvent.click(screen.getByRole("button", { name: /manage billing/i }));
    expect(await screen.findByText(/no billing account yet/i)).toBeInTheDocument();
  });
});
