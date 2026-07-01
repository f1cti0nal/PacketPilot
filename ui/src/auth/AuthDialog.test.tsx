import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AuthDialog } from "./AuthDialog";

const anon = (login: unknown = vi.fn().mockResolvedValue(undefined)) => ({
  status: "anon" as const,
  login: login as never,
});

describe("AuthDialog", () => {
  it("starts Auth0 login on Sign in", async () => {
    const login = vi.fn().mockResolvedValue(undefined);
    render(<AuthDialog session={anon(login)} onClose={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    expect(login).toHaveBeenCalledWith(undefined);
  });

  it("starts Auth0 sign-up on Create account", async () => {
    const login = vi.fn().mockResolvedValue(undefined);
    render(<AuthDialog session={anon(login)} onClose={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: /create account/i }));
    expect(login).toHaveBeenCalledWith({ signUp: true });
  });

  it("surfaces an error if the redirect can't start", async () => {
    const login = vi.fn().mockRejectedValue(new Error("boom"));
    render(<AuthDialog session={anon(login)} onClose={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    expect(await screen.findByText(/couldn't start sign-in/i)).toBeInTheDocument();
  });

  it("closes on the X button", async () => {
    const onClose = vi.fn();
    render(<AuthDialog session={anon()} onClose={onClose} />);
    await userEvent.click(screen.getByRole("button", { name: /close/i }));
    expect(onClose).toHaveBeenCalled();
  });
});
