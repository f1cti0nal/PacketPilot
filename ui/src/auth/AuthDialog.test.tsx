import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AuthDialog } from "./AuthDialog";

const anon = (over: Partial<{ signIn: unknown; signUp: unknown; signInWithProvider: unknown }> = {}) => ({
  status: "anon" as const,
  signIn: (over.signIn as never) ?? vi.fn().mockResolvedValue({ ok: true }),
  signUp: (over.signUp as never) ?? vi.fn().mockResolvedValue({ ok: true, needsConfirm: true }),
  signInWithProvider: (over.signInWithProvider as never) ?? vi.fn().mockResolvedValue({ ok: true }),
});

describe("AuthDialog", () => {
  it("signs in with entered credentials and closes on success", async () => {
    const signIn = vi.fn().mockResolvedValue({ ok: true });
    const onClose = vi.fn();
    render(<AuthDialog session={anon({ signIn })} onClose={onClose} />);
    await userEvent.type(screen.getByLabelText(/email/i), "a@b.com");
    await userEvent.type(screen.getByLabelText(/password/i), "secret");
    await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    expect(signIn).toHaveBeenCalledWith("a@b.com", "secret");
    expect(onClose).toHaveBeenCalled();
  });

  it("shows the sign-in error", async () => {
    const signIn = vi.fn().mockResolvedValue({ ok: false, error: "Invalid login credentials" });
    render(<AuthDialog session={anon({ signIn })} onClose={vi.fn()} />);
    await userEvent.type(screen.getByLabelText(/email/i), "a@b.com");
    await userEvent.type(screen.getByLabelText(/password/i), "bad");
    await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    expect(await screen.findByText(/invalid login credentials/i)).toBeInTheDocument();
  });

  it("starts a Google OAuth redirect", async () => {
    const signInWithProvider = vi.fn().mockResolvedValue({ ok: true });
    render(<AuthDialog session={anon({ signInWithProvider })} onClose={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: /continue with google/i }));
    expect(signInWithProvider).toHaveBeenCalledWith("google");
  });

  it("starts a GitHub OAuth redirect", async () => {
    const signInWithProvider = vi.fn().mockResolvedValue({ ok: true });
    render(<AuthDialog session={anon({ signInWithProvider })} onClose={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: /continue with github/i }));
    expect(signInWithProvider).toHaveBeenCalledWith("github");
  });

  it("surfaces an OAuth start error", async () => {
    const signInWithProvider = vi.fn().mockResolvedValue({ ok: false, error: "provider disabled" });
    render(<AuthDialog session={anon({ signInWithProvider })} onClose={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: /continue with github/i }));
    expect(await screen.findByText(/provider disabled/i)).toBeInTheDocument();
  });

  it("toggles to sign-up and shows the confirm panel on needsConfirm", async () => {
    const signUp = vi.fn().mockResolvedValue({ ok: true, needsConfirm: true });
    render(<AuthDialog session={anon({ signUp })} onClose={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: /create one/i }));
    await userEvent.type(screen.getByLabelText(/email/i), "new@b.com");
    await userEvent.type(screen.getByLabelText(/password/i), "secret");
    await userEvent.click(screen.getByRole("button", { name: /create account/i }));
    expect(signUp).toHaveBeenCalledWith("new@b.com", "secret");
    expect(await screen.findByText(/check your email/i)).toBeInTheDocument();
    expect(screen.getByText(/new@b.com/)).toBeInTheDocument();
  });
});
