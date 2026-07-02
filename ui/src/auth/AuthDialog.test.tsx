import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AuthDialog } from "./AuthDialog";
import type { SessionState } from "./useSession";

type AnonSession = Extract<SessionState, { status: "anon" }>;

const anon = (over: Partial<AnonSession> = {}): AnonSession => ({
  status: "anon",
  signIn: vi.fn(async () => ({ ok: true })),
  signUp: vi.fn(async () => ({ ok: true })),
  signInWithProvider: vi.fn(async () => ({ ok: true })),
  resendVerification: vi.fn(async () => ({ ok: true })),
  ...over,
});

describe("AuthDialog", () => {
  it("signs in with email/password on submit", async () => {
    const signIn = vi.fn(async () => ({ ok: true }));
    const onClose = vi.fn();
    render(<AuthDialog session={anon({ signIn })} onClose={onClose} />);
    await userEvent.type(screen.getByLabelText(/email/i), "a@b.com");
    await userEvent.type(screen.getByLabelText(/password/i), "hunter2");
    await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    expect(signIn).toHaveBeenCalledWith("a@b.com", "hunter2");
    expect(onClose).toHaveBeenCalled();
  });

  it("signs up after toggling to create-account mode", async () => {
    const signUp = vi.fn(async () => ({ ok: true }));
    render(<AuthDialog session={anon({ signUp })} onClose={vi.fn()} />);
    // Toggle from the default sign-in mode into create-account mode.
    await userEvent.click(screen.getByRole("button", { name: /no account\? create one/i }));
    await userEvent.type(screen.getByLabelText(/email/i), "a@b.com");
    await userEvent.type(screen.getByLabelText(/password/i), "hunter2");
    await userEvent.click(screen.getByRole("button", { name: /create account/i }));
    expect(signUp).toHaveBeenCalledWith("a@b.com", "hunter2");
  });

  it("starts an OAuth sign-in on the provider buttons", async () => {
    const signInWithProvider = vi.fn(async () => ({ ok: true }));
    // A successful OAuth click keeps the dialog "busy" (the browser is navigating away), which
    // disables the other provider button — so each provider is exercised in its own render.
    const { unmount } = render(<AuthDialog session={anon({ signInWithProvider })} onClose={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: /continue with google/i }));
    expect(signInWithProvider).toHaveBeenCalledWith("google");
    unmount();
    render(<AuthDialog session={anon({ signInWithProvider })} onClose={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: /continue with github/i }));
    expect(signInWithProvider).toHaveBeenCalledWith("github");
  });

  it("surfaces an error when sign-in fails", async () => {
    const signIn = vi.fn(async () => ({ ok: false, error: "Invalid login credentials" }));
    render(<AuthDialog session={anon({ signIn })} onClose={vi.fn()} />);
    await userEvent.type(screen.getByLabelText(/email/i), "a@b.com");
    await userEvent.type(screen.getByLabelText(/password/i), "nope");
    await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/invalid login credentials/i);
  });

  it("closes on the X button", async () => {
    const onClose = vi.fn();
    render(<AuthDialog session={anon()} onClose={onClose} />);
    await userEvent.click(screen.getByRole("button", { name: /close/i }));
    expect(onClose).toHaveBeenCalled();
  });

  it("closes on overlay click", async () => {
    const onClose = vi.fn();
    render(<AuthDialog session={anon()} onClose={onClose} />);
    // The overlay is the dialog's parent; the dialog stops click propagation, so clicking the
    // overlay (not the card) is what closes it.
    const dialog = screen.getByRole("dialog");
    await userEvent.click(dialog.parentElement as HTMLElement);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("closes on Escape", async () => {
    const onClose = vi.fn();
    render(<AuthDialog session={anon()} onClose={onClose} />);
    const dialog = screen.getByRole("dialog");
    // Escape is handled by the dialog root's onKeyDown; dispatch from a focused in-dialog control
    // so it bubbles there regardless of the mount-time async focus timing.
    (screen.getByLabelText(/email/i) as HTMLElement).focus();
    await userEvent.keyboard("{Escape}");
    expect(dialog).toBeInTheDocument();
    expect(onClose).toHaveBeenCalled();
  });
});
