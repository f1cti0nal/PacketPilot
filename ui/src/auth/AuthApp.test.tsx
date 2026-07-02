import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { SessionState } from "./useSession";

const sess = vi.hoisted(() => ({ useSession: vi.fn() }));
vi.mock("./useSession", () => sess);
vi.mock("../cockpit/ThemeToggle", () => ({ ThemeToggle: () => <div>theme</div> }));

import { AuthApp, modeFromPath } from "./AuthApp";

const origLocation = window.location;
function setLocation(pathname: string, assign = vi.fn()) {
  Object.defineProperty(window, "location", {
    writable: true,
    value: { pathname, assign, origin: "http://localhost" },
  });
  return assign;
}

const anon = (over: Partial<Extract<SessionState, { status: "anon" }>> = {}): SessionState => ({
  status: "anon",
  signIn: vi.fn(async () => ({ ok: true })),
  signUp: vi.fn(async () => ({ ok: true })),
  signInWithProvider: vi.fn(async () => ({ ok: true })),
  resendVerification: vi.fn(async () => ({ ok: true })),
  ...over,
});

beforeEach(() => {
  sess.useSession.mockReturnValue(anon());
});
afterEach(() => {
  vi.clearAllMocks();
  Object.defineProperty(window, "location", { writable: true, value: origLocation });
});

describe("modeFromPath", () => {
  it("maps each path to its mode (trailing slash ignored)", () => {
    expect(modeFromPath("/login")).toBe("login");
    expect(modeFromPath("/login/")).toBe("login");
    expect(modeFromPath("/signup")).toBe("signup");
    expect(modeFromPath("/logout")).toBe("logout");
  });
});

describe("AuthApp", () => {
  it("/login renders a native sign-in form and signs in via the session", async () => {
    setLocation("/login");
    const signIn = vi.fn(async () => ({ ok: true }));
    sess.useSession.mockReturnValue(anon({ signIn }));
    render(<AuthApp />);
    expect(screen.getByRole("heading", { name: /welcome back/i })).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText(/email/i), "a@b.com");
    await userEvent.type(screen.getByLabelText(/password/i), "hunter2");
    await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    expect(signIn).toHaveBeenCalledWith("a@b.com", "hunter2");
  });

  it("/signup renders a native sign-up form and signs up via the session", async () => {
    setLocation("/signup");
    const signUp = vi.fn(async () => ({ ok: true }));
    sess.useSession.mockReturnValue(anon({ signUp }));
    render(<AuthApp />);
    expect(screen.getByRole("heading", { name: /create your account/i })).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText(/email/i), "a@b.com");
    await userEvent.type(screen.getByLabelText(/password/i), "hunter2");
    await userEvent.click(screen.getByRole("button", { name: /create account/i }));
    expect(signUp).toHaveBeenCalledWith("a@b.com", "hunter2");
  });

  it("starts an OAuth redirect via the session", async () => {
    setLocation("/login");
    const signInWithProvider = vi.fn(async () => ({ ok: true }));
    sess.useSession.mockReturnValue(anon({ signInWithProvider }));
    render(<AuthApp />);
    await userEvent.click(screen.getByRole("button", { name: /continue with google/i }));
    expect(signInWithProvider).toHaveBeenCalledWith("google");
  });

  it("/logout ends the session and returns home", async () => {
    const assign = setLocation("/logout");
    const signOut = vi.fn(async () => {});
    sess.useSession.mockReturnValue({
      status: "authed",
      email: "a@b.com",
      emailVerified: true,
      profile: { email: "a@b.com", full_name: "A", plan: "free", hasBilling: false, trialEndsAt: null },
      resendVerification: vi.fn(async () => ({ ok: true })),
      signOut,
    } satisfies SessionState);
    render(<AuthApp />);
    expect(screen.getByText(/signing out/i)).toBeInTheDocument();
    expect(signOut).toHaveBeenCalled();
    await vi.waitFor(() => expect(assign).toHaveBeenCalledWith("/"));
  });

  it("bounces an already-signed-in user to /app", () => {
    const assign = setLocation("/login");
    sess.useSession.mockReturnValue({
      status: "authed",
      email: "a@b.com",
      emailVerified: true,
      profile: { email: "a@b.com", full_name: "A", plan: "free", hasBilling: false, trialEndsAt: null },
      resendVerification: vi.fn(async () => ({ ok: true })),
      signOut: vi.fn(async () => {}),
    } satisfies SessionState);
    render(<AuthApp />);
    expect(assign).toHaveBeenCalledWith("/app");
  });
});
