import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "../test/render";
import type { SessionState } from "./useSession";

/** GoTrue session shape refreshSession returns (session.user = { email_confirmed_at }). */
type FakeSession = { user: { email?: string; email_confirmed_at?: string | null } } | null;

// Control surface: the config flag, the session state, and the token refresh used by the
// verify-email screen.
const h = {
  supabaseConfigured: true,
  session: { status: "loading" } as SessionState,
  refreshSession: vi.fn(async () => ({ data: { session: null as FakeSession } })),
  resendVerification: vi.fn(async () => ({ ok: true })),
  signOut: vi.fn(async () => {}),
};

// App is heavy (wasm, the whole shell) — stub it so the gate is what's under test. The stub
// echoes the `demo` prop so we can assert the demo path renders the app in demo mode.
vi.mock("../App", () => ({
  default: ({ demo }: { demo?: boolean }) => <div data-testid="app">app demo={String(!!demo)}</div>,
}));
vi.mock("./useSession", () => ({ useSession: () => h.session }));
vi.mock("../lib/supabase", () => ({
  get supabaseConfigured() {
    return h.supabaseConfigured;
  },
  supabase: {
    auth: {
      refreshSession: (...a: unknown[]) => h.refreshSession(...(a as [])),
    },
  },
}));
vi.mock("../cockpit/ThemeToggle", () => ({ ThemeToggle: () => null }));

import { AppGate } from "./AppGate";

const anon = (): SessionState => ({
  status: "anon",
  signIn: vi.fn(async () => ({ ok: true })),
  signUp: vi.fn(async () => ({ ok: true })),
  signInWithProvider: vi.fn(async () => ({ ok: true })),
  resendVerification: vi.fn(async () => ({ ok: true })),
});

const authed = (emailVerified: boolean): SessionState => ({
  status: "authed",
  email: "a@b.com",
  emailVerified,
  profile: { email: "a@b.com", full_name: "A", plan: "free", hasBilling: false },
  resendVerification: h.resendVerification,
  signOut: h.signOut,
});

let origLocation: Location;
beforeEach(() => {
  h.supabaseConfigured = true;
  h.session = { status: "loading" };
  h.refreshSession.mockReset();
  h.refreshSession.mockResolvedValue({ data: { session: null } });
  h.resendVerification.mockReset();
  h.resendVerification.mockResolvedValue({ ok: true });
  h.signOut.mockReset();
  origLocation = window.location;
  // jsdom's location can't be spied on directly — replace it with a minimal stub.
  Object.defineProperty(window, "location", {
    configurable: true,
    value: { assign: vi.fn(), reload: vi.fn(), search: "", pathname: "/app", origin: "http://localhost", href: "http://localhost/app" },
  });
});
afterEach(() => {
  Object.defineProperty(window, "location", { configurable: true, value: origLocation });
});

describe("AppGate", () => {
  it("renders the app open (no gate) when identity is unconfigured (offline/self-host)", () => {
    h.supabaseConfigured = false;
    h.session = anon();
    render(<AppGate />);
    expect(screen.getByTestId("app")).toHaveTextContent("demo=false");
    expect(window.location.assign).not.toHaveBeenCalled();
  });

  it("renders the app in demo mode for /app?sample=1 without requiring auth", () => {
    window.location.search = "?sample=1";
    h.session = anon();
    render(<AppGate />);
    expect(screen.getByTestId("app")).toHaveTextContent("demo=true");
    expect(window.location.assign).not.toHaveBeenCalled();
  });

  it("shows a loading state while the session resolves", () => {
    h.session = { status: "loading" };
    render(<AppGate />);
    expect(screen.getByText("Loading…")).toBeInTheDocument();
    expect(screen.queryByTestId("app")).toBeNull();
  });

  it("redirects a signed-out visitor to /login", async () => {
    h.session = anon();
    render(<AppGate />);
    await waitFor(() => expect(window.location.assign).toHaveBeenCalledWith("/login"));
    expect(screen.getByText("Redirecting to sign in…")).toBeInTheDocument();
    expect(screen.queryByTestId("app")).toBeNull();
  });

  it("holds a signed-in but unverified account on the verify-email screen", () => {
    h.session = authed(false);
    render(<AppGate />);
    expect(screen.getByRole("heading", { name: /verify your email/i })).toBeInTheDocument();
    expect(screen.getByText(/a@b\.com/)).toBeInTheDocument();
    expect(screen.queryByTestId("app")).toBeNull();
  });

  it("renders the app for a signed-in, email-verified account", () => {
    h.session = authed(true);
    render(<AppGate />);
    expect(screen.getByTestId("app")).toHaveTextContent("demo=false");
  });

  it("reloads once the email is confirmed after clicking continue", async () => {
    h.session = authed(false);
    h.refreshSession.mockResolvedValue({
      data: { session: { user: { email: "a@b.com", email_confirmed_at: "2026-07-02T00:00:00Z" } } },
    });
    render(<AppGate />);
    fireEvent.click(screen.getByRole("button", { name: /i've verified/i }));
    await waitFor(() => expect(window.location.reload).toHaveBeenCalled());
  });

  it("shows a 'not verified yet' notice when the email is still unconfirmed", async () => {
    h.session = authed(false);
    h.refreshSession.mockResolvedValue({ data: { session: { user: { email: "a@b.com", email_confirmed_at: null } } } });
    render(<AppGate />);
    fireEvent.click(screen.getByRole("button", { name: /i've verified/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/not verified yet/i);
    expect(window.location.reload).not.toHaveBeenCalled();
  });

  it("recovers (re-enables the buttons) if the token refresh throws", async () => {
    h.session = authed(false);
    h.refreshSession.mockRejectedValue(new Error("network down"));
    render(<AppGate />);
    fireEvent.click(screen.getByRole("button", { name: /i've verified/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/not verified yet/i);
    // busy must be reset so the user isn't stranded with a dead screen.
    expect(screen.getByRole("button", { name: /i've verified/i })).toBeEnabled();
    expect(window.location.reload).not.toHaveBeenCalled();
  });

  it("resends the verification email from the verify-email screen", async () => {
    h.session = authed(false);
    render(<AppGate />);
    fireEvent.click(screen.getByRole("button", { name: /resend verification email/i }));
    await waitFor(() => expect(h.resendVerification).toHaveBeenCalled());
    expect(await screen.findByRole("status")).toHaveTextContent(/check your inbox/i);
  });

  it("signs out from the verify-email screen", () => {
    h.session = authed(false);
    render(<AppGate />);
    fireEvent.click(screen.getByRole("button", { name: /sign out/i }));
    expect(h.signOut).toHaveBeenCalled();
  });
});
