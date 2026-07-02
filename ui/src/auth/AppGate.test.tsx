import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "../test/render";
import type { SessionState } from "./useSession";

// Control surface: the two config flags, the session state, and the token refresh.
const h = {
  supabaseConfigured: true,
  auth0Configured: true,
  session: { status: "loading" } as SessionState,
  refreshUser: vi.fn(),
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
}));
vi.mock("./auth0Client", () => ({
  get auth0Configured() {
    return h.auth0Configured;
  },
  auth0RefreshUser: (...a: unknown[]) => h.refreshUser(...a),
}));
vi.mock("../cockpit/ThemeToggle", () => ({ ThemeToggle: () => null }));

import { AppGate } from "./AppGate";

const authed = (emailVerified: boolean): SessionState => ({
  status: "authed",
  email: "a@b.com",
  emailVerified,
  profile: { email: "a@b.com", full_name: "A", plan: "free", hasBilling: false, trialEndsAt: null },
  signOut: h.signOut,
});

let origLocation: Location;
beforeEach(() => {
  h.supabaseConfigured = true;
  h.auth0Configured = true;
  h.session = { status: "loading" };
  h.refreshUser.mockReset();
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
    h.session = { status: "anon", login: vi.fn(async () => {}) };
    render(<AppGate />);
    expect(screen.getByTestId("app")).toHaveTextContent("demo=false");
    expect(window.location.assign).not.toHaveBeenCalled();
  });

  it("renders the app in demo mode for /app?sample=1 without requiring auth", () => {
    window.location.search = "?sample=1";
    h.session = { status: "anon", login: vi.fn(async () => {}) };
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
    h.session = { status: "anon", login: vi.fn(async () => {}) };
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
    h.refreshUser.mockResolvedValue({ email: "a@b.com", email_verified: true });
    render(<AppGate />);
    fireEvent.click(screen.getByRole("button", { name: /i've verified/i }));
    await waitFor(() => expect(window.location.reload).toHaveBeenCalled());
  });

  it("shows a 'not verified yet' notice when the email is still unconfirmed", async () => {
    h.session = authed(false);
    h.refreshUser.mockResolvedValue({ email: "a@b.com", email_verified: false });
    render(<AppGate />);
    fireEvent.click(screen.getByRole("button", { name: /i've verified/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/not verified yet/i);
    expect(window.location.reload).not.toHaveBeenCalled();
  });

  it("signs out from the verify-email screen", () => {
    h.session = authed(false);
    render(<AppGate />);
    fireEvent.click(screen.getByRole("button", { name: /sign out/i }));
    expect(h.signOut).toHaveBeenCalled();
  });
});
