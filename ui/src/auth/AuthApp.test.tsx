import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const sess = vi.hoisted(() => ({ useSession: vi.fn() }));
vi.mock("./useSession", () => sess);
const a0 = vi.hoisted(() => ({ auth0Logout: vi.fn(), auth0Login: vi.fn() }));
vi.mock("./auth0Client", () => ({
  auth0Logout: (...args: unknown[]) => a0.auth0Logout(...args),
  auth0Login: (...args: unknown[]) => a0.auth0Login(...args),
}));
vi.mock("../cockpit/ThemeToggle", () => ({ ThemeToggle: () => <div>theme</div> }));

import { AuthApp, modeFromPath } from "./AuthApp";

const origLocation = window.location;
function setLocation(pathname: string, assign = vi.fn()) {
  Object.defineProperty(window, "location", { writable: true, value: { pathname, assign } });
  return assign;
}

beforeEach(() => {
  a0.auth0Logout.mockResolvedValue(undefined);
  sess.useSession.mockReturnValue({ status: "anon", login: vi.fn() });
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
  it("/login renders a sign-in page and launches Auth0 login (returns to /app)", async () => {
    setLocation("/login");
    render(<AuthApp />);
    expect(screen.getByRole("heading", { name: /^sign in$/i })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    expect(a0.auth0Login).toHaveBeenCalledWith({ signUp: false, returnTo: "/app" });
  });

  it("/signup renders a sign-up page and launches Auth0 sign-up", async () => {
    setLocation("/signup");
    render(<AuthApp />);
    expect(screen.getByRole("heading", { name: /create your account/i })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /create account/i }));
    expect(a0.auth0Login).toHaveBeenCalledWith({ signUp: true, returnTo: "/app" });
  });

  it("/logout ends the Auth0 session", () => {
    setLocation("/logout");
    render(<AuthApp />);
    expect(a0.auth0Logout).toHaveBeenCalled();
    expect(screen.getByText(/signing out/i)).toBeInTheDocument();
  });

  it("bounces an already-signed-in user to /app", () => {
    const assign = setLocation("/login");
    sess.useSession.mockReturnValue({ status: "authed", email: "a@b.com", profile: {}, signOut: vi.fn() });
    render(<AuthApp />);
    expect(assign).toHaveBeenCalledWith("/app");
  });
});
