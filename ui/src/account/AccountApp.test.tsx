import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

const sess = vi.hoisted(() => ({ useSession: vi.fn() }));
vi.mock("../auth/useSession", () => sess);
vi.mock("./AccountPage", () => ({ AccountPage: () => <div>account-page</div> }));

import { AccountApp } from "./AccountApp";

const origUrl = window.location;
beforeEach(() => {
  Object.defineProperty(window, "location", { writable: true, value: { assign: vi.fn() } });
});
afterEach(() => {
  vi.clearAllMocks();
  Object.defineProperty(window, "location", { writable: true, value: origUrl });
});

describe("AccountApp", () => {
  it("shows a loading state while the session resolves", () => {
    sess.useSession.mockReturnValue({ status: "loading" });
    render(<AccountApp />);
    expect(screen.getByText(/loading account/i)).toBeInTheDocument();
  });

  it("redirects anonymous visitors to /app", async () => {
    sess.useSession.mockReturnValue({ status: "anon", signIn: vi.fn(), signUp: vi.fn() });
    render(<AccountApp />);
    await waitFor(() => expect(window.location.assign).toHaveBeenCalledWith("/app"));
  });

  it("renders the account page for a signed-in user", () => {
    sess.useSession.mockReturnValue({
      status: "authed",
      email: "a@b.com",
      profile: { email: "a@b.com", full_name: "A", plan: "pro" },
      signOut: vi.fn(),
    });
    render(<AccountApp />);
    expect(screen.getByText("account-page")).toBeInTheDocument();
  });
});
