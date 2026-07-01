import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const api = vi.hoisted(() => ({
  sendPasswordReset: vi.fn(),
  signOutEverywhere: vi.fn(),
  deleteAccount: vi.fn(),
}));
vi.mock("../api", () => api);
import { SecuritySection } from "./SecuritySection";

const origUrl = window.location;
beforeEach(() => {
  api.sendPasswordReset.mockResolvedValue({ ok: true });
  api.signOutEverywhere.mockResolvedValue({ ok: true });
  api.deleteAccount.mockResolvedValue({ ok: true });
  Object.defineProperty(window, "location", { writable: true, value: { assign: vi.fn() } });
});
afterEach(() => {
  vi.clearAllMocks();
  Object.defineProperty(window, "location", { writable: true, value: origUrl });
});

describe("SecuritySection", () => {
  it("sends a password reset email via Auth0", async () => {
    render(<SecuritySection email="ada@x.com" />);
    fireEvent.click(screen.getByRole("button", { name: /send password reset email/i }));
    await waitFor(() => expect(api.sendPasswordReset).toHaveBeenCalledWith("ada@x.com"));
    expect(await screen.findByText(/check your email/i)).toBeInTheDocument();
  });

  it("surfaces a reset error", async () => {
    api.sendPasswordReset.mockResolvedValue({ ok: false, error: "Couldn't send reset email (500)" });
    render(<SecuritySection email="ada@x.com" />);
    fireEvent.click(screen.getByRole("button", { name: /send password reset email/i }));
    expect(await screen.findByText(/couldn't send reset email/i)).toBeInTheDocument();
  });

  it("notes that email + connected logins are provider-managed", () => {
    render(<SecuritySection email="ada@x.com" />);
    expect(screen.getByText(/managed by your identity provider/i)).toBeInTheDocument();
  });

  it("signs out of all devices and redirects", async () => {
    render(<SecuritySection email="ada@x.com" />);
    fireEvent.click(screen.getByRole("button", { name: /sign out everywhere/i }));
    await waitFor(() => expect(api.signOutEverywhere).toHaveBeenCalled());
    expect(window.location.assign).toHaveBeenCalledWith("/app");
  });

  it("arms delete only when the email matches, then deletes", async () => {
    render(<SecuritySection email="ada@x.com" />);
    const del = screen.getByRole("button", { name: /delete my account/i });
    expect(del).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/type your email to confirm/i), { target: { value: "ada@x.com" } });
    expect(del).toBeEnabled();
    fireEvent.click(del);
    await waitFor(() => expect(api.deleteAccount).toHaveBeenCalled());
    expect(window.location.assign).toHaveBeenCalledWith("/");
  });
});
