import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const api = vi.hoisted(() => ({
  updatePassword: vi.fn(),
  signOutEverywhere: vi.fn(),
  deleteAccount: vi.fn(),
}));
vi.mock("../api", () => api);
import { SecuritySection } from "./SecuritySection";

const origUrl = window.location;
beforeEach(() => {
  api.updatePassword.mockResolvedValue({ ok: true });
  api.signOutEverywhere.mockResolvedValue({ ok: true });
  api.deleteAccount.mockResolvedValue({ ok: true });
  Object.defineProperty(window, "location", { writable: true, value: { assign: vi.fn() } });
});
afterEach(() => {
  vi.clearAllMocks();
  Object.defineProperty(window, "location", { writable: true, value: origUrl });
});

describe("SecuritySection", () => {
  it("updates the password inline when both fields match", async () => {
    render(<SecuritySection email="ada@x.com" />);
    fireEvent.change(screen.getByLabelText(/^new password$/i), { target: { value: "hunter2pass" } });
    fireEvent.change(screen.getByLabelText(/confirm new password/i), { target: { value: "hunter2pass" } });
    fireEvent.click(screen.getByRole("button", { name: /update password/i }));
    await waitFor(() => expect(api.updatePassword).toHaveBeenCalledWith("hunter2pass"));
    expect(await screen.findByText(/password updated/i)).toBeInTheDocument();
  });

  it("rejects a too-short password without calling the API", async () => {
    render(<SecuritySection email="ada@x.com" />);
    fireEvent.change(screen.getByLabelText(/^new password$/i), { target: { value: "short" } });
    fireEvent.change(screen.getByLabelText(/confirm new password/i), { target: { value: "short" } });
    fireEvent.click(screen.getByRole("button", { name: /update password/i }));
    expect(await screen.findByText(/at least 8 characters/i)).toBeInTheDocument();
    expect(api.updatePassword).not.toHaveBeenCalled();
  });

  it("rejects mismatched passwords without calling the API", async () => {
    render(<SecuritySection email="ada@x.com" />);
    fireEvent.change(screen.getByLabelText(/^new password$/i), { target: { value: "hunter2pass" } });
    fireEvent.change(screen.getByLabelText(/confirm new password/i), { target: { value: "different99" } });
    fireEvent.click(screen.getByRole("button", { name: /update password/i }));
    expect(await screen.findByText(/passwords don't match/i)).toBeInTheDocument();
    expect(api.updatePassword).not.toHaveBeenCalled();
  });

  it("surfaces an update error", async () => {
    api.updatePassword.mockResolvedValue({ ok: false, error: "Couldn't update password (500)" });
    render(<SecuritySection email="ada@x.com" />);
    fireEvent.change(screen.getByLabelText(/^new password$/i), { target: { value: "hunter2pass" } });
    fireEvent.change(screen.getByLabelText(/confirm new password/i), { target: { value: "hunter2pass" } });
    fireEvent.click(screen.getByRole("button", { name: /update password/i }));
    expect(await screen.findByText(/couldn't update password/i)).toBeInTheDocument();
  });

  it("notes that email + connected logins are provider-managed", () => {
    render(<SecuritySection email="ada@x.com" />);
    expect(screen.getByText(/managed by your identity provider/i)).toBeInTheDocument();
  });

  it("signs out of all devices and redirects", async () => {
    render(<SecuritySection email="ada@x.com" />);
    fireEvent.click(screen.getByRole("button", { name: /sign out everywhere/i }));
    await waitFor(() => expect(api.signOutEverywhere).toHaveBeenCalled());
    expect(window.location.assign).toHaveBeenCalledWith("/");
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
