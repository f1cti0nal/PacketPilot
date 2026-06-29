import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const api = vi.hoisted(() => ({
  changePassword: vi.fn(),
  changeEmail: vi.fn(),
  signOutEverywhere: vi.fn(),
  deleteAccount: vi.fn(),
}));
vi.mock("../api", () => api);
import { SecuritySection } from "./SecuritySection";

const origUrl = window.location;
beforeEach(() => {
  api.changePassword.mockResolvedValue({ ok: true });
  api.changeEmail.mockResolvedValue({ ok: true });
  api.signOutEverywhere.mockResolvedValue({ ok: true });
  api.deleteAccount.mockResolvedValue({ ok: true });
  Object.defineProperty(window, "location", { writable: true, value: { assign: vi.fn() } });
});
afterEach(() => {
  vi.clearAllMocks();
  Object.defineProperty(window, "location", { writable: true, value: origUrl });
});

describe("SecuritySection", () => {
  it("changes the password through re-auth", async () => {
    render(<SecuritySection email="ada@x.com" />);
    fireEvent.change(screen.getByLabelText("Current password"), { target: { value: "old" } });
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "longenough1" } });
    fireEvent.change(screen.getByLabelText("Confirm new password"), { target: { value: "longenough1" } });
    fireEvent.click(screen.getByRole("button", { name: /update password/i }));
    await waitFor(() => expect(api.changePassword).toHaveBeenCalledWith("ada@x.com", "old", "longenough1"));
    expect(await screen.findByText(/password updated/i)).toBeInTheDocument();
  });

  it("blocks mismatched passwords before calling the api", () => {
    render(<SecuritySection email="ada@x.com" />);
    fireEvent.change(screen.getByLabelText("Current password"), { target: { value: "old" } });
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "aaaaaaaa1" } });
    fireEvent.change(screen.getByLabelText("Confirm new password"), { target: { value: "bbbbbbbb1" } });
    fireEvent.click(screen.getByRole("button", { name: /update password/i }));
    expect(api.changePassword).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent(/don't match/i);
  });

  it("requests an email change and shows the confirmation note", async () => {
    render(<SecuritySection email="ada@x.com" />);
    fireEvent.change(screen.getByLabelText(/new email address/i), { target: { value: "new@x.com" } });
    fireEvent.click(screen.getByRole("button", { name: /send confirmation/i }));
    await waitFor(() => expect(api.changeEmail).toHaveBeenCalledWith("new@x.com"));
    expect(await screen.findByText(/check your new email/i)).toBeInTheDocument();
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
