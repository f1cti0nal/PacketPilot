import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const api = vi.hoisted(() => ({ updateName: vi.fn(), uploadAvatar: vi.fn(), removeAvatar: vi.fn() }));
vi.mock("../api", () => api);
import { AccountSection } from "./AccountSection";
import type { AccountProfile } from "../useAccount";

const profile: AccountProfile = {
  id: "u1",
  email: "ada@x.com",
  full_name: "Ada Lovelace",
  avatar_url: null,
  role: "user",
  created_at: "2026-01-15T00:00:00Z",
};

beforeEach(() => {
  api.updateName.mockResolvedValue({ ok: true });
  api.uploadAvatar.mockResolvedValue({ ok: true, url: "https://cdn/a.png" });
  api.removeAvatar.mockResolvedValue({ ok: true });
  vi.clearAllMocks();
});

describe("AccountSection", () => {
  it("renders identity fields", () => {
    render(<AccountSection profile={profile} onChanged={vi.fn()} />);
    expect(screen.getByText("ada@x.com")).toBeInTheDocument();
    expect(screen.getByText("user")).toBeInTheDocument();
    expect(screen.getByText("Ada Lovelace")).toBeInTheDocument();
    expect(screen.getByText(/2026/)).toBeInTheDocument();
  });

  it("edits the display name", async () => {
    const onChanged = vi.fn();
    render(<AccountSection profile={profile} onChanged={onChanged} />);
    fireEvent.click(screen.getByRole("button", { name: /edit display name/i }));
    const input = screen.getByRole("textbox", { name: /display name/i });
    fireEvent.change(input, { target: { value: "Grace Hopper" } });
    fireEvent.click(screen.getByRole("button", { name: /save/i }));
    await waitFor(() => expect(api.updateName).toHaveBeenCalledWith("u1", "Grace Hopper"));
    expect(onChanged).toHaveBeenCalled();
  });

  it("uploads an avatar on file selection", async () => {
    const onChanged = vi.fn();
    render(<AccountSection profile={profile} onChanged={onChanged} />);
    const file = new File(["x"], "a.png", { type: "image/png" });
    fireEvent.change(screen.getByLabelText(/upload avatar/i), { target: { files: [file] } });
    await waitFor(() => expect(api.uploadAvatar).toHaveBeenCalledWith("u1", file));
    expect(onChanged).toHaveBeenCalled();
  });

  it("surfaces an upload error", async () => {
    api.uploadAvatar.mockResolvedValue({ ok: false, error: "Image must be 2 MB or smaller" });
    render(<AccountSection profile={profile} onChanged={vi.fn()} />);
    const file = new File(["x"], "a.png", { type: "image/png" });
    fireEvent.change(screen.getByLabelText(/upload avatar/i), { target: { files: [file] } });
    expect(await screen.findByRole("alert")).toHaveTextContent(/2 MB/);
  });
});
