/**
 * SettingsDialog tests for the Tauri (desktop) surface.
 * Kept in a separate file because vi.mock is hoisted module-wide,
 * so the isTauri mock value cannot vary within a single test file.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SettingsDialog } from "./SettingsDialog";

vi.mock("../lib/reputation/settings", () => ({
  // isTauri === true in this suite
  isTauri: () => true,
  repEnabled: () => false,
  setRepEnabled: vi.fn(),
  domainEnabled: () => false,
  setDomainEnabled: vi.fn(),
  getProxyUrl: () => "",
  setProxyUrl: vi.fn(),
  getKey: () => "",
  setKey: vi.fn(),
}));

// Mock @tauri-apps/api/core for keychain save
const mockTauriInvoke = vi.fn<[string, any?], Promise<void>>(async () => {});
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: any[]) => mockTauriInvoke(...(args as [string, any?])),
}));

describe("SettingsDialog — Tauri (desktop) surface", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockTauriInvoke.mockResolvedValue(undefined);
  });

  it("does NOT render the reputation proxy URL field (hidden on Tauri)", () => {
    render(<SettingsDialog onClose={vi.fn()} />);
    // On Tauri the reputation proxy field is hidden (!isTauri guard)
    const proxyFields = screen.queryAllByLabelText(/proxy url/i);
    expect(proxyFields.length).toBe(0);
  });

  it("does NOT render any AI fields", () => {
    render(<SettingsDialog onClose={vi.fn()} />);
    expect(screen.queryByText(/AI Analyst/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/api key/i)).not.toBeInTheDocument();
  });

  it("renders the reputation section", () => {
    render(<SettingsDialog onClose={vi.fn()} />);
    expect(screen.getByText(/online reputation/i)).toBeInTheDocument();
  });

  it("calls onClose when Cancel is clicked", async () => {
    const u = userEvent.setup();
    const onClose = vi.fn();
    render(<SettingsDialog onClose={onClose} />);
    await u.click(screen.getByRole("button", { name: /cancel/i }));
    expect(onClose).toHaveBeenCalled();
  });

  it("saves reputation settings on Save", async () => {
    const u = userEvent.setup();
    const onClose = vi.fn();
    render(<SettingsDialog onClose={onClose} />);
    await u.click(screen.getByRole("button", { name: /save/i }));
    expect(onClose).toHaveBeenCalled();
  });
});
