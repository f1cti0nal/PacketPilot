/**
 * SettingsDialog tests for the Tauri (desktop) surface.
 * Kept in a separate file because vi.mock is hoisted module-wide,
 * so the isTauri mock value cannot vary within a single test file.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SettingsDialog } from "./SettingsDialog";

const mockSetAiEnabled = vi.fn();
const mockSetAiBaseUrl = vi.fn();
const mockSetAiModel = vi.fn();

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

vi.mock("../lib/ai/settings", () => ({
  AI_PRESETS: [
    { id: "anthropic", label: "Anthropic", baseUrl: "https://api.anthropic.com/v1", model: "claude-opus-4-8" },
    { id: "custom", label: "Custom", baseUrl: "", model: "" },
  ],
  getAiEnabled: () => false,
  setAiEnabled: (...args: any[]) => mockSetAiEnabled(...args),
  getAiBaseUrl: () => "https://api.anthropic.com/v1",
  setAiBaseUrl: (...args: any[]) => mockSetAiBaseUrl(...args),
  getAiModel: () => "claude-opus-4-8",
  setAiModel: (...args: any[]) => mockSetAiModel(...args),
  getAiKey: () => "",
  setAiKey: vi.fn(),
  getProxyUrl: () => "",
  setProxyUrl: vi.fn(),
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
    // The AI proxy field is also hidden on Tauri
    expect(proxyFields.length).toBe(0);
  });

  it("saves AI base settings via setAiEnabled/setAiBaseUrl on Save", async () => {
    const u = userEvent.setup();
    const onClose = vi.fn();
    render(<SettingsDialog onClose={onClose} />);
    await u.click(screen.getByRole("button", { name: /save/i }));
    expect(mockSetAiEnabled).toHaveBeenCalled();
    expect(mockSetAiBaseUrl).toHaveBeenCalled();
    expect(mockSetAiModel).toHaveBeenCalled();
    expect(onClose).toHaveBeenCalled();
  });

  it("calls tauri invoke set_ai_key when AI key is entered on Tauri", async () => {
    const u = userEvent.setup();
    render(<SettingsDialog onClose={vi.fn()} />);
    const keyInput = screen.getByLabelText(/api key/i);
    await u.type(keyInput, "sk-tauri-key");
    await u.click(screen.getByRole("button", { name: /save/i }));
    expect(mockTauriInvoke).toHaveBeenCalledWith(
      "set_ai_key",
      expect.objectContaining({ provider: "default", key: "sk-tauri-key" }),
    );
  });

  it("shows error when tauri invoke for AI key fails", async () => {
    mockTauriInvoke.mockRejectedValueOnce(new Error("keychain locked"));
    const u = userEvent.setup();
    render(<SettingsDialog onClose={vi.fn()} />);
    const keyInput = screen.getByLabelText(/api key/i);
    await u.type(keyInput, "sk-fail");
    await u.click(screen.getByRole("button", { name: /save/i }));
    expect(await screen.findByText(/Failed to save AI key.*keychain locked/i)).toBeInTheDocument();
  });
});
