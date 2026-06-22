import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SettingsDialog } from "./SettingsDialog";

vi.mock("../lib/reputation/settings", () => ({
  isTauri: () => false,
  repEnabled: () => false,
  setRepEnabled: vi.fn(),
  getProxyUrl: () => "",
  setProxyUrl: vi.fn(),
  getKey: () => "",
  setKey: vi.fn(),
}));

vi.mock("../lib/ai/settings", () => ({
  AI_PRESETS: [
    { id: "anthropic", label: "Anthropic", baseUrl: "https://api.anthropic.com/v1", model: "claude-opus-4-8" },
    { id: "ollama", label: "Ollama (local)", baseUrl: "http://localhost:11434/v1", model: "llama3.1" },
    { id: "custom", label: "Custom", baseUrl: "", model: "" },
  ],
  getAiEnabled: () => false,
  setAiEnabled: vi.fn(),
  getAiBaseUrl: () => "https://api.anthropic.com/v1",
  setAiBaseUrl: vi.fn(),
  getAiModel: () => "claude-opus-4-8",
  setAiModel: vi.fn(),
  getAiKey: () => "",
  setAiKey: vi.fn(),
  getProxyUrl: () => "",
  setProxyUrl: vi.fn(),
}));

describe("SettingsDialog — AI section", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders the AI section with enable checkbox", () => {
    render(<SettingsDialog onClose={vi.fn()} />);
    expect(screen.getByText(/AI Analyst/i)).toBeInTheDocument();
    const checkbox = screen.getByRole("checkbox", { name: /enable ai/i });
    expect(checkbox).toBeInTheDocument();
    expect((checkbox as HTMLInputElement).checked).toBe(false);
  });

  it("renders preset dropdown with AI_PRESETS options", () => {
    render(<SettingsDialog onClose={vi.fn()} />);
    expect(screen.getByRole("combobox", { name: /preset/i })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /anthropic/i })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /ollama/i })).toBeInTheDocument();
  });

  it("renders baseUrl, model, and API key inputs", () => {
    render(<SettingsDialog onClose={vi.fn()} />);
    expect(screen.getByLabelText(/base url/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/model/i)).toBeInTheDocument();
    const keyInput = screen.getByLabelText(/api key/i);
    expect(keyInput).toBeInTheDocument();
    expect((keyInput as HTMLInputElement).type).toBe("password");
  });

  it("renders AI proxy URL input (browser only - isTauri is false)", () => {
    render(<SettingsDialog onClose={vi.fn()} />);
    const proxyInputs = screen.getAllByLabelText(/proxy url/i);
    expect(proxyInputs.length).toBeGreaterThanOrEqual(1);
  });

  it("calls onClose when Cancel is clicked", async () => {
    const u = userEvent.setup();
    const onClose = vi.fn();
    render(<SettingsDialog onClose={onClose} />);
    await u.click(screen.getByRole("button", { name: /cancel/i }));
    expect(onClose).toHaveBeenCalled();
  });

  it("saves AI settings and closes on Save", async () => {
    const { setAiEnabled, setAiBaseUrl, setAiModel, setAiKey } = await import("../lib/ai/settings");
    const u = userEvent.setup();
    const onClose = vi.fn();
    render(<SettingsDialog onClose={onClose} />);
    await u.click(screen.getByRole("button", { name: /save/i }));
    expect(setAiEnabled).toHaveBeenCalled();
    expect(setAiBaseUrl).toHaveBeenCalled();
    expect(setAiModel).toHaveBeenCalled();
    expect(setAiKey).toHaveBeenCalled();
    expect(onClose).toHaveBeenCalled();
  });
});
