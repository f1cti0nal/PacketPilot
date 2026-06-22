import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SettingsDialog } from "./SettingsDialog";

const mockSetAiEnabled = vi.fn();
const mockSetAiBaseUrl = vi.fn();
const mockSetAiModel = vi.fn();
const mockSetAiKey = vi.fn();
const mockSetAiProxyUrl = vi.fn();
const mockSetRepEnabled = vi.fn();
const mockSetDomainEnabled = vi.fn();

vi.mock("../lib/reputation/settings", () => ({
  isTauri: () => false,
  repEnabled: () => false,
  setRepEnabled: (...args: any[]) => mockSetRepEnabled(...args),
  domainEnabled: () => false,
  setDomainEnabled: (...args: any[]) => mockSetDomainEnabled(...args),
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
  setAiEnabled: (...args: any[]) => mockSetAiEnabled(...args),
  getAiBaseUrl: () => "https://api.anthropic.com/v1",
  setAiBaseUrl: (...args: any[]) => mockSetAiBaseUrl(...args),
  getAiModel: () => "claude-opus-4-8",
  setAiModel: (...args: any[]) => mockSetAiModel(...args),
  getAiKey: () => "",
  setAiKey: (...args: any[]) => mockSetAiKey(...args),
  getProxyUrl: () => "",
  setProxyUrl: (...args: any[]) => mockSetAiProxyUrl(...args),
}));

describe("SettingsDialog — AI section", () => {
  beforeEach(() => { vi.clearAllMocks(); });

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
    const u = userEvent.setup();
    const onClose = vi.fn();
    render(<SettingsDialog onClose={onClose} />);
    await u.click(screen.getByRole("button", { name: /save/i }));
    expect(mockSetAiEnabled).toHaveBeenCalled();
    expect(mockSetAiBaseUrl).toHaveBeenCalled();
    expect(mockSetAiModel).toHaveBeenCalled();
    expect(mockSetAiKey).toHaveBeenCalled();
    expect(onClose).toHaveBeenCalled();
  });

  it("selecting Ollama preset updates baseUrl and model", async () => {
    const u = userEvent.setup();
    render(<SettingsDialog onClose={vi.fn()} />);
    const preset = screen.getByRole("combobox", { name: /preset/i });
    await u.selectOptions(preset, "ollama");
    // After selecting ollama, the baseUrl field should update
    const baseUrlInput = screen.getByLabelText(/base url/i) as HTMLInputElement;
    expect(baseUrlInput.value).toBe("http://localhost:11434/v1");
    const modelInput = screen.getByLabelText(/model/i) as HTMLInputElement;
    expect(modelInput.value).toBe("llama3.1");
  });

  it("typing in baseUrl field switches preset to custom", async () => {
    const u = userEvent.setup();
    render(<SettingsDialog onClose={vi.fn()} />);
    const baseUrlInput = screen.getByLabelText(/base url/i);
    await u.clear(baseUrlInput);
    await u.type(baseUrlInput, "https://my-custom-api.com/v1");
    const preset = screen.getByRole("combobox", { name: /preset/i }) as HTMLSelectElement;
    expect(preset.value).toBe("custom");
  });

  it("typing in model field switches preset to custom", async () => {
    const u = userEvent.setup();
    render(<SettingsDialog onClose={vi.fn()} />);
    const modelInput = screen.getByLabelText(/model/i);
    await u.clear(modelInput);
    await u.type(modelInput, "my-custom-model");
    const preset = screen.getByRole("combobox", { name: /preset/i }) as HTMLSelectElement;
    expect(preset.value).toBe("custom");
  });

  it("toggling AI enable checkbox changes the state", async () => {
    const u = userEvent.setup();
    render(<SettingsDialog onClose={vi.fn()} />);
    const checkbox = screen.getByRole("checkbox", { name: /enable ai/i }) as HTMLInputElement;
    expect(checkbox.checked).toBe(false);
    await u.click(checkbox);
    expect(checkbox.checked).toBe(true);
  });

  it("selecting Custom preset does not auto-fill baseUrl/model", async () => {
    const u = userEvent.setup();
    render(<SettingsDialog onClose={vi.fn()} />);
    // First switch to ollama to change values
    const preset = screen.getByRole("combobox", { name: /preset/i });
    await u.selectOptions(preset, "ollama");
    // Now switch to custom — it should not overwrite
    await u.selectOptions(preset, "custom");
    // The baseUrl should remain as ollama's (not blanked)
    const baseUrlInput = screen.getByLabelText(/base url/i) as HTMLInputElement;
    expect(baseUrlInput.value).toBe("http://localhost:11434/v1");
  });

  it("renders the domain reputation checkbox unchecked by default", () => {
    render(<SettingsDialog onClose={vi.fn()} />);
    const checkboxes = screen.getAllByRole("checkbox");
    // Find the domain checkbox by accessible text
    const domainLabel = screen.getByText(/enable domain reputation lookups/i);
    expect(domainLabel).toBeInTheDocument();
    // The checkbox is within the same label element
    const domainCheckbox = checkboxes.find((cb) =>
      cb.closest("label")?.textContent?.match(/domain reputation/i)
    ) as HTMLInputElement | undefined;
    expect(domainCheckbox).toBeDefined();
    expect(domainCheckbox!.checked).toBe(false);
  });

  it("toggling domain checkbox persists via setDomainEnabled on Save", async () => {
    const u = userEvent.setup();
    const onClose = vi.fn();
    render(<SettingsDialog onClose={onClose} />);
    const checkboxes = screen.getAllByRole("checkbox");
    const domainCheckbox = checkboxes.find((cb) =>
      cb.closest("label")?.textContent?.match(/domain reputation/i)
    ) as HTMLInputElement;
    expect(domainCheckbox.checked).toBe(false);
    await u.click(domainCheckbox);
    expect(domainCheckbox.checked).toBe(true);
    await u.click(screen.getByRole("button", { name: /save/i }));
    expect(mockSetDomainEnabled).toHaveBeenCalledWith(true);
    expect(onClose).toHaveBeenCalled();
  });

  it("setDomainEnabled(false) is called when domain checkbox left unchecked on Save", async () => {
    const u = userEvent.setup();
    render(<SettingsDialog onClose={vi.fn()} />);
    await u.click(screen.getByRole("button", { name: /save/i }));
    expect(mockSetDomainEnabled).toHaveBeenCalledWith(false);
  });
});
