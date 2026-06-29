import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SettingsDialog } from "./SettingsDialog";

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

describe("SettingsDialog", () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it("does NOT render the AI section (no enable-AI checkbox, no preset, no base URL, no API Key)", () => {
    render(<SettingsDialog onClose={vi.fn()} />);
    expect(screen.queryByRole("checkbox", { name: /enable ai/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("combobox", { name: /preset/i })).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/base url/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/api key/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/AI Analyst/i)).not.toBeInTheDocument();
  });

  it("renders the reputation section with enable checkbox", () => {
    render(<SettingsDialog onClose={vi.fn()} />);
    expect(screen.getByText(/online reputation/i)).toBeInTheDocument();
    const checkbox = screen.getByRole("checkbox", { name: /enable reputation lookups/i });
    expect(checkbox).toBeInTheDocument();
    expect((checkbox as HTMLInputElement).checked).toBe(false);
  });

  it("renders the domain reputation checkbox", () => {
    render(<SettingsDialog onClose={vi.fn()} />);
    const domainLabel = screen.getByText(/enable domain reputation lookups/i);
    expect(domainLabel).toBeInTheDocument();
  });

  it("calls onClose when Cancel is clicked", async () => {
    const u = userEvent.setup();
    const onClose = vi.fn();
    render(<SettingsDialog onClose={onClose} />);
    await u.click(screen.getByRole("button", { name: /cancel/i }));
    expect(onClose).toHaveBeenCalled();
  });

  it("saves reputation settings and closes on Save", async () => {
    const u = userEvent.setup();
    const onClose = vi.fn();
    render(<SettingsDialog onClose={onClose} />);
    await u.click(screen.getByRole("button", { name: /save/i }));
    expect(mockSetRepEnabled).toHaveBeenCalled();
    expect(mockSetDomainEnabled).toHaveBeenCalled();
    expect(onClose).toHaveBeenCalled();
  });

  it("renders the domain reputation checkbox unchecked by default", () => {
    render(<SettingsDialog onClose={vi.fn()} />);
    const checkboxes = screen.getAllByRole("checkbox");
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
