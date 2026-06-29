import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const hookState = vi.fn();
const reload = vi.fn();
const updateValue = vi.fn().mockResolvedValue({ ok: true });
const updateDescription = vi.fn().mockResolvedValue({ ok: true });
const createSetting = vi.fn().mockResolvedValue({ ok: true });
const deleteSetting = vi.fn().mockResolvedValue({ ok: true });
vi.mock("./useAdminAppSettings", () => ({
  useAdminAppSettings: () => ({ state: hookState(), reload }),
  updateValue: (...a: unknown[]) => updateValue(...a),
  updateDescription: (...a: unknown[]) => updateDescription(...a),
  createSetting: (...a: unknown[]) => createSetting(...a),
  deleteSetting: (...a: unknown[]) => deleteSetting(...a),
}));

import { SettingsView } from "./SettingsView";

const SETTINGS = [
  { key: "branding", value: { product_name: "PacketPilot" }, description: "Branding", updated_at: "2026-06-20T00:00:00Z" },
  { key: "announcement_banner", value: { text: "", severity: "info", dismissible: true }, description: "Banner", updated_at: "2026-06-21T00:00:00Z" },
  { key: "ai_config", value: { enabled: false, provider: "anthropic", model: "claude-opus-4-8" }, description: "AI config", updated_at: "2026-06-22T00:00:00Z" },
];

const SETTINGS_WITH_REP = [
  ...SETTINGS,
  { key: "rep_config", value: { enabled: false, domain_enabled: false, providers: [] }, description: "Rep config", updated_at: "2026-06-23T00:00:00Z" },
];

beforeEach(() => {
  hookState.mockReturnValue({ status: "ready", settings: SETTINGS });
  reload.mockClear();
  updateValue.mockClear().mockResolvedValue({ ok: true });
  createSetting.mockClear().mockResolvedValue({ ok: true });
  deleteSetting.mockClear().mockResolvedValue({ ok: true });
});

describe("SettingsView", () => {
  it("renders a row per setting", () => {
    render(<SettingsView />);
    const table = screen.getByRole("table");
    expect(within(table).getByText("branding")).toBeInTheDocument();
    expect(within(table).getByText("announcement_banner")).toBeInTheDocument();
  });
  it("edits the banner via the typed editor", async () => {
    render(<SettingsView />);
    const text = screen.getByRole("textbox", { name: /announcement text/i });
    await userEvent.type(text, "Hello");
    await userEvent.tab();
    await waitFor(() => expect(updateValue).toHaveBeenCalled());
    const lastArg = updateValue.mock.calls.at(-1)![1] as { text: string };
    expect(lastArg.text).toContain("Hello");
  });
  it("rejects invalid JSON in a json-kind setting (no write)", async () => {
    render(<SettingsView />);
    const ta = screen.getByRole("textbox", { name: /value json for branding/i });
    await userEvent.clear(ta);
    await userEvent.type(ta, "{{not json");
    await userEvent.tab();
    expect(updateValue).not.toHaveBeenCalledWith("branding", expect.anything());
    expect(await screen.findByText(/invalid json/i)).toBeInTheDocument();
  });
  it("adds and deletes a setting", async () => {
    render(<SettingsView />);
    await userEvent.type(screen.getByRole("textbox", { name: /new setting key/i }), "new_key");
    await userEvent.click(screen.getByRole("button", { name: /add setting/i }));
    expect(createSetting).toHaveBeenCalledWith("new_key", "");
    await userEvent.click(screen.getByRole("button", { name: /delete branding/i }));
    expect(deleteSetting).toHaveBeenCalledWith("branding");
  });
  it("renders the AI config editor for ai_config key", async () => {
    render(<SettingsView />);
    const table = screen.getByRole("table");
    expect(within(table).getByText("ai_config")).toBeInTheDocument();
    // AI editor has enabled checkbox, provider select, model input
    expect(screen.getByRole("checkbox", { name: /ai enabled/i })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: /ai provider/i })).toBeInTheDocument();
    const modelInput = screen.getByRole("textbox", { name: /ai model/i }) as HTMLInputElement;
    expect(modelInput.value).toBe("claude-opus-4-8");
    expect(screen.getByText(/API key is set as a server secret/i)).toBeInTheDocument();
  });
  it("changing the AI model calls updateValue with ai_config object", async () => {
    render(<SettingsView />);
    const modelInput = screen.getByRole("textbox", { name: /ai model/i });
    await userEvent.clear(modelInput);
    await userEvent.type(modelInput, "claude-sonnet-4-5");
    await userEvent.tab();
    await waitFor(() => expect(updateValue).toHaveBeenCalledWith(
      "ai_config",
      expect.objectContaining({ model: "claude-sonnet-4-5" }),
    ));
  });
  it("renders empty and error states", () => {
    hookState.mockReturnValue({ status: "ready", settings: [] });
    const { rerender } = render(<SettingsView />);
    expect(screen.getByText(/no settings/i)).toBeInTheDocument();
    hookState.mockReturnValue({ status: "error", error: "backend down" });
    rerender(<SettingsView />);
    expect(screen.getByText(/backend down/i)).toBeInTheDocument();
  });
  it("toggling a rep_config provider calls updateValue with the updated providers array", async () => {
    hookState.mockReturnValue({ status: "ready", settings: SETTINGS_WITH_REP });
    render(<SettingsView />);
    const table = screen.getByRole("table");
    expect(within(table).getByText("rep_config")).toBeInTheDocument();
    // Toggle the abuseipdb provider checkbox
    const abuseipdbCheckbox = screen.getByRole("checkbox", { name: /provider abuseipdb/i });
    await userEvent.click(abuseipdbCheckbox);
    await waitFor(() => expect(updateValue).toHaveBeenCalledWith(
      "rep_config",
      expect.objectContaining({ providers: expect.arrayContaining(["abuseipdb"]) }),
    ));
  });
});
