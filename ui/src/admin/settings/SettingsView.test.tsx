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
  it("renders empty and error states", () => {
    hookState.mockReturnValue({ status: "ready", settings: [] });
    const { rerender } = render(<SettingsView />);
    expect(screen.getByText(/no settings/i)).toBeInTheDocument();
    hookState.mockReturnValue({ status: "error", error: "backend down" });
    rerender(<SettingsView />);
    expect(screen.getByText(/backend down/i)).toBeInTheDocument();
  });
});
