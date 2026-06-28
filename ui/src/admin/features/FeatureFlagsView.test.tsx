import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const hookState = vi.fn();
const reload = vi.fn();
const setEnabled = vi.fn().mockResolvedValue({ ok: true });
const setPlanGate = vi.fn().mockResolvedValue({ ok: true });
const setDescription = vi.fn().mockResolvedValue({ ok: true });
const createFlag = vi.fn().mockResolvedValue({ ok: true });
const deleteFlag = vi.fn().mockResolvedValue({ ok: true });
vi.mock("./useAdminFeatureFlags", () => ({
  useAdminFeatureFlags: () => ({ state: hookState(), reload }),
  setEnabled: (...a: unknown[]) => setEnabled(...a),
  setPlanGate: (...a: unknown[]) => setPlanGate(...a),
  setDescription: (...a: unknown[]) => setDescription(...a),
  createFlag: (...a: unknown[]) => createFlag(...a),
  deleteFlag: (...a: unknown[]) => deleteFlag(...a),
}));

import { FeatureFlagsView } from "./FeatureFlagsView";

const FLAGS = [
  { key: "ai_assist", description: "AI assist", enabled: true, plan_gate: null, updated_at: "2026-06-20T00:00:00Z" },
  { key: "pcap_export", description: "PCAP export", enabled: false, plan_gate: "pro", updated_at: "2026-06-21T00:00:00Z" },
];

beforeEach(() => {
  hookState.mockReturnValue({ status: "ready", flags: FLAGS });
  reload.mockClear();
  setEnabled.mockClear().mockResolvedValue({ ok: true });
  createFlag.mockClear().mockResolvedValue({ ok: true });
  deleteFlag.mockClear().mockResolvedValue({ ok: true });
});

describe("FeatureFlagsView", () => {
  it("renders a row per flag", () => {
    render(<FeatureFlagsView />);
    const table = screen.getByRole("table");
    expect(within(table).getByText("ai_assist")).toBeInTheDocument();
    expect(within(table).getByText("pcap_export")).toBeInTheDocument();
  });

  it("toggling enabled calls setEnabled then reloads", async () => {
    render(<FeatureFlagsView />);
    await userEvent.click(screen.getByRole("checkbox", { name: /enable ai_assist/i }));
    expect(setEnabled).toHaveBeenCalledWith("ai_assist", false);
    await waitFor(() => expect(reload).toHaveBeenCalled());
  });

  it("changing plan gate calls setPlanGate", async () => {
    render(<FeatureFlagsView />);
    await userEvent.selectOptions(screen.getByRole("combobox", { name: /plan gate for ai_assist/i }), "pro");
    expect(setPlanGate).toHaveBeenCalledWith("ai_assist", "pro");
  });

  it("adds a flag", async () => {
    render(<FeatureFlagsView />);
    await userEvent.type(screen.getByRole("textbox", { name: /new flag key/i }), "new_flag");
    await userEvent.click(screen.getByRole("button", { name: /add flag/i }));
    expect(createFlag).toHaveBeenCalledWith("new_flag", "");
  });

  it("deletes a flag", async () => {
    render(<FeatureFlagsView />);
    await userEvent.click(screen.getByRole("button", { name: /delete pcap_export/i }));
    expect(deleteFlag).toHaveBeenCalledWith("pcap_export");
  });

  it("shows an alert when a mutation fails", async () => {
    setEnabled.mockResolvedValue({ ok: false, error: "denied" });
    render(<FeatureFlagsView />);
    await userEvent.click(screen.getByRole("checkbox", { name: /enable ai_assist/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent("denied");
  });

  it("renders empty and error states", () => {
    hookState.mockReturnValue({ status: "ready", flags: [] });
    const { rerender } = render(<FeatureFlagsView />);
    expect(screen.getByText(/no feature flags/i)).toBeInTheDocument();
    hookState.mockReturnValue({ status: "error", error: "backend down" });
    rerender(<FeatureFlagsView />);
    expect(screen.getByText(/backend down/i)).toBeInTheDocument();
  });
});
