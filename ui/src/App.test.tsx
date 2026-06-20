import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, userEvent, waitFor } from "./test/render";
import { makeOutput, makeFlows } from "./test/fixtures";

vi.mock("./lib/data", () => ({
  loadSummary: vi.fn(async () => makeOutput()),
  loadFlows: vi.fn(async () => makeFlows()),
}));
vi.mock("./lib/platform", () => ({
  isTauri: () => false,
  openCaptureDialog: vi.fn(),
  analyzeViaTauri: vi.fn(),
  exportReport: vi.fn(),
}));
vi.mock("./lib/wasmEngine", () => ({
  analyzeViaWasm: vi.fn(),
}));
vi.mock("./lib/recent", () => ({
  listRecent: vi.fn(() => []),
  recordRecent: vi.fn(() => []),
  getFlows: vi.fn(async () => null),
  putFlows: vi.fn(async () => false),
  entryId: vi.fn(() => "test-entry-id"),
  removeRecent: vi.fn(() => []),
  clearRecent: vi.fn(() => []),
}));

import App from "./App";

describe("App routing", () => {
  beforeEach(() => localStorage.clear());

  it("rail click on the incident host opens its flyout on the dashboard", async () => {
    const u = userEvent.setup();
    render(<App />);
    // Wait for the rail to be populated (data loaded); may have multiple matching buttons
    const buttons10 = await screen.findAllByRole("button", { name: /^10\.13\.37\.7/ });
    // Click the first (rail button)
    await u.click(buttons10[0]);
    await waitFor(() =>
      expect(
        screen.getByRole("dialog", { name: /Incident detail for 10\.13\.37\.7/i }),
      ).toBeInTheDocument(),
    );
  });

  it("rail click on a non-incident host routes to filtered Flows", async () => {
    const u = userEvent.setup();
    render(<App />);
    // There may be multiple buttons for 45.77.13.37 (rail + watchlist); use the first
    const buttons = await screen.findAllByRole("button", { name: /^45\.77\.13\.37/ });
    await u.click(buttons[0]);
    const filter = await screen.findByLabelText("Filter flows");
    expect((filter as HTMLInputElement).value).toBe("45.77.13.37");
  });
});
