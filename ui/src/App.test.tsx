import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, userEvent, waitFor } from "./test/render";
import { makeOutput, makeFlows } from "./test/fixtures";

const mockLoadSummary = vi.fn(async () => makeOutput());
const mockLoadFlows = vi.fn(async () => makeFlows());

vi.mock("./lib/data", () => ({
  loadSummary: (...args: Parameters<typeof mockLoadSummary>) => mockLoadSummary(...args),
  loadFlows: (...args: Parameters<typeof mockLoadFlows>) => mockLoadFlows(...args),
}));
vi.mock("./lib/platform", () => ({
  isTauri: () => false,
  openCaptureDialog: vi.fn(),
  analyzeViaTauri: vi.fn(),
  exportReport: vi.fn(),
}));
vi.mock("./lib/wasmEngine", () => ({
  analyzeViaWasm: vi.fn(),
  isCaptureFile: vi.fn(() => false),
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
  beforeEach(() => {
    localStorage.clear();
    mockLoadSummary.mockResolvedValue(makeOutput());
    mockLoadFlows.mockResolvedValue(makeFlows());
  });

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

  it("shows a loading state on mount while data is loading", () => {
    // Block both fetches so we can observe the loading state
    mockLoadSummary.mockReturnValue(new Promise(() => {}));
    mockLoadFlows.mockReturnValue(new Promise(() => {}));
    render(<App />);
    // The loading label appears before data resolves
    expect(screen.getAllByText(/Loading summary/i).length).toBeGreaterThanOrEqual(1);
  });

  it("shows an error state when loadSummary rejects", async () => {
    mockLoadSummary.mockRejectedValue(new Error("network error"));
    render(<App />);
    await waitFor(() => {
      // "network error" appears in both the CommandBar status area and ErrorState component
      const elements = screen.getAllByText(/network error/i);
      expect(elements.length).toBeGreaterThanOrEqual(1);
    });
  });

  it("Dashboard renders after data loads: shows KPI cluster", async () => {
    render(<App />);
    // KpiCluster renders "Packets" as a cell label
    await waitFor(() =>
      expect(screen.getByText("Packets")).toBeInTheDocument(),
    );
  });

  it("jumpToFlows: clicking Flows tab navigates to the flows view", async () => {
    const u = userEvent.setup();
    render(<App />);
    // Wait for the dashboard to load (KPI cluster visible)
    await waitFor(() =>
      expect(screen.getByText("Packets")).toBeInTheDocument(),
    );
    // Click the "Flows" tab button in the nav
    const flowsTab = screen.getByRole("button", { name: /^Flows$/i });
    await u.click(flowsTab);
    // After navigating to Flows tab, the filter bar should appear
    await waitFor(() =>
      expect(screen.getByLabelText("Filter flows")).toBeInTheDocument(),
    );
  });
});
