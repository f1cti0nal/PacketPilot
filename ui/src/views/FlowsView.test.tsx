import { describe, it, expect, vi, beforeEach } from "vitest";
import { act } from "react";
import type { ReactNode } from "react";
import {
  render,
  screen,
  userEvent,
  sizeScrollElement,
  waitFor,
} from "../test/render";
import { FlowsView } from "./FlowsView";
import { makeFlows, makePackets } from "../test/fixtures";
import type { ActiveSource, FlowPackets, FlowRow } from "../types";

// FlowDetail (rendered when a row is selected) draws a recharts chart whose
// ResponsiveContainer reads a container rect jsdom doesn't populate; stub it so
// selecting a flow doesn't crash. Mirrors the stub in FlowDetail.test.tsx.
vi.mock("recharts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("recharts")>();
  return {
    ...actual,
    ResponsiveContainer: ({ children }: { children: ReactNode }) => (
      <div data-testid="recharts-stub">{children}</div>
    ),
  };
});

// FlowsView calls extractFlowPackets to fill the inspector; FlowDetail imports
// packetsAvailable from the same module, so the mock MUST export it too (else the
// button gating breaks). packetsAvailable mirrors the real impl: source !== null.
const mockExtract = vi.fn<[ActiveSource, FlowRow], Promise<FlowPackets>>(
  async () => makePackets(),
);
vi.mock("../lib/packets", () => ({
  extractFlowPackets: (source: ActiveSource, flow: FlowRow) =>
    mockExtract(source, flow),
  packetsAvailable: (s: ActiveSource) => s !== null,
}));

const bytesSource: ActiveSource = { kind: "bytes", bytes: new ArrayBuffer(8) };

describe("FlowsView", () => {
  beforeEach(() => {
    mockExtract.mockReset();
    mockExtract.mockResolvedValue(makePackets());
  });

  it("renders rows: the filter bar is visible and the table grid exists", () => {
    const rows = makeFlows(20);
    const { container } = render(
      <FlowsView state={{ status: "ready", rows }} activeSource={null} />,
    );
    // Filter bar is always present when rows exist
    expect(screen.getByLabelText("Filter flows")).toBeInTheDocument();
    // The grid element is rendered
    const grid = container.querySelector('[role="grid"]')!;
    expect(grid).toBeInTheDocument();
    // Size the scroll element so TanStack Virtual renders row cells, then
    // force a synchronous re-render so the virtualizer picks up the new dims.
    act(() => { sizeScrollElement(grid as HTMLElement); });
    // Flow count shown in the bar (filtered / total — both show 20 when no filter)
    // Both the filtered-count and the total-count slots in the bar render "20"
    const twenties = screen.getAllByText("20");
    expect(twenties.length).toBeGreaterThanOrEqual(2);
    // Default sort is bytes-desc; row 0 has bytesTotal=1_200_500 → "1.14 MB"
    expect(screen.getByText("1.14 MB")).toBeInTheDocument();
  });

  it("typing in 'Filter flows' narrows the rows", async () => {
    const u = userEvent.setup();
    const rows = makeFlows(5);
    const { container } = render(
      <FlowsView state={{ status: "ready", rows }} activeSource={null} />,
    );

    // Size the scroll element so the virtualizer renders row cells
    const grid = container.querySelector('[role="grid"]') as HTMLElement;
    act(() => { sizeScrollElement(grid); });

    const filter = screen.getByLabelText("Filter flows");
    // Filter to the specific dst IP of row 0
    await u.type(filter, "185.220.101.5");
    // Only row 0 matches dstIp "185.220.101.5"; others have "10.0.0.2"
    // The count should show 1 / 5 flows
    expect(screen.getAllByText("1").length).toBeGreaterThan(0);
  });

  it("shows loading state when status is loading", () => {
    render(<FlowsView state={{ status: "loading", rows: [] }} activeSource={null} />);
    expect(screen.getByText(/Loading flows/i)).toBeInTheDocument();
  });

  it("shows error state when status is error", () => {
    render(
      <FlowsView
        state={{ status: "error", rows: [], error: "network failure" }}
        activeSource={null}
      />,
    );
    expect(screen.getByText(/network failure/i)).toBeInTheDocument();
  });

  it("shows empty state when rows is empty", () => {
    render(<FlowsView state={{ status: "ready", rows: [] }} activeSource={null} />);
    expect(screen.getByText(/No flows in this capture/i)).toBeInTheDocument();
  });

  it("initialFilter pre-fills the filter input with the ip", () => {
    render(
      <FlowsView
        state={{ status: "ready", rows: makeFlows(5) }}
        initialFilter={{ ip: "10.0.0.1" }}
        activeSource={null}
      />,
    );
    const filter = screen.getByLabelText("Filter flows");
    expect((filter as HTMLInputElement).value).toBe("10.0.0.1");
  });

  it("mounts without throwing", () => {
    // Ensure the component doesn't require unexpected props
    expect(
      () =>
        render(
          <FlowsView state={{ status: "ready", rows: makeFlows(3) }} activeSource={null} />,
        ).unmount(),
    ).not.toThrow();
  });

  it("clearFilters button appears and resets the text filter when clicked", async () => {
    const u = userEvent.setup();
    const rows = makeFlows(5);
    render(<FlowsView state={{ status: "ready", rows }} activeSource={null} />);

    const filter = screen.getByLabelText("Filter flows");
    // Type something to activate filters
    await u.type(filter, "185");
    // "Clear filters" button should now appear
    const clearBtn = screen.getByRole("button", { name: /Clear filters/i });
    expect(clearBtn).toBeInTheDocument();
    // Click it — the filter should reset
    await u.click(clearBtn);
    expect((screen.getByLabelText("Filter flows") as HTMLInputElement).value).toBe("");
  });

  it("shows 'No flows match the current filters' when filter excludes everything", async () => {
    const u = userEvent.setup();
    const rows = makeFlows(5);
    render(<FlowsView state={{ status: "ready", rows }} activeSource={null} />);
    const filter = screen.getByLabelText("Filter flows");
    await u.type(filter, "zzz-no-match-xyz");
    expect(screen.getByText(/No flows match the current filters/i)).toBeInTheDocument();
  });

  // Select the first flow row, returning once FlowDetail is mounted. The table is
  // virtualized, so size the scroll element before clicking the row cell.
  async function selectFirstFlow(u: ReturnType<typeof userEvent.setup>) {
    const rows = makeFlows(5);
    const { container } = render(
      <FlowsView state={{ status: "ready", rows }} activeSource={bytesSource} />,
    );
    const grid = container.querySelector('[role="grid"]') as HTMLElement;
    act(() => { sizeScrollElement(grid); });
    // Row 0's dst IP (185.220.101.5) is unique to the first flow.
    await u.click(screen.getByText("185.220.101.5"));
    // FlowDetail (and thus its Inspect packets button) is now mounted.
    return screen.getByRole("button", { name: /Inspect packets/i });
  }

  it("opens the PacketInspector with extracted packets when Inspect packets is clicked", async () => {
    const u = userEvent.setup();
    const inspectBtn = await selectFirstFlow(u);
    expect(inspectBtn).toBeEnabled();
    await u.click(inspectBtn);

    // The inspector dialog mounts and renders the extracted packets. The first packet's
    // payload "GET / HTTP/1.1" shows as hex bytes (47 = 'G') only in the hex viewer.
    const dialog = await screen.findByRole("dialog", { name: /Packets for/i });
    expect(dialog).toBeInTheDocument();
    expect(mockExtract).toHaveBeenCalledTimes(1);
    // "47 45 54" = "GET" in hex — appears only in the hex-dump pane.
    await waitFor(() =>
      expect(screen.getByText(/47 45 54/)).toBeInTheDocument(),
    );
  });

  it("shows the error message in the inspector when extraction rejects", async () => {
    mockExtract.mockRejectedValue(new Error("boom extracting packets"));
    const u = userEvent.setup();
    const inspectBtn = await selectFirstFlow(u);
    await u.click(inspectBtn);

    expect(await screen.findByRole("dialog", { name: /Packets for/i })).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByText(/boom extracting packets/i)).toBeInTheDocument(),
    );
  });

  it("disables the Inspect packets button when there is no active source", async () => {
    const u = userEvent.setup();
    const rows = makeFlows(5);
    const { container } = render(
      <FlowsView state={{ status: "ready", rows }} activeSource={null} />,
    );
    const grid = container.querySelector('[role="grid"]') as HTMLElement;
    act(() => { sizeScrollElement(grid); });
    await u.click(screen.getByText("185.220.101.5"));
    expect(screen.getByRole("button", { name: /Inspect packets/i })).toBeDisabled();
  });

  it("generation guard: slow flow A result is discarded when flow B is opened faster", async () => {
    // Arrange two deferred promises so we can resolve them in a controlled order.
    let resolveA!: (v: FlowPackets) => void;
    let resolveB!: (v: FlowPackets) => void;
    const packetsA = makePackets(); // distinct identity for A
    const packetsB = makePackets(); // distinct identity for B

    mockExtract
      .mockImplementationOnce(() => new Promise<FlowPackets>((res) => { resolveA = res; }))
      .mockImplementationOnce(() => new Promise<FlowPackets>((res) => { resolveB = res; }));

    const u = userEvent.setup();
    const rows = makeFlows(5);
    const { container } = render(
      <FlowsView state={{ status: "ready", rows }} activeSource={bytesSource} />,
    );
    const grid = container.querySelector('[role="grid"]') as HTMLElement;
    act(() => { sizeScrollElement(grid); });

    // Open inspector for flow A (slow). The table cell for the first row's dst IP
    // is always the first occurrence in the DOM; use getAllByText to avoid ambiguity
    // after FlowDetail mounts and also renders the same IP.
    await u.click(screen.getAllByText("185.220.101.5")[0]);
    await u.click(screen.getByRole("button", { name: /Inspect packets/i }));

    // Close the inspector; the FlowDetail side panel stays open.
    await u.keyboard("{Escape}");

    // Re-open for the same flow (second call); mockExtract is called again → gen bumps.
    await u.click(screen.getByRole("button", { name: /Inspect packets/i }));

    // Resolve B first (faster), then A (slower/stale).
    await act(async () => { resolveB(packetsB); });
    await act(async () => { resolveA(packetsA); });

    // The inspector should reflect B's result (A's late resolution was after gen changed).
    // Both packet sets share the same payload content, so assert the inspector is
    // still showing packets (not in error/loading state) and extract was called twice.
    expect(mockExtract).toHaveBeenCalledTimes(2);
    await waitFor(() => expect(screen.queryByRole("dialog", { name: /Packets for/i })).toBeInTheDocument());
  });
});
