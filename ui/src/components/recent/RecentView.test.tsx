import { describe, it, expect, vi } from "vitest";
import { render, screen, userEvent } from "../../test/render";
import { RecentView } from "./RecentView";
import type { RecentEntry } from "../../types";
import { makeOutput } from "../../test/fixtures";

const noop = () => {};

function makeEntry(overrides: Partial<RecentEntry> = {}): RecentEntry {
  return {
    id: "test-entry-1",
    name: "test-capture.pcap",
    sizeBytes: 6_000_000,
    analyzedAt: Date.now() - 60_000, // 1 minute ago
    engineVersion: "0.1.0",
    origin: "upload",
    summary: makeOutput(),
    flowCount: 39_000,
    flowsCached: false,
    ...overrides,
  };
}

describe("RecentView", () => {
  it("renders the entry name", () => {
    const entry = makeEntry();
    render(
      <RecentView
        entries={[entry]}
        onOpen={vi.fn()}
        onReanalyze={vi.fn()}
        onRemove={vi.fn()}
        onClear={vi.fn()}
        onLoadNew={vi.fn()}
      />,
    );
    expect(screen.getByText("test-capture.pcap")).toBeInTheDocument();
  });

  it("clicking the entry name button calls onOpen", async () => {
    const u = userEvent.setup();
    const onOpen = vi.fn();
    const entry = makeEntry();
    render(
      <RecentView
        entries={[entry]}
        onOpen={onOpen}
        onReanalyze={vi.fn()}
        onRemove={vi.fn()}
        onClear={vi.fn()}
        onLoadNew={vi.fn()}
      />,
    );
    // The card name is wrapped in a button
    await u.click(screen.getByText("test-capture.pcap"));
    expect(onOpen).toHaveBeenCalledWith(entry);
  });

  it("clicking the Open button calls onOpen", async () => {
    const u = userEvent.setup();
    const onOpen = vi.fn();
    const entry = makeEntry();
    render(
      <RecentView
        entries={[entry]}
        onOpen={onOpen}
        onReanalyze={vi.fn()}
        onRemove={vi.fn()}
        onClear={vi.fn()}
        onLoadNew={vi.fn()}
      />,
    );
    await u.click(screen.getByRole("button", { name: "Open" }));
    expect(onOpen).toHaveBeenCalledWith(entry);
  });

  it("clicking the remove button calls onRemove", async () => {
    const u = userEvent.setup();
    const onRemove = vi.fn();
    const entry = makeEntry();
    render(
      <RecentView
        entries={[entry]}
        onOpen={vi.fn()}
        onReanalyze={vi.fn()}
        onRemove={onRemove}
        onClear={vi.fn()}
        onLoadNew={vi.fn()}
      />,
    );
    await u.click(
      screen.getByRole("button", { name: /Remove test-capture\.pcap/i }),
    );
    expect(onRemove).toHaveBeenCalledWith(entry);
  });

  it("shows a per-capture verdict chip matching the Home overview", () => {
    const entry = makeEntry(); // makeOutput() has a critical incident
    render(
      <RecentView
        entries={[entry]}
        onOpen={vi.fn()}
        onReanalyze={vi.fn()}
        onRemove={vi.fn()}
        onClear={vi.fn()}
        onLoadNew={vi.fn()}
      />,
    );
    expect(screen.getByText("1 Critical")).toBeInTheDocument();
  });

  it("shows the workspace rollup header", () => {
    const entry = makeEntry();
    render(
      <RecentView
        entries={[entry]}
        onOpen={vi.fn()}
        onReanalyze={vi.fn()}
        onRemove={vi.fn()}
        onClear={vi.fn()}
        onLoadNew={vi.fn()}
      />,
    );
    expect(screen.getByText("Captures")).toBeInTheDocument();
    expect(screen.getByText("Critical / high")).toBeInTheDocument();
  });

  it("shows empty state when no entries", () => {
    render(
      <RecentView
        entries={[]}
        onOpen={vi.fn()}
        onReanalyze={vi.fn()}
        onRemove={vi.fn()}
        onClear={vi.fn()}
        onLoadNew={vi.fn()}
      />,
    );
    expect(screen.getByText("No recent captures yet")).toBeInTheDocument();
  });

  it("active entry shows Active badge", () => {
    const entry = makeEntry();
    render(
      <RecentView
        entries={[entry]}
        activeId={entry.id}
        onOpen={vi.fn()}
        onReanalyze={vi.fn()}
        onRemove={vi.fn()}
        onClear={vi.fn()}
        onLoadNew={vi.fn()}
      />,
    );
    expect(screen.getByText("Active")).toBeInTheDocument();
  });
});

describe("RecentView compare selection", () => {
  it("enables Compare only at exactly 2 selections and calls onCompare older-first", async () => {
    const user = userEvent.setup();
    const onCompare = vi.fn();
    const entryNew: RecentEntry = {
      id: "new", name: "new", sizeBytes: 1, analyzedAt: 200,
      engineVersion: "x", origin: "upload",
      flowCount: 1, flowsCached: false, summary: makeOutput(),
    };
    const entryOld: RecentEntry = {
      id: "old", name: "old", sizeBytes: 1, analyzedAt: 100,
      engineVersion: "x", origin: "upload",
      flowCount: 1, flowsCached: false, summary: makeOutput(),
    };
    render(
      <RecentView
        entries={[entryNew, entryOld]}
        onOpen={noop} onReanalyze={noop} onRemove={noop} onClear={noop} onLoadNew={noop}
        onCompare={onCompare}
      />,
    );
    const compareBtn = screen.getByRole("button", { name: /compare/i });
    expect(compareBtn).toBeDisabled();
    const checkboxes = screen.getAllByRole("checkbox");
    await user.click(checkboxes[0]);
    expect(screen.getByRole("button", { name: /compare/i })).toBeDisabled(); // 1 selected
    await user.click(checkboxes[1]);
    const enabled = screen.getByRole("button", { name: /compare/i });
    expect(enabled).toBeEnabled(); // 2 selected
    await user.click(enabled);
    expect(onCompare).toHaveBeenCalledWith("old", "new"); // older (100) first
  });
});
