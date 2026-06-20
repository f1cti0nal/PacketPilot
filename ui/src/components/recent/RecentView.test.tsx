import { describe, it, expect, vi } from "vitest";
import { render, screen, userEvent } from "../../test/render";
import { RecentView } from "./RecentView";
import type { RecentEntry } from "../../types";
import { makeOutput } from "../../test/fixtures";

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
