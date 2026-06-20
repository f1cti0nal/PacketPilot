import { describe, it, expect, vi } from "vitest";
import { act } from "react";
import { render, screen, userEvent, sizeScrollElement } from "../test/render";
import type { RenderResult } from "@testing-library/react";
import { PacketInspector } from "./PacketInspector";
import { makePackets, makeFlows } from "../test/fixtures";

const flow = makeFlows(1)[0];

describe("PacketInspector", () => {
  it("loading state renders Extracting text", () => {
    render(<PacketInspector flow={flow} packets={null} loading error={null} onClose={() => {}} />);
    expect(screen.getByText(/extracting/i)).toBeInTheDocument();
  });

  it("empty state renders no-packets message", () => {
    render(
      <PacketInspector
        flow={flow}
        packets={{ total: 0, truncated: false, packets: [] }}
        loading={false}
        error={null}
        onClose={() => {}}
      />
    );
    expect(screen.getByText(/no packets/i)).toBeInTheDocument();
  });

  it("error state renders the error message", () => {
    render(
      <PacketInspector
        flow={flow}
        packets={null}
        loading={false}
        error="Failed to extract packets"
        onClose={() => {}}
      />
    );
    expect(screen.getByText(/Failed to extract packets/)).toBeInTheDocument();
  });

  it("renders rows and selected packet hex in the viewer (row 0 default-selected)", async () => {
    render(
      <PacketInspector
        flow={flow}
        packets={makePackets()}
        loading={false}
        error={null}
        onClose={() => {}}
      />
    );

    // The hex viewer (bottom panel) is NOT virtualized and renders immediately.
    // Packet 0 payload is "GET / HTTP/1.1\r\n" — 16 bytes.
    // hexLines produces exactly one row: offset "00000000", hex, and ascii.
    // Assert on the hex bytes column — proves hexLines ran on the real payload.
    expect(screen.getByText("47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a")).toBeInTheDocument();

    // Size the scroll container so the virtualizer materializes list rows.
    // Must be wrapped in act() so React processes the ResizeObserver-triggered re-render.
    const scrollEl = document.querySelector(".min-h-0.flex-1.overflow-y-auto") as HTMLElement;
    act(() => { sizeScrollElement(scrollEl); });

    // Now the list rows should be visible — packet index 0 row.
    // The ascii preview for "GET / HTTP/1.1\r\n" is "GET / HTTP/1.1.." (dots for \r\n).
    const previews = screen.getAllByText(/GET \/ HTTP/);
    // At least one match: the ascii-preview column in the list row.
    expect(previews.length).toBeGreaterThanOrEqual(1);
  });

  it("selecting a different packet updates the hex viewer", async () => {
    const u = userEvent.setup();
    render(
      <PacketInspector
        flow={flow}
        packets={makePackets()}
        loading={false}
        error={null}
        onClose={() => {}}
      />
    );

    // Size the scroll container so virtualizer renders rows.
    // Must be wrapped in act() so React processes the ResizeObserver-triggered re-render.
    const scrollEl = document.querySelector(".min-h-0.flex-1.overflow-y-auto") as HTMLElement;
    act(() => { sizeScrollElement(scrollEl); });

    // Click the second row (index 1, "HTTP/1.1 200 OK\r\n").
    // asciiPreview of "HTTP/1.1 200 OK\r\n" is "HTTP/1.1 200 OK.."
    // Use getAllByText to handle potential multi-match and pick the list row span.
    const row1Previews = screen.getAllByText(/HTTP\/1\.1 200 OK/);
    await u.click(row1Previews[0]);

    // After clicking row 1, hex viewer should show payload for "HTTP/1.1 200 OK\r\n".
    // H=48, T=54, T=54, P=50, /=2f, 1=31, .=2e, 1=31, space=20, 2=32, 0=30, 0=30, space=20, O=4f, K=4b, \r=0d
    // \n=0a — wait, "HTTP/1.1 200 OK\r\n" = 17 bytes → two hex rows (16 + 1).
    // First row hex: 48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d
    expect(screen.getByText("48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d")).toBeInTheDocument();
  });

  it("Escape key calls onClose", async () => {
    const u = userEvent.setup();
    const onClose = vi.fn();
    render(
      <PacketInspector
        flow={flow}
        packets={makePackets()}
        loading={false}
        error={null}
        onClose={onClose}
      />
    );
    await u.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("close button calls onClose", async () => {
    const u = userEvent.setup();
    const onClose = vi.fn();
    render(
      <PacketInspector
        flow={flow}
        packets={makePackets()}
        loading={false}
        error={null}
        onClose={onClose}
      />
    );
    await u.click(screen.getByRole("button", { name: /close packet inspector/i }));
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("truncated notice shown when packets.truncated is true", () => {
    render(
      <PacketInspector
        flow={flow}
        packets={makePackets({ truncated: true, total: 5000 })}
        loading={false}
        error={null}
        onClose={() => {}}
      />
    );
    // Header shows "first N of 5,000 packets"
    expect(screen.getByText(/first.*of.*5,000/i)).toBeInTheDocument();
  });

  it("resets selection to row 0 when packets prop changes", async () => {
    // Render with first packet set.
    const firstPackets = makePackets();
    const { rerender } = render(
      <PacketInspector
        flow={flow}
        packets={firstPackets}
        loading={false}
        error={null}
        onClose={() => {}}
      />
    ) as RenderResult & { rerender: (element: React.ReactElement) => void };

    // Hex viewer should show the first packet's payload ("GET / HTTP/1.1\r\n").
    expect(screen.getByText("47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a")).toBeInTheDocument();

    // Size scroll container and select a different row (index 1).
    const scrollEl = document.querySelector(".min-h-0.flex-1.overflow-y-auto") as HTMLElement;
    act(() => { sizeScrollElement(scrollEl); });

    const row1Previews = screen.getAllByText(/HTTP\/1\.1 200 OK/);
    await userEvent.setup().click(row1Previews[0]);

    // Verify row 1 is now selected (hex viewer shows "HTTP/1.1 200 OK\r\n").
    expect(screen.getByText("48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d")).toBeInTheDocument();

    // Create a DIFFERENT packet object (new identity).
    const secondPackets = makePackets();

    // Rerender with the new packets prop.
    rerender(
      <PacketInspector
        flow={flow}
        packets={secondPackets}
        loading={false}
        error={null}
        onClose={() => {}}
      />
    );

    // Selection should have reset to row 0, so hex viewer shows the first packet's payload again.
    expect(screen.getByText("47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a")).toBeInTheDocument();
  });
});
