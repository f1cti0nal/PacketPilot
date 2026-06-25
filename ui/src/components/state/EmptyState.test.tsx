import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "../../test/render";
import { EmptyState } from "./EmptyState";

describe("EmptyState", () => {
  it("renders the title and a default hint", () => {
    render(<EmptyState title="No capture loaded" />);
    expect(screen.getByText("No capture loaded")).toBeInTheDocument();
    expect(screen.getByText(/Drop a \.pcap/i)).toBeInTheDocument();
  });

  it("renders no CTA without onLoad", () => {
    render(<EmptyState title="No capture loaded" />);
    expect(screen.queryByRole("button", { name: /load capture/i })).toBeNull();
  });

  it("renders the load CTA and fires onLoad when clicked", () => {
    const onLoad = vi.fn();
    render(<EmptyState title="No capture loaded" onLoad={onLoad} />);
    fireEvent.click(screen.getByRole("button", { name: /load capture/i }));
    expect(onLoad).toHaveBeenCalledTimes(1);
  });

  it("accepts a custom hint", () => {
    render(<EmptyState title="x" hint="custom hint" />);
    expect(screen.getByText("custom hint")).toBeInTheDocument();
  });
});
