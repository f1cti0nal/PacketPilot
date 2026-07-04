import { describe, it, expect, vi } from "vitest";
import { render, screen, userEvent } from "../test/render";
import { CommandBar } from "./CommandBar";

const defaultProps = {
  captureName: "test.pcap",
};

describe("CommandBar", () => {
  it("Load button calls onRequestLoad", async () => {
    const u = userEvent.setup();
    const onRequestLoad = vi.fn();
    render(<CommandBar {...defaultProps} onRequestLoad={onRequestLoad} />);
    await u.click(screen.getByRole("button", { name: "Load capture" }));
    expect(onRequestLoad).toHaveBeenCalled();
  });

  it("Command palette button calls onOpenPalette", async () => {
    const u = userEvent.setup();
    const onOpenPalette = vi.fn();
    render(<CommandBar {...defaultProps} onOpenPalette={onOpenPalette} />);
    await u.click(screen.getByRole("button", { name: "Command palette" }));
    expect(onOpenPalette).toHaveBeenCalled();
  });

  it("Export button is disabled when onExport is omitted", () => {
    render(<CommandBar {...defaultProps} />);
    const exportBtn = screen.getByRole("button", { name: "Export" });
    expect(exportBtn).toBeDisabled();
  });

  it("shows capture name when status is ready", () => {
    render(<CommandBar {...defaultProps} captureStatus="ready" captureName="mycap.pcap" />);
    expect(screen.getByText("mycap.pcap")).toBeInTheDocument();
  });

  it("renders the clickable brand only when showBrand is set", async () => {
    const u = userEvent.setup();
    const onGoHome = vi.fn();
    const { rerender } = render(<CommandBar {...defaultProps} onGoHome={onGoHome} />);
    expect(screen.queryByRole("button", { name: "Go to overview" })).toBeNull();

    rerender(<CommandBar {...defaultProps} showBrand onGoHome={onGoHome} />);
    await u.click(screen.getByRole("button", { name: "Go to overview" }));
    expect(onGoHome).toHaveBeenCalled();
  });
});
