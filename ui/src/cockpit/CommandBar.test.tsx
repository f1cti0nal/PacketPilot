import { describe, it, expect, vi } from "vitest";
import { render, screen, userEvent } from "../test/render";
import { CommandBar } from "./CommandBar";

const defaultProps = {
  captureName: "test.pcap",
  activeTab: "dashboard" as const,
  onTab: vi.fn(),
  collapsed: false,
  onToggleCollapse: vi.fn(),
};

describe("CommandBar", () => {
  it("shows badge count on tab", () => {
    render(
      <CommandBar
        {...defaultProps}
        tabs={[
          { id: "dashboard", label: "Dashboard" },
          { id: "recent", label: "Recent", badge: 3 },
        ]}
      />,
    );
    expect(screen.getByText("3")).toBeInTheDocument();
  });

  it("active tab has aria-pressed true", () => {
    render(
      <CommandBar
        {...defaultProps}
        activeTab="dashboard"
        tabs={[
          { id: "dashboard", label: "Dashboard" },
          { id: "flows", label: "Flows" },
        ]}
      />,
    );
    const dashBtn = screen.getByRole("button", { name: "Dashboard" });
    expect(dashBtn).toHaveAttribute("aria-pressed", "true");
    const flowsBtn = screen.getByRole("button", { name: "Flows" });
    expect(flowsBtn).toHaveAttribute("aria-pressed", "false");
  });

  it("clicking a tab calls onTab", async () => {
    const u = userEvent.setup();
    const onTab = vi.fn();
    render(
      <CommandBar
        {...defaultProps}
        onTab={onTab}
        tabs={[
          { id: "dashboard", label: "Dashboard" },
          { id: "flows", label: "Flows" },
        ]}
      />,
    );
    await u.click(screen.getByRole("button", { name: "Flows" }));
    expect(onTab).toHaveBeenCalledWith("flows");
  });

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
});
