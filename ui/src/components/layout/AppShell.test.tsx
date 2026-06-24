import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, userEvent } from "../../test/render";
import { AppShell } from "./AppShell";
import type { AppShellProps } from "./AppShell";
import { makeOutput } from "../../test/fixtures";

function minimalProps(overrides: Partial<AppShellProps> = {}): AppShellProps {
  return {
    activeTab: "dashboard",
    onTabChange: vi.fn(),
    summary: { status: "ready", data: makeOutput() },
    recentCount: 0,
    onReplaceData: vi.fn(),
    onAnalyzePcap: vi.fn(),
    onRequestLoad: vi.fn(),
    loadDialogOpen: false,
    onLoadDialogOpenChange: vi.fn(),
    onExport: vi.fn(async () => undefined),
    threats: makeOutput().summary.ip_threats ?? [],
    activeIp: null,
    onSelectThreat: vi.fn(),
    collapsed: false,
    onToggleCollapse: vi.fn(),
    onOpenPalette: vi.fn(),
    paletteOpen: false,
    onPaletteOpenChange: vi.fn(),
    children: <div>child content</div>,
    ...overrides,
  };
}

describe("AppShell", () => {
  beforeEach(() => localStorage.clear());

  it("renders its children", () => {
    render(<AppShell {...minimalProps()} />);
    expect(screen.getByText("child content")).toBeInTheDocument();
  });

  it("renders the threat rail with the provided threats", () => {
    render(<AppShell {...minimalProps()} />);
    // Both threats from makeOutput() should appear as buttons in the rail
    expect(
      screen.getByRole("button", { name: /^10\.13\.37\.7/ }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /^45\.77\.13\.37/ }),
    ).toBeInTheDocument();
  });

  it("Ctrl+K calls onPaletteOpenChange(true)", () => {
    const onPaletteOpenChange = vi.fn();
    render(<AppShell {...minimalProps({ onPaletteOpenChange })} />);
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    expect(onPaletteOpenChange).toHaveBeenCalledWith(true);
  });

  it("Ctrl+K does not fire when palette is already open", () => {
    const onPaletteOpenChange = vi.fn();
    render(
      <AppShell {...minimalProps({ paletteOpen: true, onPaletteOpenChange })} />,
    );
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    expect(onPaletteOpenChange).not.toHaveBeenCalledWith(true);
  });

  it("clicking Export opens the dropdown and invoking HTML report calls onExport", async () => {
    const u = userEvent.setup();
    const onExport = vi.fn(async () => ({ ok: true as const, message: "Report saved" }));
    render(
      <AppShell {...minimalProps({ onExport })} />,
    );
    // The Export button opens a dropdown; click it then pick the first item
    const exportBtn = screen.getByRole("button", { name: /export/i });
    await u.click(exportBtn);
    await u.click(screen.getByText("HTML report"));
    expect(onExport).toHaveBeenCalled();
    // After a successful export, a hint message appears
    await screen.findByText(/Report saved/i);
  });

  it("Sigma rules export and copy actions are wired to their handlers", async () => {
    const u = userEvent.setup();
    const onExportSigma = vi.fn(async () => ({ ok: true as const, message: "Sigma rules saved" }));
    const onCopySigma = vi.fn(async () => ({ ok: true as const, message: "Copied" }));
    render(<AppShell {...minimalProps({ onExportSigma, onCopySigma })} />);

    await u.click(screen.getByRole("button", { name: /export/i }));
    await u.click(screen.getByText("Sigma rules — download"));
    expect(onExportSigma).toHaveBeenCalled();

    await u.click(screen.getByRole("button", { name: /export/i }));
    await u.click(screen.getByText("Sigma rules — copy"));
    expect(onCopySigma).toHaveBeenCalled();
  });

  it("shows the capture filename from the summary source_path", () => {
    render(<AppShell {...minimalProps()} />);
    // makeOutput().source_path = "captures/test.pcap" → basename = "test.pcap"
    expect(screen.getByText("test.pcap")).toBeInTheDocument();
  });

  it("renders the LoadCaptureDialog when loadDialogOpen is true", () => {
    render(<AppShell {...minimalProps({ loadDialogOpen: true })} />);
    expect(screen.getByRole("dialog", { name: /load capture/i })).toBeInTheDocument();
  });

  it("renders the CommandPalette when paletteOpen is true", () => {
    render(<AppShell {...minimalProps({ paletteOpen: true })} />);
    // The CommandPalette renders with a specific aria-label on its input
    expect(screen.getByLabelText("Command palette query")).toBeInTheDocument();
  });
});
