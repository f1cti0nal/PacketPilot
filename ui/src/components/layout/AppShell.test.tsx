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

  it("mobile layout: drops the rail/top tabs for a bottom bar + threat drawer", () => {
    const real = window.matchMedia;
    window.matchMedia = ((q: string) => ({
      matches: true,
      media: q,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    })) as unknown as typeof window.matchMedia;
    try {
      render(<AppShell {...minimalProps()} />);

      // No always-on rail, and the top Views switcher is gone.
      expect(screen.queryByRole("complementary")).toBeNull();
      expect(screen.queryByRole("navigation", { name: "Views" })).toBeNull();

      // Primary navigation is the bottom tab bar.
      expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument();

      // Tapping "Threats" opens the drawer, which exposes the rail threats.
      fireEvent.click(screen.getByRole("button", { name: /Threat watchlist/ }));
      expect(screen.getByRole("dialog", { name: "Threats" })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /^10\.13\.37\.7/ })).toBeInTheDocument();
    } finally {
      window.matchMedia = real;
    }
  });

  it("pressing ? opens the keyboard shortcuts overlay", () => {
    render(<AppShell {...minimalProps()} />);
    expect(screen.queryByRole("dialog", { name: "Keyboard shortcuts" })).toBeNull();
    fireEvent.keyDown(window, { key: "?" });
    expect(screen.getByRole("dialog", { name: "Keyboard shortcuts" })).toBeInTheDocument();
  });

  it("digit keys jump to the matching tab", () => {
    const onTabChange = vi.fn();
    render(<AppShell {...minimalProps({ onTabChange })} />);
    fireEvent.keyDown(window, { key: "2" });
    expect(onTabChange).toHaveBeenCalledWith("flows");
  });

  it("shortcut keys are inert while the command palette is open", () => {
    const onTabChange = vi.fn();
    render(<AppShell {...minimalProps({ paletteOpen: true, onTabChange })} />);
    fireEvent.keyDown(window, { key: "2" });
    fireEvent.keyDown(window, { key: "?" });
    expect(onTabChange).not.toHaveBeenCalled();
    expect(screen.queryByRole("dialog", { name: "Keyboard shortcuts" })).toBeNull();
  });

  it("digit keys are inert while the shortcuts overlay is open", () => {
    const onTabChange = vi.fn();
    render(<AppShell {...minimalProps({ onTabChange })} />);
    fireEvent.keyDown(window, { key: "?" });
    expect(screen.getByRole("dialog", { name: "Keyboard shortcuts" })).toBeInTheDocument();
    fireEvent.keyDown(window, { key: "2" });
    expect(onTabChange).not.toHaveBeenCalled();
  });

  it("digit keys are inert while a text field is focused", () => {
    const onTabChange = vi.fn();
    render(<AppShell {...minimalProps({ onTabChange })} />);
    const input = document.createElement("input");
    document.body.appendChild(input);
    input.focus();
    fireEvent.keyDown(window, { key: "2" });
    expect(onTabChange).not.toHaveBeenCalled();
    input.remove();
  });
});
