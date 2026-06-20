import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "../../test/render";
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
});
