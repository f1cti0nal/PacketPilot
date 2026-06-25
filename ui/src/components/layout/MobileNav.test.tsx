import { describe, it, expect, afterEach, vi } from "vitest";
import { render, screen, fireEvent, act } from "../../test/render";
import { useIsMobile, BottomTabBar, MobileThreatDrawer } from "./MobileNav";
import { makeOutput } from "../../test/fixtures";

const realMatchMedia = window.matchMedia;
afterEach(() => {
  window.matchMedia = realMatchMedia;
});

const threats = makeOutput().summary.ip_threats ?? [];
const tabs = [
  { id: "dashboard" as const, label: "Dashboard" },
  { id: "flows" as const, label: "Flows" },
  { id: "recent" as const, label: "Recent", badge: 2 },
];

function HookProbe() {
  return <div data-testid="probe">{useIsMobile() ? "mobile" : "desktop"}</div>;
}

describe("useIsMobile", () => {
  it("is desktop when the media query does not match", () => {
    render(<HookProbe />);
    expect(screen.getByTestId("probe")).toHaveTextContent("desktop");
  });

  it("is mobile when the query matches and follows change events", () => {
    let cb: (() => void) | null = null;
    const mql = {
      matches: true,
      media: "",
      onchange: null,
      addEventListener: (_: string, fn: () => void) => { cb = fn; },
      removeEventListener: () => { cb = null; },
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    };
    window.matchMedia = (() => mql) as unknown as typeof window.matchMedia;

    render(<HookProbe />);
    expect(screen.getByTestId("probe")).toHaveTextContent("mobile");

    mql.matches = false;
    act(() => cb?.());
    expect(screen.getByTestId("probe")).toHaveTextContent("desktop");
  });
});

describe("BottomTabBar", () => {
  it("renders tabs, marks the active one, and routes taps", () => {
    const onTab = vi.fn();
    const onOpenThreats = vi.fn();
    render(
      <BottomTabBar tabs={tabs} activeTab="dashboard" onTab={onTab} threatCount={3} onOpenThreats={onOpenThreats} />,
    );

    expect(screen.getByRole("button", { name: "Dashboard" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("button", { name: "Flows" })).not.toHaveAttribute("aria-current");

    fireEvent.click(screen.getByRole("button", { name: "Flows" }));
    expect(onTab).toHaveBeenCalledWith("flows");

    fireEvent.click(screen.getByRole("button", { name: "Threat watchlist, 3 hosts" }));
    expect(onOpenThreats).toHaveBeenCalled();
  });

  it("singularizes the threat count label", () => {
    render(<BottomTabBar tabs={tabs} activeTab="flows" onTab={vi.fn()} threatCount={1} onOpenThreats={vi.fn()} />);
    expect(screen.getByRole("button", { name: "Threat watchlist, 1 host" })).toBeInTheDocument();
  });
});

describe("MobileThreatDrawer", () => {
  it("renders nothing when closed", () => {
    const { container } = render(
      <MobileThreatDrawer open={false} onClose={vi.fn()} threats={threats} activeIp={null} onSelect={vi.fn()} />,
    );
    expect(container.querySelector('[role="dialog"]')).toBeNull();
  });

  it("shows the rail threats when open, and closes on Escape and Tab traps focus", () => {
    const onClose = vi.fn();
    render(<MobileThreatDrawer open onClose={onClose} threats={threats} activeIp={null} onSelect={vi.fn()} />);

    const dialog = screen.getByRole("dialog", { name: "Threats" });
    expect(dialog).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^10\.13\.37\.7/ })).toBeInTheDocument();

    fireEvent.keyDown(dialog, { key: "Tab" });
    fireEvent.keyDown(dialog, { key: "Escape" });
    expect(onClose).toHaveBeenCalled();
  });

  it("selecting a host calls onSelect and closes the drawer", () => {
    const onSelect = vi.fn();
    const onClose = vi.fn();
    render(<MobileThreatDrawer open onClose={onClose} threats={threats} activeIp={null} onSelect={onSelect} />);

    fireEvent.click(screen.getByRole("button", { name: /^10\.13\.37\.7/ }));
    expect(onSelect).toHaveBeenCalledWith("10.13.37.7");
    expect(onClose).toHaveBeenCalled();
  });

  it("closes via the close button and the backdrop", () => {
    const onClose = vi.fn();
    const { container } = render(
      <MobileThreatDrawer open onClose={onClose} threats={threats} activeIp={null} onSelect={vi.fn()} />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Close threat watchlist" }));
    expect(onClose).toHaveBeenCalledTimes(1);

    fireEvent.click(container.querySelector(".bg-black\\/50")!);
    expect(onClose).toHaveBeenCalledTimes(2);
  });
});
