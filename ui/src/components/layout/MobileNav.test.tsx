import { describe, it, expect, afterEach, vi } from "vitest";
import { render, screen, fireEvent, act } from "../../test/render";
import { useIsMobile, BottomTabBar } from "./MobileNav";

const realMatchMedia = window.matchMedia;
afterEach(() => {
  window.matchMedia = realMatchMedia;
});

const tabs = [
  { id: "dashboard" as const, label: "Dashboard" },
  { id: "flows" as const, label: "Flows" },
  { id: "threats" as const, label: "Threats", badge: 3 },
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
  it("renders tabs (including Threats), marks the active one, and routes taps", () => {
    const onTab = vi.fn();
    render(<BottomTabBar tabs={tabs} activeTab="dashboard" onTab={onTab} />);

    expect(screen.getByRole("button", { name: "Dashboard" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("button", { name: "Flows" })).not.toHaveAttribute("aria-current");
    expect(screen.getByRole("button", { name: "Threats" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Threats" }));
    expect(onTab).toHaveBeenCalledWith("threats");
  });
});
