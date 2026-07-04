import { describe, it, expect, vi } from "vitest";
import type { ComponentProps } from "react";
import { render, screen, userEvent, within } from "../../test/render";
import { SideNav } from "./SideNav";

const tabs = [
  { id: "dashboard" as const, label: "Dashboard" },
  { id: "flows" as const, label: "Flows" },
  { id: "threats" as const, label: "Threats", badge: 2 },
  { id: "recent" as const, label: "Recent", badge: 3 },
];

type Props = ComponentProps<typeof SideNav>;
function props(overrides: Partial<Props> = {}): Props {
  return {
    tabs,
    activeTab: "dashboard",
    onTab: vi.fn(),
    collapsed: false,
    onToggleCollapse: vi.fn(),
    onGoHome: vi.fn(),
    ...overrides,
  };
}

describe("SideNav", () => {
  it("renders the views and marks the active one", () => {
    render(<SideNav {...props({ activeTab: "flows" })} />);
    const nav = screen.getByRole("navigation", { name: "Views" });
    expect(within(nav).getByRole("button", { name: "Flows" })).toHaveAttribute("aria-current", "page");
    expect(within(nav).getByRole("button", { name: "Dashboard" })).not.toHaveAttribute("aria-current");
  });

  it("clicking a view calls onTab", async () => {
    const u = userEvent.setup();
    const onTab = vi.fn();
    render(<SideNav {...props({ onTab })} />);
    await u.click(screen.getByRole("button", { name: "Threats" }));
    expect(onTab).toHaveBeenCalledWith("threats");
  });

  it("shows a badge count on a view", () => {
    render(<SideNav {...props()} />);
    expect(screen.getByText("3")).toBeInTheDocument(); // Recent badge
  });

  it("toggles collapse and reflects the state in its label", async () => {
    const u = userEvent.setup();
    const onToggleCollapse = vi.fn();
    const { rerender } = render(<SideNav {...props({ onToggleCollapse })} />);
    await u.click(screen.getByRole("button", { name: "Collapse sidebar" }));
    expect(onToggleCollapse).toHaveBeenCalled();

    rerender(<SideNav {...props({ collapsed: true })} />);
    expect(screen.getByRole("button", { name: "Expand sidebar" })).toBeInTheDocument();
    // Collapsed to an icon rail, each view is still reachable by its accessible label.
    expect(screen.getByRole("button", { name: "Threats" })).toBeInTheDocument();
  });

  it("clicking the brand calls onGoHome", async () => {
    const u = userEvent.setup();
    const onGoHome = vi.fn();
    render(<SideNav {...props({ onGoHome })} />);
    await u.click(screen.getByRole("button", { name: "Go to overview" }));
    expect(onGoHome).toHaveBeenCalled();
  });
});
