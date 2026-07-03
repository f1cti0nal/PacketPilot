import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Activity } from "lucide-react";
import {
  AdminCard,
  Avatar,
  Badge,
  IconButton,
  MenuButton,
  MiniStat,
  PillButton,
  ProgressStat,
  SearchInput,
  StatCard,
  StatusPill,
  TableCard,
  TrendPill,
} from "./kit";

describe("TrendPill", () => {
  it("renders a signed percentage for a real up delta", () => {
    render(<TrendPill delta={{ pct: 12, dir: "up" }} />);
    expect(screen.getByText("+12%")).toBeInTheDocument();
  });
  it("renders a negative delta", () => {
    render(<TrendPill delta={{ pct: -8, dir: "down" }} />);
    expect(screen.getByText("-8%")).toBeInTheDocument();
  });
  it("shows 'New' when there is no prior baseline", () => {
    render(<TrendPill delta={{ pct: null, dir: "up" }} />);
    expect(screen.getByText("New")).toBeInTheDocument();
  });
  it("shows a dash when flat with no percent", () => {
    render(<TrendPill delta={{ pct: null, dir: "down" }} />);
    expect(screen.getByText("—")).toBeInTheDocument();
  });
});

describe("StatCard", () => {
  it("renders label, value, delta and a menu", () => {
    render(
      <StatCard
        label="Total Users"
        value="1,234"
        icon={Activity}
        delta={{ pct: 5, dir: "up" }}
        caption="all accounts"
        menu={<MenuButton items={[{ label: "Refresh", onSelect: vi.fn() }]} />}
      />,
    );
    expect(screen.getByText("Total Users")).toBeInTheDocument();
    expect(screen.getByText("1,234")).toBeInTheDocument();
    expect(screen.getByText("+5%")).toBeInTheDocument();
    expect(screen.getByText("all accounts")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /options/i })).toBeInTheDocument();
  });
});

describe("MiniStat", () => {
  it("keeps the value inside the label's parent element", () => {
    render(<MiniStat label="Active MRR" value="$19" delta={{ pct: 4, dir: "up" }} />);
    expect(screen.getByText("Active MRR").parentElement).toHaveTextContent("$19");
    expect(screen.getByText("+4%")).toBeInTheDocument();
  });
});

describe("ProgressStat", () => {
  it("renders label + value and clamps the bar width", () => {
    const { container } = render(<ProgressStat label="Conversion" value="42%" pct={140} caption="paid / total" />);
    expect(screen.getByText("Conversion")).toBeInTheDocument();
    expect(screen.getByText("42%")).toBeInTheDocument();
    const bar = container.querySelector('[style*="width"]') as HTMLElement;
    expect(bar.style.width).toBe("100%");
  });
});

describe("Avatar / StatusPill / Badge", () => {
  it("renders initials", () => {
    render(<Avatar name="Alice Smith" email="a@b.com" />);
    expect(screen.getByText("AS")).toBeInTheDocument();
  });
  it("renders a status label", () => {
    render(<StatusPill label="active" color="var(--color-sev-low)" />);
    expect(screen.getByText("active")).toBeInTheDocument();
  });
  it("renders accent and neutral badges", () => {
    render(
      <>
        <Badge tone="accent">pro</Badge>
        <Badge>free</Badge>
      </>,
    );
    expect(screen.getByText("pro")).toBeInTheDocument();
    expect(screen.getByText("free")).toBeInTheDocument();
  });
});

describe("PillButton / IconButton", () => {
  it("fires onClick and renders children across variants", async () => {
    const onClick = vi.fn();
    render(
      <PillButton variant="primary" onClick={onClick}>
        Export
      </PillButton>,
    );
    await userEvent.click(screen.getByRole("button", { name: "Export" }));
    expect(onClick).toHaveBeenCalled();
  });
  it("renders an icon-only button", async () => {
    const onClick = vi.fn();
    render(<IconButton icon={Activity} aria-label="Refresh" onClick={onClick} />);
    await userEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect(onClick).toHaveBeenCalled();
  });
});

describe("SearchInput", () => {
  it("is a searchbox with the provided label", () => {
    render(<SearchInput aria-label="Search users" placeholder="Search…" />);
    expect(screen.getByRole("searchbox", { name: /search users/i })).toBeInTheDocument();
  });
});

describe("TableCard / AdminCard", () => {
  it("renders a titled table card with count, actions and footer", () => {
    render(
      <TableCard title="Users" count={3} right={<button type="button">Filter</button>} footer="latest sync">
        <table>
          <tbody>
            <tr>
              <td>row</td>
            </tr>
          </tbody>
        </table>
      </TableCard>,
    );
    expect(screen.getByText("Users")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Filter" })).toBeInTheDocument();
    expect(screen.getByText("latest sync")).toBeInTheDocument();
    expect(screen.getByText("row")).toBeInTheDocument();
  });
  it("renders an AdminCard with title, subtitle and right slot", () => {
    render(
      <AdminCard title="Overview" subtitle="last 14 days" right={<span>right</span>}>
        <p>body</p>
      </AdminCard>,
    );
    expect(screen.getByText("Overview")).toBeInTheDocument();
    expect(screen.getByText("last 14 days")).toBeInTheDocument();
    expect(screen.getByText("body")).toBeInTheDocument();
  });
});

describe("MenuButton", () => {
  it("opens, invokes an item, and closes", async () => {
    const onSelect = vi.fn();
    render(<MenuButton label="Row options" items={[{ label: "Edit", onSelect }]} />);
    const trigger = screen.getByRole("button", { name: "Row options" });
    await userEvent.click(trigger);
    const menu = screen.getByRole("menu");
    await userEvent.click(within(menu).getByRole("menuitem", { name: "Edit" }));
    expect(onSelect).toHaveBeenCalled();
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });
  it("closes on Escape", async () => {
    render(<MenuButton items={[{ label: "Delete", onSelect: vi.fn(), danger: true }]} />);
    await userEvent.click(screen.getByRole("button", { name: /options/i }));
    expect(screen.getByRole("menu")).toBeInTheDocument();
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });
  it("closes on an outside click", async () => {
    render(
      <div>
        <button type="button">outside</button>
        <MenuButton items={[{ label: "Edit", onSelect: vi.fn() }]} />
      </div>,
    );
    await userEvent.click(screen.getByRole("button", { name: /options/i }));
    expect(screen.getByRole("menu")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "outside" }));
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });
});
