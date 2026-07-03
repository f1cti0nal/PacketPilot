import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AdminTopBar } from "./AdminTopBar";

describe("AdminTopBar", () => {
  it("renders the section title and subtitle", () => {
    render(<AdminTopBar title="Payments" subtitle="Subscriptions and revenue" onJump={vi.fn()} />);
    expect(screen.getByRole("heading", { name: "Payments" })).toBeInTheDocument();
    expect(screen.getByText("Subscriptions and revenue")).toBeInTheDocument();
  });

  it("jumps to the first matching section on submit", async () => {
    const onJump = vi.fn();
    render(<AdminTopBar title="Dashboard" onJump={onJump} />);
    await userEvent.type(screen.getByRole("searchbox", { name: /jump to a section/i }), "pay{Enter}");
    expect(onJump).toHaveBeenCalledWith("payments");
  });

  it("does nothing when the query matches no section", async () => {
    const onJump = vi.fn();
    render(<AdminTopBar title="Dashboard" onJump={onJump} />);
    await userEvent.type(screen.getByRole("searchbox", { name: /jump to a section/i }), "zzz{Enter}");
    expect(onJump).not.toHaveBeenCalled();
  });
});
