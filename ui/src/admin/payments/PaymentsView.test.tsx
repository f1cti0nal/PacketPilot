import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const hookState = vi.fn();
const reload = vi.fn();
vi.mock("./useAdminPayments", () => ({ useAdminPayments: () => ({ state: hookState(), reload }) }));

import { PaymentsView } from "./PaymentsView";

const PAYMENTS = [
  { id: "s1", email: "bob@x.com", full_name: "Bob", status: "active", amount_cents: 1900, currency: "usd",
    price_id: "price_1", current_period_end: "2026-07-20T00:00:00Z", cancel_at_period_end: false,
    created_at: "2026-06-20T00:00:00Z", stripe_subscription_id: "sub_1", stripe_customer_id: "cus_1" },
  { id: "s2", email: "al@x.com", full_name: "Al", status: "canceled", amount_cents: 1900, currency: "usd",
    price_id: "price_1", current_period_end: null, cancel_at_period_end: true,
    created_at: "2026-06-21T00:00:00Z", stripe_subscription_id: "sub_2", stripe_customer_id: "cus_2" },
];

beforeEach(() => {
  hookState.mockReturnValue({ status: "ready", payments: PAYMENTS, mrrCents: 1900 });
  reload.mockClear();
});

describe("PaymentsView", () => {
  it("renders a row per subscription and an Active-MRR/active-count KPI strip", () => {
    render(<PaymentsView />);
    const table = screen.getByRole("table");
    expect(within(table).getByText("bob@x.com")).toBeInTheDocument();
    expect(within(table).getByText("al@x.com")).toBeInTheDocument();
    expect(screen.getByText("Active MRR").parentElement).toHaveTextContent("$19");
    expect(screen.getByText("Active subs").parentElement).toHaveTextContent("1");
  });

  it("shows a Cancels-at-period-end badge", () => {
    render(<PaymentsView />);
    expect(screen.getByText(/cancels at period end/i)).toBeInTheDocument();
  });

  it("filters rows client-side by email", async () => {
    render(<PaymentsView />);
    await userEvent.type(screen.getByRole("searchbox", { name: /search payments/i }), "bob");
    const table = screen.getByRole("table");
    expect(within(table).getByText("bob@x.com")).toBeInTheDocument();
    expect(within(table).queryByText("al@x.com")).not.toBeInTheDocument();
  });

  it("Refresh triggers a reload", async () => {
    render(<PaymentsView />);
    await userEvent.click(screen.getByRole("button", { name: /refresh/i }));
    expect(reload).toHaveBeenCalled();
  });

  it("renders the empty and error states", () => {
    hookState.mockReturnValue({ status: "ready", payments: [], mrrCents: 0 });
    const { rerender } = render(<PaymentsView />);
    expect(screen.getByText(/no subscriptions yet/i)).toBeInTheDocument();
    hookState.mockReturnValue({ status: "error", error: "backend down" });
    rerender(<PaymentsView />);
    expect(screen.getByText(/backend down/i)).toBeInTheDocument();
  });
});
