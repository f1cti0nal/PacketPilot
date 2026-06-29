import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

const billing = vi.hoisted(() => ({ startCheckout: vi.fn(), openPortal: vi.fn() }));
vi.mock("../../auth/billing", () => billing);
import { BillingSection } from "./BillingSection";
import type { AccountSubscription } from "../useAccount";

const sub: AccountSubscription = {
  status: "active",
  price_id: "price_1",
  amount_cents: 1900,
  currency: "usd",
  current_period_end: "2026-07-20T00:00:00Z",
  cancel_at_period_end: false,
  stripe_customer_id: "cus_1",
};

beforeEach(() => {
  billing.startCheckout.mockResolvedValue({ ok: true });
  billing.openPortal.mockResolvedValue({ ok: true });
  vi.clearAllMocks();
});

describe("BillingSection", () => {
  it("shows subscription detail + Manage billing for pro", () => {
    render(<BillingSection plan="pro" subscription={sub} />);
    expect(screen.getByText(/active/)).toBeInTheDocument();
    expect(screen.getByText(/\$19\.00\/mo/)).toBeInTheDocument();
    expect(screen.getByText(/Renews on/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /manage billing/i }));
    expect(billing.openPortal).toHaveBeenCalled();
  });

  it("shows Upgrade for a free user with no subscription", () => {
    render(<BillingSection plan="free" subscription={null} />);
    expect(screen.getByText(/Free plan/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /upgrade to pro/i }));
    expect(billing.startCheckout).toHaveBeenCalled();
  });

  it("explains comped Pro (no subscription) and offers no billing button", () => {
    render(<BillingSection plan="pro" subscription={null} />);
    expect(screen.getByText(/granted by an administrator/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /manage billing/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /upgrade to pro/i })).not.toBeInTheDocument();
  });

  it("treats a Pro with a subscription row but no Stripe customer as comped", () => {
    render(<BillingSection plan="pro" subscription={{ ...sub, stripe_customer_id: null }} />);
    expect(screen.getByText(/granted by an administrator/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /manage billing/i })).not.toBeInTheDocument();
  });

  it("surfaces a billing error inline", async () => {
    billing.openPortal.mockResolvedValue({ ok: false, error: "No billing account yet" });
    render(<BillingSection plan="pro" subscription={sub} />);
    fireEvent.click(screen.getByRole("button", { name: /manage billing/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent("No billing account yet");
  });

  it("labels the date as Cancels on when cancel_at_period_end", () => {
    render(<BillingSection plan="pro" subscription={{ ...sub, cancel_at_period_end: true }} />);
    expect(screen.getByText(/Cancels on/i)).toBeInTheDocument();
  });
});
