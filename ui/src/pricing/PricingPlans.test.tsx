import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const sess = vi.hoisted(() => ({ useSession: vi.fn() }));
vi.mock("../auth/useSession", () => sess);
const pricing = vi.hoisted(() => ({ usePricing: vi.fn() }));
vi.mock("./usePricing", () => pricing);
const billing = vi.hoisted(() => ({ startCheckout: vi.fn() }));
vi.mock("../auth/billing", () => billing);
vi.mock("../auth/AuthDialog", () => ({ AuthDialog: () => <div>auth-dialog</div> }));

import { PricingPlans } from "./PricingPlans";

const authedFree = {
  status: "authed",
  email: "a@b.com",
  profile: { email: "a@b.com", full_name: "A", plan: "free", hasBilling: false },
  signOut: vi.fn(),
};
const fullStatus = { annual_available: true, founder_available: true, founder_cap: 200, founder_remaining: 137 };

beforeEach(() => {
  billing.startCheckout.mockResolvedValue({ ok: true });
  sess.useSession.mockReturnValue(authedFree);
  pricing.usePricing.mockReturnValue({ status: fullStatus, loading: false });
});
afterEach(() => {
  vi.clearAllMocks();
});

describe("PricingPlans", () => {
  it("renders the Pro + Founder cards with the live seat counter", () => {
    render(<PricingPlans />);
    expect(screen.getByRole("heading", { name: "Pro" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /founder/i })).toBeInTheDocument();
    expect(screen.getByText("$190")).toBeInTheDocument(); // annual default
    expect(screen.getByText(/137 of 200 seats left/i)).toBeInTheDocument();
  });

  it("subscribes a free user to the annual plan", async () => {
    render(<PricingPlans />);
    fireEvent.click(screen.getByRole("button", { name: /get pro/i }));
    await waitFor(() => expect(billing.startCheckout).toHaveBeenCalledWith("annual"));
  });

  it("switches to monthly via the toggle", async () => {
    render(<PricingPlans />);
    fireEvent.click(screen.getByRole("button", { name: /^monthly/i }));
    expect(screen.getByText("$19")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /get pro/i }));
    await waitFor(() => expect(billing.startCheckout).toHaveBeenCalledWith("monthly"));
  });

  it("claims a founder seat", async () => {
    render(<PricingPlans />);
    fireEvent.click(screen.getByRole("button", { name: /claim a founder seat/i }));
    await waitFor(() => expect(billing.startCheckout).toHaveBeenCalledWith("founder"));
  });

  it("disables the founder CTA when sold out", () => {
    pricing.usePricing.mockReturnValue({ status: { ...fullStatus, founder_remaining: 0 }, loading: false });
    render(<PricingPlans />);
    expect(screen.getByRole("button", { name: /sold out/i })).toBeDisabled();
  });

  it("prompts an anonymous visitor to sign in instead of checking out", () => {
    sess.useSession.mockReturnValue({ status: "anon", signIn: vi.fn(), signUp: vi.fn() });
    render(<PricingPlans />);
    fireEvent.click(screen.getByRole("button", { name: /get pro/i }));
    expect(screen.getByText("auth-dialog")).toBeInTheDocument();
    expect(billing.startCheckout).not.toHaveBeenCalled();
  });

  it("shows a manage-billing link (not Get Pro) for an existing Pro user", () => {
    sess.useSession.mockReturnValue({ ...authedFree, profile: { ...authedFree.profile, plan: "pro" } });
    render(<PricingPlans />);
    expect(screen.getByRole("link", { name: /manage billing/i })).toHaveAttribute("href", "/account");
    expect(screen.queryByRole("button", { name: /get pro/i })).not.toBeInTheDocument();
  });
});
