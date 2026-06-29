import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";

vi.mock("./PricingPlans", () => ({ PricingPlans: () => <div>pricing-plans</div> }));
import { PricingApp } from "./PricingApp";

describe("PricingApp", () => {
  it("renders the shell with the plans and a way back home", () => {
    render(<PricingApp />);
    expect(screen.getByText("pricing-plans")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /back to home/i })).toHaveAttribute("href", "/");
  });
});
