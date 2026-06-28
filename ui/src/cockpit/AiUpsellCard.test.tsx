import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const startCheckout = vi.fn().mockResolvedValue({ ok: true });
vi.mock("../auth/billing", () => ({ startCheckout: () => startCheckout() }));

import { AiUpsellCard } from "./AiUpsellCard";

describe("AiUpsellCard", () => {
  it("renders the upsell and starts checkout on click", async () => {
    render(<AiUpsellCard />);
    expect(screen.getByText(/pro feature/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /upgrade to pro/i }));
    expect(startCheckout).toHaveBeenCalled();
  });
});
