import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { DemoBanner } from "./DemoBanner";

describe("DemoBanner", () => {
  it("nudges the visitor to sign in or create an account", () => {
    render(<DemoBanner />);
    expect(screen.getByText(/exploring a sample capture/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /create a free account/i })).toHaveAttribute("href", "/signup");
    expect(screen.getByRole("link", { name: /^sign in$/i })).toHaveAttribute("href", "/login");
  });
});
