import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { PreferencesSection } from "./PreferencesSection";

describe("PreferencesSection", () => {
  it("renders Theme + Density controls", () => {
    render(<PreferencesSection />);
    expect(screen.getByRole("heading", { name: /preferences/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /theme/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /density/i })).toBeInTheDocument();
  });
});
