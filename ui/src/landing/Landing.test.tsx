import { render } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { Landing } from "./Landing";

describe("Landing", () => {
  it("renders the scoped marketing page with hero copy", () => {
    const { container } = render(<Landing />);
    expect(container.querySelector(".pp-landing")).not.toBeNull();
    expect(container.textContent).toContain("Network forensics");
  });

  it("points every primary CTA at the app route", () => {
    const { container } = render(<Landing />);
    const launches = container.querySelectorAll('a.pp-btn-primary[href="/app"]');
    expect(launches.length).toBeGreaterThanOrEqual(2);
  });

  it("uses the honest, right-sized detector count (no overstated 50+)", () => {
    const { container } = render(<Landing />);
    expect(container.textContent).not.toContain("50+");
    expect(container.textContent).toContain("20+");
  });
});
