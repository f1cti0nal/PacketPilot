import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ToolPage } from "./ToolPage";
import { SEO_PAGES } from "./registry";

describe("ToolPage", () => {
  it("renders the hero, a CTA to the app, FAQ, and related links", () => {
    const page = SEO_PAGES[0];
    render(<ToolPage page={page} />);
    expect(screen.getByRole("heading", { level: 1, name: page.h1 })).toBeInTheDocument();
    expect(screen.getByText(page.lead)).toBeInTheDocument();
    // at least one CTA links to the app, plus a "try a sample" deep-link
    const appLinks = screen.getAllByRole("link").filter((a) => a.getAttribute("href") === "/app");
    expect(appLinks.length).toBeGreaterThan(0);
    expect(screen.getByRole("link", { name: /try a sample/i })).toHaveAttribute("href", "/app?sample=1");
    // FAQ heading present
    expect(screen.getByRole("heading", { name: /frequently asked/i })).toBeInTheDocument();
    // a related link points at another tool page
    const other = SEO_PAGES.find((p) => p.slug !== page.slug)!;
    expect(screen.getByRole("link", { name: other.h1 })).toHaveAttribute("href", `/${other.slug}`);
  });
});
