import { describe, it, expect } from "vitest";
import { SEO_PAGES, seoBySlug } from "./registry";
import { TOOL_SLUGS } from "./slugs";

describe("seo registry", () => {
  it("pages.json covers exactly the routed TOOL_SLUGS", () => {
    expect(new Set(SEO_PAGES.map((p) => p.slug))).toEqual(new Set(TOOL_SLUGS));
  });

  it("every page has SEO-ready meta + body content", () => {
    for (const p of SEO_PAGES) {
      expect(p.metaTitle.length, p.slug).toBeGreaterThan(10);
      expect(p.metaTitle.length, p.slug).toBeLessThanOrEqual(70);
      expect(p.metaDescription.length, p.slug).toBeGreaterThan(50);
      expect(p.metaDescription.length, p.slug).toBeLessThanOrEqual(170);
      expect(p.h1.length, p.slug).toBeGreaterThan(0);
      expect(p.sections.length, p.slug).toBeGreaterThan(0);
      expect(p.faq.length, p.slug).toBeGreaterThan(0);
      expect(seoBySlug[p.slug]).toBe(p);
    }
  });
});
