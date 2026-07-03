import { describe, expect, it } from "vitest";
import { BLOG_POSTS, blogBySlug } from "./registry";
import { BLOG_SLUGS } from "./slugs";

describe("blog registry", () => {
  it("posts.json covers exactly the BLOG_SLUGS", () => {
    expect(new Set(BLOG_POSTS.map((p) => p.slug))).toEqual(new Set(BLOG_SLUGS));
  });

  it("each post has sane, crawlable metadata", () => {
    for (const p of BLOG_POSTS) {
      expect(p.metaTitle.length, p.slug).toBeGreaterThan(10);
      expect(p.metaTitle.length, p.slug).toBeLessThanOrEqual(70);
      expect(p.metaDescription.length, p.slug).toBeGreaterThan(50);
      expect(p.metaDescription.length, p.slug).toBeLessThanOrEqual(170);
      expect(p.title.length, p.slug).toBeGreaterThan(0);
      expect(p.dek.length, p.slug).toBeGreaterThan(0);
      expect(/^\d{4}-\d{2}-\d{2}$/.test(p.date), p.slug).toBe(true);
      expect(p.readingMinutes, p.slug).toBeGreaterThan(0);
      expect(p.sections.length, p.slug).toBeGreaterThan(0);
      expect(blogBySlug[p.slug]).toBe(p);
    }
  });

  it("orders posts newest-first", () => {
    const dates = BLOG_POSTS.map((p) => p.date);
    expect([...dates].sort().reverse()).toEqual(dates);
  });
});
