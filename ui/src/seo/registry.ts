import pagesJson from "./pages.json";
import type { SeoPage } from "./types";

export const SEO_PAGES = pagesJson as SeoPage[];
export const seoBySlug: Record<string, SeoPage | undefined> = Object.fromEntries(
  SEO_PAGES.map((p) => [p.slug, p]),
);
