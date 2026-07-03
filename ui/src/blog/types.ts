import type { SeoSection } from "../seo/types";

/** A blog post. Body `sections` reuse the shared SeoSection/SeoBlock content model
 *  (paragraphs, bullet lists, comparison tables) rendered by ContentSections. */
export interface BlogPost {
  slug: string;
  metaTitle: string;
  metaDescription: string;
  title: string;
  /** One-line standfirst under the title. */
  dek: string;
  /** ISO date (YYYY-MM-DD) — used for display and the sitemap/JSON-LD. */
  date: string;
  readingMinutes: number;
  tags: string[];
  author: string;
  sections: SeoSection[];
}
