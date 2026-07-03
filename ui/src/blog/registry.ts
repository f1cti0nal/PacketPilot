import postsJson from "./posts.json";
import type { BlogPost } from "./types";

/** All posts, newest first (ISO date strings sort lexicographically). */
export const BLOG_POSTS: BlogPost[] = (postsJson as BlogPost[])
  .slice()
  .sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : 0));

export const blogBySlug: Record<string, BlogPost | undefined> = Object.fromEntries(
  BLOG_POSTS.map((p) => [p.slug, p]),
);
