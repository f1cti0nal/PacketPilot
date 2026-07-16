import { ArrowLeft, ArrowRight } from "lucide-react";
import type { BlogPost as Post } from "./types";
import { ContentSections } from "../seo/ContentSections";
import { BLOG_POSTS } from "./registry";
import { formatPostDate } from "./date";

/** Renders a single blog post: standfirst + meta, content sections, CTA, and more-posts nav. */
export function BlogPost({ post }: { post: Post }) {
  const more = BLOG_POSTS.filter((p) => p.slug !== post.slug).slice(0, 3);
  return (
    <article className="mx-auto w-full max-w-3xl px-4 py-10">
      <a
        href="/blog"
        className="inline-flex items-center gap-1.5 text-sm text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
      >
        <ArrowLeft size={14} aria-hidden /> All posts
      </a>

      <header className="mb-8 mt-6">
        <div className="flex flex-wrap items-center gap-2 t-tag text-[var(--color-text-faint)]">
          <time dateTime={post.date}>{formatPostDate(post.date)}</time>
          <span aria-hidden>·</span>
          <span>{post.readingMinutes} min read</span>
        </div>
        <h1 className="mt-3 font-display text-3xl font-medium leading-tight tracking-tight text-[var(--color-text)]">
          {post.title}
        </h1>
        <p className="mt-4 text-base leading-relaxed text-[var(--color-text-dim)]">{post.dek}</p>
        <div className="mt-4 flex flex-wrap gap-2">
          {post.tags.map((t) => (
            <span
              key={t}
              className="rounded-full border border-[var(--color-border)] px-2.5 py-0.5 t-tag text-[var(--color-text-dim)]"
            >
              {t}
            </span>
          ))}
        </div>
      </header>

      <div className="flex flex-col gap-8">
        <ContentSections sections={post.sections} />

        <div className="rounded-[var(--r-card)] border border-[var(--color-border)] bg-[var(--color-surface-2)] p-6 text-center">
          <p className="text-sm text-[var(--color-text-dim)]">
            Reproduce this in about ten seconds. No account required.
          </p>
          <a
            href="/app?sample=1"
            className="mt-3 inline-flex items-center gap-1.5 rounded-full bg-[var(--color-accent-deep)] px-5 py-2 text-sm font-medium text-[var(--color-on-accent)]"
          >
            Open the live sample
            <ArrowRight size={15} aria-hidden />
          </a>
        </div>

        {more.length > 0 && (
          <nav className="border-t border-[var(--color-border)] pt-6">
            <div className="t-label mb-2 text-[var(--color-text-faint)]">More posts</div>
            <ul className="flex flex-col gap-1.5">
              {more.map((p) => (
                <li key={p.slug}>
                  <a href={`/blog/${p.slug}`} className="text-sm text-[var(--color-accent-strong)] hover:underline">
                    {p.title}
                  </a>
                </li>
              ))}
            </ul>
          </nav>
        )}
      </div>
    </article>
  );
}

export default BlogPost;
