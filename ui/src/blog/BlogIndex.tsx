import { ArrowRight } from "lucide-react";
import { BLOG_POSTS } from "./registry";
import { formatPostDate } from "./date";

/** The /blog index — a list of post cards, newest first. */
export function BlogIndex() {
  return (
    <div className="mx-auto w-full max-w-3xl px-4 py-10">
      <header className="mb-8">
        <h1 className="font-display text-3xl font-medium tracking-tight text-[var(--color-text)]">
          The PacketPilot blog
        </h1>
        <p className="mt-3 text-base leading-relaxed text-[var(--color-text-dim)]">
          Network-forensics teardowns, detection notes, and how the engine thinks, all analyzed in the browser,
          nothing uploaded.
        </p>
      </header>

      <ul className="flex flex-col gap-4">
        {BLOG_POSTS.map((p) => (
          <li key={p.slug}>
            <a
              href={`/blog/${p.slug}`}
              className="block rounded-[var(--r-card)] border border-[var(--color-border)] bg-[var(--color-surface)] p-5 transition-colors hover:border-[var(--color-border-strong)]"
            >
              <div className="flex flex-wrap items-center gap-2 t-tag text-[var(--color-text-faint)]">
                <time dateTime={p.date}>{formatPostDate(p.date)}</time>
                <span aria-hidden>·</span>
                <span>{p.readingMinutes} min read</span>
              </div>
              <h2 className="mt-2 font-display text-xl font-medium tracking-tight text-[var(--color-text)]">
                {p.title}
              </h2>
              <p className="mt-1.5 text-sm leading-relaxed text-[var(--color-text-dim)]">{p.dek}</p>
              <span className="mt-3 inline-flex items-center gap-1 text-sm font-medium text-[var(--color-accent-strong)]">
                Read
                <ArrowRight size={14} aria-hidden />
              </span>
            </a>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default BlogIndex;
