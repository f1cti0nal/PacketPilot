import { ArrowRight } from "lucide-react";
import type { SeoPage } from "./types";
import { SEO_PAGES } from "./registry";
import { ContentSections } from "./ContentSections";

/** Renders one keyword-targeted SEO landing page: hero + CTA, content sections, FAQ, related. */
export function ToolPage({ page }: { page: SeoPage }) {
  const related = SEO_PAGES.filter((p) => p.slug !== page.slug).slice(0, 4);
  return (
    <article className="mx-auto w-full max-w-3xl px-4 py-10">
      <header className="mb-8">
        <h1 className="font-display text-3xl font-medium leading-tight tracking-tight text-[var(--color-text)]">
          {page.h1}
        </h1>
        <p className="mt-4 text-base leading-relaxed text-[var(--color-text-dim)]">{page.lead}</p>
        <div className="mt-6 flex flex-wrap items-center gap-3">
          <a
            href="/app"
            className="inline-flex items-center gap-1.5 rounded-full bg-[var(--color-accent-deep)] px-5 py-2 text-sm font-medium text-[var(--color-on-accent)]"
          >
            Analyze a PCAP — free
            <ArrowRight size={15} aria-hidden />
          </a>
          <a href="/app?sample=1" className="text-sm text-[var(--color-accent-strong)] hover:underline">
            or try a sample capture
          </a>
          <span className="t-tag text-[var(--color-text-faint)]">Free to start · nothing uploaded</span>
        </div>
      </header>

      <div className="flex flex-col gap-8">
        <ContentSections sections={page.sections} />

        <section>
          <h2 className="t-title mb-3 text-[var(--color-text)]">Frequently asked</h2>
          <div className="flex flex-col gap-4">
            {page.faq.map((f, i) => (
              <div key={i}>
                <h3 className="text-sm font-medium text-[var(--color-text)]">{f.q}</h3>
                <p className="mt-1 text-sm leading-relaxed text-[var(--color-text-dim)]">{f.a}</p>
              </div>
            ))}
          </div>
        </section>

        <div className="rounded-[var(--r-card)] border border-[var(--color-border)] bg-[var(--color-surface-2)] p-6 text-center">
          <p className="text-sm text-[var(--color-text-dim)]">
            Drop a capture and get a scored, MITRE-mapped verdict in seconds — in your browser.
          </p>
          <a
            href="/app"
            className="mt-3 inline-flex items-center gap-1.5 rounded-full bg-[var(--color-accent-deep)] px-5 py-2 text-sm font-medium text-[var(--color-on-accent)]"
          >
            Open PacketPilot
            <ArrowRight size={15} aria-hidden />
          </a>
        </div>

        {related.length > 0 && (
          <nav className="border-t border-[var(--color-border)] pt-6">
            <div className="t-label mb-2 text-[var(--color-text-faint)]">Related</div>
            <ul className="flex flex-col gap-1.5">
              {related.map((p) => (
                <li key={p.slug}>
                  <a href={`/${p.slug}`} className="text-sm text-[var(--color-accent-strong)] hover:underline">
                    {p.h1}
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

export default ToolPage;
