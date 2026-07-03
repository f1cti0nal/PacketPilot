import { ArrowRight } from "lucide-react";
import type { SeoPage } from "./types";
import { SEO_PAGES } from "./registry";

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
        {page.sections.map((s, i) => (
          <section key={i}>
            <h2 className="t-title mb-2 text-[var(--color-text)]">{s.heading}</h2>
            <div className="flex flex-col gap-3">
              {s.blocks.map((b, j) => {
                if (b.table) {
                  const t = b.table;
                  return (
                    <div key={j} className="-mx-1 overflow-x-auto">
                      <table className="w-full min-w-[560px] border-collapse text-sm">
                        {t.caption ? <caption className="sr-only">{t.caption}</caption> : null}
                        <thead>
                          <tr>
                            {t.columns.map((c, ci) => (
                              <th
                                key={ci}
                                scope="col"
                                className={
                                  "border-b border-[var(--color-border)] px-3 py-2 text-left align-bottom t-label " +
                                  (ci === t.highlight ? "text-[var(--color-accent)]" : "text-[var(--color-text-faint)]")
                                }
                              >
                                {c}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {t.rows.map((row, ri) => (
                            <tr key={ri}>
                              {row.map((cell, ci) =>
                                ci === 0 ? (
                                  <th
                                    key={ci}
                                    scope="row"
                                    className="border-t border-[var(--color-border)] px-3 py-2.5 text-left align-top font-medium text-[var(--color-text)]"
                                  >
                                    {cell}
                                  </th>
                                ) : (
                                  <td
                                    key={ci}
                                    className={
                                      "border-t border-[var(--color-border)] px-3 py-2.5 align-top leading-relaxed " +
                                      (ci === t.highlight
                                        ? "bg-[color:color-mix(in_srgb,var(--color-accent)_8%,transparent)] text-[var(--color-text)]"
                                        : "text-[var(--color-text-dim)]")
                                    }
                                  >
                                    {cell}
                                  </td>
                                ),
                              )}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  );
                }
                if (b.bullets) {
                  return (
                    <ul key={j} className="ml-5 flex list-disc flex-col gap-1.5 text-sm leading-relaxed text-[var(--color-text-dim)]">
                      {b.bullets.map((x, k) => (
                        <li key={k}>{x}</li>
                      ))}
                    </ul>
                  );
                }
                return (
                  <p key={j} className="text-sm leading-relaxed text-[var(--color-text-dim)]">
                    {b.p}
                  </p>
                );
              })}
            </div>
          </section>
        ))}

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
