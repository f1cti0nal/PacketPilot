import type { LegalContent } from "./types";

/** Generic prose renderer for a structured legal/trust page (design-token styled). */
export function LegalPage({ content }: { content: LegalContent }) {
  return (
    <article className="mx-auto w-full max-w-3xl px-4 py-10">
      <header className="mb-8">
        <h1 className="font-display text-2xl font-medium tracking-tight text-[var(--color-text)]">{content.title}</h1>
        {content.subtitle && <p className="mt-1 text-sm text-[var(--color-text-dim)]">{content.subtitle}</p>}
        {content.updated && <p className="mt-2 t-tag text-[var(--color-text-faint)]">Last updated {content.updated}</p>}
        <p className="mt-4 text-[15px] leading-relaxed text-[var(--color-text-dim)]">{content.lead}</p>
      </header>

      <div className="flex flex-col gap-8">
        {content.sections.map((s, i) => (
          <section key={i}>
            <h2 className="t-title mb-2 text-[var(--color-text)]">{s.heading}</h2>
            <div className="flex flex-col gap-3">
              {s.blocks.map((b, j) =>
                b.bullets ? (
                  <ul key={j} className="ml-5 flex list-disc flex-col gap-1.5 text-sm leading-relaxed text-[var(--color-text-dim)]">
                    {b.bullets.map((x, k) => (
                      <li key={k}>{x}</li>
                    ))}
                  </ul>
                ) : (
                  <p key={j} className="text-sm leading-relaxed text-[var(--color-text-dim)]">
                    {b.p}
                  </p>
                ),
              )}
            </div>
          </section>
        ))}

        {content.faq && content.faq.length > 0 && (
          <section>
            <h2 className="t-title mb-3 text-[var(--color-text)]">Frequently asked</h2>
            <div className="flex flex-col gap-4">
              {content.faq.map((f, i) => (
                <div key={i}>
                  <h3 className="text-sm font-medium text-[var(--color-text)]">{f.q}</h3>
                  <p className="mt-1 text-sm leading-relaxed text-[var(--color-text-dim)]">{f.a}</p>
                </div>
              ))}
            </div>
          </section>
        )}
      </div>
    </article>
  );
}

export default LegalPage;
