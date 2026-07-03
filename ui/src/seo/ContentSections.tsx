import type { SeoSection } from "./types";

/**
 * Renders an array of content sections (heading + blocks) shared by the SEO tool pages
 * and the blog. Each block is a paragraph, a bullet list, or a comparison table. Returned
 * as a fragment of <section> elements so callers control the surrounding layout/spacing.
 */
export function ContentSections({ sections }: { sections: SeoSection[] }) {
  return (
    <>
      {sections.map((s, i) => (
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
    </>
  );
}

export default ContentSections;
