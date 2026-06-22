/** Group evidence strings by the signal prefix before the first ":". Prefix-less strings group under `null`. */
function groupEvidence(evidence: string[]): { label: string | null; items: string[] }[] {
  const order: (string | null)[] = [];
  const groups = new Map<string | null, string[]>();
  for (const e of evidence) {
    const idx = e.indexOf(":");
    const label = idx > 0 ? e.slice(0, idx).trim() : null;
    const item = idx > 0 ? e.slice(idx + 1).trim() : e;
    if (!groups.has(label)) {
      groups.set(label, []);
      order.push(label);
    }
    groups.get(label)!.push(item);
  }
  return order.map((label) => ({ label, items: groups.get(label)! }));
}

/** Renders the full evidence[] list, grouped by signal prefix. Renders nothing when empty. */
export function EvidenceList({ evidence }: { evidence: string[] }) {
  if (!evidence || evidence.length === 0) return null;
  const groups = groupEvidence(evidence);
  return (
    <ul className="flex flex-col gap-1.5">
      {groups.map((g, gi) => (
        <li key={gi} className="flex flex-col gap-0.5">
          {g.label && (
            <span className="font-mono-num text-[0.65rem] uppercase tracking-wide text-[var(--color-text-faint)]">
              {g.label}
            </span>
          )}
          <ul className="flex flex-col gap-0.5">
            {g.items.map((item, ii) => (
              <li
                key={ii}
                className="flex gap-1.5 text-xs leading-snug text-[var(--color-text-faint)]"
              >
                <span aria-hidden className="select-none">·</span>
                <span className="min-w-0 break-words">{item}</span>
              </li>
            ))}
          </ul>
        </li>
      ))}
    </ul>
  );
}
