// ui/src/cockpit/match.ts
// Dependency-free subsequence fuzzy matcher for the command palette.
// Returns a score (higher = better) or null when `query` is not a subsequence
// of `target`. Case-insensitive. Empty query => 0 (matches everything).
export function fuzzyScore(query: string, target: string): number | null {
  const q = query.trim().toLowerCase();
  if (q === "") return 0;
  const t = target.toLowerCase();
  let score = 0;
  let ti = 0;
  let prev = -2;
  for (let qi = 0; qi < q.length; qi++) {
    const found = t.indexOf(q[qi], ti);
    if (found === -1) return null;
    if (found === prev + 1) score += 3; // contiguous run
    if (found === 0) score += 5; // prefix
    else if (/[.\s:_/-]/.test(t[found - 1])) score += 2; // word boundary
    score += 1;
    prev = found;
    ti = found + 1;
  }
  return score - target.length * 0.05; // prefer tighter targets
}
