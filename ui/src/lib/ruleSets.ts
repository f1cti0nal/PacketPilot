export interface RuleSet { id: string; name: string; text: string }

const KEY = "packetpilot.ruleSets.v1";
const MAX_RULESET_BYTES = 256 * 1024;

function isRuleSet(v: unknown): v is RuleSet {
  if (typeof v !== "object" || v === null) return false;
  const r = v as Record<string, unknown>;
  return typeof r.id === "string" && typeof r.name === "string" && r.name.trim() !== "" && typeof r.text === "string";
}

export function listRuleSets(): RuleSet[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) ? parsed.filter(isRuleSet) : [];
  } catch {
    return [];
  }
}

function persist(list: RuleSet[]): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(list));
  } catch {
    /* quota: drop silently (mirrors filterProfiles) */
  }
}

export function saveRuleSet(name: string, text: string): { ok: boolean; sets: RuleSet[]; message?: string } {
  const trimmed = name.trim();
  if (trimmed === "") return { ok: false, sets: listRuleSets(), message: "Empty name" };
  if (text.length > MAX_RULESET_BYTES) return { ok: false, sets: listRuleSets(), message: "Ruleset too large to save" };
  const list = listRuleSets().filter((s) => s.name !== trimmed);
  // id derives from the (unique, upsert-by-name) trimmed name WITHOUT slug-normalization, so two
  // distinct names can't collide on one id (the slug bug that bit FilterProfile ids — task_f8a7c13d).
  list.push({ id: `rs_${trimmed}`, name: trimmed, text });
  persist(list);
  return { ok: true, sets: list };
}

export function removeRuleSet(id: string): RuleSet[] {
  const list = listRuleSets().filter((s) => s.id !== id);
  persist(list);
  return list;
}

export function clearRuleSets(): RuleSet[] {
  try { localStorage.removeItem(KEY); } catch { /* ignore */ }
  return [];
}
