/** Whole days remaining in a reverse-trial (0 if expired/absent). */
export function trialDaysLeft(trialEndsAt: string | null): number {
  if (!trialEndsAt) return 0;
  const ms = Date.parse(trialEndsAt) - Date.now();
  return ms <= 0 ? 0 : Math.ceil(ms / 86_400_000);
}

/** True while a user is on an active reverse-trial: effective Pro, a future trial end, no billing. */
export function isOnTrial(p: { plan: string; trialEndsAt: string | null; hasBilling: boolean }): boolean {
  return p.plan === "pro" && !p.hasBilling && trialDaysLeft(p.trialEndsAt) > 0;
}
