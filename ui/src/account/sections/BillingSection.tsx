import { useState } from "react";
import { openPortal } from "../../auth/billing";
import { isOnTrial, trialDaysLeft } from "../../auth/trial";
import type { AccountSubscription } from "../useAccount";
import { Card, btnCls, btnGhost } from "./ui";

const money = (cents: number | null, currency: string) =>
  cents == null
    ? "—"
    : new Intl.NumberFormat(undefined, { style: "currency", currency: currency.toUpperCase() }).format(cents / 100);
const day = (iso: string | null) =>
  iso ? new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : null;

export function BillingSection({
  plan,
  subscription,
  trialEndsAt = null,
}: {
  plan: string;
  subscription: AccountSubscription | null;
  trialEndsAt?: string | null;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const isPro = plan === "pro";
  // "Real" billing means an actual Stripe customer. A Pro plan without one is an
  // admin comp (or seed/demo) — there's no portal to open, so show a note instead.
  const hasBilling = isPro && !!subscription?.stripe_customer_id;
  const onTrial = isOnTrial({ plan, trialEndsAt, hasBilling });

  const run = async (fn: () => Promise<{ ok: boolean; error?: string }>) => {
    if (busy) return;
    setBusy(true);
    setError(null);
    const r = await fn();
    if (!r?.ok) {
      setError(r?.error ?? "Something went wrong");
      setBusy(false);
    }
  };

  return (
    <Card title="Plan & billing" desc="Your subscription and payment details.">
      <div className="flex items-center gap-2">
        <span className="inline-flex items-center rounded-[var(--r-chip)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-0.5 t-tag uppercase text-[var(--color-text)]">
          {plan}
        </span>
        {hasBilling && subscription && (
          <span className="t-tag text-[var(--color-text-dim)]">· {subscription.status}</span>
        )}
      </div>

      {hasBilling && subscription ? (
        <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-sm">
          <dt className="text-[var(--color-text-dim)]">Price</dt>
          <dd className="font-mono-num text-[var(--color-text)]">{money(subscription.amount_cents, subscription.currency)}/mo</dd>
          {subscription.current_period_end && (
            <>
              <dt className="text-[var(--color-text-dim)]">{subscription.cancel_at_period_end ? "Cancels on" : "Renews on"}</dt>
              <dd className="text-[var(--color-text)]">{day(subscription.current_period_end)}</dd>
            </>
          )}
        </dl>
      ) : onTrial ? (
        <p className="text-sm text-[var(--color-text-dim)]">
          You're on a Pro trial —{" "}
          <span className="text-[var(--color-accent)]">{trialDaysLeft(trialEndsAt)} days left</span>. Upgrade to keep
          Pro features when it ends.
        </p>
      ) : (
        <p className="text-sm text-[var(--color-text-dim)]">
          {/* Pro without a Stripe customer or trial = access granted by an admin (comp), not a
              purchase — there is no billing portal to open, so don't offer one below. */}
          {isPro
            ? "Your Pro plan was granted by an administrator — there's no billing to manage here."
            : "You're on the Free plan."}
        </p>
      )}

      <div className="flex items-center gap-2 empty:hidden">
        {(!isPro || onTrial) && (
          <a href="/pricing" className={btnCls}>
            {onTrial ? "Upgrade to keep Pro" : "Upgrade to Pro"}
          </a>
        )}
        {hasBilling && (
          <button type="button" disabled={busy} onClick={() => void run(openPortal)} className={btnGhost}>
            {busy ? "Opening…" : "Manage billing"}
          </button>
        )}
      </div>
      {error && (
        <p role="alert" className="t-tag text-[var(--color-sev-critical)]">
          {error}
        </p>
      )}
    </Card>
  );
}

export default BillingSection;
