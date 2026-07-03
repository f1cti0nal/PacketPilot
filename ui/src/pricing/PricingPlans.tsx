import { useEffect, useState } from "react";
import { Check } from "lucide-react";
import { useSession } from "../auth/useSession";
import { startCheckout, type PlanChoice } from "../auth/billing";
import { AuthDialog } from "../auth/AuthDialog";
import { usePricing } from "./usePricing";

const PRO_FEATURES = [
  "Unlimited captures & larger files",
  "All exports — STIX, MISP, CEF, Sigma, HTML report",
  "AI analyst summary + reputation enrichment",
  "PCAP & file carving, multi-capture compare, saved rules",
];

const ctaPrimary =
  "mt-5 inline-flex items-center justify-center rounded-full bg-[var(--color-accent-deep)] px-5 py-2 text-sm font-medium text-[var(--color-on-accent)] disabled:opacity-50";
const ctaGhost =
  "mt-5 inline-flex items-center justify-center rounded-full border border-[var(--color-border-strong)] px-5 py-2 text-sm font-medium text-[var(--color-text-dim)] hover:text-[var(--color-text)]";

/** Survives the sign-in step (OAuth redirect or the in-page dialog) so we can resume checkout. */
const PENDING_KEY = "pp.pending_plan";

export function PricingPlans() {
  const session = useSession();
  const { status, loading } = usePricing();
  const [period, setPeriod] = useState<"monthly" | "annual">("annual");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [authOpen, setAuthOpen] = useState(false);

  // If annual isn't configured yet, the toggle is hidden — pin to monthly.
  useEffect(() => {
    if (!loading && !status.annual_available) setPeriod("monthly");
  }, [loading, status.annual_available]);

  // Only a real Stripe customer "manages billing"; trial/comp/free users can still upgrade.
  const hasBilling = session.status === "authed" && session.profile.hasBilling;

  const subscribe = async (plan: PlanChoice) => {
    if (busy) return;
    setBusy(true);
    setError(null);
    const r = await startCheckout(plan);
    if (!r.ok) {
      setError(r.error ?? "Something went wrong");
      setBusy(false);
    }
  };

  const onChoose = (plan: PlanChoice) => {
    if (session.status === "authed") void subscribe(plan);
    else {
      // OAuth sign-in is a full-page redirect, so remember the chosen plan across it.
      try {
        sessionStorage.setItem(PENDING_KEY, plan);
      } catch {
        /* storage disabled — the visitor just re-clicks after signing in */
      }
      setAuthOpen(true);
    }
  };

  // After sign-in completes, resume the checkout the visitor chose.
  useEffect(() => {
    if (session.status !== "authed") return;
    let stored: string | null = null;
    try {
      stored = sessionStorage.getItem(PENDING_KEY);
    } catch {
      /* ignore */
    }
    if (stored) {
      try {
        sessionStorage.removeItem(PENDING_KEY);
      } catch {
        /* ignore */
      }
      setAuthOpen(false);
      void subscribe(stored as PlanChoice);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.status]);

  const founderOut = status.founder_remaining <= 0;

  return (
    <div className="mx-auto w-full max-w-4xl px-4 py-10">
      <header className="mb-8 text-center">
        <h1 className="font-display text-2xl font-medium tracking-tight text-[var(--color-text)]">Simple pricing</h1>
        <p className="mt-2 text-sm text-[var(--color-text-dim)]">
          The analyzer is free forever. Upgrade to Pro for the full analyst toolkit. Cancel anytime.
        </p>
      </header>

      {status.annual_available && (
        <div className="mb-8 flex justify-center">
          <PeriodToggle period={period} onChange={setPeriod} />
        </div>
      )}

      <div className="grid gap-5 sm:grid-cols-2">
        <section className="card flex flex-col p-6">
          <h2 className="t-title text-[var(--color-text)]">Pro</h2>
          <div className="mt-2 flex items-baseline gap-1">
            <span className="font-display text-3xl font-medium text-[var(--color-text)]">
              {period === "annual" ? "$190" : "$19"}
            </span>
            <span className="text-sm text-[var(--color-text-dim)]">/{period === "annual" ? "yr" : "mo"}</span>
          </div>
          {period === "annual" && <p className="t-tag mt-1 text-[var(--color-accent)]">2 months free vs monthly</p>}
          <ul className="mt-4 flex flex-1 flex-col gap-2">
            {PRO_FEATURES.map((f) => (
              <li key={f} className="flex items-start gap-2 text-sm text-[var(--color-text-dim)]">
                <Check size={15} className="mt-0.5 shrink-0 text-[var(--color-accent)]" aria-hidden />
                {f}
              </li>
            ))}
          </ul>
          {hasBilling ? (
            <a href="/account" className={ctaGhost}>
              You're on Pro — manage billing
            </a>
          ) : (
            <button type="button" disabled={busy} onClick={() => onChoose(period)} className={ctaPrimary}>
              {busy ? "Starting…" : "Get Pro"}
            </button>
          )}
        </section>

        {status.founder_available ? (
          <section className="card relative flex flex-col p-6">
            <span className="absolute right-4 top-4 inline-flex items-center rounded-[var(--r-chip)] border border-[color:color-mix(in_srgb,var(--color-accent)_45%,transparent)] bg-[color:color-mix(in_srgb,var(--color-accent)_12%,transparent)] px-2 py-0.5 t-tag uppercase text-[var(--color-accent)]">
              Founder
            </span>
            <h2 className="t-title text-[var(--color-text)]">Founder — annual</h2>
            <div className="mt-2 flex items-baseline gap-1">
              <span className="font-display text-3xl font-medium text-[var(--color-text)]">$149</span>
              <span className="text-sm text-[var(--color-text-dim)]">/yr, rate locked for life</span>
            </div>
            <p className="t-tag mt-1 text-[var(--color-text-dim)]">
              {founderOut ? "Sold out" : `${status.founder_remaining} of ${status.founder_cap} seats left`}
            </p>
            <ul className="mt-4 flex flex-1 flex-col gap-2">
              <li className="flex items-start gap-2 text-sm text-[var(--color-text-dim)]">
                <Check size={15} className="mt-0.5 shrink-0 text-[var(--color-accent)]" aria-hidden />
                Everything in Pro, at a price that never goes up
              </li>
              <li className="flex items-start gap-2 text-sm text-[var(--color-text-dim)]">
                <Check size={15} className="mt-0.5 shrink-0 text-[var(--color-accent)]" aria-hidden />
                Back an indie tool early + help shape the roadmap
              </li>
            </ul>
            <button type="button" disabled={busy || founderOut || hasBilling} onClick={() => onChoose("founder")} className={ctaPrimary}>
              {founderOut ? "Sold out" : hasBilling ? "You're on Pro" : busy ? "Starting…" : "Claim a founder seat"}
            </button>
          </section>
        ) : (
          <section className="card flex flex-col p-6">
            <h2 className="t-title text-[var(--color-text)]">Free</h2>
            <div className="mt-2 flex items-baseline gap-1">
              <span className="font-display text-3xl font-medium text-[var(--color-text)]">$0</span>
            </div>
            <ul className="mt-4 flex flex-1 flex-col gap-2">
              <li className="flex items-start gap-2 text-sm text-[var(--color-text-dim)]">
                <Check size={15} className="mt-0.5 shrink-0 text-[var(--color-accent)]" aria-hidden />
                Full in-browser triage — unlimited on the free plan
              </li>
              <li className="flex items-start gap-2 text-sm text-[var(--color-text-dim)]">
                <Check size={15} className="mt-0.5 shrink-0 text-[var(--color-accent)]" aria-hidden />
                Behavioral detectors, MITRE mapping, dashboards
              </li>
            </ul>
            <a href="/app" className={ctaGhost}>
              Open the app
            </a>
          </section>
        )}
      </div>

      {error && (
        <p role="alert" className="mt-4 text-center t-tag text-[var(--color-sev-critical)]">
          {error}
        </p>
      )}

      {authOpen && session.status === "anon" && (
        <AuthDialog
          session={session}
          onClose={() => setAuthOpen(false)}
        />
      )}
    </div>
  );
}

function PeriodToggle({ period, onChange }: { period: "monthly" | "annual"; onChange: (p: "monthly" | "annual") => void }) {
  return (
    <div role="group" aria-label="Billing period" className="inline-flex items-center gap-0.5 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] p-0.5">
      {(["monthly", "annual"] as const).map((p) => (
        <button
          key={p}
          type="button"
          aria-pressed={period === p}
          onClick={() => onChange(p)}
          className={
            "rounded-[var(--r-chip)] px-3 py-1 text-xs font-medium capitalize transition-colors " +
            (period === p
              ? "bg-[var(--color-bg)] text-[var(--color-text)]"
              : "text-[var(--color-text-dim)] hover:text-[var(--color-text)]")
          }
        >
          {p}
          {p === "annual" && <span className="ml-1 text-[var(--color-accent)]">−17%</span>}
        </button>
      ))}
    </div>
  );
}

export default PricingPlans;
