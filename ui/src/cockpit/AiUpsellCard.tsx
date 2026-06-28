import { Sparkles } from "lucide-react";
import { startCheckout } from "../auth/billing";

export function AiUpsellCard() {
  return (
    <div className="rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] p-4">
      <div className="flex items-center gap-2 text-sm text-[var(--color-text)]">
        <Sparkles size={16} className="text-[var(--color-accent-strong)]" aria-hidden />
        AI Analyst is a Pro feature
      </div>
      <p className="mt-1 t-tag text-[var(--color-text-dim)]">
        Upgrade to Pro to generate an executive summary and chat over this capture.
      </p>
      <button
        type="button"
        onClick={() => void startCheckout()}
        className="mt-2 rounded-[var(--r-micro)] bg-[var(--color-accent)] px-3 py-1.5 text-xs font-medium text-[var(--color-on-accent)] hover:opacity-90"
      >
        Upgrade to Pro
      </button>
    </div>
  );
}

export default AiUpsellCard;
