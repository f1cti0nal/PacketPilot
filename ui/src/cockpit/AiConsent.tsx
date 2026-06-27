import { useDialogA11y } from "../lib/useDialogA11y";
import { isLoopbackUrl, aiNeedsRelay } from "../lib/ai/loopback";

export function AiConsent({ baseUrl, model, onProceed, onCancel }:
  { baseUrl: string; model: string; onProceed: () => void; onCancel: () => void }) {
  // Exact-hostname loopback check (shared with pickTransport) — never a prefix match, so a
  // spoof like http://localhost.evil.com is NOT reassured as "stays on this device".
  const local = isLoopbackUrl(baseUrl);
  // In the browser a non-loopback endpoint with no relay configured will fail at egress; warn now
  // rather than after the user proceeds into a terse runtime error.
  const needsRelay = aiNeedsRelay(baseUrl);
  const { ref, onKeyDown } = useDialogA11y(onCancel);
  return (
    <div ref={ref} onKeyDown={onKeyDown} role="dialog" aria-modal="true" aria-label="AI consent" className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="w-full max-w-md rounded-[var(--r-card)] border border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text)] shadow-[var(--sh-float)]">
        <div className="border-b border-[var(--color-border)] px-5 py-4">
          <h2 className="text-sm font-medium">Send the analysis summary to the model?</h2>
        </div>
        <div className="px-5 py-4">
          <p className="text-xs text-[var(--color-text-dim)]">
            Your analysis <b>summary</b> — severity counts, top incidents, threat IPs (with evidence), and the domains contacted
            (never raw packets, payloads, or the capture file) — will be sent to <b>{baseUrl}</b> using
            model <b>{model}</b>. {local ? "This endpoint is local — it stays on this device." : ""}
          </p>
          {needsRelay && (
            <p className="mt-3 rounded-[var(--r-micro)] border border-[var(--color-sev-medium)] bg-[var(--color-surface-2)] p-3 text-xs text-[var(--color-text-dim)]">
              In the browser this cloud endpoint needs a <b>relay URL</b> (set one as the Proxy URL in
              Settings), or the request will fail. Alternatively use a local model (Ollama on localhost)
              or the desktop app, which talk to the provider directly.
            </p>
          )}
        </div>
        <div className="flex justify-end gap-2 border-t border-[var(--color-border)] px-5 py-3">
          <button type="button" className="rounded-[var(--r-micro)] border border-[var(--color-border)] bg-transparent px-3 py-1.5 text-xs font-medium text-[var(--color-text-dim)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]" onClick={onCancel}>Cancel</button>
          <button type="button" className="rounded-[var(--r-micro)] bg-[var(--color-accent-deep)] px-3 py-1.5 text-xs font-medium text-[var(--color-on-accent)] transition-opacity hover:opacity-90" onClick={onProceed}>Proceed</button>
        </div>
      </div>
    </div>
  );
}
