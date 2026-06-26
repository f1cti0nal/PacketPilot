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
    <div ref={ref} onKeyDown={onKeyDown} role="dialog" aria-modal="true" aria-label="AI consent" className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="max-w-md rounded-lg bg-[var(--color-surface)] p-5 text-[var(--color-text)]">
        <h2 className="text-sm font-semibold">Send the analysis summary to the model?</h2>
        <p className="mt-2 text-xs text-[var(--color-text-faint)]">
          Your analysis <b>summary</b> — severity counts, top incidents, threat IPs (with evidence), and the domains contacted
          (never raw packets, payloads, or the capture file) — will be sent to <b>{baseUrl}</b> using
          model <b>{model}</b>. {local ? "This endpoint is local — it stays on this device." : ""}
        </p>
        {needsRelay && (
          <p className="mt-2 rounded border border-[var(--color-sev-medium)] p-2 text-xs text-[var(--color-text-dim)]">
            ⚠ In the browser this cloud endpoint needs a <b>relay URL</b> (set one as the Proxy URL in
            Settings), or the request will fail. Alternatively use a local model (Ollama on localhost)
            or the desktop app, which talk to the provider directly.
          </p>
        )}
        <div className="mt-4 flex justify-end gap-2">
          <button type="button" className="t-tag" onClick={onCancel}>Cancel</button>
          <button type="button" className="t-tag font-semibold" onClick={onProceed}>Proceed</button>
        </div>
      </div>
    </div>
  );
}
