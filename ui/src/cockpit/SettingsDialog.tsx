import { useState } from "react";
import { useDialogA11y } from "../lib/useDialogA11y";
import { isTauri, repEnabled, setRepEnabled, domainEnabled, setDomainEnabled, getProxyUrl, setProxyUrl, getKey, setKey, type Provider } from "../lib/reputation/settings";

const PROVIDERS: Provider[] = ["abuseipdb", "greynoise", "virustotal"];

export function SettingsDialog({ onClose }: { onClose: () => void }) {
  const { ref, onKeyDown } = useDialogA11y(onClose);
  const [enabled, setEnabled] = useState(repEnabled());
  const [domainEnabledState, setDomainEnabledState] = useState(domainEnabled());
  const [proxy, setProxy] = useState(getProxyUrl());
  const [keys, setKeys] = useState<Record<string, string>>(() =>
    Object.fromEntries(PROVIDERS.map((p) => [p, isTauri() ? "" : getKey(p)])));
  const [error, setError] = useState<string | null>(null);

  async function save() {
    setError(null);
    // Save reputation settings
    setRepEnabled(enabled);
    setDomainEnabled(domainEnabledState);
    if (!isTauri()) setProxyUrl(proxy);
    try {
      for (const p of PROVIDERS) {
        if (!keys[p]) continue;
        if (isTauri()) {
          const { invoke } = await import("@tauri-apps/api/core");
          await invoke("set_reputation_key", { provider: p, key: keys[p] });
        } else {
          setKey(p, keys[p]);
        }
      }
    } catch (err) {
      setError(`Failed to save key: ${String((err as Error)?.message ?? err)}`);
      return;
    }

    onClose();
  }

  const inputCls = "mt-1 w-full rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2.5 py-1.5 font-mono text-xs text-[var(--color-text)] placeholder:text-[var(--color-text-faint)] focus:border-[var(--color-accent)] focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)]";

  return (
    <div ref={ref} onKeyDown={onKeyDown} role="dialog" aria-modal="true" aria-label="Settings" className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="w-full max-w-[30rem] max-h-[90vh] overflow-y-auto rounded-[var(--r-card)] border border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text)] shadow-[var(--sh-float)]">
        {/* Dialog header */}
        <div className="border-b border-[var(--color-border)] px-5 py-4">
          <h2 className="text-sm font-medium text-[var(--color-text)]">Settings</h2>
        </div>

        <div className="px-5 py-4 space-y-6">
          {/* Reputation section */}
          <section>
            <h3 className="mb-3 text-[11px] font-medium uppercase tracking-wider text-[var(--color-text-faint)]">Online reputation</h3>
            <div className="space-y-3">
              <label className="flex items-center gap-2.5 text-xs text-[var(--color-text-dim)] cursor-pointer">
                <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} className="rounded" /> Enable reputation lookups
              </label>
              <label className="flex items-center gap-2.5 text-xs text-[var(--color-text-dim)] cursor-pointer">
                <input type="checkbox" checked={domainEnabledState} onChange={(e) => setDomainEnabledState(e.target.checked)} className="rounded" /> Enable domain reputation lookups (sends SNI hostnames to VirusTotal)
              </label>
              {!isTauri() && (
                <label className="block text-xs text-[var(--color-text-dim)]">
                  Proxy URL (required in the browser)
                  <input className={inputCls} value={proxy} onChange={(e) => setProxy(e.target.value)} placeholder="https://your-relay.example/relay" />
                </label>
              )}
              {PROVIDERS.map((p) => (
                <label key={p} className="block text-xs uppercase text-[var(--color-text-faint)]">{p}
                  <input type="password" className={inputCls}
                    value={keys[p]} onChange={(e) => setKeys({ ...keys, [p]: e.target.value })}
                    placeholder={isTauri() ? "stored in OS keychain" : "stored locally"} />
                </label>
              ))}
            </div>
          </section>
        </div>

        {error && (
          <p className="px-5 pb-3 text-xs text-[var(--color-sev-high)]">{error}</p>
        )}

        {/* Footer */}
        <div className="flex justify-end gap-2 border-t border-[var(--color-border)] px-5 py-3">
          <button
            className="rounded-[var(--r-micro)] border border-[var(--color-border)] bg-transparent px-3 py-1.5 text-xs font-medium text-[var(--color-text-dim)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]"
            onClick={onClose}
          >
            Cancel
          </button>
          <button
            className="rounded-[var(--r-micro)] bg-[var(--color-accent-deep)] px-3 py-1.5 text-xs font-medium text-[var(--color-on-accent)] transition-opacity hover:opacity-90"
            onClick={save}
          >
            Save
          </button>
        </div>
      </div>
    </div>
  );
}
