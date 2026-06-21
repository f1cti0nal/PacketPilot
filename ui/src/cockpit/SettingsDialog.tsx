import { useState } from "react";
import { isTauri, repEnabled, setRepEnabled, getProxyUrl, setProxyUrl, getKey, setKey, type Provider } from "../lib/reputation/settings";

const PROVIDERS: Provider[] = ["abuseipdb", "greynoise", "virustotal"];

export function SettingsDialog({ onClose }: { onClose: () => void }) {
  const [enabled, setEnabled] = useState(repEnabled());
  const [proxy, setProxy] = useState(getProxyUrl());
  const [keys, setKeys] = useState<Record<string, string>>(() =>
    Object.fromEntries(PROVIDERS.map((p) => [p, isTauri() ? "" : getKey(p)])));
  const [error, setError] = useState<string | null>(null);

  async function save() {
    setError(null);
    setRepEnabled(enabled);
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

  return (
    <div role="dialog" aria-label="Reputation settings" className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="w-[28rem] rounded-lg bg-[var(--color-surface)] p-5 text-[var(--color-text)]">
        <h2 className="text-sm font-semibold">Online reputation</h2>
        <label className="mt-3 flex items-center gap-2 text-xs">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enable reputation lookups
        </label>
        {!isTauri() && (
          <label className="mt-3 block text-xs">Proxy URL (required in the browser)
            <input className="mt-1 w-full rounded bg-[var(--color-bg)] p-1 font-mono text-xs" value={proxy} onChange={(e) => setProxy(e.target.value)} placeholder="https://your-relay.example/relay" />
          </label>
        )}
        {PROVIDERS.map((p) => (
          <label key={p} className="mt-3 block text-xs uppercase">{p}
            <input type="password" className="mt-1 w-full rounded bg-[var(--color-bg)] p-1 font-mono text-xs"
              value={keys[p]} onChange={(e) => setKeys({ ...keys, [p]: e.target.value })}
              placeholder={isTauri() ? "stored in OS keychain" : "stored locally"} />
          </label>
        ))}
        {error && (
          <p className="mt-3 text-xs text-[var(--color-severity-high,#f87171)]">{error}</p>
        )}
        <div className="mt-4 flex justify-end gap-2">
          <button className="t-tag" onClick={onClose}>Cancel</button>
          <button className="t-tag font-semibold" onClick={save}>Save</button>
        </div>
      </div>
    </div>
  );
}
