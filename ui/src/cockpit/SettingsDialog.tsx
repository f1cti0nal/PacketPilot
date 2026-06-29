import { useState } from "react";
import { useDialogA11y } from "../lib/useDialogA11y";
import { isTauri, repEnabled, setRepEnabled, domainEnabled, setDomainEnabled, getProxyUrl, setProxyUrl, getKey, setKey, type Provider } from "../lib/reputation/settings";
import {
  AI_PRESETS,
  getAiEnabled, setAiEnabled,
  getAiBaseUrl, setAiBaseUrl,
  getAiModel, setAiModel,
  getAiKey, setAiKey,
  getProxyUrl as getAiProxyUrl,
  setProxyUrl as setAiProxyUrl,
} from "../lib/ai/settings";
function isLoopbackUrl(url: string): boolean {
  try {
    const host = new URL(url).hostname.toLowerCase();
    return host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
  } catch { return false; }
}

const PROVIDERS: Provider[] = ["abuseipdb", "greynoise", "virustotal"];

export function SettingsDialog({ onClose }: { onClose: () => void }) {
  const { ref, onKeyDown } = useDialogA11y(onClose);
  const [enabled, setEnabled] = useState(repEnabled());
  const [domainEnabledState, setDomainEnabledState] = useState(domainEnabled());
  const [proxy, setProxy] = useState(getProxyUrl());
  const [keys, setKeys] = useState<Record<string, string>>(() =>
    Object.fromEntries(PROVIDERS.map((p) => [p, isTauri() ? "" : getKey(p)])));
  const [error, setError] = useState<string | null>(null);

  // AI section state
  const [aiEnabled, setAiEnabledState] = useState(getAiEnabled());
  const [aiPreset, setAiPreset] = useState(() => {
    const url = getAiBaseUrl();
    const match = AI_PRESETS.find((p) => p.id !== "custom" && p.baseUrl === url);
    return match?.id ?? "custom";
  });
  const [aiBaseUrl, setAiBaseUrlState] = useState(getAiBaseUrl());
  const [aiModel, setAiModelState] = useState(getAiModel());
  const [aiKey, setAiKeyState] = useState(isTauri() ? "" : getAiKey());
  const [aiProxy, setAiProxy] = useState(getAiProxyUrl());

  function handlePresetChange(id: string) {
    setAiPreset(id);
    const preset = AI_PRESETS.find((p) => p.id === id);
    if (preset && preset.id !== "custom") {
      setAiBaseUrlState(preset.baseUrl);
      setAiModelState(preset.model);
    }
  }

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

    // Save AI settings
    setAiEnabled(aiEnabled);
    setAiBaseUrl(aiBaseUrl);
    setAiModel(aiModel);
    if (!isTauri()) {
      setAiKey(aiKey);
      setAiProxyUrl(aiProxy);
    }
    if (isTauri() && aiKey) {
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        await invoke("set_ai_key", { provider: "default", key: aiKey });
      } catch (err) {
        setError(`Failed to save AI key: ${String((err as Error)?.message ?? err)}`);
        return;
      }
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

          {/* AI section */}
          <section>
            <h3 className="mb-3 text-[11px] font-medium uppercase tracking-wider text-[var(--color-text-faint)]">AI Analyst</h3>
            <div className="space-y-3">
              <label className="flex items-center gap-2.5 text-xs text-[var(--color-text-dim)] cursor-pointer">
                <input type="checkbox" checked={aiEnabled} onChange={(e) => setAiEnabledState(e.target.checked)} className="rounded" /> Enable AI analysis
              </label>
              <label className="block text-xs text-[var(--color-text-dim)]">
                Preset
                <select
                  className={inputCls}
                  value={aiPreset}
                  onChange={(e) => handlePresetChange(e.target.value)}
                  aria-label="Preset"
                >
                  {AI_PRESETS.map((p) => (
                    <option key={p.id} value={p.id}>{p.label}</option>
                  ))}
                </select>
              </label>
              <label className="block text-xs text-[var(--color-text-dim)]">
                Base URL
                <input
                  className={inputCls}
                  value={aiBaseUrl}
                  onChange={(e) => { setAiBaseUrlState(e.target.value); setAiPreset("custom"); }}
                  placeholder="https://api.anthropic.com/v1"
                  aria-label="Base URL"
                />
              </label>
              <label className="block text-xs text-[var(--color-text-dim)]">
                Model
                <input
                  className={inputCls}
                  value={aiModel}
                  onChange={(e) => { setAiModelState(e.target.value); setAiPreset("custom"); }}
                  placeholder="claude-opus-4-8"
                  aria-label="Model"
                />
              </label>
              <label className="block text-xs text-[var(--color-text-dim)]">
                API Key
                <input
                  type="password"
                  className={inputCls}
                  value={aiKey}
                  onChange={(e) => setAiKeyState(e.target.value)}
                  placeholder={isTauri() ? "stored in OS keychain" : "stored locally"}
                  aria-label="API Key"
                />
              </label>
              {!isTauri() && (
                <label className="block text-xs text-[var(--color-text-dim)]">
                  Proxy URL (required in the browser for cloud providers)
                  <input
                    className={inputCls}
                    value={aiProxy}
                    onChange={(e) => setAiProxy(e.target.value)}
                    placeholder="https://your-relay.example/ai-relay"
                    aria-label="Proxy URL"
                  />
                  {aiEnabled && aiProxy.trim() === "" && !isLoopbackUrl(aiBaseUrl) && (
                    <span className="mt-1.5 block text-[11px] text-[var(--color-text-faint)]">
                      A browser can't reach a cloud provider directly (CORS + your key would be exposed).
                      Set a relay here, or pick the Ollama (local) preset, or use the desktop app.
                    </span>
                  )}
                </label>
              )}
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
