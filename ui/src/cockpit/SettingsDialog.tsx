import { useState } from "react";
import { isTauri, repEnabled, setRepEnabled, getProxyUrl, setProxyUrl, getKey, setKey, type Provider } from "../lib/reputation/settings";
import {
  AI_PRESETS,
  getAiEnabled, setAiEnabled,
  getAiBaseUrl, setAiBaseUrl,
  getAiModel, setAiModel,
  getAiKey, setAiKey,
  getProxyUrl as getAiProxyUrl,
  setProxyUrl as setAiProxyUrl,
} from "../lib/ai/settings";

const PROVIDERS: Provider[] = ["abuseipdb", "greynoise", "virustotal"];

export function SettingsDialog({ onClose }: { onClose: () => void }) {
  const [enabled, setEnabled] = useState(repEnabled());
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

  return (
    <div role="dialog" aria-label="Settings" className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="w-[28rem] max-h-[90vh] overflow-y-auto rounded-lg bg-[var(--color-surface)] p-5 text-[var(--color-text)]">
        {/* Reputation section */}
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

        {/* AI section */}
        <h2 className="mt-6 text-sm font-semibold">AI Analyst</h2>
        <label className="mt-3 flex items-center gap-2 text-xs">
          <input type="checkbox" checked={aiEnabled} onChange={(e) => setAiEnabledState(e.target.checked)} /> Enable AI analysis
        </label>
        <label className="mt-3 block text-xs">Preset
          <select
            className="mt-1 w-full rounded bg-[var(--color-bg)] p-1 font-mono text-xs"
            value={aiPreset}
            onChange={(e) => handlePresetChange(e.target.value)}
            aria-label="Preset"
          >
            {AI_PRESETS.map((p) => (
              <option key={p.id} value={p.id}>{p.label}</option>
            ))}
          </select>
        </label>
        <label className="mt-3 block text-xs">Base URL
          <input
            className="mt-1 w-full rounded bg-[var(--color-bg)] p-1 font-mono text-xs"
            value={aiBaseUrl}
            onChange={(e) => { setAiBaseUrlState(e.target.value); setAiPreset("custom"); }}
            placeholder="https://api.anthropic.com/v1"
            aria-label="Base URL"
          />
        </label>
        <label className="mt-3 block text-xs">Model
          <input
            className="mt-1 w-full rounded bg-[var(--color-bg)] p-1 font-mono text-xs"
            value={aiModel}
            onChange={(e) => { setAiModelState(e.target.value); setAiPreset("custom"); }}
            placeholder="claude-opus-4-8"
            aria-label="Model"
          />
        </label>
        <label className="mt-3 block text-xs">API Key
          <input
            type="password"
            className="mt-1 w-full rounded bg-[var(--color-bg)] p-1 font-mono text-xs"
            value={aiKey}
            onChange={(e) => setAiKeyState(e.target.value)}
            placeholder={isTauri() ? "stored in OS keychain" : "stored locally"}
            aria-label="API Key"
          />
        </label>
        {!isTauri() && (
          <label className="mt-3 block text-xs">Proxy URL (browser only)
            <input
              className="mt-1 w-full rounded bg-[var(--color-bg)] p-1 font-mono text-xs"
              value={aiProxy}
              onChange={(e) => setAiProxy(e.target.value)}
              placeholder="https://your-relay.example/ai-relay"
              aria-label="Proxy URL"
            />
          </label>
        )}

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
