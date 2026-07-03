import { useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import { LoadingState } from "../../components/state/LoadingState";
import { ErrorState } from "../../components/state/ErrorState";
import { joinedDate } from "../dashboard/format";
import { AdminCard, PillButton, SectionTitle, TableCard } from "../ui/kit";
import {
  useAdminAppSettings,
  updateValue,
  updateDescription,
  createSetting,
  deleteSetting,
  type AdminSetting,
} from "./useAdminAppSettings";
import { settingKind } from "./settingMeta";
import type { Json } from "../../lib/supabase/types";
import type { AnnouncementBanner } from "../../lib/settings/publicSettings";

type Mutator = () => Promise<{ ok: boolean; error?: string }>;
const SEVERITIES: AnnouncementBanner["severity"][] = ["info", "warning", "critical"];

export function SettingsView() {
  const { state, reload } = useAdminAppSettings();
  const [error, setError] = useState<string | null>(null);
  const [newKey, setNewKey] = useState("");

  const run = async (fn: Mutator) => {
    setError(null);
    const r = await fn();
    if (!r) return;
    if (r.ok) reload();
    else setError(r.error ?? "Update failed");
  };

  const add = async () => {
    const key = newKey.trim();
    if (!key) return;
    await run(() => createSetting(key, ""));
    setNewKey("");
  };

  return (
    <div className="flex flex-col gap-[var(--density-gap)]">
      <SectionTitle title="Settings" subtitle="App configuration and content" />
      {error && (
        <p role="alert" className="rounded-xl border border-[color-mix(in_srgb,var(--color-sev-critical)_35%,transparent)] bg-[var(--color-surface-1)] px-3 py-2 text-sm text-[var(--color-sev-critical)]">
          {error}
        </p>
      )}
      {state.status === "loading" ? (
        <LoadingState label="Loading settings…" />
      ) : state.status === "error" ? (
        <ErrorState title="Couldn't load settings" message={state.error} />
      ) : state.settings.length === 0 ? (
        <AdminCard>
          <p className="py-4 text-center text-sm text-[var(--color-text-dim)]">No settings yet.</p>
        </AdminCard>
      ) : (
        <TableCard title="App settings" count={state.settings.length}>
          <table className="pp-table">
            <thead>
              <tr>
                <th>Key</th>
                <th>Value</th>
                <th>Description</th>
                <th>Updated</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {state.settings.map((s) => (
                <SettingRow key={s.key} s={s} run={run} />
              ))}
            </tbody>
          </table>
        </TableCard>
      )}
      <AdminCard title="Add a setting" subtitle="Create a new app setting key">
        <div className="flex flex-wrap items-center gap-2">
          <input
            type="text"
            value={newKey}
            onChange={(e) => setNewKey(e.target.value)}
            placeholder="new_setting_key"
            aria-label="New setting key"
            className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] px-3 py-1.5 text-sm text-[var(--color-text)] outline-none transition-colors placeholder:text-[var(--color-text-faint)] focus:border-[var(--color-accent)]"
          />
          <PillButton icon={Plus} variant="primary" onClick={() => void add()}>
            Add setting
          </PillButton>
        </div>
      </AdminCard>
    </div>
  );
}

function SettingRow({ s, run }: { s: AdminSetting; run: (fn: Mutator) => void }) {
  const [desc, setDesc] = useState(s.description ?? "");
  return (
    <tr>
      <td className="font-mono-num align-top">{s.key}</td>
      <td>
        {settingKind(s.key) === "banner" ? (
          <BannerEditor s={s} run={run} />
        ) : settingKind(s.key) === "ai" ? (
          <AiConfigEditor s={s} run={run} />
        ) : settingKind(s.key) === "rep" ? (
          <RepConfigEditor s={s} run={run} />
        ) : (
          <JsonEditor s={s} run={run} />
        )}
      </td>
      <td className="align-top">
        <input
          type="text"
          value={desc}
          onChange={(e) => setDesc(e.target.value)}
          onBlur={() => desc !== (s.description ?? "") && run(() => updateDescription(s.key, desc))}
          aria-label={`Description for ${s.key}`}
          className="w-full rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-1 text-sm text-[var(--color-text)]"
        />
      </td>
      <td className="font-mono-num align-top text-[var(--color-text-dim)]">{joinedDate(s.updated_at)}</td>
      <td className="align-top">
        <button
          type="button"
          onClick={() => run(() => deleteSetting(s.key))}
          aria-label={`Delete ${s.key}`}
          className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs font-medium text-[var(--color-sev-critical)] transition-colors hover:bg-[color-mix(in_srgb,var(--color-sev-critical)_10%,transparent)]"
        >
          <Trash2 size={13} aria-hidden />
          Delete
        </button>
      </td>
    </tr>
  );
}

function BannerEditor({ s, run }: { s: AdminSetting; run: (fn: Mutator) => void }) {
  const v = (s.value && typeof s.value === "object" ? s.value : {}) as Record<string, unknown>;
  const [text, setText] = useState(typeof v.text === "string" ? v.text : "");
  const severity = (SEVERITIES.includes(v.severity as AnnouncementBanner["severity"]) ? v.severity : "info") as AnnouncementBanner["severity"];
  const dismissible = v.dismissible !== false;
  const save = (next: { text?: string; severity?: string; dismissible?: boolean }) =>
    run(() =>
      updateValue(s.key, {
        text: next.text ?? text,
        severity: next.severity ?? severity,
        dismissible: next.dismissible ?? dismissible,
      } as Json),
    );
  return (
    <div className="flex flex-wrap items-center gap-2">
      <input
        type="text"
        value={text}
        onChange={(e) => setText(e.target.value)}
        onBlur={() => text !== (typeof v.text === "string" ? v.text : "") && save({ text })}
        placeholder="Announcement text (empty = hidden)"
        aria-label="Announcement text"
        className="min-w-[14rem] flex-1 rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-1 text-sm text-[var(--color-text)]"
      />
      <select
        aria-label="Announcement severity"
        value={severity}
        onChange={(e) => save({ severity: e.target.value })}
        className="rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-1.5 py-0.5 t-tag uppercase text-[var(--color-text-dim)]"
      >
        {SEVERITIES.map((sv) => (
          <option key={sv} value={sv}>
            {sv}
          </option>
        ))}
      </select>
      <label className="flex items-center gap-1 t-tag text-[var(--color-text-dim)]">
        <input type="checkbox" checked={dismissible} aria-label="Announcement dismissible" onChange={(e) => save({ dismissible: e.target.checked })} />
        dismissible
      </label>
    </div>
  );
}

const AI_PROVIDERS = ["anthropic", "openai", "openrouter", "ollama"] as const;

function AiConfigEditor({ s, run }: { s: AdminSetting; run: (fn: Mutator) => void }) {
  const v = (s.value && typeof s.value === "object" ? s.value : {}) as Record<string, unknown>;
  const [enabled, setEnabled] = useState(v.enabled === true);
  const [provider, setProvider] = useState(typeof v.provider === "string" ? v.provider : "anthropic");
  const [model, setModel] = useState(typeof v.model === "string" ? v.model : "");

  const save = (next: { enabled?: boolean; provider?: string; model?: string }) =>
    run(() =>
      updateValue(s.key, {
        enabled: next.enabled ?? enabled,
        provider: next.provider ?? provider,
        model: next.model ?? model,
      } as Json),
    );

  return (
    <div className="flex flex-wrap items-center gap-2">
      <label className="flex items-center gap-1 t-tag text-[var(--color-text-dim)]">
        <input
          type="checkbox"
          checked={enabled}
          aria-label="AI enabled"
          onChange={(e) => { setEnabled(e.target.checked); save({ enabled: e.target.checked }); }}
        />
        enabled
      </label>
      <select
        aria-label="AI provider"
        value={provider}
        onChange={(e) => { setProvider(e.target.value); save({ provider: e.target.value }); }}
        className="rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-1.5 py-0.5 t-tag text-[var(--color-text-dim)]"
      >
        {AI_PROVIDERS.map((p) => (
          <option key={p} value={p}>{p}</option>
        ))}
      </select>
      <input
        type="text"
        value={model}
        onChange={(e) => setModel(e.target.value)}
        onBlur={() => model !== (typeof v.model === "string" ? v.model : "") && save({ model })}
        placeholder="model name"
        aria-label="AI model"
        className="min-w-[12rem] flex-1 rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-1 text-sm text-[var(--color-text)]"
      />
      <span className="w-full t-tag text-[var(--color-text-dim)]">
        API key is set as a server secret (Environment).
      </span>
    </div>
  );
}

const REP_PROVIDERS = ["abuseipdb", "greynoise", "virustotal"] as const;

function RepConfigEditor({ s, run }: { s: AdminSetting; run: (fn: Mutator) => void }) {
  const v = (s.value && typeof s.value === "object" ? s.value : {}) as Record<string, unknown>;
  const rawProviders = Array.isArray(v.providers) ? (v.providers as unknown[]).filter((p): p is string => typeof p === "string") : [];
  const [enabled, setEnabled] = useState(v.enabled === true);
  const [domainEnabled, setDomainEnabled] = useState(v.domain_enabled === true);
  const [fileEnabled, setFileEnabled] = useState(v.file_enabled === true);
  const [providers, setProviders] = useState<string[]>(rawProviders);

  const save = (next: { enabled?: boolean; domain_enabled?: boolean; file_enabled?: boolean; providers?: string[] }) =>
    run(() =>
      updateValue(s.key, {
        enabled: next.enabled ?? enabled,
        domain_enabled: next.domain_enabled ?? domainEnabled,
        file_enabled: next.file_enabled ?? fileEnabled,
        providers: next.providers ?? providers,
      } as Json),
    );

  const toggleProvider = (p: string, checked: boolean) => {
    const next = checked ? [...providers, p] : providers.filter((x) => x !== p);
    setProviders(next);
    save({ providers: next });
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      <label className="flex items-center gap-1 t-tag text-[var(--color-text-dim)]">
        <input
          type="checkbox"
          checked={enabled}
          aria-label="Reputation enabled"
          onChange={(e) => { setEnabled(e.target.checked); save({ enabled: e.target.checked }); }}
        />
        enabled
      </label>
      <label className="flex items-center gap-1 t-tag text-[var(--color-text-dim)]">
        <input
          type="checkbox"
          checked={domainEnabled}
          aria-label="Domain reputation enabled"
          onChange={(e) => { setDomainEnabled(e.target.checked); save({ domain_enabled: e.target.checked }); }}
        />
        domain_enabled
      </label>
      <label className="flex items-center gap-1 t-tag text-[var(--color-text-dim)]">
        <input
          type="checkbox"
          checked={fileEnabled}
          aria-label="File-hash reputation enabled"
          onChange={(e) => { setFileEnabled(e.target.checked); save({ file_enabled: e.target.checked }); }}
        />
        file_enabled
      </label>
      <span className="flex items-center gap-2 t-tag text-[var(--color-text-dim)]">
        {REP_PROVIDERS.map((p) => (
          <label key={p} className="flex items-center gap-1">
            <input
              type="checkbox"
              checked={providers.includes(p)}
              aria-label={`Provider ${p}`}
              onChange={(e) => toggleProvider(p, e.target.checked)}
            />
            {p}
          </label>
        ))}
      </span>
      <span className="w-full t-tag text-[var(--color-text-dim)]">
        API keys are server secrets (Environment).
      </span>
    </div>
  );
}

function JsonEditor({ s, run }: { s: AdminSetting; run: (fn: Mutator) => void }) {
  const [raw, setRaw] = useState(JSON.stringify(s.value, null, 2));
  const [bad, setBad] = useState(false);
  return (
    <div className="flex flex-col gap-1">
      <textarea
        value={raw}
        onChange={(e) => {
          setRaw(e.target.value);
          setBad(false);
        }}
        onBlur={() => {
          if (raw === JSON.stringify(s.value, null, 2)) return;
          try {
            const parsed = JSON.parse(raw) as Json;
            run(() => updateValue(s.key, parsed));
          } catch {
            setBad(true);
          }
        }}
        aria-label={`Value JSON for ${s.key}`}
        rows={2}
        className="w-full rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-1 font-mono-num text-xs text-[var(--color-text)]"
      />
      {bad && <span className="t-tag text-[var(--color-sev-critical)]">Invalid JSON — not saved.</span>}
    </div>
  );
}

export default SettingsView;
