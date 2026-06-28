import { useState } from "react";
import { LoadingState } from "../../components/state/LoadingState";
import { ErrorState } from "../../components/state/ErrorState";
import { joinedDate } from "../dashboard/format";
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
      {error && (
        <p role="alert" className="t-tag text-[var(--color-sev-critical)]">
          {error}
        </p>
      )}
      {state.status === "loading" ? (
        <LoadingState label="Loading settings…" />
      ) : state.status === "error" ? (
        <ErrorState title="Couldn't load settings" message={state.error} />
      ) : state.settings.length === 0 ? (
        <p className="text-sm text-[var(--color-text-dim)]">No settings yet.</p>
      ) : (
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
      )}
      <div className="flex items-center gap-2">
        <input
          type="text"
          value={newKey}
          onChange={(e) => setNewKey(e.target.value)}
          placeholder="new_setting_key"
          aria-label="New setting key"
          className="rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-sm text-[var(--color-text)] placeholder:text-[var(--color-text-dim)]"
        />
        <button
          type="button"
          onClick={() => void add()}
          className="rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-xs text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
        >
          Add setting
        </button>
      </div>
    </div>
  );
}

function SettingRow({ s, run }: { s: AdminSetting; run: (fn: Mutator) => void }) {
  const [desc, setDesc] = useState(s.description ?? "");
  return (
    <tr>
      <td className="font-mono-num align-top">{s.key}</td>
      <td>{settingKind(s.key) === "banner" ? <BannerEditor s={s} run={run} /> : <JsonEditor s={s} run={run} />}</td>
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
          className="rounded-[var(--r-micro)] px-2 py-1 t-tag uppercase text-[var(--color-sev-critical)] hover:bg-[var(--color-surface-2)]"
        >
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
