import { useState } from "react";
import { LoadingState } from "../../components/state/LoadingState";
import { ErrorState } from "../../components/state/ErrorState";
import { joinedDate } from "../dashboard/format";
import {
  useAdminFeatureFlags,
  setEnabled,
  setPlanGate,
  setDescription,
  createFlag,
  deleteFlag,
  type AdminFlag,
} from "./useAdminFeatureFlags";

type Mutator = () => Promise<{ ok: boolean; error?: string }>;
const GATES = ["all", "free", "pro"] as const;

export function FeatureFlagsView() {
  const { state, reload } = useAdminFeatureFlags();
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
    await run(() => createFlag(key, ""));
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
        <LoadingState label="Loading feature flags…" />
      ) : state.status === "error" ? (
        <ErrorState title="Couldn't load feature flags" message={state.error} />
      ) : state.flags.length === 0 ? (
        <p className="text-sm text-[var(--color-text-dim)]">No feature flags yet.</p>
      ) : (
        <table className="pp-table">
          <thead>
            <tr>
              <th>Key</th>
              <th>Description</th>
              <th>Enabled</th>
              <th>Plan gate</th>
              <th>Updated</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {state.flags.map((f) => (
              <FlagRow key={f.key} f={f} run={run} />
            ))}
          </tbody>
        </table>
      )}
      <div className="flex items-center gap-2">
        <input
          type="text"
          value={newKey}
          onChange={(e) => setNewKey(e.target.value)}
          placeholder="new_flag_key"
          aria-label="New flag key"
          className="rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-sm text-[var(--color-text)] placeholder:text-[var(--color-text-dim)]"
        />
        <button
          type="button"
          onClick={() => void add()}
          className="rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-xs text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
        >
          Add flag
        </button>
      </div>
    </div>
  );
}

function FlagRow({ f, run }: { f: AdminFlag; run: (fn: Mutator) => void }) {
  const [desc, setDesc] = useState(f.description ?? "");
  return (
    <tr>
      <td className="font-mono-num">{f.key}</td>
      <td>
        <input
          type="text"
          value={desc}
          onChange={(e) => setDesc(e.target.value)}
          onBlur={() => desc !== (f.description ?? "") && run(() => setDescription(f.key, desc))}
          aria-label={`Description for ${f.key}`}
          className="w-full rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-1 text-sm text-[var(--color-text)]"
        />
      </td>
      <td>
        <input
          type="checkbox"
          checked={f.enabled}
          onChange={(e) => run(() => setEnabled(f.key, e.target.checked))}
          aria-label={`Enable ${f.key}`}
        />
      </td>
      <td>
        <select
          aria-label={`Plan gate for ${f.key}`}
          value={f.plan_gate ?? "all"}
          onChange={(e) => run(() => setPlanGate(f.key, e.target.value === "all" ? null : (e.target.value as "free" | "pro")))}
          className="rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-1.5 py-0.5 t-tag uppercase text-[var(--color-text-dim)]"
        >
          {GATES.map((g) => (
            <option key={g} value={g}>
              {g}
            </option>
          ))}
        </select>
      </td>
      <td className="font-mono-num text-[var(--color-text-dim)]">{joinedDate(f.updated_at)}</td>
      <td>
        <button
          type="button"
          onClick={() => run(() => deleteFlag(f.key))}
          aria-label={`Delete ${f.key}`}
          className="rounded-[var(--r-micro)] px-2 py-1 t-tag uppercase text-[var(--color-sev-critical)] hover:bg-[var(--color-surface-2)]"
        >
          Delete
        </button>
      </td>
    </tr>
  );
}

export default FeatureFlagsView;
