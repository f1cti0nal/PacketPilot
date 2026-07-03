import { useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import { LoadingState } from "../../components/state/LoadingState";
import { ErrorState } from "../../components/state/ErrorState";
import { joinedDate } from "../dashboard/format";
import { AdminCard, PillButton, SectionTitle, TableCard } from "../ui/kit";
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

const inputCls =
  "rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] px-3 py-1.5 text-sm text-[var(--color-text)] outline-none transition-colors placeholder:text-[var(--color-text-faint)] focus:border-[var(--color-accent)]";

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
      <SectionTitle title="App Features" subtitle="Toggle features and plan gates" />
      {error && (
        <p role="alert" className="rounded-xl border border-[color-mix(in_srgb,var(--color-sev-critical)_35%,transparent)] bg-[var(--color-surface-1)] px-3 py-2 text-sm text-[var(--color-sev-critical)]">
          {error}
        </p>
      )}
      {state.status === "loading" ? (
        <LoadingState label="Loading feature flags…" />
      ) : state.status === "error" ? (
        <ErrorState title="Couldn't load feature flags" message={state.error} />
      ) : state.flags.length === 0 ? (
        <AdminCard>
          <p className="py-4 text-center text-sm text-[var(--color-text-dim)]">No feature flags yet.</p>
        </AdminCard>
      ) : (
        <TableCard title="Feature flags" count={state.flags.length}>
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
        </TableCard>
      )}
      <AdminCard title="Add a flag" subtitle="Create a new feature flag key">
        <div className="flex flex-wrap items-center gap-2">
          <input
            type="text"
            value={newKey}
            onChange={(e) => setNewKey(e.target.value)}
            placeholder="new_flag_key"
            aria-label="New flag key"
            className={inputCls}
          />
          <PillButton icon={Plus} variant="primary" onClick={() => void add()}>
            Add flag
          </PillButton>
        </div>
      </AdminCard>
    </div>
  );
}

function FlagRow({ f, run }: { f: AdminFlag; run: (fn: Mutator) => void }) {
  const [desc, setDesc] = useState(f.description ?? "");
  return (
    <tr>
      <td className="font-mono-num font-medium text-[var(--color-text)]">{f.key}</td>
      <td>
        <input
          type="text"
          value={desc}
          onChange={(e) => setDesc(e.target.value)}
          onBlur={() => desc !== (f.description ?? "") && run(() => setDescription(f.key, desc))}
          aria-label={`Description for ${f.key}`}
          className={`w-full ${inputCls}`}
        />
      </td>
      <td>
        <input
          type="checkbox"
          checked={f.enabled}
          onChange={(e) => run(() => setEnabled(f.key, e.target.checked))}
          aria-label={`Enable ${f.key}`}
          className="h-4 w-4 accent-[var(--color-accent-deep)]"
        />
      </td>
      <td>
        <select
          aria-label={`Plan gate for ${f.key}`}
          value={f.plan_gate ?? "all"}
          onChange={(e) => run(() => setPlanGate(f.key, e.target.value === "all" ? null : (e.target.value as "free" | "pro")))}
          className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] px-2 py-1 text-xs font-medium capitalize text-[var(--color-text)] outline-none focus:border-[var(--color-accent)]"
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
          className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs font-medium text-[var(--color-sev-critical)] transition-colors hover:bg-[color-mix(in_srgb,var(--color-sev-critical)_10%,transparent)]"
        >
          <Trash2 size={13} aria-hidden />
          Delete
        </button>
      </td>
    </tr>
  );
}

export default FeatureFlagsView;
