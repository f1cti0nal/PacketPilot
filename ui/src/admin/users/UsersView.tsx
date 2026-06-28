import { useState } from "react";
import { LoadingState } from "../../components/state/LoadingState";
import { ErrorState } from "../../components/state/ErrorState";
import { joinedDate } from "../dashboard/format";
import { useAdminUsers, setPlan, setRole, setStatus, type AdminUser } from "./useAdminUsers";

const STATUS_COLOR: Record<string, string> = {
  active: "var(--color-sev-low)",
  suspended: "var(--color-sev-medium)",
  blocked: "var(--color-sev-critical)",
};

const PLANS = ["free", "pro"];
const ROLES = ["user", "admin"];
const STATUSES = ["active", "suspended", "blocked"];

type Mutator = () => Promise<{ ok: boolean; error?: string }>;

export function UsersView({ adminEmail }: { adminEmail: string }) {
  const [search, setSearch] = useState("");
  const [error, setError] = useState<string | null>(null);
  const { state, reload } = useAdminUsers(search);

  const run = async (fn: Mutator) => {
    setError(null);
    const r = await fn();
    if (r.ok) reload();
    else setError(r.error ?? "Update failed");
  };

  return (
    <div className="flex flex-col gap-[var(--density-gap)]">
      <input
        type="search"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="Search by email…"
        aria-label="Search users by email"
        className="w-full max-w-sm rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-sm text-[var(--color-text)] placeholder:text-[var(--color-text-dim)]"
      />
      {error && (
        <p role="alert" className="t-tag text-[var(--color-sev-critical)]">
          {error}
        </p>
      )}
      {state.status === "loading" ? (
        <LoadingState label="Loading users…" />
      ) : state.status === "error" ? (
        <ErrorState title="Couldn't load users" message={state.error} />
      ) : state.users.length === 0 ? (
        <p className="text-sm text-[var(--color-text-dim)]">No users match.</p>
      ) : (
        <table className="pp-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Email</th>
              <th>Plan</th>
              <th>Role</th>
              <th>Status</th>
              <th>Joined</th>
            </tr>
          </thead>
          <tbody>
            {state.users.map((u) => (
              <UserRow key={u.id} u={u} isSelf={u.email === adminEmail} run={run} />
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function UserRow({ u, isSelf, run }: { u: AdminUser; isSelf: boolean; run: (fn: Mutator) => void }) {
  const color = STATUS_COLOR[u.status] ?? "var(--color-text-dim)";
  return (
    <tr>
      <td>{u.full_name ?? u.email.split("@")[0]}</td>
      <td className="text-[var(--color-text-dim)]">{u.email}</td>
      <td>
        <RowSelect label={`Plan for ${u.email}`} value={u.plan} options={PLANS} onChange={(v) => run(() => setPlan(u.id, v))} />
      </td>
      <td>
        <RowSelect label={`Role for ${u.email}`} value={u.role} options={ROLES} disabled={isSelf} onChange={(v) => run(() => setRole(u.id, v))} />
      </td>
      <td>
        <span aria-hidden className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full align-middle" style={{ background: color }} />
        <RowSelect label={`Status for ${u.email}`} value={u.status} options={STATUSES} onChange={(v) => run(() => setStatus(u.id, v))} />
      </td>
      <td className="font-mono-num text-[var(--color-text-dim)]">{joinedDate(u.created_at)}</td>
    </tr>
  );
}

function RowSelect({
  label,
  value,
  options,
  onChange,
  disabled,
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (v: string) => void;
  disabled?: boolean;
}) {
  return (
    <select
      aria-label={label}
      value={value}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value)}
      className="rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-1.5 py-0.5 t-tag uppercase text-[var(--color-text-dim)] disabled:opacity-60"
    >
      {options.map((o) => (
        <option key={o} value={o}>
          {o}
        </option>
      ))}
    </select>
  );
}

export default UsersView;
