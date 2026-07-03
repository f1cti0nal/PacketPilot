import { useState } from "react";
import { LoadingState } from "../../components/state/LoadingState";
import { ErrorState } from "../../components/state/ErrorState";
import { joinedDate } from "../dashboard/format";
import { useAdminUsers, setPlan, setRole, setStatus, type AdminUser } from "./useAdminUsers";
import { AdminCard, Avatar, SearchInput, SectionTitle, TableCard } from "../ui/kit";

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
      <div className="flex flex-wrap items-center gap-3">
        <SectionTitle title="Users" subtitle="Manage accounts, plans and roles" />
        <div className="ml-auto w-full max-w-xs">
          <SearchInput
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by email…"
            aria-label="Search users by email"
          />
        </div>
      </div>
      {error && (
        <p role="alert" className="rounded-xl border border-[color-mix(in_srgb,var(--color-sev-critical)_35%,transparent)] bg-[var(--color-surface-1)] px-3 py-2 text-sm text-[var(--color-sev-critical)]">
          {error}
        </p>
      )}
      {state.status === "loading" ? (
        <LoadingState label="Loading users…" />
      ) : state.status === "error" ? (
        <ErrorState title="Couldn't load users" message={state.error} />
      ) : state.users.length === 0 ? (
        <AdminCard>
          <p className="py-4 text-center text-sm text-[var(--color-text-dim)]">No users match.</p>
        </AdminCard>
      ) : (
        <TableCard title="All users" count={state.users.length}>
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
        </TableCard>
      )}
    </div>
  );
}

function UserRow({ u, isSelf, run }: { u: AdminUser; isSelf: boolean; run: (fn: Mutator) => void }) {
  const color = STATUS_COLOR[u.status] ?? "var(--color-text-dim)";
  return (
    <tr>
      <td>
        <div className="flex items-center gap-2.5">
          <Avatar name={u.full_name} email={u.email} size={30} />
          <span className="font-medium text-[var(--color-text)]">{u.full_name ?? u.email.split("@")[0]}</span>
        </div>
      </td>
      <td className="text-[var(--color-text-dim)]">{u.email}</td>
      <td>
        <RowSelect label={`Plan for ${u.email}`} value={u.plan} options={PLANS} onChange={(v) => run(() => setPlan(u.id, v))} />
      </td>
      <td>
        <RowSelect label={`Role for ${u.email}`} value={u.role} options={ROLES} disabled={isSelf} onChange={(v) => run(() => setRole(u.id, v))} />
      </td>
      <td>
        <span className="flex items-center gap-2">
          <span aria-hidden className="inline-block h-2 w-2 shrink-0 rounded-full" style={{ background: color }} />
          <RowSelect label={`Status for ${u.email}`} value={u.status} options={STATUSES} onChange={(v) => run(() => setStatus(u.id, v))} />
        </span>
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
      className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] px-2 py-1 text-xs font-medium capitalize text-[var(--color-text)] outline-none transition-colors hover:border-[var(--color-border-strong)] focus:border-[var(--color-accent)] disabled:opacity-55"
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
