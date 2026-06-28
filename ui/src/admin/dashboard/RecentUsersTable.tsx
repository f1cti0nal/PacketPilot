import type { RecentUser } from "../useAdminDashboard";
import { joinedDate } from "./format";

const STATUS_COLOR: Record<string, string> = {
  active: "var(--color-sev-low)",
  suspended: "var(--color-sev-medium)",
  blocked: "var(--color-sev-critical)",
};

export function RecentUsersTable({ users }: { users: RecentUser[] }) {
  if (users.length === 0) {
    return <p className="text-sm text-[var(--color-text-dim)]">No users yet.</p>;
  }
  return (
    <table className="pp-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Email</th>
          <th>Plan</th>
          <th>Status</th>
          <th>Joined</th>
        </tr>
      </thead>
      <tbody>
        {users.map((u) => {
          const color = STATUS_COLOR[u.status] ?? "var(--color-text-dim)";
          return (
            <tr key={u.email}>
              <td>{u.full_name ?? u.email.split("@")[0]}</td>
              <td className="text-[var(--color-text-dim)]">{u.email}</td>
              <td>
                <span className="inline-flex items-center rounded-[var(--r-chip)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-1.5 py-0.5 t-tag uppercase text-[var(--color-text-dim)]">
                  {u.plan}
                </span>
              </td>
              <td>
                <span className="inline-flex items-center gap-1.5 t-tag uppercase" style={{ color }}>
                  <span aria-hidden className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
                  {u.status}
                </span>
              </td>
              <td className="font-mono-num text-[var(--color-text-dim)]">{joinedDate(u.created_at)}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

export default RecentUsersTable;
