import type { RecentUser } from "../useAdminDashboard";
import { joinedDate } from "./format";
import { Avatar, Badge, StatusPill } from "../ui/kit";

const STATUS_COLOR: Record<string, string> = {
  active: "var(--color-sev-low)",
  suspended: "var(--color-sev-medium)",
  blocked: "var(--color-sev-critical)",
};

export function RecentUsersTable({ users }: { users: RecentUser[] }) {
  if (users.length === 0) {
    return <p className="px-5 py-4 text-sm text-[var(--color-text-dim)]">No users yet.</p>;
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
          const name = u.full_name ?? u.email.split("@")[0];
          const color = STATUS_COLOR[u.status] ?? "var(--color-text-dim)";
          return (
            <tr key={u.email}>
              <td>
                <div className="flex items-center gap-2.5">
                  <Avatar name={u.full_name} email={u.email} size={30} />
                  <span className="font-medium text-[var(--color-text)]">{name}</span>
                </div>
              </td>
              <td className="text-[var(--color-text-dim)]">{u.email}</td>
              <td>
                <Badge tone={u.plan === "pro" ? "accent" : "neutral"}>{u.plan}</Badge>
              </td>
              <td>
                <StatusPill label={u.status} color={color} />
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
