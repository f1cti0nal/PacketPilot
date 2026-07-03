import { useState } from "react";
import { Download, RefreshCw } from "lucide-react";
import { LoadingState } from "../../components/state/LoadingState";
import { ErrorState } from "../../components/state/ErrorState";
import { useAdminDashboard } from "../useAdminDashboard";
import { KpiCards } from "./KpiCards";
import { SignupsAreaChart } from "./SignupsAreaChart";
import { SubscriptionsBarChart } from "./SubscriptionsBarChart";
import { RecentUsersTable } from "./RecentUsersTable";
import { joinedDate } from "./format";
import { AdminCard, PillButton, ProgressStat, SectionTitle, TableCard } from "../ui/kit";
import { ratioPct, toCsv, weekOverWeek } from "../ui/helpers";
import { downloadTextFile } from "../ui/download";

/** Outer wrapper: a bump to `nonce` remounts the body, forcing a fresh fetch. */
export function AdminDashboard() {
  const [nonce, setNonce] = useState(0);
  return <DashboardView key={nonce} reload={() => setNonce((n) => n + 1)} />;
}

function DashboardView({ reload }: { reload: () => void }) {
  const state = useAdminDashboard();
  if (state.status === "loading") return <LoadingState label="Loading dashboard…" />;
  if (state.status === "error") return <ErrorState title="Couldn't load the dashboard" message={state.error} />;

  const { stats, recentUsers, signups, subscriptions } = state.data;
  const total = stats.total_users;
  const signupsDelta = weekOverWeek(signups.map((d) => d.count));
  const paidPct = ratioPct(stats.paid_users, total);
  const activePct = ratioPct(stats.active_today, total);
  const freePct = ratioPct(stats.free_users, total);

  const exportCsv = () => {
    const rows = recentUsers.map((u) => [
      u.full_name ?? u.email.split("@")[0],
      u.email,
      u.plan,
      u.status,
      joinedDate(u.created_at),
    ]);
    downloadTextFile("recent-users.csv", toCsv(["Name", "Email", "Plan", "Status", "Joined"], rows));
  };

  return (
    <div className="flex flex-col gap-[var(--density-gap)]">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3">
        <SectionTitle title="Overview" subtitle="Key metrics across your workspace" />
        <div className="ml-auto flex items-center gap-2">
          <PillButton icon={Download} variant="secondary" onClick={exportCsv} disabled={recentUsers.length === 0}>
            Export
          </PillButton>
          <PillButton icon={RefreshCw} variant="primary" onClick={reload}>
            Refresh
          </PillButton>
        </div>
      </div>

      <KpiCards stats={stats} healthy={true} signupsDelta={signupsDelta} />

      {/* Charts */}
      <div className="grid gap-[var(--density-gap)] lg:grid-cols-2">
        <AdminCard title="Daily New Users" subtitle="Signups over the last 14 days">
          <SignupsAreaChart data={signups} />
        </AdminCard>
        <AdminCard title="New Subscriptions" subtitle="New paid subscriptions per day">
          <SubscriptionsBarChart data={subscriptions} />
        </AdminCard>
      </div>

      {/* Performance + recent users */}
      <div className="grid gap-[var(--density-gap)] lg:grid-cols-3">
        <AdminCard title="Performance" subtitle="Share of your user base" className="lg:col-span-1">
          <div className="flex flex-col gap-4 pt-1">
            <ProgressStat
              label="Paid conversion"
              value={`${paidPct}%`}
              pct={paidPct}
              color="var(--color-accent)"
              caption={`${stats.paid_users.toLocaleString()} of ${total.toLocaleString()} users`}
            />
            <ProgressStat
              label="Active today"
              value={`${activePct}%`}
              pct={activePct}
              color="var(--color-sev-info)"
              caption={`${stats.active_today.toLocaleString()} active`}
            />
            <ProgressStat
              label="Free plan"
              value={`${freePct}%`}
              pct={freePct}
              color="var(--color-sev-none)"
              caption={`${stats.free_users.toLocaleString()} on Free`}
            />
          </div>
        </AdminCard>

        <TableCard
          title="Recent Users"
          count={recentUsers.length}
          className="lg:col-span-2"
          right={
            <PillButton size="sm" variant="ghost" icon={Download} onClick={exportCsv} disabled={recentUsers.length === 0}>
              Export CSV
            </PillButton>
          }
        >
          <RecentUsersTable users={recentUsers} />
        </TableCard>
      </div>
    </div>
  );
}

export default AdminDashboard;
