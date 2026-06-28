import { Card } from "../../cockpit/primitives";
import { LoadingState } from "../../components/state/LoadingState";
import { ErrorState } from "../../components/state/ErrorState";
import { useAdminDashboard } from "../useAdminDashboard";
import { KpiCards } from "./KpiCards";
import { SignupsAreaChart } from "./SignupsAreaChart";
import { SubscriptionsBarChart } from "./SubscriptionsBarChart";
import { RecentUsersTable } from "./RecentUsersTable";

export function AdminDashboard() {
  const state = useAdminDashboard();
  if (state.status === "loading") return <LoadingState label="Loading dashboard…" />;
  if (state.status === "error") return <ErrorState title="Couldn't load the dashboard" message={state.error} />;
  const { stats, recentUsers, signups, subscriptions } = state.data;
  return (
    <div className="flex flex-col gap-[var(--density-gap)]">
      <KpiCards stats={stats} healthy={true} />
      <div className="grid gap-[var(--density-gap)] lg:grid-cols-2">
        <Card title="Daily New Users">
          <SignupsAreaChart data={signups} />
        </Card>
        <Card title="New Subscriptions">
          <SubscriptionsBarChart data={subscriptions} />
        </Card>
      </div>
      <Card title="Recent Users">
        <RecentUsersTable users={recentUsers} />
      </Card>
    </div>
  );
}

export default AdminDashboard;
