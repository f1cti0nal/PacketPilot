import { Card } from "../../cockpit/primitives";

/** Phase-3 placeholder for the admin dashboard. Phase 4 replaces this with the
 *  real KPI cards + charts sourced from public.admin_dashboard_stats. */
export function AdminDashboard() {
  return (
    <Card title="Dashboard">
      <p className="text-sm text-[var(--color-text-dim)]">
        Overview metrics arrive in Phase 4 (users, active today, revenue, system health).
      </p>
    </Card>
  );
}

export default AdminDashboard;
