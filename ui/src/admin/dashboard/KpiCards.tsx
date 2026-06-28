import { StatTile } from "../../cockpit/primitives";
import type { DashboardStats } from "../useAdminDashboard";
import { money } from "./format";

/** Real System Health: "Operational" when the dashboard loaded, "Degraded" otherwise.
 *  No fabricated uptime number. */
export function SystemHealthCard({ healthy }: { healthy: boolean }) {
  const color = healthy ? "var(--color-sev-low)" : "var(--color-sev-high)";
  return (
    <div className="rounded-[var(--r-tile)] bg-[var(--color-surface-2)] px-3 py-2.5">
      <div className="t-label text-[var(--color-text-dim)]">System Health</div>
      <div className="mt-0.5 text-[var(--fs-display)] font-medium leading-none" style={{ color }}>
        {healthy ? "Operational" : "Degraded"}
      </div>
      <div className="mt-1 t-tag text-[var(--color-text-faint)]">
        {healthy ? "All systems normal" : "Check connectivity"}
      </div>
    </div>
  );
}

export function KpiCards({ stats, healthy }: { stats: DashboardStats; healthy: boolean }) {
  return (
    <div className="grid grid-cols-2 gap-[var(--density-gap-sm)] sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7">
      <StatTile label="Total Users" value={stats.total_users.toLocaleString()} />
      <StatTile label="Paid Users" value={stats.paid_users.toLocaleString()} accent />
      <StatTile label="Free Users" value={stats.free_users.toLocaleString()} />
      <StatTile label="Active Today" value={stats.active_today.toLocaleString()} />
      <StatTile label="Revenue (MRR)" value={money(stats.mrr_cents)} />
      <StatTile label="New (7d)" value={stats.signups_7d.toLocaleString()} />
      <SystemHealthCard healthy={healthy} />
    </div>
  );
}

export default KpiCards;
