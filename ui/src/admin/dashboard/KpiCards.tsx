import { Activity, CreditCard, DollarSign, ShieldCheck, TrendingUp, UserPlus, Users } from "lucide-react";
import { StatCard, StatusPill } from "../ui/kit";
import { ratioPct, type Delta } from "../ui/helpers";
import type { DashboardStats } from "../useAdminDashboard";
import { money } from "./format";

/** Real System Health: "Operational" when the dashboard loaded, "Degraded" otherwise.
 *  No fabricated uptime number. */
export function SystemHealthCard({ healthy }: { healthy: boolean }) {
  const color = healthy ? "var(--color-sev-low)" : "var(--color-sev-high)";
  return (
    <div className="admin-card flex flex-col gap-3 px-4 py-4">
      <div className="flex items-center gap-2 text-[var(--color-text-dim)]">
        <span className="flex h-7 w-7 items-center justify-center rounded-full bg-[color-mix(in_srgb,var(--color-accent)_13%,transparent)] text-[var(--color-accent)]">
          <ShieldCheck size={15} aria-hidden />
        </span>
        <span className="text-[13px] font-medium">System Health</span>
      </div>
      <div>
        <StatusPill label={healthy ? "Operational" : "Degraded"} color={color} />
      </div>
      <div className="text-xs text-[var(--color-text-dim)]">
        {healthy ? "All systems normal" : "Check connectivity"}
      </div>
    </div>
  );
}

export function KpiCards({
  stats,
  healthy,
  signupsDelta,
}: {
  stats: DashboardStats;
  healthy: boolean;
  signupsDelta?: Delta;
}) {
  const total = stats.total_users;
  return (
    <div className="grid grid-cols-2 gap-[var(--density-gap-sm)] md:grid-cols-3 xl:grid-cols-4">
      <StatCard icon={Users} label="Total Users" value={total.toLocaleString()} caption="All accounts" />
      <StatCard
        icon={CreditCard}
        label="Paid Users"
        value={stats.paid_users.toLocaleString()}
        caption={`${ratioPct(stats.paid_users, total)}% of total`}
      />
      <StatCard icon={UserPlus} label="Free Users" value={stats.free_users.toLocaleString()} caption="On the Free plan" />
      <StatCard icon={Activity} label="Active Today" value={stats.active_today.toLocaleString()} caption="Signed in today" />
      <StatCard icon={DollarSign} label="Revenue (MRR)" value={money(stats.mrr_cents)} caption="Monthly recurring" />
      <StatCard
        icon={TrendingUp}
        label="New (7d)"
        value={stats.signups_7d.toLocaleString()}
        delta={signupsDelta}
        caption="New signups"
      />
      <SystemHealthCard healthy={healthy} />
    </div>
  );
}

export default KpiCards;
