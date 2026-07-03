import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { DayPoint } from "../useAdminDashboard";
import { shortDay } from "./format";

const ACCENT = "var(--color-accent)";

export function SubscriptionsBarChart({ data }: { data: DayPoint[] }) {
  if (data.length === 0) {
    return (
      <div className="flex h-48 items-center justify-center text-sm text-[var(--color-text-faint)]">No data</div>
    );
  }
  return (
    <div data-component="SubscriptionsBarChart" className="h-56 w-full text-[var(--color-text-dim)]">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 12, bottom: 4, left: 4 }}>
          <CartesianGrid stroke="var(--color-grid)" strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="day" tickFormatter={shortDay} tick={{ fill: "var(--color-text-faint)", fontSize: 11 }} stroke="var(--color-border)" minTickGap={24} tickMargin={8} />
          <YAxis width={32} allowDecimals={false} tick={{ fill: "var(--color-text-faint)", fontSize: 11 }} stroke="var(--color-border)" />
          <Tooltip
            cursor={{ fill: "var(--color-surface-2)", fillOpacity: 0.5 }}
            contentStyle={{ background: "var(--color-surface-2)", border: "1px solid var(--color-border)", borderRadius: 8, fontSize: 12 }}
          />
          <Bar dataKey="count" name="New subscriptions" fill={ACCENT} radius={[6, 6, 0, 0]} maxBarSize={30} isAnimationActive={false} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export default SubscriptionsBarChart;
