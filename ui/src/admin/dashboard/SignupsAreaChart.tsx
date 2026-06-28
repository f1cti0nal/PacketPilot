import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { DayPoint } from "../useAdminDashboard";
import { shortDay } from "./format";

const ACCENT = "var(--color-accent)";

export function SignupsAreaChart({ data }: { data: DayPoint[] }) {
  if (data.length === 0) {
    return (
      <div className="flex h-48 items-center justify-center text-sm text-[var(--color-text-faint)]">No data</div>
    );
  }
  return (
    <div data-component="SignupsAreaChart" className="h-48 w-full text-[var(--color-text-dim)]">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 8, right: 12, bottom: 4, left: 4 }}>
          <defs>
            <linearGradient id="signups-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={ACCENT} stopOpacity={0.35} />
              <stop offset="100%" stopColor={ACCENT} stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="var(--color-grid)" strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="day" tickFormatter={shortDay} tick={{ fill: "var(--color-text-faint)", fontSize: 11 }} stroke="var(--color-border)" minTickGap={24} tickMargin={8} />
          <YAxis width={32} allowDecimals={false} tick={{ fill: "var(--color-text-faint)", fontSize: 11 }} stroke="var(--color-border)" />
          <Tooltip
            cursor={{ stroke: ACCENT, strokeOpacity: 0.4 }}
            contentStyle={{ background: "var(--color-surface-2)", border: "1px solid var(--color-border)", borderRadius: 8, fontSize: 12 }}
          />
          <Area type="monotone" dataKey="count" name="New users" stroke={ACCENT} strokeWidth={1.75} fill="url(#signups-fill)" isAnimationActive={false} dot={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

export default SignupsAreaChart;
