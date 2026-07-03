import { AdminCard, MiniStat, SectionTitle, TableCard } from "../ui/kit";
import { LoadingState } from "../../components/state/LoadingState";
import { ErrorState } from "../../components/state/ErrorState";
import { SignupsAreaChart } from "../dashboard/SignupsAreaChart";
import { joinedDate } from "../dashboard/format";
import { useAdminTraffic, type RecentEvent, type TopPath } from "./useAdminTraffic";

export function TrafficView() {
  const { state } = useAdminTraffic();
  if (state.status === "loading") return <LoadingState label="Loading traffic…" />;
  if (state.status === "error") return <ErrorState title="Couldn't load traffic" message={state.error} />;
  const { stats, byDay, topPaths, recent } = state.data;
  const empty = stats.pageviews_today === 0 && byDay.every((d) => d.count === 0) && topPaths.length === 0 && recent.length === 0;

  return (
    <div className="flex flex-col gap-[var(--density-gap)]">
      <SectionTitle title="Live Traffic" subtitle="Live visits and page activity" />

      <div className="grid grid-cols-2 gap-[var(--density-gap-sm)] md:grid-cols-4">
        <MiniStat label="Active users today" value={String(stats.active_today)} />
        <MiniStat label="Page views today" value={String(stats.pageviews_today)} />
        <MiniStat label="Signed-in" value={String(stats.authed_today)} />
        <MiniStat label="Anonymous" value={String(stats.anon_today)} />
      </div>

      {empty ? (
        <p className="text-sm text-[var(--color-text-dim)]">No traffic yet.</p>
      ) : (
        <>
          <AdminCard title="Page views" subtitle="Daily views over the last 14 days">
            <SignupsAreaChart data={byDay} />
          </AdminCard>
          <div className="grid gap-[var(--density-gap)] lg:grid-cols-2">
            <TableCard title="Top paths" count={topPaths.length}>
              <TopPathsTable rows={topPaths} />
            </TableCard>
            <TableCard title="Recent activity" count={recent.length}>
              <RecentTable rows={recent} />
            </TableCard>
          </div>
        </>
      )}
    </div>
  );
}

function TopPathsTable({ rows }: { rows: TopPath[] }) {
  if (rows.length === 0) return <p className="px-5 py-4 text-sm text-[var(--color-text-dim)]">No paths yet.</p>;
  return (
    <table className="pp-table">
      <thead>
        <tr>
          <th>Path</th>
          <th>Views</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.path}>
            <td className="font-mono-num">{r.path}</td>
            <td className="font-mono-num text-[var(--color-text-dim)]">{r.count}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function RecentTable({ rows }: { rows: RecentEvent[] }) {
  if (rows.length === 0) return <p className="px-5 py-4 text-sm text-[var(--color-text-dim)]">No recent activity.</p>;
  return (
    <table className="pp-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Path</th>
          <th>Signed in?</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={`${r.created_at}-${i}`}>
            <td className="font-mono-num text-[var(--color-text-dim)]">{joinedDate(r.created_at)}</td>
            <td className="font-mono-num">{r.path}</td>
            <td className="text-xs font-medium text-[var(--color-text-dim)]">{r.signedIn ? "Yes" : "No"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default TrafficView;
