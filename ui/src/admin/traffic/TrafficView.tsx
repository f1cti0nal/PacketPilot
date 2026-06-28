import { Card } from "../../cockpit/primitives";
import { LoadingState } from "../../components/state/LoadingState";
import { ErrorState } from "../../components/state/ErrorState";
import { SignupsAreaChart } from "../dashboard/SignupsAreaChart";
import { joinedDate } from "../dashboard/format";
import { useAdminTraffic, type RecentEvent, type TopPath } from "./useAdminTraffic";

function Kpi({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2">
      <div className="t-tag uppercase text-[var(--color-text-dim)]">{label}</div>
      <div className="font-mono-num text-lg text-[var(--color-text)]">{value}</div>
    </div>
  );
}

export function TrafficView() {
  const { state } = useAdminTraffic();
  if (state.status === "loading") return <LoadingState label="Loading traffic…" />;
  if (state.status === "error") return <ErrorState title="Couldn't load traffic" message={state.error} />;
  const { stats, byDay, topPaths, recent } = state.data;
  const empty = stats.pageviews_today === 0 && byDay.every((d) => d.count === 0) && topPaths.length === 0 && recent.length === 0;

  return (
    <div className="flex flex-col gap-[var(--density-gap)]">
      <div className="flex flex-wrap items-end gap-3">
        <Kpi label="Active users today" value={String(stats.active_today)} />
        <Kpi label="Page views today" value={String(stats.pageviews_today)} />
        <Kpi label="Signed-in" value={String(stats.authed_today)} />
        <Kpi label="Anonymous" value={String(stats.anon_today)} />
      </div>
      {empty ? (
        <p className="text-sm text-[var(--color-text-dim)]">No traffic yet.</p>
      ) : (
        <>
          <Card title="Page views (14d)">
            <SignupsAreaChart data={byDay} />
          </Card>
          <div className="grid gap-[var(--density-gap)] lg:grid-cols-2">
            <Card title="Top paths (7d)">
              <TopPathsTable rows={topPaths} />
            </Card>
            <Card title="Recent activity">
              <RecentTable rows={recent} />
            </Card>
          </div>
        </>
      )}
    </div>
  );
}

function TopPathsTable({ rows }: { rows: TopPath[] }) {
  if (rows.length === 0) return <p className="text-sm text-[var(--color-text-dim)]">No paths yet.</p>;
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
            <td className="font-mono-num">{r.count}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function RecentTable({ rows }: { rows: RecentEvent[] }) {
  if (rows.length === 0) return <p className="text-sm text-[var(--color-text-dim)]">No recent activity.</p>;
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
            <td className="t-tag uppercase text-[var(--color-text-dim)]">{r.signedIn ? "Yes" : "No"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default TrafficView;
