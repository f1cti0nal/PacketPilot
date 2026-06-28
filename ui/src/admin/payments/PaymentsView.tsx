import { useMemo, useState } from "react";
import { LoadingState } from "../../components/state/LoadingState";
import { ErrorState } from "../../components/state/ErrorState";
import { joinedDate, money } from "../dashboard/format";
import { useAdminPayments, type AdminPayment } from "./useAdminPayments";
import { paymentsSummary } from "./summary";

const STATUS_COLOR: Record<string, string> = {
  active: "var(--color-sev-low)",
  trialing: "var(--color-sev-low)",
  past_due: "var(--color-sev-medium)",
  unpaid: "var(--color-sev-medium)",
  canceled: "var(--color-text-dim)",
  incomplete: "var(--color-text-dim)",
  incomplete_expired: "var(--color-text-dim)",
  paused: "var(--color-text-dim)",
};

export function PaymentsView() {
  const { state, reload } = useAdminPayments();
  const [search, setSearch] = useState("");

  const payments = state.status === "ready" ? state.payments : [];
  const mrrCents = state.status === "ready" ? state.mrrCents : 0;
  const capped = payments.length === 100;
  const summary = useMemo(() => paymentsSummary(payments), [payments]);
  const anyNonUsd = payments.some((p) => p.currency !== "usd");
  const term = search.trim().toLowerCase();
  const rows = term
    ? payments.filter(
        (p) => (p.email ?? "").toLowerCase().includes(term) || (p.full_name ?? "").toLowerCase().includes(term),
      )
    : payments;

  return (
    <div className="flex flex-col gap-[var(--density-gap)]">
      <div className="flex flex-wrap items-end gap-3">
        <Kpi label="Active MRR" value={money(mrrCents)} />
        <Kpi label="Active subs" value={String(summary.activeCount)} />
        <Kpi label="Past due" value={String(summary.statusCounts.past_due ?? 0)} />
        <Kpi label="Canceled" value={String(summary.statusCounts.canceled ?? 0)} />
        <button
          type="button"
          onClick={reload}
          className="ml-auto rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-xs text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
        >
          Refresh
        </button>
      </div>
      <input
        type="search"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="Search by email…"
        aria-label="Search payments by email"
        className="w-full max-w-sm rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-sm text-[var(--color-text)] placeholder:text-[var(--color-text-dim)]"
      />
      {state.status === "loading" ? (
        <LoadingState label="Loading payments…" />
      ) : state.status === "error" ? (
        <ErrorState title="Couldn't load payments" message={state.error} />
      ) : rows.length === 0 ? (
        <p className="text-sm text-[var(--color-text-dim)]">
          {payments.length === 0 ? "No subscriptions yet." : "No matches."}
        </p>
      ) : (
        <table className="pp-table">
          <thead>
            <tr>
              <th>User</th>
              <th>Amount</th>
              <th>Status</th>
              <th>Renews</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((p) => (
              <PaymentRow key={p.id} p={p} showCurrency={anyNonUsd} />
            ))}
          </tbody>
        </table>
      )}
      <p className="t-tag text-[var(--color-text-dim)]">
        Reflects the latest Stripe sync.
        {capped && " Showing the latest 100 subscriptions; the counts above describe this page (Active MRR is global)."}
      </p>
    </div>
  );
}

function PaymentRow({ p, showCurrency }: { p: AdminPayment; showCurrency: boolean }) {
  const color = STATUS_COLOR[p.status] ?? "var(--color-text-dim)";
  return (
    <tr title={p.price_id ?? undefined}>
      <td>
        <div>{p.email ?? p.id}</div>
        {p.full_name && <div className="t-tag text-[var(--color-text-dim)]">{p.full_name}</div>}
      </td>
      <td className="font-mono-num">
        {money(p.amount_cents)}
        {showCurrency && <span className="ml-1 t-tag uppercase text-[var(--color-text-dim)]">{p.currency}</span>}
      </td>
      <td>
        <span className="inline-flex items-center gap-1.5 t-tag uppercase" style={{ color }}>
          <span aria-hidden className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
          {p.status}
        </span>
      </td>
      <td className="font-mono-num text-[var(--color-text-dim)]">
        {p.current_period_end ? joinedDate(p.current_period_end) : "—"}
        {p.cancel_at_period_end && (
          <span className="ml-1.5 inline-flex items-center rounded-[var(--r-chip)] border border-[var(--color-border)] px-1.5 py-0.5 t-tag uppercase text-[var(--color-sev-medium)]">
            Cancels at period end
          </span>
        )}
      </td>
      <td className="font-mono-num text-[var(--color-text-dim)]">{joinedDate(p.created_at)}</td>
    </tr>
  );
}

function Kpi({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2">
      <div className="t-tag uppercase text-[var(--color-text-dim)]">{label}</div>
      <div className="font-mono-num text-lg text-[var(--color-text)]">{value}</div>
    </div>
  );
}

export default PaymentsView;
