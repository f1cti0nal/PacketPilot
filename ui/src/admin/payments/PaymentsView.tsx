import { useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";
import { LoadingState } from "../../components/state/LoadingState";
import { ErrorState } from "../../components/state/ErrorState";
import { joinedDate, money } from "../dashboard/format";
import { useAdminPayments, type AdminPayment } from "./useAdminPayments";
import { paymentsSummary } from "./summary";
import { MiniStat, PillButton, SearchInput, SectionTitle, StatusPill, TableCard } from "../ui/kit";

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
      <div className="flex flex-wrap items-center gap-3">
        <SectionTitle title="Payments" subtitle="Subscriptions and revenue from Stripe" />
        <PillButton className="ml-auto" icon={RefreshCw} variant="secondary" onClick={reload}>
          Refresh
        </PillButton>
      </div>

      <div className="grid grid-cols-2 gap-[var(--density-gap-sm)] md:grid-cols-4">
        <MiniStat label="Active MRR" value={money(mrrCents)} />
        <MiniStat label="Active subs" value={String(summary.activeCount)} />
        <MiniStat label="Past due" value={String(summary.statusCounts.past_due ?? 0)} />
        <MiniStat label="Canceled" value={String(summary.statusCounts.canceled ?? 0)} />
      </div>

      <div className="w-full max-w-xs">
        <SearchInput
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by email…"
          aria-label="Search payments by email"
        />
      </div>

      {state.status === "loading" ? (
        <LoadingState label="Loading payments…" />
      ) : state.status === "error" ? (
        <ErrorState title="Couldn't load payments" message={state.error} />
      ) : rows.length === 0 ? (
        <p className="text-sm text-[var(--color-text-dim)]">
          {payments.length === 0 ? "No subscriptions yet." : "No matches."}
        </p>
      ) : (
        <TableCard
          title="Subscriptions"
          count={rows.length}
          footer={
            <>
              Reflects the latest Stripe sync.
              {capped &&
                " Showing the latest 100 subscriptions; the counts above describe this page (Active MRR is global)."}
            </>
          }
        >
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
        </TableCard>
      )}
    </div>
  );
}

function PaymentRow({ p, showCurrency }: { p: AdminPayment; showCurrency: boolean }) {
  const color = STATUS_COLOR[p.status] ?? "var(--color-text-dim)";
  return (
    <tr title={p.price_id ?? undefined}>
      <td>
        <div className="font-medium text-[var(--color-text)]">{p.email ?? p.id}</div>
        {p.full_name && <div className="text-xs text-[var(--color-text-dim)]">{p.full_name}</div>}
      </td>
      <td className="font-mono-num">
        {money(p.amount_cents)}
        {showCurrency && <span className="ml-1 text-xs uppercase text-[var(--color-text-dim)]">{p.currency}</span>}
      </td>
      <td>
        <StatusPill label={p.status} color={color} />
      </td>
      <td className="font-mono-num text-[var(--color-text-dim)]">
        {p.current_period_end ? joinedDate(p.current_period_end) : "—"}
        {p.cancel_at_period_end && (
          <span className="ml-1.5 inline-flex items-center rounded-full border border-[var(--color-sev-medium)] bg-[var(--color-surface-2)] px-2 py-0.5 text-xs font-medium text-[var(--color-sev-medium)]">
            Cancels at period end
          </span>
        )}
      </td>
      <td className="font-mono-num text-[var(--color-text-dim)]">{joinedDate(p.created_at)}</td>
    </tr>
  );
}

export default PaymentsView;
