/** Minimal shape paymentsSummary needs; AdminPayment satisfies it. */
export interface PaymentLike {
  status: string;
  amount_cents: number;
}

export interface PaymentsSummary {
  activeMrrCents: number;
  activeCount: number;
  statusCounts: Record<string, number>;
}

export function paymentsSummary(payments: readonly PaymentLike[]): PaymentsSummary {
  let activeMrrCents = 0;
  let activeCount = 0;
  const statusCounts: Record<string, number> = {};
  for (const p of payments) {
    statusCounts[p.status] = (statusCounts[p.status] ?? 0) + 1;
    if (p.status === "active") {
      activeMrrCents += p.amount_cents;
      activeCount += 1;
    }
  }
  return { activeMrrCents, activeCount, statusCounts };
}
