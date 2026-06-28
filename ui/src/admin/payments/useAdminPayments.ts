import { useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../../lib/supabase";

export interface AdminPayment {
  id: string;
  email: string | null;
  full_name: string | null;
  status: string;
  amount_cents: number;
  currency: string;
  price_id: string | null;
  current_period_end: string | null;
  cancel_at_period_end: boolean;
  created_at: string;
  stripe_subscription_id: string | null;
  stripe_customer_id: string | null;
}

export type AdminPaymentsState =
  | { status: "loading" }
  | { status: "error"; error: string }
  | { status: "ready"; payments: AdminPayment[] };

const SEL =
  "id,status,amount_cents,currency,price_id,current_period_end,cancel_at_period_end,created_at,stripe_subscription_id,stripe_customer_id,profiles(email,full_name)";

interface RawProfile {
  email: string | null;
  full_name: string | null;
}
interface RawRow {
  id: string;
  status: string;
  amount_cents: number | null;
  currency: string | null;
  price_id: string | null;
  current_period_end: string | null;
  cancel_at_period_end: boolean | null;
  created_at: string;
  stripe_subscription_id: string | null;
  stripe_customer_id: string | null;
  profiles: RawProfile | RawProfile[] | null;
}

function toPayment(r: RawRow): AdminPayment {
  const p = Array.isArray(r.profiles) ? r.profiles[0] : r.profiles;
  return {
    id: r.id,
    email: p?.email ?? null,
    full_name: p?.full_name ?? null,
    status: r.status,
    amount_cents: r.amount_cents ?? 0,
    currency: r.currency ?? "usd",
    price_id: r.price_id,
    current_period_end: r.current_period_end,
    cancel_at_period_end: r.cancel_at_period_end ?? false,
    created_at: r.created_at,
    stripe_subscription_id: r.stripe_subscription_id,
    stripe_customer_id: r.stripe_customer_id,
  };
}

export function useAdminPayments(): { state: AdminPaymentsState; reload: () => void } {
  const [state, setState] = useState<AdminPaymentsState>({ status: "loading" });
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    if (!supabaseConfigured || !supabase) {
      setState({ status: "error", error: "Backend not configured" });
      return;
    }
    const client = supabase;
    let cancelled = false;
    void (async () => {
      try {
        const { data, error } = await client
          .from("subscriptions")
          .select(SEL)
          .order("created_at", { ascending: false })
          .limit(100);
        if (error) throw new Error((error as { message?: string }).message ?? "Query failed");
        if (cancelled) return;
        const payments = ((data ?? []) as unknown as RawRow[]).map(toPayment);
        setState({ status: "ready", payments });
      } catch (e) {
        if (!cancelled) setState({ status: "error", error: e instanceof Error ? e.message : String(e) });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [nonce]);

  return { state, reload: () => setNonce((n) => n + 1) };
}
