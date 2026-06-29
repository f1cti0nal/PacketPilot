import { useEffect, useState } from "react";
import { supabase } from "../lib/supabase";

export interface PricingStatus {
  annual_available: boolean;
  founder_available: boolean;
  founder_cap: number;
  founder_remaining: number;
}

const DEFAULT: PricingStatus = {
  annual_available: false,
  founder_available: false,
  founder_cap: 200,
  founder_remaining: 200,
};

/** Reads the public pricing status (which paid plans are live + Founder seats left). */
export function usePricing(): { status: PricingStatus; loading: boolean } {
  const [status, setStatus] = useState<PricingStatus>(DEFAULT);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!supabase) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    void supabase.rpc("get_pricing_status").then(
      ({ data }) => {
        if (cancelled) return;
        if (data && typeof data === "object") setStatus({ ...DEFAULT, ...(data as Partial<PricingStatus>) });
        setLoading(false);
      },
      () => {
        if (!cancelled) setLoading(false);
      },
    );
    return () => {
      cancelled = true;
    };
  }, []);

  return { status, loading };
}
