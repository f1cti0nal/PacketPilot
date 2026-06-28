import { useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../supabase";
import { parsePublicSettings, SETTINGS_DEFAULTS, type PublicSettings } from "./publicSettings";

export function useAppSettings(): PublicSettings {
  const [settings, setSettings] = useState<PublicSettings>(SETTINGS_DEFAULTS);

  useEffect(() => {
    if (!supabaseConfigured || !supabase) return; // offline → DEFAULTS, no network
    const client = supabase;
    let cancelled = false;
    void (async () => {
      try {
        const { data, error } = await client.rpc("get_public_settings");
        if (error || cancelled) return; // fail-open: keep DEFAULTS
        if (!cancelled) setSettings(parsePublicSettings(data));
      } catch {
        /* fail-open: keep DEFAULTS */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return settings;
}
