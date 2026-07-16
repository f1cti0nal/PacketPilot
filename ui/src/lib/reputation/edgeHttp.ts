import { supabase } from "../supabase";
import type { HttpGet } from "./http";

const FN_URL = `${import.meta.env.VITE_SUPABASE_URL ?? ""}/functions/v1/reputation-proxy`;

/** HttpGet that relays {url,headers} through the public reputation-proxy (the provider key is
 *  injected server-side). No sign-in — PacketPilot has no accounts — so only the anon apikey
 *  rides along. */
export function edgeRepHttp(): HttpGet {
  return async (url, headers) => {
    if (!supabase) return { status: 0, body: "" };
    try {
      const resp = await fetch(FN_URL, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          apikey: import.meta.env.VITE_SUPABASE_ANON_KEY ?? "",
        },
        body: JSON.stringify({ url, headers }),
      });
      if (!resp.ok) return { status: resp.status, body: "" };
      const d = await resp.json();
      return { status: Number(d.status) || 0, body: typeof d.body === "string" ? d.body : "" };
    } catch {
      return { status: 0, body: "" };
    }
  };
}
