import { supabase } from "../supabase";
import type { HttpGet } from "./http";

const FN_URL = `${import.meta.env.VITE_SUPABASE_URL ?? ""}/functions/v1/reputation-proxy`;

/** HttpGet that relays {url,headers} through the authed reputation-proxy (the key is injected server-side). */
export function edgeRepHttp(): HttpGet {
  return async (url, headers) => {
    if (!supabase) return { status: 0, body: "" };
    const { data } = await supabase.auth.getSession();
    const token = data.session?.access_token;
    if (!token) return { status: 0, body: "" };
    try {
      const resp = await fetch(FN_URL, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          apikey: import.meta.env.VITE_SUPABASE_ANON_KEY ?? "",
          Authorization: `Bearer ${token}`,
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
