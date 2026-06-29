import { supabaseConfigured } from "../../lib/supabase";
import { useAdminAppSettings } from "../settings/useAdminAppSettings";
import { joinedDate } from "../dashboard/format";
import { maskKey, maskUrl } from "./envMask";

const PUBLIC_VARS: { name: string; value: string | undefined; mask: (v: string | undefined) => string }[] = [
  { name: "VITE_SUPABASE_URL", value: import.meta.env.VITE_SUPABASE_URL, mask: maskUrl },
  { name: "VITE_SUPABASE_ANON_KEY", value: import.meta.env.VITE_SUPABASE_ANON_KEY, mask: maskKey },
];

// Static inventory — the browser CANNOT and MUST NOT query these. Names + locations only.
const SERVER_SECRETS: { name: string; location: string; usedBy: string }[] = [
  { name: "STRIPE_SECRET_KEY", location: "Supabase → Edge Function secrets", usedBy: "create-checkout-session, create-portal-session, stripe-webhook" },
  { name: "STRIPE_WEBHOOK_SECRET", location: "Supabase → Edge Function secrets", usedBy: "stripe-webhook" },
  { name: "STRIPE_PRICE_PRO", location: "Supabase → Edge Function secrets", usedBy: "create-checkout-session" },
  { name: "SUPABASE_SERVICE_ROLE_KEY", location: "Supabase → Edge Function secrets", usedBy: "stripe-webhook" },
  { name: "AI_API_KEY", location: "Supabase → Edge Function secrets", usedBy: "ai-proxy" },
  { name: "ABUSEIPDB_KEY", location: "Supabase → Edge Function secrets", usedBy: "reputation-proxy" },
  { name: "GREYNOISE_KEY", location: "Supabase → Edge Function secrets", usedBy: "reputation-proxy" },
  { name: "VIRUSTOTAL_KEY", location: "Supabase → Edge Function secrets", usedBy: "reputation-proxy" },
];

function Chip({ ok }: { ok: boolean }) {
  return (
    <span className="t-tag uppercase" style={{ color: ok ? "var(--color-sev-low)" : "var(--color-sev-medium)" }}>
      {ok ? "Configured" : "Missing"}
    </span>
  );
}

export function EnvironmentView() {
  const { state } = useAdminAppSettings();
  return (
    <div className="flex flex-col gap-[var(--density-gap)]">
      <section>
        <h3 className="mb-1 t-tag uppercase text-[var(--color-text-dim)]">Public app config (browser)</h3>
        <table className="pp-table" aria-label="Public app config">
          <thead>
            <tr><th>Variable</th><th>Status</th><th>Value (masked)</th></tr>
          </thead>
          <tbody>
            {PUBLIC_VARS.map((v) => (
              <tr key={v.name}>
                <td className="font-mono-num">{v.name}</td>
                <td><Chip ok={Boolean(v.value)} /></td>
                <td className="font-mono-num text-[var(--color-text-dim)]">{v.mask(v.value)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="mt-1 t-tag text-[var(--color-text-dim)]">
          {supabaseConfigured ? "Backend configured." : "Backend not configured (set these in the Vercel project)."}
        </p>
      </section>

      <section>
        <h3 className="mb-1 t-tag uppercase text-[var(--color-text-dim)]">Server secrets (managed server-side — not visible here)</h3>
        <table className="pp-table" aria-label="Server secrets">
          <thead>
            <tr><th>Secret</th><th>Status</th><th>Where it's set</th><th>Used by</th></tr>
          </thead>
          <tbody>
            {SERVER_SECRETS.map((s) => (
              <tr key={s.name}>
                <td className="font-mono-num">{s.name}</td>
                <td className="t-tag uppercase text-[var(--color-text-dim)]">Server-managed</td>
                <td className="text-[var(--color-text-dim)]">{s.location}</td>
                <td className="t-tag text-[var(--color-text-dim)]">{s.usedBy}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section>
        <h3 className="mb-1 t-tag uppercase text-[var(--color-text-dim)]">App settings (read-only)</h3>
        {state.status === "ready" ? (
          <table className="pp-table" aria-label="App settings mirror">
            <thead>
              <tr><th>Key</th><th>Value</th><th>Updated</th></tr>
            </thead>
            <tbody>
              {state.settings.map((s) => (
                <tr key={s.key}>
                  <td className="font-mono-num">{s.key}</td>
                  <td className="font-mono-num text-[var(--color-text-dim)]">{JSON.stringify(s.value).slice(0, 80)}</td>
                  <td className="font-mono-num text-[var(--color-text-dim)]">{joinedDate(s.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="text-sm text-[var(--color-text-dim)]">Settings unavailable.</p>
        )}
      </section>
    </div>
  );
}

export default EnvironmentView;
