import { supabaseConfigured } from "../../lib/supabase";
import { useAdminAppSettings } from "../settings/useAdminAppSettings";
import { joinedDate } from "../dashboard/format";
import { maskKey, maskUrl } from "./envMask";
import { SectionTitle, StatusPill, TableCard } from "../ui/kit";

const PUBLIC_VARS: { name: string; value: string | undefined; mask: (v: string | undefined) => string }[] = [
  { name: "VITE_SUPABASE_URL", value: import.meta.env.VITE_SUPABASE_URL, mask: maskUrl },
  { name: "VITE_SUPABASE_ANON_KEY", value: import.meta.env.VITE_SUPABASE_ANON_KEY, mask: maskKey },
  { name: "VITE_GA_MEASUREMENT_ID", value: import.meta.env.VITE_GA_MEASUREMENT_ID, mask: (v) => v ?? "—" },
];

// Static inventory — the browser CANNOT and MUST NOT query these. Names + locations only.
const SERVER_SECRETS: { name: string; location: string; usedBy: string }[] = [
  { name: "STRIPE_SECRET_KEY", location: "Supabase → Edge Function secrets", usedBy: "stripe-webhook (legacy-subscription wind-down)" },
  { name: "STRIPE_WEBHOOK_SECRET", location: "Supabase → Edge Function secrets", usedBy: "stripe-webhook" },
  { name: "SUPABASE_SERVICE_ROLE_KEY", location: "Supabase → Edge Function secrets", usedBy: "stripe-webhook" },
  { name: "AI_API_KEY", location: "Supabase → Edge Function secrets", usedBy: "ai-proxy" },
  { name: "ABUSEIPDB_KEY", location: "Supabase → Edge Function secrets", usedBy: "reputation-proxy" },
  { name: "GREYNOISE_KEY", location: "Supabase → Edge Function secrets", usedBy: "reputation-proxy" },
  { name: "VIRUSTOTAL_KEY", location: "Supabase → Edge Function secrets", usedBy: "reputation-proxy" },
];

function Chip({ ok }: { ok: boolean }) {
  return <StatusPill label={ok ? "Configured" : "Missing"} color={ok ? "var(--color-sev-low)" : "var(--color-sev-medium)"} />;
}

export function EnvironmentView() {
  const { state } = useAdminAppSettings();
  return (
    <div className="flex flex-col gap-[var(--density-gap)]">
      <SectionTitle title="Environment" subtitle="Environment variables and secrets" />

      <TableCard
        title="Public app config"
        footer={supabaseConfigured ? "Backend configured." : "Backend not configured (set these in the Vercel project)."}
      >
        <table className="pp-table" aria-label="Public app config">
          <thead>
            <tr><th>Variable</th><th>Status</th><th>Value (masked)</th></tr>
          </thead>
          <tbody>
            {PUBLIC_VARS.map((v) => (
              <tr key={v.name}>
                <td className="font-mono-num font-medium text-[var(--color-text)]">{v.name}</td>
                <td><Chip ok={Boolean(v.value)} /></td>
                <td className="font-mono-num text-[var(--color-text-dim)]">{v.mask(v.value)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableCard>

      <TableCard title="Server secrets" footer="Managed server-side — never fetched into the browser.">
        <table className="pp-table" aria-label="Server secrets">
          <thead>
            <tr><th>Secret</th><th>Status</th><th>Where it's set</th><th>Used by</th></tr>
          </thead>
          <tbody>
            {SERVER_SECRETS.map((s) => (
              <tr key={s.name}>
                <td className="font-mono-num font-medium text-[var(--color-text)]">{s.name}</td>
                <td className="text-xs font-medium uppercase text-[var(--color-text-dim)]">Server-managed</td>
                <td className="text-[var(--color-text-dim)]">{s.location}</td>
                <td className="text-xs text-[var(--color-text-dim)]">{s.usedBy}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableCard>

      <TableCard title="App settings (read-only)">
        {state.status === "ready" ? (
          <table className="pp-table" aria-label="App settings mirror">
            <thead>
              <tr><th>Key</th><th>Value</th><th>Updated</th></tr>
            </thead>
            <tbody>
              {state.settings.map((s) => (
                <tr key={s.key}>
                  <td className="font-mono-num font-medium text-[var(--color-text)]">{s.key}</td>
                  <td className="font-mono-num text-[var(--color-text-dim)]">{JSON.stringify(s.value).slice(0, 80)}</td>
                  <td className="font-mono-num text-[var(--color-text-dim)]">{joinedDate(s.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="px-5 py-4 text-sm text-[var(--color-text-dim)]">Settings unavailable.</p>
        )}
      </TableCard>
    </div>
  );
}

export default EnvironmentView;
