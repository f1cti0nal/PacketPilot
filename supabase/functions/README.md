# Edge Functions

PacketPilot is free for everyone with no user accounts. The functions that remain operational:

- `ai-proxy` (JWT OFF — public, rate-limited) — streams AI analyst completions using the
  operator's `AI_API_KEY`; provider/model come from admin-managed `app_settings.ai_config`.
- `reputation-proxy` (JWT OFF — public, rate-limited) — relays reputation lookups to an exact
  host allowlist, injecting the operator's provider keys server-side.
- `stripe-webhook` (JWT OFF — Stripe-signed) — still deployed to keep `subscriptions` /
  `profiles.plan` records consistent while the operator winds down the legacy paid-era
  subscriptions directly in Stripe. Secrets: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`.
  Do not remove until every legacy subscription is cancelled.

Tombstones (deployed as permanent 410s so stale clients get a clear answer, not a gateway 404):
`create-checkout-session`, `create-portal-session`, `delete-account`.

Rate limiting: both proxies call the `check_rate_limit` RPC (migration 0021) with a per-IP key
and a global backstop key — the cost brake on the operator's AI/reputation keys now that the
proxies are anonymous. The admin kill-switches (`ai_config.enabled` / `rep_config.enabled`)
remain the hard off switch.
