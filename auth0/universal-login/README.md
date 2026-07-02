# Auth0 Universal Login — PacketPilot branding

Custom **New Universal Login** for the Auth0 hosted login/signup/reset/MFA screens, matched to
the PacketPilot design system (slate-navy `#0b1220`, enterprise-blue `#60a5fa`, Geist).

The redirect flow is unchanged — users still go to Auth0 to enter credentials. We only skin what
Auth0 renders. **This means your Post-Login Action pipeline (role claim + `provision_profile` +
admin MFA) is completely untouched** — branding lives in a different subsystem and cannot affect
token claims or provisioning.

## Files

| File | What it controls | How it's applied |
|------|------------------|------------------|
| `page-template.liquid` | The **surround**: split-screen layout, branding panel, page background. | `PUT /api/v2/branding/templates/universal-login` (or `auth0 ul templates update`) |
| `theme.json` | The **login box**: widget colors, borders, fonts, logo slot. | Merge into the tenant theme, then `PATCH /api/v2/branding/themes/{id}` (or the Dashboard theme editor) |

**Two rules that matter:**
1. **Never hand-CSS the widget internals.** Auth0 regenerates the login box's CSS class names on
   every build, so any selector targeting them breaks silently. The template styles only *our*
   elements; the box is styled via the theme. That split is deliberate — keep it.
2. **Page templates require a Custom Domain** (see step 1). Until one is configured, Auth0 ignores
   the template and shows the default page.

---

## Step 1 — Configure a Custom Domain (the gate) ⚠️ required

The tenant currently serves login on `dev-z7p2u0ds62xilshu.us.auth0.com` and has **no custom
domain**, so page templates won't render yet.

1. Auth0 Dashboard → **Branding → Custom Domains** → add `auth.packetpilot.app`.
   - Self-managed vs Auth0-managed: pick **Auth0-managed** (simplest; Auth0 handles the cert).
   - Custom domains are available even on the **Free** plan, but require a one-time credit-card
     verification (no charge).
2. Add the CNAME it gives you (e.g. `auth` → `…edge.tenants.auth0.com`) at your DNS provider
   (packetpilot.app is on Vercel nameservers).
3. Wait for **Verified + Ready**.

> You have already done exactly this dance for `admin.packetpilot.app` — same steps, different host.

## Step 2 — Point the app at the custom domain (recommended, but read the ⚠️)

Configuring the custom domain unlocks the template. For the cleanest UX you also want the login
*URL* to read `auth.packetpilot.app` instead of `dev-…auth0.com`, which means switching the SPA to
initiate auth against the custom domain:

- Vercel env: `VITE_AUTH0_DOMAIN = auth.packetpilot.app` (client id unchanged:
  `aEaW25tXlwSHWM4HRQrx5xqHq08De8sm`).

**⚠️ This changes the token issuer** (`iss` becomes `https://auth.packetpilot.app/`). Because
Supabase Third-Party Auth and the inlined Edge-Function JWKS verifier both validate `iss` and fetch
JWKS from `https://<domain>/.well-known/jwks.json`, switching the SPA domain **without** updating
the backend will 401 every authenticated request. If you switch, also update **all three**:

1. **Supabase** → Authentication → Third-Party Auth → the Auth0 entry's issuer/domain →
   `auth.packetpilot.app`.
2. Edge Function secret `AUTH0_DOMAIN = auth.packetpilot.app`, then redeploy the 5 authed functions
   (`ai-proxy`, `reputation-proxy`, `create-checkout-session`, `create-portal-session`,
   `delete-account`) — their verifier's `iss` check + JWKS URL are inlined per `index.ts`.
3. `auth0SendPasswordReset` in `ui/src/auth/auth0Client.ts` posts to `https://${domain}/dbconnections/change_password`,
   so it follows `VITE_AUTH0_DOMAIN` automatically — no code change, just re-verify it works.

**Lower-risk alternative:** configure the custom domain (step 1) to unlock the template but leave
`VITE_AUTH0_DOMAIN` on the canonical tenant domain. The branded template still renders; the visible
URL just stays `dev-…auth0.com`. Do the domain switch as a deliberate follow-up once you've verified
the look, exactly like the admin-subdomain rollout.

## Step 3 — Apply the page template

**Auth0 CLI (recommended — no token handling):**
```bash
auth0 login                       # once, opens browser
auth0 ul templates update         # opens the current template in your editor, then deploys on save
#   → paste the contents of page-template.liquid, save, confirm the deploy
```
> `templates update` deploys but does **not** render a live preview. To preview branding changes in
> a browser, use `auth0 universal-login customize` (Standard mode), or the Dashboard theme editor.

**Or Management API** (needs a Management API token with `update:branding`):
```bash
# jq builds the JSON body so the Liquid is safely escaped.
curl -sX PUT "https://$AUTH0_DOMAIN/api/v2/branding/templates/universal-login" \
  -H "Authorization: Bearer $MGMT_TOKEN" \
  -H 'Content-Type: application/json' \
  --data "$(jq -Rs '{template: .}' auth0/universal-login/page-template.liquid)"
```

## Step 4 — Apply the theme

The theme API validates the **whole** object, so start from your live theme and overlay
`theme.json`'s values (don't send only these keys).

**Dashboard (easiest):** Branding → **Universal Login → Customization** (the visual theme editor).
Punch in the values from `theme.json`: widget background `#0f1828`, primary button `#1d4ed8` /
white label, body text `#e7edf7`, inputs `#141e30` on `#223049`, links/focus `#60a5fa`, widget
radius `12`, button/input radius `8`, page background `#0b1220`, **logo → None** (the template draws
the mark), and the Geist font URL under Fonts.

**Or Management API:**
```bash
# 1. read the default theme id
THEME_ID=$(curl -s "https://$AUTH0_DOMAIN/api/v2/branding/themes/default" \
  -H "Authorization: Bearer $MGMT_TOKEN" | jq -r '.themeId')

# 2. merge our values over it and PATCH (strip the $comment helper keys first)
curl -s "https://$AUTH0_DOMAIN/api/v2/branding/themes/default" \
  -H "Authorization: Bearer $MGMT_TOKEN" \
| jq --slurpfile pp <(jq 'del(.. | .["$comment"]?)' auth0/universal-login/theme.json) \
     '. * $pp[0] | del(.themeId)' \
| curl -sX PATCH "https://$AUTH0_DOMAIN/api/v2/branding/themes/$THEME_ID" \
    -H "Authorization: Bearer $MGMT_TOKEN" -H 'Content-Type: application/json' --data @-
```

## Step 5 — (Optional) enable social login

The reference mock shows Google / GitHub / Facebook. There are currently **0** OAuth-linked users,
so this is opt-in. To add them: Auth0 Dashboard → Authentication → **Social** → enable the
connection(s) and attach them to the SPA app. They then render on the login box automatically,
below the credentials form (Auth0 controls that placement — matching the reference). No template
change needed. `theme.json`'s `social_buttons_layout` only sets the label position *within* each
social button, not whether the block sits above or below the form.

> If you enable a second connection, also turn on Auth0 **Account Linking** (one human → one `sub`)
> — otherwise a user who signs in with a different provider gets a new `sub` and `provision_profile`
> denies the duplicate. This is already called out in `docs/auth0-migration-plan.md`.

## Step 6 — Verify (real browser)

Because the app already wires the entry points, testing is just visiting them:

- `https://packetpilot.app/login` → launches Universal Login → **split-screen, dark, Geist**, radar
  mark above the box, branding panel on the right.
- `https://packetpilot.app/signup` → same, but the panel copy switches to the signup line
  (`AuthApp` already sends `screen_hint=signup` → `prompt.name == "signup"` in the template).
- **Forgot password** and any **MFA** prompt → the template applies to *all* prompts; confirm the
  panel still reads sensibly (it's intentionally generic) and the box is legible.
- Resize below ~900px → the branding panel hides, the box stays centered and usable.
- Confirm end-to-end still works: sign in → you land on `/app` with your data (proves the token
  claims / provisioning path is unaffected by the reskin).

---

## Notes & gotchas

- **Fonts:** `theme.json` points `font_url` at the Geist **variable** woff2 (one file, all weights).
  Auth0 documents WOFF/WOFF2 but not variable fonts specifically — **test it in a non-prod tenant**;
  if the widget font doesn't apply, fall back to a static single-weight woff2 (URL in `theme.json`'s
  fonts comment). The template loads Geist from Google Fonts for the *branding panel*. Air-gapped
  build → self-host both and swap the URLs.
- **Login box width:** the template sets `--prompt-width: 400px` (Auth0's default). Bump it there
  if you want a wider box.
- **This is the Page-Templates path, not ACUL.** Advanced Customizations for Universal Login (ACUL —
  building the screens as your own React app) is the heavier, pixel-perfect alternative and is *not*
  used here; note Auth0 deprecated the legacy ACUL "advanced mode" on 2026-06-15 in favor of
  `auth0 acul config`. Liquid page templates remain the supported way to brand the surround.
- **`prompt.name`** drives the panel's contextual line; it degrades to the default copy if absent.
- The branding panel is `aria-hidden` so assistive tech lands directly on the login form.
