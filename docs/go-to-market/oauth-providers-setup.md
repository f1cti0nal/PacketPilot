# OAuth Sign-In Setup (Google + GitHub)

The app shows **Continue with Google** / **Continue with GitHub** buttons in the sign-in
dialog. The code is complete and deployed — but each provider must be enabled **once** in the
Supabase dashboard with an OAuth app's credentials, or the button returns
*"Unsupported provider: provider is not enabled"*.

No code or redeploy is needed after this; it's pure dashboard configuration.

## 1. Supabase redirect allow-list (do this first)

Supabase Dashboard → **Authentication → URL Configuration**:

- **Site URL**: the production origin, e.g. `https://packet-pilot.vercel.app`
- **Redirect URLs**: add the app return path the code uses —
  `https://packet-pilot.vercel.app/app` (and `http://localhost:5173/app` for local dev).

The browser is redirected back to `/app`, where Supabase's `detectSessionInUrl` exchanges the
code for a session (the same mechanism the email-confirm link already uses).

## 2. Google

1. **Google Cloud Console** → APIs & Services → **Credentials** → *Create OAuth client ID* →
   *Web application*.
2. **Authorized redirect URI**: the Supabase callback (NOT the app URL) —
   `https://<project-ref>.supabase.co/auth/v1/callback`
   (find `<project-ref>` in Supabase → Project Settings → API).
3. Configure the OAuth consent screen (app name, support email, scopes: `email`, `profile`).
4. Copy the **Client ID** and **Client secret**.
5. Supabase → **Authentication → Providers → Google** → enable, paste Client ID + secret, save.

## 3. GitHub

1. **GitHub** → Settings → Developer settings → **OAuth Apps** → *New OAuth App*.
2. **Authorization callback URL**: the Supabase callback —
   `https://<project-ref>.supabase.co/auth/v1/callback`
3. Generate a **client secret**, copy the **Client ID** + secret.
4. Supabase → **Authentication → Providers → GitHub** → enable, paste Client ID + secret, save.

## 4. Verify

Open the deployed app → **Sign in** → click each provider. You should be bounced to the
provider's consent screen and returned to `/app` signed in. A new `profiles` row is created by
the existing signup trigger on first login.

> Until both providers are enabled, the email/password sign-in still works unchanged.
