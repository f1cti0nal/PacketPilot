import { createAuth0Client, type Auth0Client, type User } from "@auth0/auth0-spa-js";

// Auth0 is the primary identity provider; Supabase (Data API / RLS / Storage / Edge
// Functions) trusts the Auth0-issued JWT via Third-Party Auth. The client id is public
// (SPA + PKCE) — no secret ships to the browser.
const domain = import.meta.env.VITE_AUTH0_DOMAIN;
const clientId = import.meta.env.VITE_AUTH0_CLIENT_ID;

/** True when both public Auth0 env vars are present; sign-in is unavailable otherwise. */
export const auth0Configured: boolean = Boolean(domain && clientId);

let clientPromise: Promise<Auth0Client> | null = null;

/** Lazily create the shared Auth0 SPA client (or null when unconfigured). */
export function getAuth0(): Promise<Auth0Client> | null {
  if (!auth0Configured) return null;
  if (!clientPromise) {
    clientPromise = createAuth0Client({
      domain: domain as string,
      clientId: clientId as string,
      authorizationParams: { redirect_uri: `${window.location.origin}/app` },
      // Survive full-page reloads (every login is a redirect) and refresh silently.
      cacheLocation: "localstorage",
      useRefreshTokens: true,
    });
  }
  return clientPromise;
}

/**
 * The raw Auth0 ID token (JWT) for the current session, or null when signed out.
 * Supabase reads the required `role: "authenticated"` custom claim reliably from the
 * ID token (an access token would need a configured API audience). This feeds the
 * Supabase client's `accessToken` option and the manual Edge Function fetches.
 */
export async function auth0IdToken(): Promise<string | null> {
  try {
    const c = await getAuth0();
    if (!c) return null;
    if (!(await c.isAuthenticated())) return null;
    // getIdTokenClaims() returns the cached ID token with NO expiry check, so a long-open tab
    // would keep sending an expired token. Refresh silently first (updates the cached id_token
    // via the refresh token). If refresh is unavailable, fall back to the cached token — a truly
    // dead session then goes anon and the user re-authenticates, rather than 401-storming.
    try {
      await c.getTokenSilently();
    } catch {
      /* refresh unavailable — use whatever is cached */
    }
    const claims = await c.getIdTokenClaims();
    return claims?.__raw ?? null;
  } catch {
    return null;
  }
}

/** Current Auth0 user (sub/email/name/picture), or null when signed out. */
export async function auth0User(): Promise<User | null> {
  try {
    const c = await getAuth0();
    if (!c) return null;
    if (!(await c.isAuthenticated())) return null;
    return (await c.getUser()) ?? null;
  } catch {
    return null;
  }
}

/**
 * Complete the Auth0 exchange if we're returning from Universal Login (?code&state in
 * the URL) and strip those params. Safe to call on every page load; a no-op otherwise.
 */
export async function completeAuth0RedirectIfPresent(): Promise<void> {
  try {
    const c = await getAuth0();
    if (!c) return;
    const q = window.location.search;
    if (!(q.includes("code=") && q.includes("state="))) return;
    try {
      await c.handleRedirectCallback();
    } catch {
      /* stale/replayed callback — ignore and fall through to the normal session check */
    }
    const url = new URL(window.location.href);
    url.searchParams.delete("code");
    url.searchParams.delete("state");
    window.history.replaceState({}, "", url.pathname + url.search + url.hash);
  } catch {
    /* getAuth0 init failed — nothing to complete */
  }
}

/** Redirect to Auth0 Universal Login. Returns to `returnTo` (must be a registered Auth0
 *  callback path) if given, else the current page. */
export async function auth0Login(opts?: { signUp?: boolean; returnTo?: string }): Promise<void> {
  const c = await getAuth0();
  if (!c) return;
  const path = opts?.returnTo ?? window.location.pathname;
  await c.loginWithRedirect({
    authorizationParams: {
      redirect_uri: `${window.location.origin}${path}`,
      ...(opts?.signUp ? { screen_hint: "signup" } : {}),
    },
  });
}

/** End the Auth0 session and return to the app. */
export async function auth0Logout(): Promise<void> {
  const c = await getAuth0();
  if (!c) return;
  await c.logout({ logoutParams: { returnTo: `${window.location.origin}/app` } });
}

/** Send an Auth0 password-reset email for a database-connection account. */
export async function auth0SendPasswordReset(email: string): Promise<{ ok: boolean; error?: string }> {
  if (!auth0Configured) return { ok: false, error: "Accounts are unavailable" };
  try {
    const resp = await fetch(`https://${domain}/dbconnections/change_password`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_id: clientId,
        email,
        connection: import.meta.env.VITE_AUTH0_DB_CONNECTION || "Username-Password-Authentication",
      }),
    });
    if (!resp.ok) return { ok: false, error: `Couldn't send reset email (${resp.status})` };
    return { ok: true };
  } catch {
    return { ok: false, error: "Network error sending reset email" };
  }
}

export type { User as Auth0User };
