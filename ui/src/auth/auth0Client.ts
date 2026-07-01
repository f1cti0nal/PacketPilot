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
  const c = await getAuth0();
  if (!c) return null;
  try {
    if (!(await c.isAuthenticated())) return null;
    const claims = await c.getIdTokenClaims();
    return claims?.__raw ?? null;
  } catch {
    return null;
  }
}

/** Current Auth0 user (sub/email/name/picture), or null when signed out. */
export async function auth0User(): Promise<User | null> {
  const c = await getAuth0();
  if (!c) return null;
  try {
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
}

/** Redirect to Auth0 Universal Login, returning to the current page. */
export async function auth0Login(opts?: { signUp?: boolean }): Promise<void> {
  const c = await getAuth0();
  if (!c) return;
  await c.loginWithRedirect({
    authorizationParams: {
      redirect_uri: `${window.location.origin}${window.location.pathname}`,
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
