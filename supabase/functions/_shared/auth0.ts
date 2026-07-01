// Verify Auth0 (Third-Party Auth) JWTs inside Edge Functions and map the Auth0 subject
// to the internal profile id. The Data API/RLS trusts Auth0 tokens via the project's
// Third-Party Auth integration; Edge Functions verify them explicitly here (JWKS) rather
// than relying on GoTrue's getUser, then resolve identity through profiles.auth0_sub.
import { createRemoteJWKSet, jwtVerify } from "npm:jose@^5";
import type { SupabaseClient } from "jsr:@supabase/supabase-js@2";

const DOMAIN = Deno.env.get("AUTH0_DOMAIN") ?? "";
const CLIENT_ID = Deno.env.get("AUTH0_CLIENT_ID") ?? "";
const ISSUER = DOMAIN ? `https://${DOMAIN}/` : "";
// The browser sends the Auth0 ID token, whose `aud` is the SPA client id.
const JWKS = DOMAIN ? createRemoteJWKSet(new URL(`https://${DOMAIN}/.well-known/jwks.json`)) : null;

export interface Auth0Identity {
  sub: string;
  email?: string;
}

/** Verify the Auth0 token from the Authorization header. Returns null if absent/invalid. */
export async function verifyAuth0(req: Request): Promise<Auth0Identity | null> {
  if (!JWKS || !ISSUER) return null;
  const authz = req.headers.get("Authorization") ?? "";
  const token = authz.startsWith("Bearer ") ? authz.slice(7).trim() : "";
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, JWKS, { issuer: ISSUER, audience: CLIENT_ID });
    if (!payload.sub) return null;
    return { sub: String(payload.sub), email: typeof payload.email === "string" ? payload.email : undefined };
  } catch {
    return null;
  }
}

/** Resolve the internal profile (uuid id + email) for an Auth0 subject. */
export async function resolveProfileId(
  admin: SupabaseClient,
  sub: string,
): Promise<{ id: string; email: string | null } | null> {
  const { data } = await admin.from("profiles").select("id,email").eq("auth0_sub", sub).maybeSingle();
  if (!data) return null;
  return { id: data.id as string, email: (data.email as string | null) ?? null };
}

/** Best-effort delete of the Auth0 user via the Management API (needs M2M creds; skips if unset). */
export async function deleteAuth0User(sub: string): Promise<void> {
  const mgmtId = Deno.env.get("AUTH0_MGMT_CLIENT_ID");
  const mgmtSecret = Deno.env.get("AUTH0_MGMT_CLIENT_SECRET");
  if (!DOMAIN || !mgmtId || !mgmtSecret) return;
  try {
    const tokenResp = await fetch(`https://${DOMAIN}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        grant_type: "client_credentials",
        client_id: mgmtId,
        client_secret: mgmtSecret,
        audience: `https://${DOMAIN}/api/v2/`,
      }),
    });
    if (!tokenResp.ok) return;
    const { access_token } = await tokenResp.json();
    if (!access_token) return;
    await fetch(`https://${DOMAIN}/api/v2/users/${encodeURIComponent(sub)}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${access_token}` },
    });
  } catch {
    // Never block account deletion on an Auth0 API error.
  }
}
