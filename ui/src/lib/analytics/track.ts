import { supabase } from "../supabase";

// The ONLY paths ever sent. Adding an app tab or admin section requires extending this
// (track.drift.test enforces it). Off-list paths are dropped, so a path can never carry
// an IP, host, SNI, hash, or query string.
const ROUTES = new Set<string>([
  "/",
  "/app#dashboard",
  "/app#flows",
  "/app#findings",
  "/app#threats",
  "/app#recent",
  "/app#compare",
  "/admin#dashboard",
  "/admin#users",
  "/admin#payments",
  "/admin#traffic",
  "/admin#features",
  "/admin#settings",
  "/admin#env",
]);

/** Test-only view of the allowlist for the drift guard. */
export const ROUTES_FOR_TESTS: ReadonlySet<string> = ROUTES;

const SID_KEY = "pp_sid";
let lastPath: string | null = null;
const noop = () => {};

function sessionId(): string {
  try {
    let sid = sessionStorage.getItem(SID_KEY);
    if (!sid) {
      sid = crypto.randomUUID();
      sessionStorage.setItem(SID_KEY, sid);
    }
    return sid;
  } catch {
    return crypto.randomUUID();
  }
}

/**
 * Record a page view for an allowlisted canonical route token. Fire-and-forget,
 * failure-silent, and incapable of carrying capture data (off-list paths are dropped).
 * Reads only the auth session from supabase — never any capture/analysis state.
 */
export function trackPageView(path: string): void {
  if (!ROUTES.has(path) || path === lastPath) return;
  lastPath = path;
  const client = supabase;
  if (!client) return;
  const session_id = sessionId();
  // Anonymous attribution: user_id is left null on this hot path (the RLS insert policy allows a
  // null user_id for both anon and authenticated). Keeping it null avoids reading the session on
  // every page view and never carries capture data — the path allowlist above is the only field.
  void client
    .from("analytics_events")
    .insert({ path, session_id, user_id: null })
    .then(noop, noop);
}

/** Test-only: reset the consecutive-dedupe guard between cases. */
export function __resetTrackerForTests(): void {
  lastPath = null;
}
