/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_SUPABASE_URL?: string;
  readonly VITE_SUPABASE_ANON_KEY?: string;
  /** Comma-separated Supabase OAuth provider ids to show on the auth card (default "google,github"). */
  readonly VITE_SOCIAL_PROVIDERS?: string;
  /** Google Analytics 4 measurement id (e.g. "G-XXXXXXXXXX"). When unset, GA is fully disabled. */
  readonly VITE_GA_MEASUREMENT_ID?: string;
}
interface ImportMeta {
  readonly env: ImportMetaEnv;
}
