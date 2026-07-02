/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_SUPABASE_URL?: string;
  readonly VITE_SUPABASE_ANON_KEY?: string;
  /** Comma-separated Supabase OAuth provider ids to show on the auth card (default "google,github"). */
  readonly VITE_SOCIAL_PROVIDERS?: string;
}
interface ImportMeta {
  readonly env: ImportMetaEnv;
}
