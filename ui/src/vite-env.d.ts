/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_SUPABASE_URL?: string;
  readonly VITE_SUPABASE_ANON_KEY?: string;
  readonly VITE_AUTH0_DOMAIN?: string;
  readonly VITE_AUTH0_CLIENT_ID?: string;
  /** Auth0 database connection name for password resets (defaults to Username-Password-Authentication). */
  readonly VITE_AUTH0_DB_CONNECTION?: string;
}
interface ImportMeta {
  readonly env: ImportMetaEnv;
}
