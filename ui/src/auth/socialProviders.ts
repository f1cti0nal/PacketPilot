import type { ComponentType, SVGProps } from "react";
import { GitHubIcon, GoogleIcon } from "./BrandIcons";
import type { OAuthProvider } from "./useSession";

export interface SocialProvider {
  /** Supabase OAuth provider id — passed to `signInWithProvider(provider)`. */
  provider: OAuthProvider;
  /** Provider name shown in the button ("Continue with {label}"). */
  label: string;
  Icon: ComponentType<SVGProps<SVGSVGElement>>;
}

/** Providers we know how to label + draw, keyed by the Supabase provider id. */
const KNOWN: Record<OAuthProvider, Omit<SocialProvider, "provider">> = {
  google: { label: "Google", Icon: GoogleIcon },
  github: { label: "GitHub", Icon: GitHubIcon },
};

/**
 * Social sign-in buttons to render, derived from `VITE_SOCIAL_PROVIDERS` — a comma-separated list
 * of Supabase provider ids (e.g. "google,github"). Defaults to both, which are enabled on the
 * project; set the env to a subset (or "" for none) if a provider isn't enabled, since clicking a
 * disabled provider would error. Order follows the list; unknown ids are ignored so a typo can't
 * render a broken button.
 */
export function socialProviders(
  raw: string | undefined = import.meta.env.VITE_SOCIAL_PROVIDERS,
): SocialProvider[] {
  const list = (raw ?? "google,github").split(",");
  const seen = new Set<string>();
  const out: SocialProvider[] = [];
  for (const name of list) {
    const provider = name.trim() as OAuthProvider;
    if (!provider || seen.has(provider) || !(provider in KNOWN)) continue;
    seen.add(provider);
    out.push({ provider, ...KNOWN[provider] });
  }
  return out;
}
