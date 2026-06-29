export interface AnnouncementBanner {
  text: string;
  severity: "info" | "warning" | "critical";
  dismissible: boolean;
}
export interface AiAppConfig { enabled: boolean; provider: string; model: string }
export interface RepAppConfig { enabled: boolean; domain_enabled: boolean; file_enabled: boolean; providers: string[] }
export interface PublicSettings {
  announcement_banner: AnnouncementBanner | null;
  ai: AiAppConfig;
  rep: RepAppConfig;
}
export const SETTINGS_DEFAULTS: PublicSettings = {
  announcement_banner: null,
  ai: { enabled: false, provider: "anthropic", model: "claude-opus-4-8" },
  rep: { enabled: false, domain_enabled: false, file_enabled: false, providers: [] },
};

const SEVERITIES: AnnouncementBanner["severity"][] = ["info", "warning", "critical"];

export function parsePublicSettings(raw: unknown): PublicSettings {
  const obj = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  const b = obj.announcement_banner;
  let banner: AnnouncementBanner | null = null;
  if (b && typeof b === "object") {
    const bb = b as Record<string, unknown>;
    const text = typeof bb.text === "string" ? bb.text : "";
    if (text.trim()) {
      const severity = SEVERITIES.includes(bb.severity as AnnouncementBanner["severity"])
        ? (bb.severity as AnnouncementBanner["severity"])
        : "info";
      banner = { text, severity, dismissible: bb.dismissible !== false };
    }
  }
  const a = obj.ai_config && typeof obj.ai_config === "object" ? (obj.ai_config as Record<string, unknown>) : {};
  const ai: AiAppConfig = {
    enabled: a.enabled === true,
    provider: typeof a.provider === "string" && a.provider ? a.provider : "anthropic",
    model: typeof a.model === "string" && a.model ? a.model : "claude-opus-4-8",
  };
  const VALID_PROVIDERS = ["abuseipdb", "greynoise", "virustotal"];
  const rc = obj.rep_config && typeof obj.rep_config === "object" ? (obj.rep_config as Record<string, unknown>) : {};
  const rep: RepAppConfig = {
    enabled: rc.enabled === true,
    domain_enabled: rc.domain_enabled === true,
    file_enabled: rc.file_enabled === true,
    providers: Array.isArray(rc.providers)
      ? (rc.providers as unknown[]).filter((p): p is string => typeof p === "string" && VALID_PROVIDERS.includes(p))
      : [],
  };
  return { announcement_banner: banner, ai, rep };
}
