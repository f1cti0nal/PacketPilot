export interface AnnouncementBanner {
  text: string;
  severity: "info" | "warning" | "critical";
  dismissible: boolean;
}
export interface AiAppConfig { enabled: boolean; provider: string; model: string }
export interface PublicSettings {
  announcement_banner: AnnouncementBanner | null;
  ai: AiAppConfig;
}
export const SETTINGS_DEFAULTS: PublicSettings = {
  announcement_banner: null,
  ai: { enabled: false, provider: "anthropic", model: "claude-opus-4-8" },
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
  return { announcement_banner: banner, ai };
}
