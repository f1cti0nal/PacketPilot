import type { AiConfig } from "../../types";

/** Provider presets for the settings dropdown; all fields overridable. */
export const AI_PRESETS: { id: string; label: string; baseUrl: string; model: string }[] = [
  { id: "anthropic", label: "Anthropic", baseUrl: "https://api.anthropic.com/v1", model: "claude-opus-4-8" },
  { id: "openai", label: "OpenAI", baseUrl: "https://api.openai.com/v1", model: "gpt-4o" },
  { id: "openrouter", label: "OpenRouter", baseUrl: "https://openrouter.ai/api/v1", model: "anthropic/claude-opus-4-8" },
  { id: "ollama", label: "Ollama (local)", baseUrl: "http://localhost:11434/v1", model: "llama3.1" },
  { id: "custom", label: "Custom", baseUrl: "", model: "" },
];

export function getAiEnabled(): boolean { return localStorage.getItem("pp.ai.enabled") === "1"; }
export function setAiEnabled(b: boolean): void { localStorage.setItem("pp.ai.enabled", b ? "1" : "0"); }
export function getAiBaseUrl(): string { return localStorage.getItem("pp.ai.baseUrl") ?? AI_PRESETS[0].baseUrl; }
export function setAiBaseUrl(s: string): void { localStorage.setItem("pp.ai.baseUrl", s); }
export function getAiModel(): string { return localStorage.getItem("pp.ai.model") ?? AI_PRESETS[0].model; }
export function setAiModel(s: string): void { localStorage.setItem("pp.ai.model", s); }
export function getProxyUrl(): string { return localStorage.getItem("pp.ai.proxyUrl") ?? ""; }
export function setProxyUrl(s: string): void { localStorage.setItem("pp.ai.proxyUrl", s); }
export function aiConsentGiven(): boolean { return localStorage.getItem("pp.ai.consent") === "1"; }
export function giveAiConsent(): void { localStorage.setItem("pp.ai.consent", "1"); }

/** Browser-only key access. On desktop the key lives in the OS keychain (Tauri commands). */
export function getAiKey(): string { return localStorage.getItem("pp.ai.key") ?? ""; }
export function setAiKey(s: string): void { localStorage.setItem("pp.ai.key", s); }

export function getAiConfig(): AiConfig {
  return { enabled: getAiEnabled(), baseUrl: getAiBaseUrl(), model: getAiModel(), apiKey: getAiKey() };
}
