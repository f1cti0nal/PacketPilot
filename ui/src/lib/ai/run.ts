import type { AnalysisOutput, AiConfig } from "../../types";
import { isTauri } from "../tauri-detect";
import { buildContext } from "./context";
import { SUMMARY_SYSTEM, CHAT_SYSTEM } from "./prompts";
import { chatCompletion, type AiMessage } from "./client";
import { proxyTransport, directTransport, type StreamTransport, type LlmRequest } from "./transport";
import { getProxyUrl } from "./settings";
import { SseAccumulator } from "./sse";

/** Desktop transport: stream the upstream POST through the Tauri `ai_chat_stream` command via a Channel. */
export function tauriTransport(): StreamTransport {
  return async (req: LlmRequest, onChunk) => {
    const { invoke, Channel } = await import("@tauri-apps/api/core");
    const channel = new Channel<string>();
    channel.onmessage = (chunk) => onChunk(chunk);
    await invoke("ai_chat_stream", { url: req.url, body: req.body, onChunk: channel });
  };
}

/** Pick the transport for the current surface + config. Desktop → Tauri; browser → relay, or direct to localhost. */
export function pickTransport(config: AiConfig): StreamTransport {
  if (isTauri()) return tauriTransport();
  const proxy = getProxyUrl();
  if (proxy) return proxyTransport(proxy);
  // Direct (relay-free) egress is allowed ONLY to genuine loopback. Match the exact
  // hostname, not a prefix — an unanchored test let `http://localhost.evil.com` /
  // `http://127.0.0.1.attacker.io` pass and exfiltrate the capture context + API key.
  let isLocal = false;
  try {
    const host = new URL(config.baseUrl).hostname.toLowerCase();
    isLocal = host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
  } catch {
    isLocal = false; // unparseable URL → not local
  }
  if (isLocal) return directTransport();
  throw new Error("Browser AI needs a relay URL (Settings) for non-local endpoints.");
}

export async function generateSummary(
  output: AnalysisOutput, config: AiConfig, onToken: (t: string) => void, transport: StreamTransport = pickTransport(config),
): Promise<string> {
  const messages: AiMessage[] = [
    { role: "system", content: SUMMARY_SYSTEM },
    { role: "user", content: buildContext(output) },
  ];
  return chatCompletion(config, messages, transport, onToken);
}

export async function askChat(
  output: AnalysisOutput, history: AiMessage[], question: string, config: AiConfig,
  onToken: (t: string) => void, transport: StreamTransport = pickTransport(config),
): Promise<string> {
  const messages: AiMessage[] = [
    { role: "system", content: `${CHAT_SYSTEM}\n\n${buildContext(output)}` },
    ...history.slice(-8),
    { role: "user", content: question },
  ];
  return chatCompletion(config, messages, transport, onToken);
}

export { SseAccumulator };
