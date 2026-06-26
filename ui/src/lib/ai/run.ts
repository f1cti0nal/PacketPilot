import type { AnalysisOutput, AiConfig } from "../../types";
import { isTauri } from "../tauri-detect";
import { buildContext } from "./context";
import { SUMMARY_SYSTEM, CHAT_SYSTEM } from "./prompts";
import { chatCompletion, type AiMessage } from "./client";
import { proxyTransport, directTransport, type StreamTransport, type LlmRequest } from "./transport";
import { getProxyUrl } from "./settings";
import { isLoopbackUrl } from "./loopback";
import { SseAccumulator } from "./sse";

/** A relay must be an absolute http(s) URL — a scheme-less value (e.g. "relay") resolves relative
 * to the app origin, so `fetch` would POST the summary + API key there instead of to the relay. */
function isAbsoluteHttpUrl(s: string): boolean {
  try {
    const p = new URL(s).protocol;
    return p === "http:" || p === "https:";
  } catch {
    return false;
  }
}

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
  const proxy = getProxyUrl(); // trimmed; "" when unset or whitespace-only
  if (proxy) {
    // A configured-but-malformed relay must FAIL LOUDLY, never silently degrade to an
    // origin-relative POST that would leak the summary + API key.
    if (!isAbsoluteHttpUrl(proxy)) {
      throw new Error("The AI relay URL in Settings is not a valid http(s) URL.");
    }
    return proxyTransport(proxy);
  }
  // Direct (relay-free) egress is allowed ONLY to genuine loopback (exact-hostname check; see
  // isLoopbackUrl — a prefix match would let localhost.evil.com exfiltrate the context + key).
  if (isLoopbackUrl(config.baseUrl)) return directTransport();
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
