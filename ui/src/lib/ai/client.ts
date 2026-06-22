import type { AiConfig } from "../../types";
import { SseAccumulator, type LlmRequest, type StreamTransport } from "./transport";

export interface AiMessage { role: "system" | "user" | "assistant"; content: string }

/** Run one OpenAI-compatible chat completion (streaming). Returns the full assembled text;
 * `onToken` receives each content delta as it arrives. Transport is injected (browser relay / desktop). */
export async function chatCompletion(
  config: AiConfig,
  messages: AiMessage[],
  transport: StreamTransport,
  onToken: (delta: string) => void,
): Promise<string> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (config.apiKey) headers.Authorization = `Bearer ${config.apiKey}`;
  const req: LlmRequest = {
    url: `${config.baseUrl.replace(/\/$/, "")}/chat/completions`,
    headers,
    body: JSON.stringify({ model: config.model, messages, stream: true }),
  };
  const acc = new SseAccumulator();
  let full = "";
  await transport(req, (raw) => {
    for (const delta of acc.push(raw)) {
      full += delta;
      onToken(delta);
    }
  });
  return full;
}
