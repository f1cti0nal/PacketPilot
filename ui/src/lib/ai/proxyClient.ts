import { supabase } from "../supabase";
import { SseAccumulator } from "./sse";
import type { AiMessage } from "./client";

const FN_URL = `${import.meta.env.VITE_SUPABASE_URL ?? ""}/functions/v1/ai-proxy`;

/** Send messages to the ai-proxy Edge Function and stream the completion back. The proxy is
 *  public (no sign-in — PacketPilot has no accounts), so only the anon apikey is sent; the
 *  operator's AI key never reaches the browser. */
export async function runViaProxy(messages: AiMessage[], onToken: (t: string) => void): Promise<string> {
  if (!supabase) throw new Error("AI is unavailable.");
  const resp = await fetch(FN_URL, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      apikey: import.meta.env.VITE_SUPABASE_ANON_KEY ?? "",
    },
    body: JSON.stringify({ messages }),
  });
  if (!resp.ok || !resp.body) {
    throw new Error(resp.status === 503 ? "AI is not enabled." : `AI request failed (${resp.status}).`);
  }
  const reader = resp.body.getReader();
  const dec = new TextDecoder();
  const acc = new SseAccumulator();
  let full = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    for (const delta of acc.push(dec.decode(value, { stream: true }))) {
      full += delta;
      onToken(delta);
    }
  }
  return full;
}
