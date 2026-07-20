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
    if (resp.status === 503) throw new Error("AI is not enabled.");
    // The shared free endpoint returns 429 when busy — a normal transient state, not a failure.
    if (resp.status === 429) throw new Error("The AI analyst is busy right now; try again in a minute.");
    // The proxy reports provider failures as 502 with the provider's own status in the body.
    // Surface it: "model unavailable" (400/404) needs an operator config fix, not a retry.
    if (resp.status === 502) {
      const upstream = await resp
        .json()
        .then((b) => (b as { status?: unknown })?.status)
        .catch(() => undefined);
      if (typeof upstream === "number") {
        // 400/404 both cover "bad model" (OpenRouter 400s on unknown slugs; others 404), but a
        // 400 can also be a limits problem — keep the hint neutral across those causes.
        const hint =
          upstream === 400 || upstream === 404
            ? " — check the configured model and its limits"
            : upstream === 401 || upstream === 403
              ? " — the AI provider rejected the operator's key"
              : "";
        throw new Error(`The AI provider returned an error (HTTP ${upstream})${hint}.`);
      }
    }
    throw new Error(`AI request failed (${resp.status}).`);
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
