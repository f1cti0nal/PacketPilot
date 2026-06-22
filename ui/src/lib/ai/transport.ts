import { SseAccumulator } from "./sse";

export interface LlmRequest { url: string; headers: Record<string, string>; body: string }
/** Opens the upstream streaming POST and calls `onChunk` with raw response text as it arrives. */
export type StreamTransport = (req: LlmRequest, onChunk: (raw: string) => void) => Promise<void>;

async function readStream(resp: Response, onChunk: (raw: string) => void): Promise<void> {
  if (!resp.body) {
    onChunk(await resp.text());
    return;
  }
  const reader = resp.body.getReader();
  const dec = new TextDecoder();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    onChunk(dec.decode(value, { stream: true }));
  }
}

/** Browser → user's streaming relay. Contract: POST {proxyUrl} with {url,headers,method,body,stream:true};
 * the relay opens the upstream request and pipes the text/event-stream back verbatim. */
export function proxyTransport(proxyUrl: string): StreamTransport {
  return async (req, onChunk) => {
    const resp = await fetch(proxyUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url: req.url, headers: req.headers, method: "POST", body: req.body, stream: true }),
    });
    if (!resp.ok) throw new Error(`relay error ${resp.status}`);
    await readStream(resp, onChunk);
  };
}

/** Browser → local endpoint directly (e.g. Ollama on localhost with CORS enabled). */
export function directTransport(): StreamTransport {
  return async (req, onChunk) => {
    const resp = await fetch(req.url, { method: "POST", headers: req.headers, body: req.body });
    if (!resp.ok) throw new Error(`endpoint error ${resp.status}`);
    await readStream(resp, onChunk);
  };
}

export { SseAccumulator };
