/** Incremental parser for an OpenAI-compatible SSE stream. Feed raw text chunks; get content deltas. */
export class SseAccumulator {
  private buf = "";

  push(chunk: string): string[] {
    this.buf += chunk;
    const out: string[] = [];
    let idx: number;
    // Events are separated by a blank line (\n\n). Keep the trailing partial in `buf`.
    while ((idx = this.buf.indexOf("\n\n")) !== -1) {
      const rawEvent = this.buf.slice(0, idx);
      this.buf = this.buf.slice(idx + 2);
      for (const line of rawEvent.split("\n")) {
        const t = line.trim();
        if (!t.startsWith("data:")) continue;
        const data = t.slice(5).trim();
        if (data === "[DONE]" || data === "") continue;
        try {
          const delta = JSON.parse(data)?.choices?.[0]?.delta?.content;
          if (typeof delta === "string" && delta.length) out.push(delta);
        } catch {
          /* skip malformed event */
        }
      }
    }
    return out;
  }
}
