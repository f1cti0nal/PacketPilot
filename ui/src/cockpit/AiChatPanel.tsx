import { useState } from "react";
import type { AnalysisOutput } from "../types";
import type { AiMessage } from "../lib/ai/client";
import { getAiConfig } from "../lib/ai/settings";
import { askChat } from "../lib/ai/run";

export function AiChatPanel({ open, onClose, output }: { open: boolean; onClose: () => void; output: AnalysisOutput }) {
  const [msgs, setMsgs] = useState<AiMessage[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [streaming, setStreaming] = useState("");

  if (!open) return null;

  async function send() {
    const q = input.trim();
    if (!q || busy) return;
    setInput("");
    const history = [...msgs, { role: "user" as const, content: q }];
    setMsgs(history);
    setBusy(true);
    setStreaming("");
    try {
      let acc = "";
      const full = await askChat(output, msgs, q, getAiConfig(), (t) => { acc += t; setStreaming(acc); });
      setMsgs([...history, { role: "assistant", content: full }]);
    } catch (e) {
      setMsgs([...history, { role: "assistant", content: `AI request failed: ${e instanceof Error ? e.message : String(e)}` }]);
    } finally {
      setBusy(false);
      setStreaming("");
    }
  }

  return (
    <div role="dialog" aria-label="AI chat" className="fixed inset-y-0 right-0 z-50 flex w-[28rem] flex-col bg-[var(--color-surface)] shadow-xl">
      <div className="flex items-center justify-between border-b border-[var(--color-border,#222)] p-3">
        <h2 className="text-sm font-semibold">Ask about this capture</h2>
        <button className="t-tag" onClick={onClose}>Close</button>
      </div>
      <div className="flex-1 space-y-2 overflow-auto p-3 text-xs">
        {msgs.map((m, i) => (
          <div key={i} className={m.role === "user" ? "text-[var(--color-text)]" : "text-[var(--color-text-faint)]"}>
            <span className="t-tag uppercase">{m.role}</span>
            <pre className="whitespace-pre-wrap break-words">{m.content}</pre>
          </div>
        ))}
        {streaming && <pre className="whitespace-pre-wrap break-words text-[var(--color-text-faint)]">{streaming}</pre>}
      </div>
      <div className="flex gap-2 border-t border-[var(--color-border,#222)] p-3">
        <input className="flex-1 rounded bg-[var(--color-bg)] p-1 text-xs" value={input}
          onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") void send(); }}
          placeholder="e.g. which host exfiltrated data?" />
        <button className="t-tag font-semibold" onClick={() => void send()} disabled={busy}>Send</button>
      </div>
    </div>
  );
}
