import { useRef, useState } from "react";
import type { AnalysisOutput } from "../types";
import type { AiMessage } from "../lib/ai/client";
import { aiConsentGiven, giveAiConsent } from "../lib/ai/settings";
import { askChat } from "../lib/ai/run";
import { Markdown } from "../lib/markdown";
import { useDialogA11y } from "../lib/useDialogA11y";
import { AiConsent } from "./AiConsent";

export function AiChatPanel({ open, onClose, output, model }: { open: boolean; onClose: () => void; output: AnalysisOutput; model: string }) {
  const [msgs, setMsgs] = useState<AiMessage[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [streaming, setStreaming] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [showConsent, setShowConsent] = useState(false);
  // The question to send once consent is granted (mirrors AiSummaryCard's pendingRun).
  const pendingQ = useRef<string | null>(null);
  const { ref, onKeyDown } = useDialogA11y(onClose);

  if (!open) return null;

  // Performs the actual egress — only ever called once consent is satisfied.
  async function runSend(q: string) {
    const history = [...msgs, { role: "user" as const, content: q }];
    setMsgs(history);
    setBusy(true);
    setStreaming("");
    setError(null);
    try {
      let acc = "";
      const full = await askChat(output, msgs, q, (t) => { acc += t; setStreaming(acc); });
      setMsgs([...history, { role: "assistant", content: full }]);
    } catch (e) {
      // Surface failures as a real alert (not a faint assistant bubble that assistive tech / a
      // scanning user might miss).
      setError(`AI request failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(false);
      setStreaming("");
    }
  }

  // Gate every send behind the consent boundary — the chat path must never ship the analysis
  // summary to a remote model without consent.
  function send() {
    const q = input.trim();
    if (!q || busy) return;
    setError(null);
    setInput("");
    if (!aiConsentGiven()) {
      pendingQ.current = q;
      setShowConsent(true);
      return;
    }
    void runSend(q);
  }

  function handleConsentProceed() {
    giveAiConsent();
    setShowConsent(false);
    const q = pendingQ.current;
    pendingQ.current = null;
    if (q) void runSend(q);
  }

  function handleConsentCancel() {
    setShowConsent(false);
    pendingQ.current = null;
  }

  return (
    <>
      <div ref={ref} onKeyDown={onKeyDown} role="dialog" aria-modal="true" aria-label="AI chat" className="fixed inset-y-0 right-0 z-50 flex w-[28rem] max-w-full flex-col bg-[var(--color-surface)]">
        <div className="flex items-center justify-between border-b border-[var(--color-border,#222)] p-3">
          <h2 className="text-sm font-medium">Ask about this capture</h2>
          <button type="button" className="t-tag" onClick={onClose}>Close</button>
        </div>
        <div role="log" aria-live="polite" aria-label="Conversation" className="flex-1 space-y-2 overflow-auto p-3 text-xs">
          {msgs.map((m, i) => (
            <div key={i} className={m.role === "user" ? "text-[var(--color-text)]" : "text-[var(--color-text-faint)]"}>
              <span className="t-tag uppercase">{m.role}</span>
              {m.role === "assistant"
                ? <Markdown text={m.content} />
                : <pre className="whitespace-pre-wrap break-words">{m.content}</pre>}
            </div>
          ))}
          {streaming && <div className="text-[var(--color-text-faint)]"><Markdown text={streaming} /></div>}
        </div>
        {error && (
          <p role="alert" className="mx-3 mb-1 text-xs text-[var(--color-sev-critical)]">{error}</p>
        )}
        <div className="flex gap-2 border-t border-[var(--color-border,#222)] p-3">
          <input className="flex-1 rounded bg-[var(--color-bg)] p-1 text-xs" value={input}
            aria-label="Ask a question about this capture"
            onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") send(); }}
            placeholder="e.g. which host exfiltrated data?" />
          <button type="button" className="t-tag font-medium" onClick={() => send()} disabled={busy}>Send</button>
        </div>
      </div>
      {showConsent && (
        <AiConsent
          model={model}
          onProceed={handleConsentProceed}
          onCancel={handleConsentCancel}
        />
      )}
    </>
  );
}
