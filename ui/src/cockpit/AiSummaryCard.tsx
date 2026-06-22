import { useEffect, useState } from "react";
import type { AnalysisOutput } from "../types";
import { getAiEnabled, aiConsentGiven, getAiConfig } from "../lib/ai/settings";
import { getAiSummary, putAiSummary } from "../lib/ai/cache";
import { generateSummary } from "../lib/ai/run";

type State = { status: "idle" | "loading" | "ready" | "error"; text: string; error?: string };

export function AiSummaryCard({ output, captureId }: { output: AnalysisOutput; captureId: string }) {
  const [st, setSt] = useState<State>({ status: "idle", text: "" });

  useEffect(() => {
    let on = true;
    getAiSummary(captureId).then((c) => { if (on && c) setSt({ status: "ready", text: c.text }); });
    return () => { on = false; };
  }, [captureId]);

  async function run() {
    if (!getAiEnabled()) { setSt({ status: "error", text: "", error: "AI is off — enable it in Settings." }); return; }
    if (!aiConsentGiven()) { setSt({ status: "error", text: "", error: "Consent required — open Settings." }); return; }
    setSt({ status: "loading", text: "" });
    try {
      const cfg = getAiConfig();
      let acc = "";
      const full = await generateSummary(output, cfg, (t) => { acc += t; setSt({ status: "loading", text: acc }); });
      setSt({ status: "ready", text: full });
      await putAiSummary(captureId, full, cfg.model, Math.floor(Date.now() / 1000));
    } catch (e) {
      setSt({ status: "error", text: "", error: `AI request failed: ${e instanceof Error ? e.message : String(e)}` });
    }
  }

  return (
    <section className="rounded-lg bg-[var(--color-surface)] p-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold">AI Analyst Summary</h2>
        <button className="t-tag font-semibold" onClick={run} disabled={st.status === "loading"}>
          {st.status === "ready" ? "Regenerate" : st.status === "loading" ? "Generating…" : "Generate"}
        </button>
      </div>
      {st.error && <p className="mt-2 text-xs text-[var(--color-critical,#ef4444)]">{st.error}</p>}
      {st.text && <pre className="mt-2 whitespace-pre-wrap break-words text-xs text-[var(--color-text)]">{st.text}</pre>}
    </section>
  );
}
