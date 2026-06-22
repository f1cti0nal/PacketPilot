import { useEffect, useRef, useState } from "react";
import type { AnalysisOutput } from "../types";
import { getAiEnabled, aiConsentGiven, giveAiConsent, getAiConfig } from "../lib/ai/settings";
import { getAiSummary, putAiSummary } from "../lib/ai/cache";
import { generateSummary } from "../lib/ai/run";
import { AiConsent } from "./AiConsent";

type State = { status: "idle" | "loading" | "ready" | "error"; text: string; error?: string };

export function AiSummaryCard({ output, captureId }: { output: AnalysisOutput; captureId: string }) {
  const [st, setSt] = useState<State>({ status: "idle", text: "" });
  const [showConsent, setShowConsent] = useState(false);
  // Store the pending action so we can re-run it after consent is given
  const pendingRun = useRef<(() => void) | null>(null);

  useEffect(() => {
    let on = true;
    getAiSummary(captureId)
      .then((c) => { if (on && c) setSt({ status: "ready", text: c.text }); })
      .catch(() => { /* best-effort cache load — ignore */ });
    return () => { on = false; };
  }, [captureId]);

  async function doRun() {
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

  function run() {
    if (!getAiEnabled()) { setSt({ status: "error", text: "", error: "AI is off — enable it in Settings." }); return; }
    if (!aiConsentGiven()) {
      // Store the action and show the consent dialog
      pendingRun.current = () => void doRun();
      setShowConsent(true);
      return;
    }
    void doRun();
  }

  function handleConsentProceed() {
    giveAiConsent();
    setShowConsent(false);
    const fn = pendingRun.current;
    pendingRun.current = null;
    if (fn) fn();
  }

  function handleConsentCancel() {
    setShowConsent(false);
    pendingRun.current = null;
  }

  const cfg = getAiConfig();

  return (
    <>
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
      {showConsent && (
        <AiConsent
          baseUrl={cfg.baseUrl}
          model={cfg.model}
          onProceed={handleConsentProceed}
          onCancel={handleConsentCancel}
        />
      )}
    </>
  );
}
