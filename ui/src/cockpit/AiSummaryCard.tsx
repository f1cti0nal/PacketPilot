import { useEffect, useRef, useState } from "react";
import type { AnalysisOutput } from "../types";
import { aiConsentGiven, giveAiConsent } from "../lib/ai/settings";
import { getAiSummary, putAiSummary } from "../lib/ai/cache";
import { generateSummary } from "../lib/ai/run";
import { Markdown } from "../lib/markdown";
import { AiConsent } from "./AiConsent";

type State = { status: "idle" | "loading" | "ready" | "error"; text: string; error?: string };

export function AiSummaryCard({ output, captureId, model }: { output: AnalysisOutput; captureId: string; model: string }) {
  const [st, setSt] = useState<State>({ status: "idle", text: "" });
  const [showConsent, setShowConsent] = useState(false);
  // Store the pending action so we can re-run it after consent is given
  const pendingRun = useRef<(() => void) | null>(null);

  useEffect(() => {
    let on = true;
    // Reset to idle synchronously so a capture switch never flashes the previous
    // capture's summary while the (async) cache lookup is in flight.
    setSt({ status: "idle", text: "" });
    getAiSummary(captureId)
      // On a cache MISS, stay idle for the new capture — do NOT leave the prior
      // capture's narrative rendered (cross-capture content bleed).
      .then((c) => { if (on) setSt(c ? { status: "ready", text: c.text } : { status: "idle", text: "" }); })
      .catch(() => { /* best-effort cache load — ignore */ });
    return () => { on = false; };
  }, [captureId]);

  async function doRun() {
    setSt({ status: "loading", text: "" });
    try {
      let acc = "";
      const full = await generateSummary(output, (t) => { acc += t; setSt({ status: "loading", text: acc }); });
      setSt({ status: "ready", text: full });
      await putAiSummary(captureId, full, model, Math.floor(Date.now() / 1000));
    } catch (e) {
      setSt({ status: "error", text: "", error: e instanceof Error ? e.message : String(e) });
    }
  }

  function run() {
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

  return (
    <>
      <section className="rounded-lg bg-[var(--color-surface)] p-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-medium">AI Analyst Summary</h2>
          <button className="t-tag font-medium" onClick={run} disabled={st.status === "loading"}>
            {st.status === "ready" ? "Regenerate" : st.status === "loading" ? "Generating…" : "Generate"}
          </button>
        </div>
        {st.error && <p role="alert" className="mt-2 text-xs text-[var(--color-sev-critical)]">{st.error}</p>}
        {st.text && (
          <div aria-live="polite" aria-busy={st.status === "loading"} className="mt-2 text-xs text-[var(--color-text)]">
            <Markdown text={st.text} />
          </div>
        )}
      </section>
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
