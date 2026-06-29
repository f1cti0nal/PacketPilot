import type { AnalysisOutput } from "../../types";
import { buildContext } from "./context";
import { SUMMARY_SYSTEM, CHAT_SYSTEM } from "./prompts";
import type { AiMessage } from "./client";
import { runViaProxy } from "./proxyClient";

export async function generateSummary(output: AnalysisOutput, onToken: (t: string) => void): Promise<string> {
  return runViaProxy(
    [{ role: "system", content: SUMMARY_SYSTEM }, { role: "user", content: buildContext(output) }],
    onToken,
  );
}

export async function askChat(output: AnalysisOutput, history: AiMessage[], question: string, onToken: (t: string) => void): Promise<string> {
  return runViaProxy(
    [{ role: "system", content: `${CHAT_SYSTEM}\n\n${buildContext(output)}` }, ...history.slice(-8), { role: "user", content: question }],
    onToken,
  );
}
