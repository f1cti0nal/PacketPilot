import { describe, it, expect } from "vitest";
import { applyFileReputation } from "./applyFile";
import { makeOutput } from "../../test/fixtures";
import type { AnalysisOutput, RepStatus, ReputationVerdict } from "../../types";

const verdict = (status: RepStatus, malicious: boolean): ReputationVerdict => ({
  source: "virustotal", status, malicious, score: malicious ? 60 : 0, tags: [], link: null, fetched_at: 1,
});

function withFiles(): AnalysisOutput {
  const base = makeOutput();
  return makeOutput({
    summary: {
      ...base.summary,
      carved_files: [
        { client: "10.0.0.9", server: "45.77.13.37", sha256: "f".repeat(64), size: 2048, known_bad: false },
        { client: "10.0.0.8", server: "1.2.3.4", sha256: "e".repeat(64), size: 10, known_bad: false },
      ],
    },
  });
}

describe("applyFileReputation", () => {
  it("attaches verdicts to the matching carved file only", async () => {
    const v = { ["f".repeat(64)]: [verdict("malicious", true)] };
    const res = await applyFileReputation(JSON.stringify(withFiles()), v);
    const files = res.summary.carved_files!;
    expect(files.find((f) => f.sha256 === "f".repeat(64))!.reputation![0].status).toBe("malicious");
    expect(files.find((f) => f.sha256 === "e".repeat(64))!.reputation).toBeUndefined();
  });

  it("matches case-insensitively if a carved-file hash were uppercase", async () => {
    const base = makeOutput();
    const out = makeOutput({
      summary: { ...base.summary, carved_files: [
        { client: "a", server: "b", sha256: "F".repeat(64), size: 1, known_bad: false },
      ] },
    });
    const res = await applyFileReputation(JSON.stringify(out), { ["f".repeat(64)]: [verdict("malicious", true)] });
    expect(res.summary.carved_files![0].reputation![0].malicious).toBe(true);
  });

  it("is a no-op when there are no carved files", async () => {
    const res = await applyFileReputation(JSON.stringify(makeOutput()), {});
    expect(res.summary.carved_files).toBeUndefined();
  });

  it("does not mutate the input JSON's source object", async () => {
    const out = withFiles();
    await applyFileReputation(JSON.stringify(out), { ["f".repeat(64)]: [verdict("malicious", true)] });
    expect(out.summary.carved_files![0].reputation).toBeUndefined();
  });
});
