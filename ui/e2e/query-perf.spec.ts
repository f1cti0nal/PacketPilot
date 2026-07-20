import { expect, test, type Page } from "@playwright/test";

/**
 * Phase 4 performance benchmark for the query engine: synthetic FlowRow sets
 * at 100k and 1M rows, measuring table build (Arrow ingest + typed INSERT)
 * and four representative queries. Assertion ceilings are deliberately loose
 * (CI containers are slow); the real numbers are logged per run and recorded
 * in docs/nlq.md.
 *
 * Heavy (≈ 1–2 GB of browser heap at the 1M step), so it only runs when
 * PP_PERF=1 is set — it is a measurement harness, not a regression gate.
 */
test.skip(process.env.PP_PERF !== "1", "perf harness — run with PP_PERF=1");

interface Bench {
  rows: number;
  loadMs: number;
  topTalkersMs: number;
  histogramMs: number;
  pointMs: number;
  sortMs: number;
}

async function bench(page: Page, n: number): Promise<Bench> {
  return page.evaluate(async (count) => {
    const { getQueryEngine } = (await import(
      "/src/lib/query/engine.ts"
    )) as typeof import("../src/lib/query/engine.ts");
    const engine = await getQueryEngine();

    // Deterministic synthetic rows (LCG) — realistic cardinalities: /16 of
    // source IPs, 1k destinations, mixed categories/ports, 1h time spread.
    let seed = 0x2f6e2b1 >>> 0;
    const rand = () => ((seed = (seed * 1664525 + 1013904223) >>> 0), seed / 0xffffffff);
    const cats = ["web", "dns", "scan", "c2", "file_transfer", "unknown"] as const;
    const rows = new Array(count);
    const t0 = 1752900000000;
    for (let i = 0; i < count; i++) {
      const r1 = rand(), r2 = rand(), r3 = rand();
      rows[i] = {
        flowId: i, flowIdBig: BigInt(i), captureId: 0,
        srcIp: `10.${(i >> 8) & 255}.${i & 255}.${(r1 * 254 + 1) | 0}`,
        dstIp: `203.0.${(r2 * 250) | 0}.${(r3 * 4) | 0}`,
        srcPort: 1024 + ((r1 * 60000) | 0), dstPort: [80, 443, 53, 8443, 22][(r2 * 5) | 0],
        proto: r3 > 0.3 ? 6 : 17, protoLabel: r3 > 0.3 ? "TCP" : "UDP",
        appProto: r1 > 0.5 ? "https" : r2 > 0.5 ? "dns" : null,
        appProtoSrc: "payload" as string | null,
        sni: r1 > 0.7 ? `host${(r2 * 500) | 0}.example.com` : null,
        ja3: null, ja4: null, ja3s: null, httpHost: null, httpUa: null,
        tlsVersion: null, tlsCipher: null, hassh: null, hasshServer: null,
        bytesC2s: (r1 * 100000) | 0, bytesS2c: (r2 * 1000000) | 0,
        bytesTotal: 0, pkts: 2 + ((r3 * 200) | 0),
        startMs: t0 + ((r1 * 3_600_000) | 0), endMs: t0 + ((r1 * 3_600_000) | 0) + 1000,
        durationMs: 1000, tcpFlagsC2s: 0x1b, tcpFlagsS2c: 0x1b, ttlMinC2s: 64,
        category: cats[(r2 * cats.length) | 0],
        severity: (r3 > 0.98 ? "high" : "info") as "high" | "info",
        threatScore: r3 > 0.98 ? 80 : 0, ioc: r3 > 0.995,
      };
    }

    const time = async (fn: () => Promise<unknown>) => {
      const s = performance.now();
      await fn();
      return Math.round(performance.now() - s);
    };

    const loadMs = await time(() => engine.loadFlows(rows, `perf-${count}`));
    const topTalkersMs = await time(() =>
      engine.run(
        "WITH ep AS (SELECT src_ip AS ip, bytes_c2s + bytes_s2c AS b FROM flow UNION ALL SELECT dst_ip, bytes_c2s + bytes_s2c FROM flow) SELECT ip, SUM(b) AS total FROM ep GROUP BY ip ORDER BY total DESC LIMIT 50",
      ),
    );
    const histogramMs = await time(() =>
      engine.run(
        "SELECT date_trunc('second', start_ts) AS bucket, COUNT(*) AS flows, SUM(bytes_c2s + bytes_s2c) AS bytes FROM flow GROUP BY bucket ORDER BY bucket LIMIT 4000",
      ),
    );
    const pointMs = await time(() =>
      engine.run("SELECT * FROM flow WHERE src_ip = '10.0.7.13' LIMIT 100"),
    );
    const sortMs = await time(() =>
      engine.run(
        "SELECT flow_id, src_ip, dst_ip, bytes_c2s + bytes_s2c AS bytes FROM flow ORDER BY bytes DESC LIMIT 50",
      ),
    );
    return { rows: count, loadMs, topTalkersMs, histogramMs, pointMs, sortMs };
  }, n);
}

test("query engine benchmark — 100k and 1M synthetic flows", async ({ page }, testInfo) => {
  test.setTimeout(600_000);
  await page.goto("/app");
  const packets = page.getByText("Packets").first();
  const sample = page.getByRole("button", { name: /explore sample capture/i });
  await expect(packets.or(sample)).toBeVisible({ timeout: 15_000 });

  const results: Bench[] = [];
  for (const n of [100_000, 1_000_000]) {
    const r = await bench(page, n);
    results.push(r);
    console.log(`[query-perf] ${JSON.stringify(r)}`);
    testInfo.annotations.push({ type: "perf", description: JSON.stringify(r) });
  }

  const [k100, m1] = results;
  // Loose ceilings — the plan's budgets (≤2s load, ≤500ms bundled queries per
  // 100k rows) are checked against the recorded numbers, not CI variance.
  expect(k100.loadMs).toBeLessThan(20_000);
  expect(Math.max(k100.topTalkersMs, k100.histogramMs, k100.pointMs, k100.sortMs)).toBeLessThan(
    5_000,
  );
  expect(m1.loadMs).toBeLessThan(120_000);
  expect(Math.max(m1.topTalkersMs, m1.histogramMs, m1.pointMs, m1.sortMs)).toBeLessThan(15_000);
});
