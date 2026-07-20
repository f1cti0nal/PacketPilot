import { expect, test } from "@playwright/test";

/**
 * Phase 1 smoke for the in-browser query engine (lib/query/engine.ts): boots
 * real DuckDB-Wasm in the page via the dev server, loads handcrafted flows,
 * and exercises guarded execution end-to-end. The Query tab UI (Phase 2) is
 * not involved — this drives the library directly.
 */
test("query engine: boots duckdb-wasm, loads flows, runs guarded SQL locally", async ({
  page,
}) => {
  await page.goto("/app");
  // Let the SPA finish booting (it may redirect/settle right after load) so the
  // evaluation context is stable for the long-running wasm boot below.
  const packets = page.getByText("Packets").first();
  const sample = page.getByRole("button", { name: /explore sample capture/i });
  await expect(packets.or(sample)).toBeVisible({ timeout: 15_000 });

  const result = await page.evaluate(async () => {
    const { getQueryEngine } = (await import(
      "/src/lib/query/engine.ts"
    )) as typeof import("../src/lib/query/engine.ts");

    const base = {
      captureId: 0,
      srcPort: 51000,
      dstPort: 443,
      proto: 6,
      protoLabel: "TCP",
      appProto: "https" as string | null,
      appProtoSrc: "payload" as string | null,
      ja3: null,
      ja4: null,
      ja3s: null,
      httpHost: null,
      httpUa: null,
      tlsVersion: null,
      tlsCipher: null,
      hassh: null,
      hasshServer: null,
      pkts: 10,
      tcpFlagsC2s: 0x1b,
      tcpFlagsS2c: 0x1b,
      ttlMinC2s: 64,
      severity: "info" as const,
      threatScore: 0,
      ioc: false,
      durationMs: 1000,
    };
    const rows = [
      {
        ...base,
        flowId: 1,
        flowIdBig: 1n,
        srcIp: "10.0.0.1",
        dstIp: "93.184.216.34",
        sni: "example.com" as string | null,
        bytesC2s: 1000,
        bytesS2c: 9000,
        bytesTotal: 10000,
        startMs: 1752900000000,
        endMs: 1752900001000,
        category: "web" as const,
      },
      {
        ...base,
        flowId: 2,
        flowIdBig: 2n,
        srcIp: "10.0.0.1",
        dstIp: "8.8.8.8",
        dstPort: 53,
        proto: 17,
        appProto: "dns" as string | null,
        sni: null as string | null,
        bytesC2s: 80,
        bytesS2c: 200,
        bytesTotal: 280,
        startMs: 1752900002000,
        endMs: 1752900002200,
        category: "dns" as const,
      },
      {
        ...base,
        flowId: 3,
        flowIdBig: 3n,
        srcIp: "10.0.0.2",
        dstIp: "203.0.113.7",
        sni: null as string | null,
        bytesC2s: 4000,
        bytesS2c: 100,
        bytesTotal: 4100,
        startMs: 1752900003000,
        endMs: 1752900004000,
        category: "c2" as const,
        severity: "critical" as const,
        threatScore: 91,
        ioc: true,
      },
    ];

    const engine = await getQueryEngine();
    await engine.loadFlows(rows, "e2e-smoke");

    // Aggregation over the typed flow table.
    const agg = await engine.run(
      "SELECT category, COUNT(*) AS flows, SUM(bytes_c2s + bytes_s2c) AS bytes " +
        "FROM flow GROUP BY category ORDER BY bytes DESC",
    );

    // Timestamp semantics survive the epoch-ms ingestion.
    const ts = await engine.run(
      "SELECT CAST(date_trunc('second', min(start_ts)) AS VARCHAR) AS first_s, " +
        "CAST(max(end_ts) AS VARCHAR) AS last FROM flow",
    );

    // Default LIMIT injection (no top-level LIMIT in the input).
    const noLimit = await engine.run("SELECT flow_id FROM flow");
    const withLimit = await engine.run("SELECT flow_id FROM flow LIMIT 2");

    // Guard rejection.
    const guardErr = await engine
      .run("DROP TABLE flow")
      .then(() => "NO_ERROR", (e: unknown) => String(e instanceof Error ? e.message : e));

    // Engine-level hardening: external table functions must stay off.
    const externalErr = await engine
      .run("SELECT * FROM read_parquet('sample.parquet')")
      .then(() => "NO_ERROR", (e: unknown) => String(e instanceof Error ? e.message : e));

    const plain = (v: unknown) => (typeof v === "bigint" ? Number(v) : v);
    return {
      aggColumns: agg.columns.map((c) => c.name),
      aggRows: agg.rows.map((r) => r.map(plain)),
      tsRow: ts.rows[0]?.map(String),
      noLimitApplied: noLimit.limitApplied,
      withLimitApplied: withLimit.limitApplied,
      withLimitCount: withLimit.rowCount,
      guardErr,
      externalErr,
    };
  });

  expect(result.aggColumns).toEqual(["category", "flows", "bytes"]);
  expect(result.aggRows).toEqual([
    ["web", 1, 10000],
    ["c2", 1, 4100],
    ["dns", 1, 280],
  ]);

  // 1752900000000 ms = 2025-07-19T04:40:00 UTC; 1752900004000 = …:04.
  expect(result.tsRow?.[0]).toContain("2025-07-19 04:40:00");
  expect(result.tsRow?.[1]).toContain("2025-07-19 04:40:04");

  expect(result.noLimitApplied).toBe(true);
  expect(result.withLimitApplied).toBe(false);
  expect(result.withLimitCount).toBe(2);

  expect(result.guardErr).toMatch(/read-only|SELECT/);
  expect(result.externalErr).not.toBe("NO_ERROR");
  expect(result.externalErr).toMatch(/disabled|external|permission/i);
});
