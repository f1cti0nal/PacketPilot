/**
 * Bundled starter queries for the Query console. The first six are the engine's
 * shipped analyst queries that target the `flow` view — source of truth:
 * engine/crates/ppcap-core/sql/queries/ (q01, q03–q07; q02/q08 hit native
 * DuckDB tables the browser doesn't have). Adapted only cosmetically (no
 * trailing semicolon). samples.test.ts asserts every sample passes the guard.
 */

export interface SampleQuery {
  id: string;
  label: string;
  sql: string;
}

export const SAMPLE_QUERIES: SampleQuery[] = [
  {
    id: "q01",
    label: "Top talkers",
    sql: `-- Top talkers by total bytes (both directions), with flow & packet counts.
WITH ep AS (
  SELECT src_ip AS ip, bytes_c2s + bytes_s2c AS bytes, pkts, 1 AS flows FROM flow
  UNION ALL
  SELECT dst_ip AS ip, bytes_c2s + bytes_s2c AS bytes, pkts, 1 AS flows FROM flow
)
SELECT ip,
       SUM(bytes)  AS total_bytes,
       SUM(pkts)   AS total_pkts,
       SUM(flows)  AS flows
FROM ep
GROUP BY ip
ORDER BY total_bytes DESC
LIMIT 50`,
  },
  {
    id: "q03",
    label: "Category breakdown",
    sql: `-- Category breakdown over flows (flows, packets, bytes per category).
SELECT category,
       COUNT(*)                   AS flows,
       SUM(pkts)                  AS pkts,
       SUM(bytes_c2s + bytes_s2c) AS bytes
FROM flow
GROUP BY category
ORDER BY bytes DESC`,
  },
  {
    id: "q04",
    label: "Beaconing candidates",
    sql: `-- Beaconing candidates: many short, similar-sized flows from one src to
-- one dst:port (low byte variance, high flow count).
SELECT src_ip, dst_ip, dst_port,
       COUNT(*)                          AS flow_count,
       AVG(bytes_c2s + bytes_s2c)        AS avg_bytes,
       STDDEV_POP(bytes_c2s + bytes_s2c) AS std_bytes,
       MIN(start_ts)                     AS first_seen,
       MAX(end_ts)                       AS last_seen
FROM flow
GROUP BY src_ip, dst_ip, dst_port
HAVING COUNT(*) >= 5
ORDER BY flow_count DESC, std_bytes ASC
LIMIT 100`,
  },
  {
    id: "q05",
    label: "Protocol hierarchy",
    sql: `-- Protocol hierarchy: bytes & packets per (proto, app_proto) path.
SELECT proto,
       COALESCE(app_proto, 'unknown')    AS app_proto,
       COUNT(*)                          AS flows,
       SUM(pkts)                         AS pkts,
       SUM(bytes_c2s + bytes_s2c)        AS bytes
FROM flow
GROUP BY proto, COALESCE(app_proto, 'unknown')
ORDER BY bytes DESC`,
  },
  {
    id: "q06",
    label: "Port histogram",
    sql: `-- Port histogram: traffic by responder (dst) port.
SELECT dst_port,
       proto,
       COUNT(*)                          AS flows,
       SUM(pkts)                         AS pkts,
       SUM(bytes_c2s + bytes_s2c)        AS bytes
FROM flow
GROUP BY dst_port, proto
ORDER BY pkts DESC
LIMIT 50`,
  },
  {
    id: "q07",
    label: "Per-second histogram",
    sql: `-- Per-second histogram of flow starts (packets & bytes by second).
SELECT date_trunc('second', start_ts)    AS bucket,
       COUNT(*)                          AS flows,
       SUM(pkts)                         AS pkts,
       SUM(bytes_c2s + bytes_s2c)        AS bytes
FROM flow
GROUP BY bucket
ORDER BY bucket ASC`,
  },
  {
    id: "flagged",
    label: "Flagged flows (IOC / high severity)",
    // Returns flow_id so the result can be lifted back into the Flows tab
    // ("Open in Flows" cross-filter).
    sql: `-- Flows worth a second look: IOC feed matches or high/critical severity.
SELECT flow_id, src_ip, dst_ip, dst_port, app_proto, category,
       severity, threat_score, ioc,
       bytes_c2s + bytes_s2c AS bytes
FROM flow
WHERE ioc OR severity IN ('critical', 'high')
ORDER BY threat_score DESC, bytes DESC
LIMIT 500`,
  },
];
