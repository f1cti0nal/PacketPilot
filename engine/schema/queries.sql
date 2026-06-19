-- PacketPilot Phase 0 — example analyst queries (DuckDB).
-- These reference only columns present in the unified flow schema (§5). The `category`
-- token values match the category_t enum / Category::as_str(). Run against the views
-- created by crates/ppcap-core/sql/schema.sql after `ppcap init-db` has substituted {CASE_DIR}.

-- ============================================================================
-- q01 — Top talkers by total bytes (both directions), with flow & packet counts.
-- ============================================================================
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
LIMIT 50;

-- ============================================================================
-- q02 — Severity rollup from findings (per-severity counts & max confidence).
-- ============================================================================
SELECT severity,
       COUNT(*)            AS findings,
       MAX(confidence)     AS max_confidence
FROM finding
GROUP BY severity
ORDER BY array_position(['critical','high','medium','low','info'], severity::VARCHAR);

-- ============================================================================
-- q03 — Category breakdown over flows (flows, packets, bytes per category).
-- ============================================================================
SELECT category,
       COUNT(*)                  AS flows,
       SUM(pkts)                 AS pkts,
       SUM(bytes_c2s + bytes_s2c) AS bytes
FROM flow
GROUP BY category
ORDER BY bytes DESC;

-- ============================================================================
-- q04 — Beaconing candidates: many short, similar-sized flows from one src to
--       one dst:port (low byte variance, high flow count). Phase-0 heuristic.
-- ============================================================================
SELECT src_ip, dst_ip, dst_port,
       COUNT(*)                              AS flow_count,
       AVG(bytes_c2s + bytes_s2c)            AS avg_bytes,
       STDDEV_POP(bytes_c2s + bytes_s2c)     AS std_bytes,
       MIN(start_ts)                         AS first_seen,
       MAX(end_ts)                           AS last_seen
FROM flow
GROUP BY src_ip, dst_ip, dst_port
HAVING COUNT(*) >= 5
ORDER BY flow_count DESC, std_bytes ASC
LIMIT 100;

-- ============================================================================
-- q05 — Protocol hierarchy: bytes & packets per (proto, app_proto) path.
-- ============================================================================
SELECT proto,
       COALESCE(app_proto, 'unknown')        AS app_proto,
       COUNT(*)                              AS flows,
       SUM(pkts)                             AS pkts,
       SUM(bytes_c2s + bytes_s2c)            AS bytes
FROM flow
GROUP BY proto, COALESCE(app_proto, 'unknown')
ORDER BY bytes DESC;

-- ============================================================================
-- q06 — Port histogram: traffic by responder (dst) port.
-- ============================================================================
SELECT dst_port,
       proto,
       COUNT(*)                              AS flows,
       SUM(pkts)                             AS pkts,
       SUM(bytes_c2s + bytes_s2c)            AS bytes
FROM flow
GROUP BY dst_port, proto
ORDER BY pkts DESC
LIMIT 50;

-- ============================================================================
-- q07 — Per-second histogram of flow starts (packets & bytes by second).
-- ============================================================================
SELECT date_trunc('second', start_ts)        AS bucket,
       COUNT(*)                              AS flows,
       SUM(pkts)                             AS pkts,
       SUM(bytes_c2s + bytes_s2c)            AS bytes
FROM flow
GROUP BY bucket
ORDER BY bucket ASC;

-- ============================================================================
-- q08 — IP severity map: highest finding severity per host (from incidents).
-- ============================================================================
SELECT host,
       severity,
       COUNT(*)                              AS incidents,
       MAX(created_at)                       AS last_incident
FROM incident
GROUP BY host, severity
ORDER BY array_position(['critical','high','medium','low','info'], severity::VARCHAR), host;
