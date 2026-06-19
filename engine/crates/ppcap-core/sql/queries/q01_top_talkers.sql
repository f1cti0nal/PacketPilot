-- q01 — Top talkers by total bytes (both directions), with flow & packet counts.
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
