-- q04 — Beaconing candidates: many short, similar-sized flows from one src to
--       one dst:port (low byte variance, high flow count). Phase-0 heuristic.
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
