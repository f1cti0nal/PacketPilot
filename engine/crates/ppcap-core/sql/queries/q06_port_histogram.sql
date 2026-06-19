-- q06 — Port histogram: traffic by responder (dst) port.
SELECT dst_port,
       proto,
       COUNT(*)                              AS flows,
       SUM(pkts)                             AS pkts,
       SUM(bytes_c2s + bytes_s2c)            AS bytes
FROM flow
GROUP BY dst_port, proto
ORDER BY pkts DESC
LIMIT 50;
