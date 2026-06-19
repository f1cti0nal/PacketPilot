-- q03 — Category breakdown over flows (flows, packets, bytes per category).
SELECT category,
       COUNT(*)                  AS flows,
       SUM(pkts)                 AS pkts,
       SUM(bytes_c2s + bytes_s2c) AS bytes
FROM flow
GROUP BY category
ORDER BY bytes DESC;
