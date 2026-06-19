-- q07 — Per-second histogram of flow starts (packets & bytes by second).
SELECT date_trunc('second', start_ts)        AS bucket,
       COUNT(*)                              AS flows,
       SUM(pkts)                             AS pkts,
       SUM(bytes_c2s + bytes_s2c)            AS bytes
FROM flow
GROUP BY bucket
ORDER BY bucket ASC;
