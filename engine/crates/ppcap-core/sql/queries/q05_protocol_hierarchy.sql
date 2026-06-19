-- q05 — Protocol hierarchy: bytes & packets per (proto, app_proto) path.
SELECT proto,
       COALESCE(app_proto, 'unknown')        AS app_proto,
       COUNT(*)                              AS flows,
       SUM(pkts)                             AS pkts,
       SUM(bytes_c2s + bytes_s2c)            AS bytes
FROM flow
GROUP BY proto, COALESCE(app_proto, 'unknown')
ORDER BY bytes DESC;
