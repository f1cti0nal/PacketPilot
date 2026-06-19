-- q08 — IP severity map: highest finding severity per host (from incidents).
SELECT host,
       severity,
       COUNT(*)                              AS incidents,
       MAX(created_at)                       AS last_incident
FROM incident
GROUP BY host, severity
ORDER BY array_position(['critical','high','medium','low','info'], severity::VARCHAR), host;
