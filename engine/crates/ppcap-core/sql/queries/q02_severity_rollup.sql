-- q02 — Severity rollup from findings (per-severity counts & max confidence).
SELECT severity,
       COUNT(*)            AS findings,
       MAX(confidence)     AS max_confidence
FROM finding
GROUP BY severity
ORDER BY array_position(['critical','high','medium','low','info'], severity::VARCHAR);
