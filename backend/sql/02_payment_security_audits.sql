-- =====================================================================
-- Payment Gateway — Security / verification queries & automated audits
-- Run by the MAIN (equipment) app reconciliation job or an operator:
--
--     psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f backend/sql/02_payment_security_audits.sql
--
-- These run as the admin/reconciliation role, i.e. with:
--     SET app.is_admin = 'true';
-- so they can see across all tenants (RLS admin bypass).
-- =====================================================================

SET app.is_admin = 'true';

-- 1. AUTOMATED REVENUE MATRIX AUDIT ----------------------------------------
-- Successful revenue split by marketplace x payment method. Because all three
-- marketplaces share ONE merchant shortcode, this matrix is how the MAIN app
-- attributes a single settlement statement back to each tenant.
SELECT
  m.marketplace_key,
  m.display_name,
  ct.payment_method,
  COUNT(*)                                   AS success_count,
  COALESCE(SUM(ct.amount), 0)                AS gross_revenue,
  MIN(ct.completed_at)                       AS first_settlement,
  MAX(ct.completed_at)                       AS last_settlement
FROM central_transactions ct
JOIN marketplaces m ON m.id = ct.marketplace_id
WHERE ct.status = 'SUCCESS'
GROUP BY m.marketplace_key, m.display_name, ct.payment_method
ORDER BY m.marketplace_key, ct.payment_method;

-- 1b. Per-marketplace revenue rollup (single-shortcode reconciliation total).
SELECT
  m.marketplace_key,
  COUNT(*)                        AS total_success,
  COALESCE(SUM(ct.amount), 0)     AS total_revenue
FROM central_transactions ct
JOIN marketplaces m ON m.id = ct.marketplace_id
WHERE ct.status = 'SUCCESS'
GROUP BY m.marketplace_key
ORDER BY total_revenue DESC;

-- 2. SUSPICIOUS ACTIVITY AUDIT TRAIL CHECK ---------------------------------
-- 2a. Recorded security events (signature failures, replays, cross-tenant).
SELECT event_type, severity, COUNT(*) AS occurrences, MAX(created_at) AS last_seen
FROM payment_audit_log
WHERE created_at > (CURRENT_TIMESTAMP - INTERVAL '7 days')
GROUP BY event_type, severity
ORDER BY
  CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'WARN' THEN 1 ELSE 2 END,
  occurrences DESC;

-- 2b. Data-integrity check: any transaction whose marketplace_id does not
--     match its origin_app text (a sign of tampering or a mapping bug).
SELECT ct.transaction_ref, ct.origin_app, ct.marketplace_id, m.marketplace_key
FROM central_transactions ct
LEFT JOIN marketplaces m ON m.id = ct.marketplace_id
WHERE ct.marketplace_id IS NULL
   OR m.marketplace_key IS DISTINCT FROM ct.origin_app;

-- 2c. Velocity anomaly: same phone paying > 5 times in 10 minutes.
SELECT phone, COUNT(*) AS attempts, MIN(created_at) AS window_start, MAX(created_at) AS window_end
FROM central_transactions
WHERE created_at > (CURRENT_TIMESTAMP - INTERVAL '10 minutes')
GROUP BY phone
HAVING COUNT(*) > 5
ORDER BY attempts DESC;

-- 2d. Callbacks that failed signature/binding validation (possible spoofing).
SELECT payment_method, COUNT(*) AS invalid_callbacks, MAX(received_at) AS last_seen
FROM central_callbacks
WHERE signature_valid = 0
  AND received_at > (CURRENT_TIMESTAMP - INTERVAL '7 days')
GROUP BY payment_method
ORDER BY invalid_callbacks DESC;

RESET app.is_admin;
