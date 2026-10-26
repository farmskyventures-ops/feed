-- =====================================================================
-- 0047 — Sign-up RLS hardening + real-time logistics ETA/routing columns
--
-- 1. RLS: ensure the `customers` ownership policy's WITH CHECK admits the
--    privileged server-side self sign-up INSERT (run via a pinned admin
--    connection in the app). This re-asserts the policy idempotently so every
--    deployment self-heals; the app-side fix (runAsAdmin) is the primary path.
-- 2. Logistics: additive destination coordinates on logistics_shipments so the
--    live tracker can compute an Uber-like ETA (remaining distance ÷ speed) and
--    render a destination pin + route polyline.
--
-- STRICTLY ADDITIVE / NON-BREAKING. Idempotent + auto-applied by db-init.
-- Mirrored across Equipment (0049), Nia (0040) and Feed (0047).
-- =====================================================================

-- 1. Re-assert the customers ownership policy (admin bypass). Feed's ownership
--    helpers use the INTEGER current_app_user_id() form (see
--    backend/sql/03_ownership_rls_setup.sql), so we re-assert in that same form.
DO $mig$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='customers')
     AND EXISTS (SELECT 1 FROM pg_proc WHERE proname='current_app_user_id')
     AND EXISTS (SELECT 1 FROM pg_proc WHERE proname='current_app_is_admin') THEN
    EXECUTE 'ALTER TABLE customers ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE customers FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS ownership_customers ON customers';
    EXECUTE 'CREATE POLICY ownership_customers ON customers
               USING (current_app_is_admin() OR onboarded_by = current_app_user_id() OR agent_id = current_app_user_id())
               WITH CHECK (current_app_is_admin() OR onboarded_by = current_app_user_id() OR agent_id = current_app_user_id())';
  END IF;
END
$mig$;

-- 2. Real-time logistics ETA / routing columns (additive, nullable, idempotent).
ALTER TABLE logistics_shipments ADD COLUMN IF NOT EXISTS dest_lat REAL;
ALTER TABLE logistics_shipments ADD COLUMN IF NOT EXISTS dest_lng REAL;
ALTER TABLE logistics_shipments ADD COLUMN IF NOT EXISTS origin_lat REAL;
ALTER TABLE logistics_shipments ADD COLUMN IF NOT EXISTS origin_lng REAL;
