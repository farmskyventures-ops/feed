-- =====================================================================
-- Payment Gateway — Row-Level Security (RLS) + isolated DB role
-- Run ONCE by a Postgres superuser against the central DB (farmsky-central-db):
--
--     psql "$SUPERUSER_DATABASE_URL" -f backend/sql/01_payment_rls_setup.sql
--
-- This is intentionally NOT auto-applied on boot: creating roles and RLS
-- policies requires privileges the app's runtime user should not hold.
--
-- Security model
--   * The payment gateway microservice (payment-api.farmsky.africa) connects
--     as payment_api_user (NOSUPERUSER, NOCREATEDB). It can only touch the
--     payment tables and never bypasses RLS.
--   * Every payment query first sets the tenant scope:
--         SET LOCAL app.current_marketplace_id = '<id>';
--     RLS policies below restrict every row to that marketplace_id, so a
--     compromised or buggy marketplace can never read/alter another tenant's
--     transactions — enforced by the database itself.
--   * The MAIN app (equipment) reconciliation role may read all tenants via
--     the app.is_admin flag.
-- =====================================================================

-- 1. Isolated runtime role for the payment microservice ---------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'payment_api_user') THEN
    CREATE ROLE payment_api_user LOGIN PASSWORD 'CHANGE_ME_IN_PROD' NOSUPERUSER NOCREATEDB NOCREATEROLE;
  END IF;
END
$$;

-- Least-privilege grants: only the payment tables, no schema ownership.
GRANT USAGE ON SCHEMA public TO payment_api_user;
GRANT SELECT, INSERT, UPDATE ON central_transactions, central_callbacks, payment_audit_log TO payment_api_user;
GRANT SELECT ON app_clients, marketplaces TO payment_api_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO payment_api_user;

-- 2. Enable + FORCE Row-Level Security on the tenant-scoped tables ----------
ALTER TABLE central_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE central_transactions FORCE ROW LEVEL SECURITY;
ALTER TABLE central_callbacks    ENABLE ROW LEVEL SECURITY;
ALTER TABLE central_callbacks    FORCE ROW LEVEL SECURITY;
ALTER TABLE payment_audit_log    ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_audit_log    FORCE ROW LEVEL SECURITY;

-- 3. Helper: current tenant + admin flag from per-connection GUCs -----------
CREATE OR REPLACE FUNCTION current_marketplace_id() RETURNS BIGINT AS $$
  SELECT NULLIF(current_setting('app.current_marketplace_id', true), '')::BIGINT;
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION is_payment_admin() RETURNS BOOLEAN AS $$
  SELECT COALESCE(current_setting('app.is_admin', true), 'false') = 'true';
$$ LANGUAGE sql STABLE;

-- 4. Tenant-isolation policies ---------------------------------------------
-- central_transactions
DROP POLICY IF EXISTS tenant_isolation_tx ON central_transactions;
CREATE POLICY tenant_isolation_tx ON central_transactions
  USING (is_payment_admin() OR marketplace_id = current_marketplace_id())
  WITH CHECK (is_payment_admin() OR marketplace_id = current_marketplace_id());

-- central_callbacks
DROP POLICY IF EXISTS tenant_isolation_cb ON central_callbacks;
CREATE POLICY tenant_isolation_cb ON central_callbacks
  USING (is_payment_admin() OR marketplace_id = current_marketplace_id())
  WITH CHECK (is_payment_admin() OR marketplace_id = current_marketplace_id());

-- payment_audit_log (writable by any tenant scope, readable only within scope / admin)
DROP POLICY IF EXISTS tenant_isolation_audit ON payment_audit_log;
CREATE POLICY tenant_isolation_audit ON payment_audit_log
  USING (is_payment_admin() OR marketplace_id = current_marketplace_id())
  WITH CHECK (true);

-- 5. Reference (read-only) tables need to be readable by every tenant scope -
ALTER TABLE marketplaces ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS marketplaces_read_all ON marketplaces;
CREATE POLICY marketplaces_read_all ON marketplaces FOR SELECT USING (true);

ALTER TABLE app_clients ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS app_clients_read_all ON app_clients;
CREATE POLICY app_clients_read_all ON app_clients FOR SELECT USING (true);

-- Done. Verify with:  \d+ central_transactions   (Policies section)
