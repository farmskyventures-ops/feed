-- =====================================================================
-- Phase 5 — App-Scope Row-Level Security for shared cross-platform tables
-- Run ONCE by a Postgres superuser against the app DB:
--
--     psql "$SUPERUSER_DATABASE_URL" -f backend/sql/04_app_scope_rls_setup.sql
--
-- Isolates rows between the Equipment app and the Feed app on tables that
-- are shared by both codebases. Each backend sets, per connection:
--
--     SELECT set_config('app.current_app_scope', 'equipment'|'feed', false);
--
-- A row is visible when its app_scope matches the connection scope OR the
-- row is tagged 'both'. Admin/super_admin context still bypasses via the
-- helper defined in 03_ownership_rls_setup.sql (current_app_is_admin()).
-- Running any query WITHOUT app.current_app_scope surfaces only 'both' rows.
-- =====================================================================

CREATE OR REPLACE FUNCTION current_app_scope() RETURNS TEXT AS $$
  SELECT COALESCE(NULLIF(current_setting('app.current_app_scope', true), ''), '');
$$ LANGUAGE sql STABLE;

-- Row is admissible if scope matches, row is 'both', or no scope set (legacy).
CREATE OR REPLACE FUNCTION app_scope_admits(row_scope TEXT) RETURNS BOOLEAN AS $$
  SELECT current_app_scope() = ''            -- no context: do not hide
      OR COALESCE(row_scope, 'both') = 'both'  -- shared rows always visible
      OR COALESCE(row_scope, 'both') = current_app_scope();
$$ LANGUAGE sql STABLE;

-- PRODUCTS (shared catalog) -------------------------------------------
ALTER TABLE products ENABLE ROW LEVEL SECURITY;
ALTER TABLE products FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS app_scope_products ON products;
CREATE POLICY app_scope_products ON products
  USING (app_scope_admits(app_scope))
  WITH CHECK (app_scope_admits(app_scope));

-- TRANSACTIONS (shared payment records) -------------------------------
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS app_scope_transactions ON transactions;
CREATE POLICY app_scope_transactions ON transactions
  USING (app_scope_admits(app_scope))
  WITH CHECK (app_scope_admits(app_scope));

-- MERCHANT_KEYS (public merchant API credentials) ---------------------
ALTER TABLE merchant_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE merchant_keys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS app_scope_merchant_keys ON merchant_keys;
CREATE POLICY app_scope_merchant_keys ON merchant_keys
  USING (app_scope_admits(app_scope))
  WITH CHECK (app_scope_admits(app_scope));
