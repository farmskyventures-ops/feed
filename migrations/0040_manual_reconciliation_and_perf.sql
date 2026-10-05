-- =====================================================================
-- 0040 — Sales Manual Reconciliation permission + performance indexes
--
-- 1. RBAC: a new delegable permission `sales_manual_reconciliation` under the
--    Users management panel. Super-Admins hold it by default and may assign it
--    selectively to other roles/users.
--
-- 2. Performance: targeted indexes for the heavy list endpoints
--    (Customers, Users, Inventory/products) + the payment ledger joins that
--    back the invoice/receipt documents and the reconciliation flow.
--
-- Idempotent + auto-applied by db-init on boot.
-- =====================================================================

-- RBAC permission -------------------------------------------------------------
INSERT OR IGNORE INTO permission_catalog (permission_key, label, description, category) VALUES
  ('sales_manual_reconciliation', 'Sales Manual Reconciliation', 'Manually settle cash sale dues/installments paid directly to the bank using a unique transaction reference, and generate the official receipt.', 'payments');

-- Super-Admin holds it by default (role template + existing super-admin users).
UPDATE role_templates
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb || '{"sales_manual_reconciliation":true}'::jsonb)::text
 WHERE role_key = 'super_admin';
UPDATE users
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb || '{"sales_manual_reconciliation":true}'::jsonb)::text
 WHERE role = 'super_admin';

-- Performance indexes ---------------------------------------------------------
-- Customers: list/filter + agent-scoped isolation.
-- (idx_customers_agent already exists from 0001; add the filter columns.)
CREATE INDEX IF NOT EXISTS idx_customers_kyc_status   ON customers(kyc_status);
CREATE INDEX IF NOT EXISTS idx_customers_county       ON customers(county);
CREATE INDEX IF NOT EXISTS idx_customers_created_at   ON customers(created_at);

-- Users: list/filter by role/status/region.
CREATE INDEX IF NOT EXISTS idx_users_role            ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_status          ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_region          ON users(region);
CREATE INDEX IF NOT EXISTS idx_users_created_at      ON users(created_at);

-- Inventory / products: list + filter by category/source.
CREATE INDEX IF NOT EXISTS idx_products_category     ON products(category);
CREATE INDEX IF NOT EXISTS idx_products_source       ON products(source_platform);
CREATE INDEX IF NOT EXISTS idx_products_created_at   ON products(created_at);

-- Payment ledger joins that back invoices / receipts / reconciliation.
CREATE INDEX IF NOT EXISTS idx_transactions_contract ON transactions(contract_id);
CREATE INDEX IF NOT EXISTS idx_transactions_receipt  ON transactions(mpesa_receipt);
CREATE INDEX IF NOT EXISTS idx_invoices_contract     ON invoices(contract_id);
CREATE INDEX IF NOT EXISTS idx_repayments_contract   ON repayments(contract_id);
CREATE INDEX IF NOT EXISTS idx_contracts_customer    ON murabaha_contracts(customer_id);
CREATE INDEX IF NOT EXISTS idx_contracts_agent       ON murabaha_contracts(agent_id);
CREATE INDEX IF NOT EXISTS idx_contracts_status      ON murabaha_contracts(status);
