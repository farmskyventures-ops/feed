-- =====================================================================
-- 0032 — Reassign Customer/User Between Agents (Feed / Murabaha tenant)
--
-- Adds:
--   1. A dedicated RBAC permission `manage_customer_reassignment` so
--      Super-Admins can delegate the ability to transfer a customer from
--      one agent (Agent A) to another (Agent B).
--   2. A `customer_reassignments` audit/compliance table capturing WHO
--      performed the transfer, the former + new agent, the customer, and
--      an immutable timestamp — independent of the generic audit_logs.
--
-- Access re-scoping itself is data-driven: the app updates
-- customers.agent_id + customers.onboarded_by and the historical
-- murabaha_contracts.agent_id + created_by so ownership scoping immediately
-- grants Agent B and revokes Agent A.
--
-- Idempotent + auto-applied by db-init on boot.
-- =====================================================================

-- 1) RBAC permission -------------------------------------------------------
INSERT OR IGNORE INTO permission_catalog (permission_key, label, description, category) VALUES
  ('manage_customer_reassignment', 'Manage Customer Reassignment', 'Transfer a customer/user from one agent to another (grants the new agent full access and revokes the former agent).', 'users');

-- Grant to the admin role templates so it renders pre-checked in the panel.
UPDATE role_templates
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb || '{"manage_customer_reassignment":true}'::jsonb)::text
 WHERE role_key IN ('super_admin', 'admin');

-- Backfill existing admin / super_admin user rows so the panel shows it checked.
UPDATE users
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb || '{"manage_customer_reassignment":true}'::jsonb)::text
 WHERE role IN ('super_admin', 'admin');

-- 2) Audit / compliance table ---------------------------------------------
CREATE TABLE IF NOT EXISTS customer_reassignments (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id    INTEGER NOT NULL,
  from_agent_id  TEXT,
  to_agent_id    TEXT NOT NULL,
  performed_by   TEXT NOT NULL,
  reason         TEXT,
  created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_cust_reassign_customer ON customer_reassignments(customer_id);
CREATE INDEX IF NOT EXISTS idx_cust_reassign_to ON customer_reassignments(to_agent_id);
CREATE INDEX IF NOT EXISTS idx_cust_reassign_from ON customer_reassignments(from_agent_id);
