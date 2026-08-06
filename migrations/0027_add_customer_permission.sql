-- =====================================================================
-- 0027 — Dedicated "add_customer" permission for delegated user creation.
--
--   The "Add Customer" button in the Customers view opens the same unified
--   Add-User flow used by the Users / Accounts section. Per the access-control
--   requirement it must NOT be visible to Agents or other non-admin users by
--   default — only to accounts explicitly authorized via the SuperAdmin/Admin
--   permission panel. We therefore split it off from `add_farmer` (which stays
--   the Agent-facing "Onboard a Farmer" capability) into its own permission key.
--
--   Admins / Super Admins always pass canDo() regardless, but we still add the
--   key to their role templates + existing rows so it renders pre-checked in the
--   permission checklist and can be delegated to any other role/user.
-- =====================================================================

INSERT OR IGNORE INTO permission_catalog (permission_key, label, description, category) VALUES
  ('add_customer', 'Add customers (delegated)', 'Create customer/user accounts via the unified Add-User flow', 'users');

-- Grant to the two admin role templates so it appears pre-selected in the panel.
-- `permissions` is a TEXT column holding a JSON object, so cast to jsonb for the
-- merge; the result is stored back as text automatically.
UPDATE role_templates
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb || '{"add_customer":true}'::jsonb)::text
 WHERE role_key IN ('super_admin', 'admin');

-- Backfill existing admin / super_admin USER rows so the panel shows it checked.
UPDATE users
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb || '{"add_customer":true}'::jsonb)::text
 WHERE role IN ('super_admin', 'admin');
