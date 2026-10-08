-- =====================================================================
-- 0043 — Purchases & Contracts: order consolidation + agent visibility RBAC
--
--   1. Register a new opt-in permission `view_all_sales` which, when granted to
--      an agent (or any non-admin user), widens their Purchases & Contracts
--      visibility BEYOND their own farmer network to every sale permitted by the
--      cash / financed Sales-Visibility flags. By DEFAULT agents remain strictly
--      scoped to purchases & contracts tied to their OWN assigned farmers — this
--      grant is the explicit exception enumerated in the ticket.
--
--   2. Grant `view_all_sales` to the full-access system roles so admins keep an
--      org-wide view.
--
--   SCHEMA / DATA only (idempotent — applied by backend/db-init.ts on boot).
-- =====================================================================

INSERT INTO permission_catalog (permission_key, label, description, category) VALUES
    ('view_all_sales', 'View All Sales (org-wide)', 'See Purchases & Contracts beyond the user''s own farmer network (subject to cash/financed visibility)', 'sales_visibility')
ON CONFLICT (permission_key) DO NOTHING;

-- Full-access system roles get the org-wide grant explicitly. The permissions
-- column is TEXT holding a JSON object, so cast to jsonb for the merge and store
-- the result back as text.
UPDATE role_templates
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb || '{"view_all_sales":true}'::jsonb)::text
 WHERE role_key IN ('super_admin', 'admin');

-- Ensure the agent default retains network-scoped Purchases & Contracts access
-- (view_credit_purchases) WITHOUT the org-wide grant — an admin may add
-- view_all_sales per-user from the RBAC editor when a wider remit is approved.
UPDATE role_templates
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb || '{"view_credit_purchases":true}'::jsonb)::text
 WHERE role_key = 'agent'
   AND NOT (COALESCE(NULLIF(permissions, ''), '{}')::jsonb ? 'view_credit_purchases');
