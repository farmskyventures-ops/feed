-- =====================================================================
-- 0047 — Unified Bundle Payment + Offtaker role onboarding + Data isolation
--
-- NON-BREAKING MODULAR EXPANSION (additive columns / nullable only).
--  1. Bundle payment intents: let one invoice/transaction settle a whole
--     multi-item bundle (Σ item cost×qty + markups + taxes) instead of only
--     the first item. payment_intents gains a bundle_ref so a single STK /
--     gateway transaction can be reconciled across every contract in a bundle.
--  2. Offtaker onboarding: ensure the Offtaker capability flag exists and that
--     an admin can assign the Offtaker category at user creation; users in that
--     category are auto-granted offtake / spot-buy / traceability permissions.
--  3. Data isolation helper column: mark which admin/org unit owns an agent so
--     dashboards can scope strictly by assignment (super_admin stays global).
--
-- Mirrored across Equipment (host), Nia and Feed.
-- All DDL is idempotent (duplicate-column / ON CONFLICT tolerated by db-init).
-- =====================================================================

-- ---------------------------------------------------------------------------
-- 1. UNIFIED BUNDLE PAYMENT — correlate ONE transaction to a whole bundle.
-- ---------------------------------------------------------------------------
ALTER TABLE payment_intents ADD COLUMN bundle_ref TEXT;      -- when set, intent settles every contract in the bundle
ALTER TABLE payment_intents ADD COLUMN is_bundle INTEGER DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_intents_bundle ON payment_intents(bundle_ref);

-- Mark invoices/transactions that represent a consolidated bundle invoice.
ALTER TABLE invoices ADD COLUMN bundle_ref TEXT;
ALTER TABLE transactions ADD COLUMN bundle_ref TEXT;

-- ---------------------------------------------------------------------------
-- 2. OFFTAKER ONBOARDING — assignable category (role) + auto-permissions.
--    (is_offtaker already added in 0046; this guarantees it on fresh forks.)
-- ---------------------------------------------------------------------------
ALTER TABLE users ADD COLUMN is_offtaker INTEGER DEFAULT 0;

-- Register the Offtaker role template so it appears as a selectable category in
-- the admin "Create User" form. A user created with this role is AUTOMATICALLY
-- granted Offtake Contracting, Spot Buying and Traceability permissions.
INSERT OR IGNORE INTO role_templates (role_key, label, description, permissions, is_system) VALUES
  ('offtaker', 'Offtaker (Produce Buyer)', 'Ag-SME produce buyer: offtake contracting, spot buying and traceability.',
   '{"view":true,"manage_offtake":true,"spot_buy":true,"match_outgrowers":false,"view_traceability":true,"aggregate_produce":false}', 1);

-- Ensure the Offtaker permissions stay present even if the template pre-existed
-- from an earlier partial run (non-destructive merge).
UPDATE role_templates
   SET permissions = (COALESCE(NULLIF(permissions,''),'{}')::jsonb
        || '{"manage_offtake":true,"spot_buy":true,"view_traceability":true}'::jsonb)::text
 WHERE role_key = 'offtaker';

-- ---------------------------------------------------------------------------
-- 3. DATA ISOLATION — explicit owning admin/org unit for agents & records.
--    super_admin ignores this (systemwide); everyone else scopes by it.
-- ---------------------------------------------------------------------------
ALTER TABLE users ADD COLUMN managing_admin_id INTEGER;   -- which admin "owns" this agent/sub-user
ALTER TABLE users ADD COLUMN org_unit TEXT;               -- optional organizational unit label
