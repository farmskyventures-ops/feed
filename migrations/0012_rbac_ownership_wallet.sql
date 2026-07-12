-- =====================================================================
-- Operational Updates: Granular RBAC, Ownership tracking, Split-data
-- listing workflow, Extended user types, and Wallet (double-entry) system
--
--   This migration is SCHEMA + SEED only (DDL/DML that db-init auto-applies
--   on every boot, idempotently). The PostgreSQL Row-Level Security policies
--   and trigger functions that enforce it live in backend/sql/03_ownership_
--   rls_setup.sql (run once by a superuser — creating triggers/policies needs
--   privileges the runtime role should not hold).
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. RBAC — granular permission catalog entries
--    Split "who drafts inventory" from "who authorizes financial terms".
-- ---------------------------------------------------------------------
INSERT OR IGNORE INTO permission_catalog (permission_key, label, description, category) VALUES
  ('can_manage_inventory',       'Manage inventory (core + cash)', 'Add / edit core product details, reorder thresholds, cash pricing and payment availability', 'inventory'),
  ('can_manage_finance_settings','Manage finance settings',        'Add / edit finance pricing, markups, rates, discounts, terms, PAYGO and legal agreements', 'finance'),
  ('view_wallet',                'View own wallet',                'See own wallet balance, ledger and earnings statement', 'wallet'),
  ('manage_wallets',             'Manage wallets & payouts',       'Assign wallets, set earning rules, and disburse retainers / per-diems', 'wallet');

-- ---------------------------------------------------------------------
-- 2. Extended user types — new role templates
--    Adds Lender, Investor, M&E and Partner alongside the existing set.
-- ---------------------------------------------------------------------
INSERT OR IGNORE INTO role_templates (role_key, label, description, permissions, is_system) VALUES
  ('lender',   'Lender',   'Capital provider viewing financed-portfolio performance', '{"view":true,"view_credit_purchases":true}', 1),
  ('investor', 'Investor', 'Equity / fund investor viewing platform performance metrics', '{"view":true}', 1),
  ('mne',      'M & E',    'Monitoring & Evaluation officer with read access to farmer + portfolio data', '{"view":true,"view_farmers":true,"view_credit_purchases":true}', 1),
  ('partner',  'Partner',  'External partner with limited read access', '{"view":true}', 1);

-- Grant the two split-permission keys to the roles that should hold them by
-- default (super_admin/admin get everything via code; these make the intent
-- explicit and drive the frontend check-boxes / role defaults). jsonb '||'
-- merges/overwrites keys without disturbing existing ones (Postgres-native;
-- on SQLite/D1 db-init swallows the unsupported cast, roles fall back to code
-- defaults which already grant admins everything).
-- Admins & super admins: full inventory + finance authority, plus wallet management.
UPDATE role_templates
   SET permissions = (permissions::jsonb || '{"can_manage_inventory":true,"can_manage_finance_settings":true,"view_wallet":true,"manage_wallets":true}'::jsonb)::text
 WHERE role_key IN ('super_admin', 'admin');

-- Operations & finance: authorize the commercial / financing components.
UPDATE role_templates
   SET permissions = (permissions::jsonb || '{"can_manage_finance_settings":true}'::jsonb)::text
 WHERE role_key = 'operations_finance';

-- Agents may draft inventory (core details) but NOT authorize financial terms,
-- and they can view their own earnings wallet.
UPDATE role_templates
   SET permissions = (permissions::jsonb || '{"can_manage_inventory":true,"view_wallet":true}'::jsonb)::text
 WHERE role_key = 'agent';

-- ---------------------------------------------------------------------
-- 3. Ownership tracking — audit trail of who introduced each record.
-- ---------------------------------------------------------------------
ALTER TABLE products           ADD COLUMN IF NOT EXISTS created_by INTEGER;
ALTER TABLE customers          ADD COLUMN IF NOT EXISTS onboarded_by INTEGER;   -- explicit onboarding-agent relationship
ALTER TABLE murabaha_contracts ADD COLUMN IF NOT EXISTS created_by INTEGER;

-- Backfill onboarded_by from the existing agent_id relationship.
UPDATE customers SET onboarded_by = agent_id WHERE onboarded_by IS NULL AND agent_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_products_created_by   ON products(created_by);
CREATE INDEX IF NOT EXISTS idx_customers_onboarded   ON customers(onboarded_by);
CREATE INDEX IF NOT EXISTS idx_contracts_created_by  ON murabaha_contracts(created_by);

-- ---------------------------------------------------------------------
-- 4. Split-data listing workflow — finance-completion status on products.
--    A base user drafts a product; it stays 'draft' (hidden from storefront)
--    until an authorized finance user supplies the financial components and
--    marks it 'published'. 'pending_finance' is the approval-queue state.
-- ---------------------------------------------------------------------
ALTER TABLE products ADD COLUMN IF NOT EXISTS finance_status TEXT DEFAULT 'published';  -- draft | pending_finance | published
ALTER TABLE products ADD COLUMN IF NOT EXISTS finance_set_by INTEGER;                   -- authorized user who filled finance
ALTER TABLE products ADD COLUMN IF NOT EXISTS finance_set_at TIMESTAMP;
ALTER TABLE products ADD COLUMN IF NOT EXISTS finance_notes TEXT;

CREATE INDEX IF NOT EXISTS idx_products_finance_status ON products(finance_status);

-- ---------------------------------------------------------------------
-- 5. Wallet system — double-entry ledger + custom earning rules.
-- ---------------------------------------------------------------------

-- 5a. One wallet per user (assigned by an authorized admin).
CREATE TABLE IF NOT EXISTS wallets (
  id BIGSERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL UNIQUE,
  currency TEXT NOT NULL DEFAULT 'KES',
  balance NUMERIC(14,2) NOT NULL DEFAULT 0,   -- cached balance; a trigger keeps it = SUM(ledger)
  status TEXT NOT NULL DEFAULT 'active',        -- active | frozen
  assigned_by INTEGER,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_wallets_user ON wallets(user_id);

-- 5b. Double-entry ledger. Every credit/debit is an immutable row; the wallet
--     balance can only move via an inserted entry (enforced by trigger in
--     backend/sql/03). entry_type: 'credit' increases, 'debit' decreases.
CREATE TABLE IF NOT EXISTS wallet_ledger (
  id BIGSERIAL PRIMARY KEY,
  wallet_id BIGINT NOT NULL,
  user_id INTEGER NOT NULL,
  entry_type TEXT NOT NULL,                     -- credit | debit
  amount NUMERIC(14,2) NOT NULL CHECK (amount > 0),
  balance_after NUMERIC(14,2) NOT NULL,         -- running balance snapshot (double-entry integrity)
  category TEXT NOT NULL,                        -- commission | retainer | transport | per_diem | payout | adjustment
  reference TEXT,                                -- order/contract ref or batch id
  description TEXT,
  created_by INTEGER,                            -- the actor (system for auto-commission, admin for payouts)
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_wallet_ledger_wallet ON wallet_ledger(wallet_id);
CREATE INDEX IF NOT EXISTS idx_wallet_ledger_user   ON wallet_ledger(user_id);
CREATE INDEX IF NOT EXISTS idx_wallet_ledger_cat    ON wallet_ledger(category);

-- 5c. Custom earning rules per user (structural tracking table).
--     e.g. 2% commission on completed orders, KES 5,000 monthly retainer,
--     KES 500 transport per activity, per-diem allowances, etc.
CREATE TABLE IF NOT EXISTS earning_rules (
  id BIGSERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL,
  rule_type TEXT NOT NULL,                       -- commission | retainer | transport | per_diem | stipend
  calc_method TEXT NOT NULL DEFAULT 'fixed',     -- percentage | fixed
  rate NUMERIC(10,4),                             -- % when percentage (e.g. 2.0 => 2%)
  fixed_amount NUMERIC(14,2),                     -- amount when fixed
  applies_to TEXT DEFAULT 'completed_order',     -- completed_order | manual | monthly
  description TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_by INTEGER,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_earning_rules_user ON earning_rules(user_id);

-- 5d. Payout batches — audit trail for admin-issued disbursals
--     (retainers, transport, per-diems) issued globally or individually.
CREATE TABLE IF NOT EXISTS payout_batches (
  id BIGSERIAL PRIMARY KEY,
  batch_ref TEXT UNIQUE NOT NULL,
  category TEXT NOT NULL,                         -- retainer | transport | per_diem | stipend
  description TEXT,
  total_amount NUMERIC(14,2) NOT NULL DEFAULT 0,
  recipient_count INTEGER NOT NULL DEFAULT 0,
  issued_by INTEGER,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_payout_batches_ref ON payout_batches(batch_ref);
