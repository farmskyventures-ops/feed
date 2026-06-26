-- =====================================================================
-- 0004 — Security, profile & inventory workflow expansion (PostgreSQL)
-- Expands the central data models to support:
--   * Identity document asset storage (KYC images)
--   * Dynamic agricultural metrics
--   * Pruned financial profiles
--   * Granular governance controls (custom roles, permissions, supervisor)
--   * Authentication validation space (numeric reset tokens + expiry)
--   * Advanced inventory parameters (payment eligibility + markups + terms)
-- All ALTERs use ADD COLUMN IF NOT EXISTS — safe to re-run.
-- =====================================================================

-- ---------------------------------------------------------------------
-- Identity Document Asset Storage (three validation images).
-- ---------------------------------------------------------------------
ALTER TABLE users ADD COLUMN IF NOT EXISTS id_front_url TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS id_back_url TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS passport_selfie_url TEXT;

-- ---------------------------------------------------------------------
-- Dynamic Agricultural Metrics (on users so self-service can edit them)
--   farming_profile : primary tracking profile selection (crop|livestock)
--   output_tonnage  : number — recorded output tonnage (avg yield)
--   herd_count      : integer — animal quantity counter
-- ---------------------------------------------------------------------
ALTER TABLE users ADD COLUMN IF NOT EXISTS farming_profile TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS output_tonnage DOUBLE PRECISION;
ALTER TABLE users ADD COLUMN IF NOT EXISTS herd_count INTEGER;

-- ---------------------------------------------------------------------
-- Pruned Financial Profiles
--   current_loan_amount : exact currency — ongoing liabilities
--   sacco_member        : truth-value — active cooperative membership
-- ---------------------------------------------------------------------
ALTER TABLE users ADD COLUMN IF NOT EXISTS current_loan_amount DOUBLE PRECISION DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS sacco_member INTEGER DEFAULT 0;

-- Mirror the pruned financial profile + agri metrics onto customers too.
ALTER TABLE customers ADD COLUMN IF NOT EXISTS current_loan_amount DOUBLE PRECISION DEFAULT 0;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS sacco_member INTEGER DEFAULT 0;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS farming_profile TEXT;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS output_tonnage DOUBLE PRECISION;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS passport_selfie_url TEXT;

-- ---------------------------------------------------------------------
-- Granular Governance Controls
--   custom_role  : descriptive organizational role label
--   permissions  : JSON array of explicit capability permissions
--   supervisor_id: the user who supervises this user (set by Super Admin)
-- ---------------------------------------------------------------------
ALTER TABLE users ADD COLUMN IF NOT EXISTS custom_role TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS permissions TEXT;          -- JSON array
ALTER TABLE users ADD COLUMN IF NOT EXISTS supervisor_id INTEGER;     -- FK -> users(id)

-- ---------------------------------------------------------------------
-- Authentication Validation Space
--   reset_token        : temporary numerical reset validation token
--   reset_token_expires: exact timestamp (epoch ms) enforcing the window
-- ---------------------------------------------------------------------
ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expires BIGINT;

-- ---------------------------------------------------------------------
-- Advanced Inventory Parameters
--   payment_eligibility       : flag — cash | finance | both
--   finance_markup_pct        : independent percentage for financing markup
--   finance_deposit_pct       : independent minimum-deposit percentage
--   cash_terms / finance_terms: terms & conditions text (paste/upload/scan)
-- ---------------------------------------------------------------------
ALTER TABLE products ADD COLUMN IF NOT EXISTS payment_eligibility TEXT DEFAULT 'both';
ALTER TABLE products ADD COLUMN IF NOT EXISTS finance_markup_pct DOUBLE PRECISION DEFAULT 20;
ALTER TABLE products ADD COLUMN IF NOT EXISTS finance_deposit_pct DOUBLE PRECISION DEFAULT 20;
ALTER TABLE products ADD COLUMN IF NOT EXISTS cash_terms TEXT;
ALTER TABLE products ADD COLUMN IF NOT EXISTS finance_terms TEXT;

-- Backfill finance_markup_pct from legacy credit_markup_pct where present.
UPDATE products SET finance_markup_pct = credit_markup_pct
  WHERE finance_markup_pct IS NULL OR finance_markup_pct = 20;

-- ---------------------------------------------------------------------
-- Contract: record accepted terms snapshot + deposit at checkout.
-- ---------------------------------------------------------------------
ALTER TABLE murabaha_contracts ADD COLUMN IF NOT EXISTS accepted_terms TEXT;
ALTER TABLE murabaha_contracts ADD COLUMN IF NOT EXISTS terms_accepted INTEGER DEFAULT 0;
ALTER TABLE murabaha_contracts ADD COLUMN IF NOT EXISTS deposit_required DOUBLE PRECISION DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_users_supervisor ON users(supervisor_id);
