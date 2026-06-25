-- =====================================================================
-- 0004 — Security, profile & inventory workflow expansion
-- Expands the central data models to support:
--   * Identity document cryptography & asset storage (KYC images)
--   * Dynamic agricultural metrics
--   * Pruned financial profiles
--   * Granular governance controls (custom roles, permissions, supervisor)
--   * Authentication validation space (numeric reset tokens + expiry)
--   * Advanced inventory parameters (payment eligibility + markups + terms)
-- All ALTERs are additive; db-init ignores "duplicate column" on re-run.
-- =====================================================================

-- ---------------------------------------------------------------------
-- Identity Document Cryptography & Asset Storage
-- Secure path / textual data references for three validation images.
-- (id_front_url / id_back_url / selfie_url already exist on customers;
--  we also mirror them onto users so self-service profiles can store them.)
-- ---------------------------------------------------------------------
ALTER TABLE users ADD COLUMN id_front_url TEXT;
ALTER TABLE users ADD COLUMN id_back_url TEXT;
ALTER TABLE users ADD COLUMN passport_selfie_url TEXT;

-- ---------------------------------------------------------------------
-- Dynamic Agricultural Metrics (on users so self-service can edit them)
--   farming_profile : primary tracking profile selection (crop|livestock)
--   output_tonnage  : number — recorded output tonnage (avg yield)
--   herd_count      : integer — animal quantity counter
-- ---------------------------------------------------------------------
ALTER TABLE users ADD COLUMN farming_profile TEXT;
ALTER TABLE users ADD COLUMN output_tonnage REAL;
ALTER TABLE users ADD COLUMN herd_count INTEGER;

-- ---------------------------------------------------------------------
-- Pruned Financial Profiles
--   current_loan_amount : exact currency — ongoing liabilities
--   sacco_member        : truth-value — active cooperative membership
-- (legacy text credit metrics on customers are decommissioned in favour
--  of these two clean fields)
-- ---------------------------------------------------------------------
ALTER TABLE users ADD COLUMN current_loan_amount REAL DEFAULT 0;
ALTER TABLE users ADD COLUMN sacco_member INTEGER DEFAULT 0;

-- Mirror the pruned financial profile + agri metrics onto customers too.
ALTER TABLE customers ADD COLUMN current_loan_amount REAL DEFAULT 0;
ALTER TABLE customers ADD COLUMN sacco_member INTEGER DEFAULT 0;
ALTER TABLE customers ADD COLUMN farming_profile TEXT;
ALTER TABLE customers ADD COLUMN output_tonnage REAL;
ALTER TABLE customers ADD COLUMN passport_selfie_url TEXT;

-- ---------------------------------------------------------------------
-- Granular Governance Controls
--   custom_role  : descriptive organizational role label
--   permissions  : JSON array of explicit capability permissions
--   supervisor_id: the user who supervises this user (set by Super Admin)
-- ---------------------------------------------------------------------
ALTER TABLE users ADD COLUMN custom_role TEXT;
ALTER TABLE users ADD COLUMN permissions TEXT;          -- JSON array
ALTER TABLE users ADD COLUMN supervisor_id INTEGER;     -- FK -> users(id)

-- ---------------------------------------------------------------------
-- Authentication Validation Space
--   reset_token        : temporary numerical reset validation token
--   reset_token_expires: exact timestamp (epoch ms) enforcing the window
-- ---------------------------------------------------------------------
ALTER TABLE users ADD COLUMN reset_token TEXT;
ALTER TABLE users ADD COLUMN reset_token_expires INTEGER;

-- ---------------------------------------------------------------------
-- Advanced Inventory Parameters
--   payment_eligibility       : flag — cash | finance | both
--   cash_markup_pct           : (exists) standard cash markup percentage
--   finance_markup_pct        : independent percentage for financing markup
--   finance_deposit_pct       : independent markup/initial collection %
--                               (minimum deposit a buyer must pay)
--   cash_terms / finance_terms: terms & conditions text (paste/upload/scan)
-- ---------------------------------------------------------------------
ALTER TABLE products ADD COLUMN payment_eligibility TEXT DEFAULT 'both';
ALTER TABLE products ADD COLUMN finance_markup_pct REAL DEFAULT 20;
ALTER TABLE products ADD COLUMN finance_deposit_pct REAL DEFAULT 20;
ALTER TABLE products ADD COLUMN cash_terms TEXT;
ALTER TABLE products ADD COLUMN finance_terms TEXT;

-- Backfill finance_markup_pct from legacy credit_markup_pct where present.
UPDATE products SET finance_markup_pct = credit_markup_pct
  WHERE finance_markup_pct IS NULL OR finance_markup_pct = 20;

-- ---------------------------------------------------------------------
-- Contract: record accepted terms snapshot + deposit at checkout.
-- ---------------------------------------------------------------------
ALTER TABLE murabaha_contracts ADD COLUMN accepted_terms TEXT;
ALTER TABLE murabaha_contracts ADD COLUMN terms_accepted INTEGER DEFAULT 0;
ALTER TABLE murabaha_contracts ADD COLUMN deposit_required REAL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_users_supervisor ON users(supervisor_id);
