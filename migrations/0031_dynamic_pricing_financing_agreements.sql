-- ============================================================================
-- 0031 — Dynamic Pricing & Markup, Dynamic Financing Types, Agreement Engine
-- ============================================================================
-- Feed tenant port of the Equipment app's 0033 migration. Feed is a
-- Sharia-compliant, cash + Murabaha-only client of the central gateway, so the
-- seeded financing types / agreement templates are scoped accordingly.
-- Adds the schema needed for:
--   1. Dynamic pricing modes for BOTH cash and financed selling prices
--      (percentage markup / fixed-amount markup / manual overwrite).
--   2. Flexible tenure parameters (monthly / yearly / custom cycle).
--   3. A dynamic, admin-managed catalogue of financing types.
--   4. A templating engine for per-financing-type sale agreements.
--   5. Deprecation of the TransUnion product code (column kept nullable).
-- Idempotent: safe to run repeatedly (db-init applies it on every boot).
-- ----------------------------------------------------------------------------

-- 1. Pricing-mode columns on products ---------------------------------------
ALTER TABLE products ADD COLUMN IF NOT EXISTS cash_price_mode TEXT DEFAULT 'percentage';
ALTER TABLE products ADD COLUMN IF NOT EXISTS cash_markup_amount REAL DEFAULT 0;
ALTER TABLE products ADD COLUMN IF NOT EXISTS credit_price_mode TEXT DEFAULT 'percentage';
ALTER TABLE products ADD COLUMN IF NOT EXISTS credit_markup_amount REAL DEFAULT 0;

-- 2. Flexible tenure parameters ---------------------------------------------
ALTER TABLE products ADD COLUMN IF NOT EXISTS financing_tenure_unit TEXT DEFAULT 'monthly';
ALTER TABLE products ADD COLUMN IF NOT EXISTS financing_rate_per_cycle REAL DEFAULT 0;
ALTER TABLE products ADD COLUMN IF NOT EXISTS financing_amount_per_cycle REAL DEFAULT 0;
ALTER TABLE products ADD COLUMN IF NOT EXISTS financing_cycle_count INTEGER DEFAULT 0;
ALTER TABLE products ADD COLUMN IF NOT EXISTS financing_cycle_length_days INTEGER DEFAULT 30;

-- financing_type_key links a product to a row in financing_types (dynamic).
ALTER TABLE products ADD COLUMN IF NOT EXISTS financing_type_key TEXT;

-- 3. Dynamic financing-type catalogue ---------------------------------------
CREATE TABLE IF NOT EXISTS financing_types (
  id           SERIAL PRIMARY KEY,
  type_key     TEXT UNIQUE NOT NULL,
  label        TEXT NOT NULL,
  description  TEXT,
  charge_mode  TEXT DEFAULT 'percentage',
  is_system    INTEGER DEFAULT 0,
  active       INTEGER DEFAULT 1,
  sort_order   INTEGER DEFAULT 100,
  created_by   TEXT,
  created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- FEED policy: financing is offered ONLY as Sharia-compliant Murabaha.
-- Murabaha is seeded active. loan_interest / paygo are seeded INACTIVE purely
-- for schema compatibility with the shared codebase; they are not offered.
INSERT INTO financing_types (type_key, label, description, charge_mode, is_system, active, sort_order)
VALUES
  ('murabaha',      'Murabaha',                  'Sharia-compliant cost-plus-markup financing (no interest, no penalties).', 'percentage', 1, 1, 10),
  ('loan_interest', 'Financing (with interest)', 'Standard installment financing (not offered on Feed).',                    'percentage', 1, 0, 20),
  ('paygo',         'PAYGO',                     'Pay-as-you-go financing (not offered on Feed).',                           'percentage', 1, 0, 30)
ON CONFLICT (type_key) DO NOTHING;

-- 4. Agreement templates ----------------------------------------------------
CREATE TABLE IF NOT EXISTS agreement_templates (
  id             SERIAL PRIMARY KEY,
  path_key       TEXT UNIQUE NOT NULL,
  title          TEXT NOT NULL,
  overview_html  TEXT,
  body_html      TEXT,
  style_json     TEXT,
  updated_by     TEXT,
  created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO agreement_templates (path_key, title, overview_html, body_html)
VALUES
  ('cash', 'CASH SALE AGREEMENT',
   '<p>This Cash Sale Agreement is made between Farmsky Feed and the purchasing farmer for the outright cash purchase of the goods described below.</p>',
   '<p>The buyer agrees to pay the disclosed cash price in full. Ownership of the goods transfers to the buyer upon receipt of full payment. All sales are subject to Farmsky''s standard terms of service.</p>'),
  ('murabaha', 'MURABAHA SALE AGREEMENT',
   '<p>This Murabaha Sale Agreement is a Sharia-compliant cost-plus-markup sale between Farmsky Feed and the purchasing farmer.</p>',
   '<p>Farmsky discloses the cost price and the agreed profit (markup). The buyer repays the total in equal installments over the agreed term with no interest (riba), no penalties, and no compounding. Ownership transfers per the executed Murabaha agreement.</p>')
ON CONFLICT (path_key) DO NOTHING;
