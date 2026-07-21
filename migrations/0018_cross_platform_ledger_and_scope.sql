-- =====================================================================
-- 0018 — Cross-platform payment ledger + data-scope columns
--
-- Implements the shared schema for the Equipment <-> Feed unified
-- architecture:
--   Phase 2  - central_transactions & transactions gain inventory_type
--              ('equipment' | 'feed') and origin_platform
--              ('equipment_app' | 'feed_app') so the Equipment admin
--              dashboard can act as ONE ledger filterable by category
--              + origin.
--   Phase 5  - shared tables (products, transactions) gain app_scope
--              ('equipment' | 'feed' | 'both') so a single database can
--              serve both apps with backend + RLS filtering by APP_TYPE.
--
-- This migration is written in the project's SQLite dialect and is
-- transformed to PostgreSQL by backend/db-init.ts. It is idempotent:
-- ALTER ... ADD COLUMN duplicates (42701) are swallowed by db-init.
-- =====================================================================

-- ---- Phase 2: cross-platform metadata on the central ledger ----------
ALTER TABLE central_transactions ADD COLUMN inventory_type TEXT;      -- 'equipment' | 'feed'
ALTER TABLE central_transactions ADD COLUMN origin_platform TEXT;     -- 'equipment_app' | 'feed_app'

-- Backfill origin_platform from the existing origin_app value so old rows
-- are categorised in the unified ledger.
UPDATE central_transactions
   SET origin_platform = CASE
         WHEN origin_app = 'equipment' THEN 'equipment_app'
         WHEN origin_app = 'feed'      THEN 'feed_app'
         ELSE origin_platform END
 WHERE origin_platform IS NULL;

UPDATE central_transactions
   SET inventory_type = origin_app
 WHERE inventory_type IS NULL AND origin_app IN ('equipment', 'feed');

CREATE INDEX IF NOT EXISTS idx_central_tx_inv_type  ON central_transactions(inventory_type);
CREATE INDEX IF NOT EXISTS idx_central_tx_origin_pf ON central_transactions(origin_platform);

-- ---- Phase 2: same metadata on the local transactions mirror ---------
ALTER TABLE transactions ADD COLUMN inventory_type TEXT;
ALTER TABLE transactions ADD COLUMN origin_platform TEXT;

-- ---- Phase 5: data-isolation scope on shared catalog tables ----------
-- app_scope controls which app(s) a catalog row belongs to.
--   'equipment' -> visible only to the Equipment app
--   'feed'      -> visible only to the Feed app
--   'both'      -> visible to both
ALTER TABLE products ADD COLUMN app_scope TEXT NOT NULL DEFAULT 'both';
CREATE INDEX IF NOT EXISTS idx_products_app_scope ON products(app_scope);

-- transactions also carries app_scope for the unified ledger filtering.
ALTER TABLE transactions ADD COLUMN app_scope TEXT NOT NULL DEFAULT 'both';
CREATE INDEX IF NOT EXISTS idx_transactions_app_scope ON transactions(app_scope);

-- ---- Merchant API: public merchant keys (Phase 3) --------------------
-- Third-party merchants embed a Farmsky checkout button. Each merchant
-- gets a public key + secret used to HMAC-sign the standardized payload.
CREATE TABLE IF NOT EXISTS merchant_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  merchant_key TEXT NOT NULL UNIQUE,          -- public identifier (e.g. 'mk_live_xxx')
  merchant_secret TEXT NOT NULL,              -- HMAC-SHA256 shared secret
  display_name TEXT NOT NULL,
  contact_email TEXT,
  app_scope TEXT NOT NULL DEFAULT 'both',     -- which catalog this merchant may touch
  is_active INTEGER NOT NULL DEFAULT 1,
  created_by INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_merchant_keys_active ON merchant_keys(is_active);

-- Merchant-originated checkout sessions (public API entry point).
CREATE TABLE IF NOT EXISTS merchant_checkouts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  checkout_ref TEXT NOT NULL UNIQUE,
  merchant_key TEXT NOT NULL,
  inventory_type TEXT NOT NULL,               -- 'equipment' | 'feed'
  transaction_type TEXT NOT NULL,             -- 'DIRECT_PURCHASE' | 'FINANCING_REQUEST'
  item_id TEXT,
  item_title TEXT,
  amount REAL NOT NULL,
  category TEXT,
  financing_tenor_months INTEGER DEFAULT 0,
  customer_full_name TEXT,
  customer_phone TEXT,
  customer_national_id TEXT,
  success_callback_url TEXT,
  failure_callback_url TEXT,
  status TEXT NOT NULL DEFAULT 'CREATED',      -- CREATED | REDIRECTED | PAID | FAILED
  transaction_ref TEXT,                        -- links to central_transactions once paid
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_merchant_checkouts_key    ON merchant_checkouts(merchant_key);
CREATE INDEX IF NOT EXISTS idx_merchant_checkouts_status ON merchant_checkouts(status);

-- ---- Phase 4: standardized auth secret metadata (informational) ------
-- The concrete pepper / salt-rounds / key length live in env vars and are
-- read identically by backend/password.ts in BOTH apps. No column needed;
-- this comment documents the contract.
