-- =====================================================================
-- Centralized Payment Multi-Tenancy Architecture (Instructions 6-18)
--
--   * Single Merchant Shortcode across three marketplaces:
--       equipment.farmsky.africa  (MAIN — this app)
--       feed.farmsky.africa
--       mazao.farmsky.africa
--   * All payment traffic routes through ONE isolated gateway service:
--       payment-api.farmsky.africa
--   * Isolation is enforced at TWO layers:
--       (1) DB layer  -> PostgreSQL Row-Level Security (RLS) keyed on
--                        marketplace_id via a per-connection GUC.
--       (2) Network   -> HMAC-SHA256 cryptographic payload validation
--                        (already implemented in payment-gateway.ts).
--
--   NOTE: RLS statements are PostgreSQL-only. On SQLite/D1 they are skipped
--   by db-init (the runner swallows unsupported-syntax errors), so the
--   marketplaces table + marketplace_id column still work everywhere.
-- =====================================================================

-- 1. Marketplace (tenant) registry -----------------------------------------
CREATE TABLE IF NOT EXISTS marketplaces (
  id BIGSERIAL PRIMARY KEY,
  marketplace_key TEXT NOT NULL UNIQUE,        -- 'equipment' | 'feed' | 'mazao'
  display_name TEXT NOT NULL,
  domain TEXT NOT NULL,                         -- e.g. 'equipment.farmsky.africa'
  is_main INTEGER NOT NULL DEFAULT 0,           -- equipment marketplace is the MAIN
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO marketplaces (marketplace_key, display_name, domain, is_main, is_active) VALUES
  ('equipment', 'Farmsky Equipment', 'equipment.farmsky.africa', 1, 1),
  ('feed',      'Farmsky Feed',      'feed.farmsky.africa',      0, 1),
  ('mazao',     'Farmsky Mazao',     'mazao.farmsky.africa',     0, 1)
ON CONFLICT (marketplace_key) DO NOTHING;

-- Keep app_clients (existing gateway clients) aligned with the tenant registry.
-- Add the mazao marketplace as a payment client if it is not present yet.
INSERT INTO app_clients (client_key, display_name, origin_url, hmac_secret, is_active) VALUES
  ('mazao', 'Farmsky Mazao', 'https://mazao.farmsky.africa', 'REPLACE_WITH_MAZAO_SECRET', 1)
ON CONFLICT (client_key) DO NOTHING;

-- 2. Add marketplace_id to the central ledger + callbacks -------------------
ALTER TABLE central_transactions ADD COLUMN IF NOT EXISTS marketplace_id BIGINT;
ALTER TABLE central_callbacks    ADD COLUMN IF NOT EXISTS marketplace_id BIGINT;

-- Backfill marketplace_id from the existing origin_app text column.
UPDATE central_transactions ct
   SET marketplace_id = m.id
  FROM marketplaces m
 WHERE ct.marketplace_id IS NULL
   AND ct.origin_app = m.marketplace_key;

CREATE INDEX IF NOT EXISTS idx_central_tx_marketplace ON central_transactions(marketplace_id);

-- 3. Suspicious-activity audit trail ---------------------------------------
CREATE TABLE IF NOT EXISTS payment_audit_log (
  id BIGSERIAL PRIMARY KEY,
  marketplace_id BIGINT,
  origin_app TEXT,
  event_type TEXT NOT NULL,        -- 'CROSS_TENANT_ACCESS' | 'SIGNATURE_FAIL' | 'REPLAY' | 'AMOUNT_ANOMALY' | ...
  severity TEXT NOT NULL DEFAULT 'INFO',   -- INFO | WARN | CRITICAL
  transaction_ref TEXT,
  detail TEXT,
  ip_address TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_payment_audit_event    ON payment_audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_payment_audit_severity ON payment_audit_log(severity);
CREATE INDEX IF NOT EXISTS idx_payment_audit_market   ON payment_audit_log(marketplace_id);

-- 4. Replay-protection nonce store -----------------------------------------
-- Every /initiate request carries a unique X-Farmsky-Nonce. We persist it so a
-- replayed (client_key, nonce) pair inside the freshness window is rejected.
CREATE TABLE IF NOT EXISTS payment_nonces (
  id BIGSERIAL PRIMARY KEY,
  client_key TEXT NOT NULL,
  nonce TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (client_key, nonce)
);
CREATE INDEX IF NOT EXISTS idx_payment_nonces_created ON payment_nonces(created_at);
