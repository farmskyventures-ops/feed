-- =====================================================================
-- Central payment gateway tables (shared by equipment / feed / input)
-- =====================================================================

-- 1. Registered client apps (one row per marketplace)
CREATE TABLE IF NOT EXISTS app_clients (
  id BIGSERIAL PRIMARY KEY,
  client_key TEXT NOT NULL UNIQUE,             -- e.g. 'equipment', 'feed', 'input'
  display_name TEXT NOT NULL,
  origin_url TEXT NOT NULL,                    -- e.g. 'https://equipment.farmsky.africa'
  hmac_secret TEXT NOT NULL,                   -- shared secret for HMAC-SHA256 signing
  callback_url TEXT,                           -- optional URL to notify on payment completion
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Seed the three marketplaces (admin can rotate the secrets later)
INSERT INTO app_clients (client_key, display_name, origin_url, hmac_secret, is_active) VALUES
  ('equipment', 'Farmsky Equipment',  'https://equipment.farmsky.africa', 'REPLACE_WITH_EQUIPMENT_SECRET', 1),
  ('feed',      'Farmsky Feed',       'https://feed.farmsky.africa',      'REPLACE_WITH_FEED_SECRET',      1),
  ('input',     'Farmsky Inputs',     'https://input.farmsky.africa',     'REPLACE_WITH_INPUT_SECRET',     1)
ON CONFLICT (client_key) DO NOTHING;

-- 2. Central transaction ledger (one row per payment attempt, across ALL apps + methods)
CREATE TABLE IF NOT EXISTS central_transactions (
  id BIGSERIAL PRIMARY KEY,
  transaction_ref TEXT NOT NULL UNIQUE,        -- internal UUID we generate; returned to the calling app
  idempotency_key TEXT,                        -- (client_key, idempotency_key) is unique below
  origin_app TEXT NOT NULL,                    -- 'equipment' | 'feed' | 'input'
  origin_reference TEXT,                       -- the calling app's own order/contract ID
  payment_method TEXT NOT NULL,                -- 'mpesa' | 'sasapay' | 'buni'
  provider_request_id TEXT,                    -- CheckoutRequestID / MerchantRequestID from provider
  provider_receipt TEXT,                       -- M-Pesa code / SasaPay txn ID / Buni receipt
  phone TEXT NOT NULL,
  amount NUMERIC(14,2) NOT NULL,
  currency TEXT NOT NULL DEFAULT 'KES',
  description TEXT,
  status TEXT NOT NULL DEFAULT 'PENDING',      -- PENDING | SUCCESS | FAILED | EXPIRED
  result_code TEXT,
  result_desc TEXT,
  initiated_by_user INTEGER,                   -- nullable; user id on the calling app if provided
  ip_address TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  completed_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_central_tx_origin       ON central_transactions(origin_app);
CREATE INDEX IF NOT EXISTS idx_central_tx_method       ON central_transactions(payment_method);
CREATE INDEX IF NOT EXISTS idx_central_tx_status       ON central_transactions(status);
CREATE INDEX IF NOT EXISTS idx_central_tx_provider_req ON central_transactions(provider_request_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_central_tx_idem  ON central_transactions(origin_app, idempotency_key) WHERE idempotency_key IS NOT NULL;

-- 3. Raw callback log (every IPN we receive, signed or not, for audit + replay protection)
CREATE TABLE IF NOT EXISTS central_callbacks (
  id BIGSERIAL PRIMARY KEY,
  transaction_ref TEXT,
  payment_method TEXT NOT NULL,
  provider_request_id TEXT,
  raw_payload TEXT NOT NULL,
  signature_valid INTEGER,
  received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_central_cb_txref ON central_callbacks(transaction_ref);
