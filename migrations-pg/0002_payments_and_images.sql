-- Payment gateway tracking fields on transactions (PostgreSQL)
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS checkout_request_id TEXT;
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS merchant_request_id TEXT;
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS phone TEXT;
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS gateway TEXT DEFAULT 'mpesa_daraja';
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS result_desc TEXT;

CREATE TABLE IF NOT EXISTS payment_intents (
  id SERIAL PRIMARY KEY,
  checkout_request_id TEXT UNIQUE,
  merchant_request_id TEXT,
  contract_id INTEGER,
  customer_id INTEGER,
  amount DOUBLE PRECISION NOT NULL,
  phone TEXT,
  method TEXT DEFAULT 'mpesa',
  status TEXT DEFAULT 'pending',
  mpesa_receipt TEXT,
  result_desc TEXT,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_intents_checkout ON payment_intents(checkout_request_id);
