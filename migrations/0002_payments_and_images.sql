-- Payment gateway tracking fields on transactions
ALTER TABLE transactions ADD COLUMN checkout_request_id TEXT;
ALTER TABLE transactions ADD COLUMN merchant_request_id TEXT;
ALTER TABLE transactions ADD COLUMN phone TEXT;
ALTER TABLE transactions ADD COLUMN gateway TEXT DEFAULT 'mpesa_daraja';
ALTER TABLE transactions ADD COLUMN result_desc TEXT;

CREATE TABLE IF NOT EXISTS payment_intents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  checkout_request_id TEXT UNIQUE,
  merchant_request_id TEXT,
  contract_id INTEGER,
  customer_id INTEGER,
  amount REAL NOT NULL,
  phone TEXT,
  method TEXT DEFAULT 'mpesa',
  status TEXT DEFAULT 'pending',
  mpesa_receipt TEXT,
  result_desc TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_intents_checkout ON payment_intents(checkout_request_id);
