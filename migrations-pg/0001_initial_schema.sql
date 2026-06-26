-- =====================================================================
-- Farmsky - Sharia-Compliant Murabaha Lending Platform - Initial Schema
-- PostgreSQL dialect (translated from the SQLite/D1 schema)
-- =====================================================================

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  full_name TEXT NOT NULL,
  phone TEXT UNIQUE NOT NULL,
  email TEXT,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'customer',
  status TEXT NOT NULL DEFAULT 'active',
  region TEXT,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS agents (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  region TEXT,
  permissions TEXT,
  commission_rate DOUBLE PRECISION DEFAULT 0.02,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS customers (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  agent_id INTEGER REFERENCES users(id),
  full_name TEXT NOT NULL,
  national_id TEXT,
  date_of_birth TEXT,
  gender TEXT,
  mobile TEXT,
  alt_mobile TEXT,
  county TEXT,
  sub_county TEXT,
  ward TEXT,
  village TEXT,
  latitude DOUBLE PRECISION,
  longitude DOUBLE PRECISION,
  value_chain_type TEXT,
  value_chain TEXT,
  acreage DOUBLE PRECISION,
  herd_size INTEGER,
  farm_experience INTEGER,
  annual_production TEXT,
  mobile_money_usage TEXT,
  existing_loans TEXT,
  bank_account TEXT,
  sacco_membership TEXT,
  id_front_url TEXT,
  id_back_url TEXT,
  selfie_url TEXT,
  kyc_status TEXT DEFAULT 'pending',
  risk_band TEXT,
  credit_score INTEGER,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS suppliers (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  contact TEXT,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
  id SERIAL PRIMARY KEY,
  sku TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  category TEXT,
  supplier_id INTEGER REFERENCES suppliers(id),
  buying_price DOUBLE PRECISION NOT NULL,
  cash_markup_pct DOUBLE PRECISION DEFAULT 10,
  credit_markup_pct DOUBLE PRECISION DEFAULT 20,
  cash_price DOUBLE PRECISION NOT NULL,
  credit_price DOUBLE PRECISION NOT NULL,
  quantity INTEGER DEFAULT 0,
  unit TEXT DEFAULT 'unit',
  reorder_threshold INTEGER DEFAULT 10,
  image TEXT,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS stock_movements (
  id SERIAL PRIMARY KEY,
  product_id INTEGER NOT NULL REFERENCES products(id),
  movement_type TEXT NOT NULL,
  quantity INTEGER NOT NULL,
  reference TEXT,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS murabaha_contracts (
  id SERIAL PRIMARY KEY,
  contract_ref TEXT UNIQUE NOT NULL,
  customer_id INTEGER NOT NULL REFERENCES customers(id),
  agent_id INTEGER,
  product_id INTEGER NOT NULL REFERENCES products(id),
  quantity INTEGER NOT NULL,
  payment_type TEXT NOT NULL,
  supplier_cost DOUBLE PRECISION NOT NULL,
  markup_pct DOUBLE PRECISION NOT NULL,
  murabaha_price DOUBLE PRECISION NOT NULL,
  term_months INTEGER DEFAULT 0,
  monthly_payment DOUBLE PRECISION DEFAULT 0,
  delivery_location TEXT,
  status TEXT DEFAULT 'pending',
  ownership_recorded INTEGER DEFAULT 0,
  consent_given INTEGER DEFAULT 0,
  amount_paid DOUBLE PRECISION DEFAULT 0,
  outstanding DOUBLE PRECISION DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS repayments (
  id SERIAL PRIMARY KEY,
  contract_id INTEGER NOT NULL REFERENCES murabaha_contracts(id),
  installment_no INTEGER NOT NULL,
  due_date TEXT NOT NULL,
  amount_due DOUBLE PRECISION NOT NULL,
  amount_paid DOUBLE PRECISION DEFAULT 0,
  status TEXT DEFAULT 'current',
  paid_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS invoices (
  id SERIAL PRIMARY KEY,
  invoice_ref TEXT UNIQUE NOT NULL,
  contract_id INTEGER,
  customer_id INTEGER NOT NULL,
  amount DOUBLE PRECISION NOT NULL,
  status TEXT DEFAULT 'unpaid',
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transactions (
  id SERIAL PRIMARY KEY,
  txn_ref TEXT UNIQUE NOT NULL,
  contract_id INTEGER,
  customer_id INTEGER,
  amount DOUBLE PRECISION NOT NULL,
  method TEXT,
  type TEXT,
  mpesa_receipt TEXT,
  status TEXT DEFAULT 'success',
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS approvals (
  id SERIAL PRIMARY KEY,
  contract_id INTEGER NOT NULL,
  reviewer_id INTEGER,
  action TEXT,
  notes TEXT,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transunion_checks (
  id SERIAL PRIMARY KEY,
  customer_id INTEGER NOT NULL,
  credit_score INTEGER,
  risk_band TEXT,
  defaults_found INTEGER DEFAULT 0,
  raw_response TEXT,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS id_verifications (
  id SERIAL PRIMARY KEY,
  customer_id INTEGER NOT NULL,
  face_match INTEGER DEFAULT 0,
  liveness INTEGER DEFAULT 0,
  ocr_name TEXT,
  ocr_dob TEXT,
  ocr_id_number TEXT,
  status TEXT DEFAULT 'pending',
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id SERIAL PRIMARY KEY,
  user_id INTEGER,
  action TEXT,
  entity TEXT,
  detail TEXT,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tickets (
  id SERIAL PRIMARY KEY,
  customer_id INTEGER,
  subject TEXT,
  message TEXT,
  status TEXT DEFAULT 'open',
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);
CREATE INDEX IF NOT EXISTS idx_customers_agent ON customers(agent_id);
CREATE INDEX IF NOT EXISTS idx_contracts_customer ON murabaha_contracts(customer_id);
CREATE INDEX IF NOT EXISTS idx_repayments_contract ON repayments(contract_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
