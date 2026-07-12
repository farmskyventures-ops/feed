-- =====================================================================
-- Farmsky - Sharia-Compliant Murabaha Lending Platform - Initial Schema
-- =====================================================================

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT NOT NULL,
  phone TEXT UNIQUE NOT NULL,
  email TEXT,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'customer',
  status TEXT NOT NULL DEFAULT 'active',
  region TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS agents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  region TEXT,
  permissions TEXT,
  commission_rate REAL DEFAULT 0.02,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  agent_id INTEGER,
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
  latitude REAL,
  longitude REAL,
  value_chain_type TEXT,
  value_chain TEXT,
  acreage REAL,
  herd_size INTEGER,
  farm_experience INTEGER,
  annual_production TEXT,
  existing_loans TEXT,
  sacco_membership TEXT,
  id_front_url TEXT,
  id_back_url TEXT,
  selfie_url TEXT,
  kyc_status TEXT DEFAULT 'pending',
  risk_band TEXT,
  credit_score INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (agent_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS suppliers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  contact TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sku TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  category TEXT,
  supplier_id INTEGER,
  buying_price REAL NOT NULL,
  cash_markup_pct REAL DEFAULT 10,
  credit_markup_pct REAL DEFAULT 20,
  cash_price REAL NOT NULL,
  credit_price REAL NOT NULL,
  quantity INTEGER DEFAULT 0,
  unit TEXT DEFAULT 'unit',
  reorder_threshold INTEGER DEFAULT 10,
  image TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (supplier_id) REFERENCES suppliers(id)
);

CREATE TABLE IF NOT EXISTS stock_movements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id INTEGER NOT NULL,
  movement_type TEXT NOT NULL,
  quantity INTEGER NOT NULL,
  reference TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (product_id) REFERENCES products(id)
);

CREATE TABLE IF NOT EXISTS murabaha_contracts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  contract_ref TEXT UNIQUE NOT NULL,
  customer_id INTEGER NOT NULL,
  agent_id INTEGER,
  product_id INTEGER NOT NULL,
  quantity INTEGER NOT NULL,
  payment_type TEXT NOT NULL,
  supplier_cost REAL NOT NULL,
  markup_pct REAL NOT NULL,
  murabaha_price REAL NOT NULL,
  term_months INTEGER DEFAULT 0,
  monthly_payment REAL DEFAULT 0,
  delivery_location TEXT,
  status TEXT DEFAULT 'pending',
  ownership_recorded INTEGER DEFAULT 0,
  consent_given INTEGER DEFAULT 0,
  amount_paid REAL DEFAULT 0,
  outstanding REAL DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (customer_id) REFERENCES customers(id),
  FOREIGN KEY (product_id) REFERENCES products(id)
);

CREATE TABLE IF NOT EXISTS repayments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  contract_id INTEGER NOT NULL,
  installment_no INTEGER NOT NULL,
  due_date TEXT NOT NULL,
  amount_due REAL NOT NULL,
  amount_paid REAL DEFAULT 0,
  status TEXT DEFAULT 'current',
  paid_at DATETIME,
  FOREIGN KEY (contract_id) REFERENCES murabaha_contracts(id)
);

CREATE TABLE IF NOT EXISTS invoices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  invoice_ref TEXT UNIQUE NOT NULL,
  contract_id INTEGER,
  customer_id INTEGER NOT NULL,
  amount REAL NOT NULL,
  status TEXT DEFAULT 'unpaid',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  txn_ref TEXT UNIQUE NOT NULL,
  contract_id INTEGER,
  customer_id INTEGER,
  amount REAL NOT NULL,
  method TEXT,
  type TEXT,
  mpesa_receipt TEXT,
  status TEXT DEFAULT 'success',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS approvals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  contract_id INTEGER NOT NULL,
  reviewer_id INTEGER,
  action TEXT,
  notes TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transunion_checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER NOT NULL,
  credit_score INTEGER,
  risk_band TEXT,
  defaults_found INTEGER DEFAULT 0,
  raw_response TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS id_verifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER NOT NULL,
  face_match INTEGER DEFAULT 0,
  liveness INTEGER DEFAULT 0,
  ocr_name TEXT,
  ocr_dob TEXT,
  ocr_id_number TEXT,
  status TEXT DEFAULT 'pending',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT,
  entity TEXT,
  detail TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tickets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER,
  subject TEXT,
  message TEXT,
  status TEXT DEFAULT 'open',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);
CREATE INDEX IF NOT EXISTS idx_customers_agent ON customers(agent_id);
CREATE INDEX IF NOT EXISTS idx_contracts_customer ON murabaha_contracts(customer_id);
CREATE INDEX IF NOT EXISTS idx_repayments_contract ON repayments(contract_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
