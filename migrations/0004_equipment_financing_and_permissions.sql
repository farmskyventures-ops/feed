-- =====================================================================
-- Equipment financing, role permissions, dispatching, and integration hooks
-- =====================================================================

ALTER TABLE users ADD COLUMN label TEXT;
ALTER TABLE users ADD COLUMN permissions TEXT;

ALTER TABLE products ADD COLUMN description TEXT;
ALTER TABLE products ADD COLUMN product_type TEXT DEFAULT 'equipment';
ALTER TABLE products ADD COLUMN cash_enabled INTEGER DEFAULT 1;
ALTER TABLE products ADD COLUMN financing_enabled INTEGER DEFAULT 1;
ALTER TABLE products ADD COLUMN payment_option_mode TEXT DEFAULT 'both';
ALTER TABLE products ADD COLUMN financing_model TEXT DEFAULT 'loan_interest';
ALTER TABLE products ADD COLUMN financing_interest_pct REAL DEFAULT 0;
ALTER TABLE products ADD COLUMN financing_frequency TEXT DEFAULT 'monthly';
ALTER TABLE products ADD COLUMN financing_term_min_months INTEGER DEFAULT 3;
ALTER TABLE products ADD COLUMN financing_term_max_months INTEGER DEFAULT 12;
ALTER TABLE products ADD COLUMN cash_deposit_pct REAL DEFAULT 100;
ALTER TABLE products ADD COLUMN financing_deposit_pct REAL DEFAULT 10;
ALTER TABLE products ADD COLUMN cash_terms_text TEXT;
ALTER TABLE products ADD COLUMN financing_terms_text TEXT;
ALTER TABLE products ADD COLUMN cash_terms_doc_url TEXT;
ALTER TABLE products ADD COLUMN financing_terms_doc_url TEXT;
ALTER TABLE products ADD COLUMN transunion_product_code TEXT;

ALTER TABLE murabaha_contracts ADD COLUMN financing_model TEXT;
ALTER TABLE murabaha_contracts ADD COLUMN interest_rate_pct REAL DEFAULT 0;
ALTER TABLE murabaha_contracts ADD COLUMN deposit_pct REAL DEFAULT 0;
ALTER TABLE murabaha_contracts ADD COLUMN deposit_amount REAL DEFAULT 0;
ALTER TABLE murabaha_contracts ADD COLUMN finance_principal REAL DEFAULT 0;
ALTER TABLE murabaha_contracts ADD COLUMN payment_frequency TEXT DEFAULT 'monthly';
ALTER TABLE murabaha_contracts ADD COLUMN installment_amount REAL DEFAULT 0;
ALTER TABLE murabaha_contracts ADD COLUMN dispatch_status TEXT DEFAULT 'pending';
ALTER TABLE murabaha_contracts ADD COLUMN dispatched_at DATETIME;
ALTER TABLE murabaha_contracts ADD COLUMN dispatched_by INTEGER;
ALTER TABLE murabaha_contracts ADD COLUMN terms_document_url TEXT;
ALTER TABLE murabaha_contracts ADD COLUMN terms_text TEXT;

ALTER TABLE transunion_checks ADD COLUMN provider_reference TEXT;
ALTER TABLE transunion_checks ADD COLUMN integration_status TEXT DEFAULT 'stubbed';

CREATE TABLE IF NOT EXISTS change_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  requester_id INTEGER NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id INTEGER,
  requested_action TEXT NOT NULL,
  reason TEXT,
  status TEXT DEFAULT 'open',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (requester_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_change_requests_requester ON change_requests(requester_id);
CREATE INDEX IF NOT EXISTS idx_contracts_dispatch_status ON murabaha_contracts(dispatch_status);
