-- =====================================================================
-- BULK USER DATA UPLOAD & STANDARDIZATION (Task 3B)
-- An admin uploads a categorized file (Farmers / Agents / Partners). Each row
-- is parsed, mapped to the standard profile fields and normalized. Rows that
-- are missing required fields are flagged as 'exception' for the admin to fix
-- before the onboarding flow (temp password + verification) is dispatched.
-- =====================================================================

-- One row per uploaded file / batch.
CREATE TABLE IF NOT EXISTS import_batches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  -- 'farmers' | 'agents' | 'partners'
  category TEXT NOT NULL,
  filename TEXT,
  total_rows INTEGER NOT NULL DEFAULT 0,
  valid_rows INTEGER NOT NULL DEFAULT 0,
  exception_rows INTEGER NOT NULL DEFAULT 0,
  dispatched_rows INTEGER NOT NULL DEFAULT 0,
  -- 'parsing' | 'review' | 'dispatched' | 'completed'
  status TEXT NOT NULL DEFAULT 'review',
  created_by INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- One row per record in a batch (staging area before onboarding).
CREATE TABLE IF NOT EXISTS import_rows (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  batch_id INTEGER NOT NULL,
  row_number INTEGER,
  -- Standardized / normalized fields.
  full_name TEXT,
  phone TEXT,
  national_id TEXT,
  email TEXT,
  county TEXT,
  sub_county TEXT,
  ward TEXT,
  village TEXT,
  value_chain_type TEXT,
  value_chain TEXT,
  region TEXT,
  -- The original, un-normalized values (JSON) for audit / re-parse.
  raw TEXT,
  -- 'valid' | 'exception' | 'dispatched' | 'skipped'
  status TEXT NOT NULL DEFAULT 'valid',
  -- Comma-separated list of missing/invalid required fields.
  issues TEXT,
  -- Populated once onboarding creates the account.
  created_user_id INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_import_rows_batch ON import_rows (batch_id);
CREATE INDEX IF NOT EXISTS idx_import_rows_status ON import_rows (status);
