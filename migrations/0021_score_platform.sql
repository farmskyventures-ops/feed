-- =====================================================================
-- 0021 — score.farmsky.africa platform integration
--
--   Farmsky Score (score.farmsky.africa) is the identity + credit
--   evaluation platform. This migration gives Equipment (the central
--   database host) DEDICATED tables to hold Score's data so it lives in
--   its own namespace rather than being co-mingled with Equipment's own
--   customer/KYC tables.
--
--   What it adds:
--     1. A 'score' row in app_clients so Equipment's central payment
--        gateway will accept and process SUBSCRIPTION payments that
--        originate from score.farmsky.africa (HMAC-signed like the other
--        marketplaces).
--     2. score_subscriptions        — subscription plans / billing state
--                                       pushed from Score.
--     3. score_verifications         — ID verification + liveness results
--                                       retrieved from Score's APIs.
--     4. score_iprs_checks           — IPRS government-registry lookups.
--     5. score_credit_evaluations    — full credit-evaluation decisions.
--
--   Written in the project's SQLite dialect and transformed to
--   PostgreSQL by backend/db-init.ts. Idempotent + safe to re-run.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. Register Score as a central-payment-gateway client.
--    Its subscription payments (from score.farmsky.africa) are signed
--    with SCORE's own hmac_secret and processed by the same
--    /api/v1/payments/initiate endpoint the other marketplaces use.
-- ---------------------------------------------------------------------
INSERT INTO app_clients (client_key, display_name, origin_url, hmac_secret, is_active) VALUES
  ('score', 'Farmsky Score', 'https://score.farmsky.africa', 'REPLACE_WITH_SCORE_SECRET', 1)
ON CONFLICT (client_key) DO NOTHING;

-- ---------------------------------------------------------------------
-- 2. Score subscriptions (billing state pushed from score.farmsky.africa)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS score_subscriptions (
  id BIGSERIAL PRIMARY KEY,
  score_org_ref TEXT,                       -- Score-side organisation id
  score_reference TEXT UNIQUE,              -- Score-side subscription id
  plan TEXT NOT NULL,                       -- e.g. 'starter' | 'growth' | 'scale'
  billing_cycle TEXT DEFAULT 'monthly',     -- 'monthly' | 'annual'
  amount NUMERIC(14,2) NOT NULL DEFAULT 0,
  currency TEXT NOT NULL DEFAULT 'KES',
  phone TEXT,
  status TEXT NOT NULL DEFAULT 'pending',   -- pending | active | past_due | cancelled
  transaction_ref TEXT,                     -- central_transactions.transaction_ref for the latest charge
  current_period_end TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_score_sub_status ON score_subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_score_sub_txref  ON score_subscriptions(transaction_ref);

-- ---------------------------------------------------------------------
-- 3. Score ID verification + liveness results
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS score_verifications (
  id BIGSERIAL PRIMARY KEY,
  customer_id INTEGER,                       -- local Equipment customer this maps to (nullable)
  score_request_id TEXT,                     -- request_id returned by Score
  national_id TEXT,
  full_name TEXT,
  id_verified INTEGER DEFAULT 0,
  face_match INTEGER DEFAULT 0,
  liveness_passed INTEGER DEFAULT 0,
  liveness_score NUMERIC(6,4),
  raw_response TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_score_verif_customer ON score_verifications(customer_id);
CREATE INDEX IF NOT EXISTS idx_score_verif_natid    ON score_verifications(national_id);

-- ---------------------------------------------------------------------
-- 4. Score IPRS (government registry) lookups
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS score_iprs_checks (
  id BIGSERIAL PRIMARY KEY,
  customer_id INTEGER,
  score_request_id TEXT,
  national_id TEXT NOT NULL,
  status TEXT,                               -- VERIFIED | NOT_FOUND | ...
  registry_name TEXT,
  pep_sanctions_hit INTEGER DEFAULT 0,
  raw_response TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_score_iprs_customer ON score_iprs_checks(customer_id);
CREATE INDEX IF NOT EXISTS idx_score_iprs_natid    ON score_iprs_checks(national_id);

-- ---------------------------------------------------------------------
-- 5. Score full credit evaluations
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS score_credit_evaluations (
  id BIGSERIAL PRIMARY KEY,
  customer_id INTEGER,
  score_reference TEXT,                       -- lender_reference / evaluation id from Score
  applicant_type TEXT,
  composite_score INTEGER,
  risk_tier TEXT,
  decision TEXT,
  model_version TEXT,
  raw_response TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_score_credit_customer ON score_credit_evaluations(customer_id);
CREATE INDEX IF NOT EXISTS idx_score_credit_ref      ON score_credit_evaluations(score_reference);
