-- =====================================================================
-- 0029 — Score Wallet Mirror Ledger (Phase 3 / Phase 2 audit mirror)
--
--   Farmsky Score (credit.farmskyafrica) owns the PRIMARY wallet ledger.
--   Every credit/debit on Score is MIRRORED here for a consolidated,
--   cross-app audit trail — the same pattern Feed already uses through
--   the central gateway. Score POSTs HMAC-signed mirror entries to
--   POST /api/score-ledger/mirror, which inserts rows into this table.
--
--   This complements score_subscriptions (billing state) with a full
--   movement-by-movement ledger of the Score wallet.
--
--   Idempotent + safe to re-run. SQLite dialect, transformed to
--   PostgreSQL by backend/db-init.ts.
-- =====================================================================

CREATE TABLE IF NOT EXISTS score_wallet_ledger (
  id BIGSERIAL PRIMARY KEY,
  score_org_ref   TEXT NOT NULL,               -- Score-side organisation id (org_id)
  score_tx_id     TEXT UNIQUE,                  -- Score wallet_transactions.id (idempotency key)
  direction       TEXT NOT NULL,               -- credit | debit
  amount_kes      NUMERIC(14,2) NOT NULL DEFAULT 0,
  balance_after   NUMERIC(14,2),               -- Score wallet balance after the movement
  kind            TEXT NOT NULL DEFAULT 'verification', -- topup | verification | adjustment
  service_key     TEXT,                         -- billable service when kind='verification'
  reference       TEXT,                         -- payment/verification reference
  source          TEXT NOT NULL DEFAULT 'score',
  created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_score_ledger_org ON score_wallet_ledger(score_org_ref);
CREATE INDEX IF NOT EXISTS idx_score_ledger_dir ON score_wallet_ledger(direction);
CREATE INDEX IF NOT EXISTS idx_score_ledger_created ON score_wallet_ledger(created_at);

-- Ensure app_clients can carry a per-client callback_url (used to POST
-- settlement webhooks back to Score). Older schemas may not have it.
ALTER TABLE app_clients ADD COLUMN IF NOT EXISTS callback_url TEXT;
