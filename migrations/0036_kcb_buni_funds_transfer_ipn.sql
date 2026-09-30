-- =====================================================================
-- 0036 — KCB Buni: Funds Transfer, IPN & KYC-gated dashboard transactions
--
-- Extends the central payment gateway with the KCB Buni FundsTransfer and
-- Instant Payment Notification (IPN) capabilities, plus a KYC-gated
-- dashboard "Transactions" module for account-to-account, inter-bank
-- (RTGS/EFT/PesaLink), mobile-money wallet and currency-conversion transfers.
--
--   ipn_notifications — every Instant Payment Notification KCB posts to us
--     (account / till / validation), with the RSA signature-verification
--     result recorded for audit.
--
--   central_transactions.direction — normalises payin vs payout so the new
--     Funds Transfer rows (payout) sort cleanly alongside collections. The
--     gateway already writes this column when present and falls back when not.
--
-- RBAC: a new delegable permission `manage_transactions` gates the dashboard
-- Transactions module. Access in the UI is additionally restricted to users
-- who have completed KYC (kyc_status='verified') — enforced server-side.
--
-- Idempotent + auto-applied by db-init on boot.
-- =====================================================================

-- Normalise transfer direction on the shared ledger (payin = collection,
-- payout = disbursement / funds transfer). Nullable + default keeps every
-- existing row valid and backward compatible.
ALTER TABLE central_transactions ADD COLUMN IF NOT EXISTS direction TEXT DEFAULT 'payin';
CREATE INDEX IF NOT EXISTS idx_central_tx_direction ON central_transactions(direction);

-- Instant Payment Notifications received from KCB (account / till / validation).
CREATE TABLE IF NOT EXISTS ipn_notifications (
  id                  BIGSERIAL PRIMARY KEY,
  kind                TEXT NOT NULL,             -- 'account' | 'till' | 'validation'
  transaction_reference TEXT,
  request_id          TEXT,
  amount              NUMERIC(14,2),
  currency            TEXT DEFAULT 'KES',
  customer_reference  TEXT,
  customer_name       TEXT,
  customer_msisdn     TEXT,
  narration           TEXT,
  raw_payload         TEXT,
  signature_verified  INTEGER DEFAULT 0,         -- 1 = RSA signature verified with KCB public key
  created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_ipn_kind ON ipn_notifications(kind);
CREATE INDEX IF NOT EXISTS idx_ipn_txref ON ipn_notifications(transaction_reference);
CREATE INDEX IF NOT EXISTS idx_ipn_created ON ipn_notifications(created_at);

-- RBAC permission for the KYC-gated dashboard Transactions module ------------
INSERT OR IGNORE INTO permission_catalog (permission_key, label, description, category) VALUES
  ('manage_transactions', 'Bank Transfers & Transactions', 'Initiate KCB account-to-account, inter-bank (RTGS/EFT/PesaLink), mobile-money wallet and currency-conversion transfers. Restricted to KYC-verified users.', 'payments');

-- Grant to admin role templates + existing admins (pre-checked in the panel).
UPDATE role_templates
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb || '{"manage_transactions":true}'::jsonb)::text
 WHERE role_key IN ('super_admin', 'admin');
UPDATE users
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb || '{"manage_transactions":true}'::jsonb)::text
 WHERE role IN ('super_admin', 'admin');
