-- =====================================================================
-- SasaPay production integration — payouts, withdrawals, payin channels
--
--   Adds the schema needed to run SasaPay as a LIVE payment rail:
--     * payment_intents gains channel / direction / provider-reference
--       columns so a single table tracks both C2B payins AND B2C payouts.
--     * A payout_accounts table lets each user register the mobile/bank
--       destinations they can withdraw to (validated via SasaPay account
--       validation before use).
--     * A wallet_withdrawals table tracks every wallet-funded B2C disbursal
--       (withdrawal to own account, or an admin direct-pay to a third party)
--       through its full life-cycle (pending -> processing -> success/failed).
--     * payout_batches gains a payment_method column so a batch can be a
--       real B2C disbursal, not just an internal ledger credit.
--
--   All DDL is idempotent (ADD COLUMN IF NOT EXISTS / CREATE TABLE IF NOT
--   EXISTS) so db-init can re-apply on every boot. On D1/SQLite the
--   `IF NOT EXISTS` on ADD COLUMN is unsupported, but the applier swallows
--   duplicate-column errors, so this is safe on both runtimes.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. payment_intents — track channel, direction and provider references.
--    direction: 'payin'  = C2B collection (customer -> business)
--               'payout' = B2C disbursal   (business -> customer)
-- ---------------------------------------------------------------------
ALTER TABLE payment_intents ADD COLUMN IF NOT EXISTS provider TEXT DEFAULT 'sasapay';
ALTER TABLE payment_intents ADD COLUMN IF NOT EXISTS direction TEXT DEFAULT 'payin';
ALTER TABLE payment_intents ADD COLUMN IF NOT EXISTS channel_code TEXT;
ALTER TABLE payment_intents ADD COLUMN IF NOT EXISTS channel_name TEXT;
ALTER TABLE payment_intents ADD COLUMN IF NOT EXISTS account_number TEXT;
ALTER TABLE payment_intents ADD COLUMN IF NOT EXISTS transaction_reference TEXT;
ALTER TABLE payment_intents ADD COLUMN IF NOT EXISTS transaction_code TEXT;
ALTER TABLE payment_intents ADD COLUMN IF NOT EXISTS needs_otp INTEGER DEFAULT 0;
ALTER TABLE payment_intents ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

CREATE INDEX IF NOT EXISTS idx_intents_direction ON payment_intents(direction);
CREATE INDEX IF NOT EXISTS idx_intents_txref      ON payment_intents(transaction_reference);

-- ---------------------------------------------------------------------
-- 2. payout_accounts — the mobile / bank destinations a user registers so
--    they (or an admin) can disburse funds to a known, validated target.
--    account_type mirrors the SasaPay account_type used at validation:
--      0 = SasaPay wallet, 1 = Mobile money, 2 = Paybill, 3 = Till, 4 = Bank
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS payout_accounts (
  id BIGSERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL,
  label TEXT,                                   -- friendly name e.g. "My M-PESA"
  channel_code TEXT NOT NULL,                   -- SasaPay channel code (0, 63902, 01 …)
  channel_name TEXT,                            -- resolved channel name
  account_type INTEGER NOT NULL DEFAULT 1,      -- 0 wallet | 1 mobile | 2 paybill | 3 till | 4 bank
  account_number TEXT NOT NULL,                 -- mobile no (254…) or bank account number
  account_name TEXT,                            -- name confirmed by SasaPay validation
  is_verified INTEGER NOT NULL DEFAULT 0,       -- 1 once validated by SasaPay
  is_default INTEGER NOT NULL DEFAULT 0,
  created_by INTEGER,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_payout_accounts_user ON payout_accounts(user_id);

-- ---------------------------------------------------------------------
-- 3. wallet_withdrawals — every wallet-funded B2C disbursal.
--    Covers two flows:
--      (a) withdrawal   — a wallet holder cashes out to their own registered
--                         mobile/bank/SasaPay destination.
--      (b) direct_pay   — an admin pays a third party (wallet or mobile/bank)
--                         directly; the source wallet is the platform / admin.
--    status: pending -> processing -> success | failed | reversed
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS wallet_withdrawals (
  id BIGSERIAL PRIMARY KEY,
  reference TEXT UNIQUE NOT NULL,               -- MerchantTransactionReference sent to SasaPay
  flow TEXT NOT NULL DEFAULT 'withdrawal',      -- withdrawal | direct_pay
  wallet_id BIGINT,                             -- source wallet debited (NULL for pure treasury pay)
  user_id INTEGER,                              -- source wallet owner (withdrawal) / initiating admin
  recipient_user_id INTEGER,                    -- destination user when paying an internal wallet
  amount NUMERIC(14,2) NOT NULL CHECK (amount > 0),
  currency TEXT NOT NULL DEFAULT 'KES',
  channel_code TEXT NOT NULL,                   -- SasaPay channel code
  channel_name TEXT,
  receiver_number TEXT NOT NULL,                -- mobile / bank account / wallet number
  recipient_name TEXT,                          -- name resolved by SasaPay
  reason TEXT,
  status TEXT NOT NULL DEFAULT 'pending',       -- pending | processing | success | failed | reversed
  simulated INTEGER NOT NULL DEFAULT 0,
  ledger_debited INTEGER NOT NULL DEFAULT 0,    -- 1 once the source wallet has been debited
  b2c_request_id TEXT,                          -- SasaPay B2CRequestID
  conversation_id TEXT,                         -- SasaPay ConversationID
  transaction_code TEXT,                        -- SasaPayTransactionCode (on result callback)
  result_code TEXT,
  result_desc TEXT,
  transaction_charges NUMERIC(14,2) DEFAULT 0,
  created_by INTEGER,                           -- actor who initiated (admin or self)
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_withdrawals_ref     ON wallet_withdrawals(reference);
CREATE INDEX IF NOT EXISTS idx_withdrawals_user    ON wallet_withdrawals(user_id);
CREATE INDEX IF NOT EXISTS idx_withdrawals_status  ON wallet_withdrawals(status);
CREATE INDEX IF NOT EXISTS idx_withdrawals_b2c     ON wallet_withdrawals(b2c_request_id);

-- ---------------------------------------------------------------------
-- 4. payout_batches — allow a batch to be a REAL disbursal, not just an
--    internal ledger credit. payment_method: 'wallet_credit' (default,
--    legacy behaviour) or 'sasapay_b2c' (actually pushed to mobile/bank).
-- ---------------------------------------------------------------------
ALTER TABLE payout_batches ADD COLUMN IF NOT EXISTS payment_method TEXT DEFAULT 'wallet_credit';
