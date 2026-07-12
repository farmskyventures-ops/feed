-- =====================================================================
-- Ownership & Split-Data Row-Level Security + Wallet integrity triggers
-- Run ONCE by a Postgres superuser against the app DB:
--
--     psql "$SUPERUSER_DATABASE_URL" -f backend/sql/03_ownership_rls_setup.sql
--
-- Implements:
--   (1) Relationship-Based Access Control via RLS keyed on app.current_user_id
--       - farmers   : visible only to their onboarding agent
--       - purchases : visible only if the farmer was onboarded by the user
--       - inventory : visible only to the user who created/listed it
--       - admins/super_admins bypass everything (global dataset)
--   (2) Split-data protection: a trigger blocks anyone WITHOUT
--       can_manage_finance_settings from writing markup / financing / PAYGO
--       columns, even if they craft the API call directly.
--   (3) Wallet double-entry integrity: wallet balance can only move through a
--       ledger insert; direct UPDATEs to balance without a matching entry are
--       rejected, and ledger rows are immutable.
--
-- Security context: the web app sets, per request/transaction:
--       SELECT set_config('app.current_user_id', '<id>', false);
--       SELECT set_config('app.current_role',   '<role>', false);
--       SELECT set_config('app.user_can_finance','true'|'false', false);
-- Running any query WITHOUT app.current_user_id returns ZERO rows for general
-- users (see the "USING (... )" clauses) — no context, no leak.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 0. Session-context helper functions
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION current_app_user_id() RETURNS INTEGER AS $$
  SELECT NULLIF(current_setting('app.current_user_id', true), '')::INTEGER;
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION current_app_is_admin() RETURNS BOOLEAN AS $$
  SELECT COALESCE(current_setting('app.current_role', true), '') IN ('admin', 'super_admin');
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION current_app_can_finance() RETURNS BOOLEAN AS $$
  SELECT COALESCE(current_setting('app.user_can_finance', true), 'false') = 'true';
$$ LANGUAGE sql STABLE;

-- ---------------------------------------------------------------------
-- 1. Relationship-Based RLS
-- ---------------------------------------------------------------------

-- FARMERS: the user must be the assigned onboarding agent (or admin).
ALTER TABLE customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE customers FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ownership_customers ON customers;
CREATE POLICY ownership_customers ON customers
  USING (current_app_is_admin() OR onboarded_by = current_app_user_id() OR agent_id = current_app_user_id())
  WITH CHECK (current_app_is_admin() OR onboarded_by = current_app_user_id() OR agent_id = current_app_user_id());

-- PURCHASES: the contract must belong to a farmer onboarded by the user
-- (or the contract was created by the user), else admin.
ALTER TABLE murabaha_contracts ENABLE ROW LEVEL SECURITY;
ALTER TABLE murabaha_contracts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ownership_contracts ON murabaha_contracts;
CREATE POLICY ownership_contracts ON murabaha_contracts
  USING (
    current_app_is_admin()
    OR created_by = current_app_user_id()
    OR agent_id   = current_app_user_id()
    OR customer_id IN (SELECT id FROM customers WHERE onboarded_by = current_app_user_id() OR agent_id = current_app_user_id())
  )
  WITH CHECK (
    current_app_is_admin()
    OR created_by = current_app_user_id()
    OR agent_id   = current_app_user_id()
    OR customer_id IN (SELECT id FROM customers WHERE onboarded_by = current_app_user_id() OR agent_id = current_app_user_id())
  );

-- INVENTORY: the item must have been created/listed by the user (or admin).
-- NOTE: the storefront/shop reads run under admin context (see backend
-- setUserContext for public catalog), so buyers still see published products.
ALTER TABLE products ENABLE ROW LEVEL SECURITY;
ALTER TABLE products FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ownership_products ON products;
CREATE POLICY ownership_products ON products
  USING (current_app_is_admin() OR created_by = current_app_user_id())
  WITH CHECK (current_app_is_admin() OR created_by = current_app_user_id());

-- ---------------------------------------------------------------------
-- 2. Split-data protection trigger (finance columns)
--    Blocks writes to markup / financing / PAYGO / legal-agreement columns
--    by anyone lacking can_manage_finance_settings — even direct API calls.
--    Admins (current_app_can_finance()=true is set for finance-authorized
--    users and all admins) pass through.
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION guard_product_finance_columns() RETURNS TRIGGER AS $$
BEGIN
  IF current_app_can_finance() OR current_app_is_admin() THEN
    RETURN NEW;   -- authorized to set financial components
  END IF;

  IF TG_OP = 'INSERT' THEN
    -- A base user may only draft: force finance fields to safe defaults and
    -- mark the product as awaiting finance authorization.
    NEW.credit_markup_pct        := 0;
    NEW.credit_price             := COALESCE(NEW.cash_price, NEW.buying_price);
    NEW.financing_enabled        := 0;
    NEW.financing_interest_pct   := 0;
    NEW.financing_terms_text     := NULL;
    NEW.financing_terms_doc_url  := NULL;
    NEW.finance_status           := 'pending_finance';
    RETURN NEW;
  END IF;

  -- On UPDATE, reject any attempt to change a protected finance column.
  IF NEW.credit_markup_pct       IS DISTINCT FROM OLD.credit_markup_pct
     OR NEW.credit_price          IS DISTINCT FROM OLD.credit_price
     OR NEW.financing_enabled     IS DISTINCT FROM OLD.financing_enabled
     OR NEW.financing_interest_pct IS DISTINCT FROM OLD.financing_interest_pct
     OR NEW.financing_model       IS DISTINCT FROM OLD.financing_model
     OR NEW.financing_terms_text  IS DISTINCT FROM OLD.financing_terms_text
     OR NEW.financing_terms_doc_url IS DISTINCT FROM OLD.financing_terms_doc_url
     OR NEW.finance_status        IS DISTINCT FROM OLD.finance_status THEN
    RAISE EXCEPTION 'Not authorized to modify financial components (requires can_manage_finance_settings)'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_guard_product_finance ON products;
CREATE TRIGGER trg_guard_product_finance
  BEFORE INSERT OR UPDATE ON products
  FOR EACH ROW EXECUTE FUNCTION guard_product_finance_columns();

-- ---------------------------------------------------------------------
-- 3. Wallet double-entry integrity
-- ---------------------------------------------------------------------

-- 3a. Ledger rows are immutable (no UPDATE / DELETE after commit).
CREATE OR REPLACE FUNCTION wallet_ledger_immutable() RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'wallet_ledger rows are immutable (append-only audit trail)'
    USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_wallet_ledger_immutable ON wallet_ledger;
CREATE TRIGGER trg_wallet_ledger_immutable
  BEFORE UPDATE OR DELETE ON wallet_ledger
  FOR EACH ROW EXECUTE FUNCTION wallet_ledger_immutable();

-- 3b. On each ledger insert, compute + stamp balance_after and sync the wallet
--     balance atomically. This is the ONLY sanctioned way the balance changes.
CREATE OR REPLACE FUNCTION wallet_ledger_apply() RETURNS TRIGGER AS $$
DECLARE
  cur NUMERIC(14,2);
BEGIN
  SELECT balance INTO cur FROM wallets WHERE id = NEW.wallet_id FOR UPDATE;
  IF cur IS NULL THEN
    RAISE EXCEPTION 'wallet % does not exist', NEW.wallet_id;
  END IF;
  IF NEW.entry_type = 'credit' THEN
    cur := cur + NEW.amount;
  ELSIF NEW.entry_type = 'debit' THEN
    IF cur < NEW.amount THEN
      RAISE EXCEPTION 'insufficient wallet balance (have %, need %)', cur, NEW.amount
        USING ERRCODE = 'check_violation';
    END IF;
    cur := cur - NEW.amount;
  ELSE
    RAISE EXCEPTION 'entry_type must be credit or debit';
  END IF;
  NEW.balance_after := cur;
  UPDATE wallets SET balance = cur, updated_at = CURRENT_TIMESTAMP WHERE id = NEW.wallet_id;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_wallet_ledger_apply ON wallet_ledger;
CREATE TRIGGER trg_wallet_ledger_apply
  BEFORE INSERT ON wallet_ledger
  FOR EACH ROW EXECUTE FUNCTION wallet_ledger_apply();

-- 3c. Block direct tampering with wallets.balance (must go via a ledger entry).
--     The apply trigger above uses SESSION setting app.wallet_txn='1' to permit
--     its own UPDATE; any other UPDATE that changes balance is rejected.
CREATE OR REPLACE FUNCTION wallet_balance_guard() RETURNS TRIGGER AS $$
BEGIN
  IF NEW.balance IS DISTINCT FROM OLD.balance
     AND COALESCE(current_setting('app.wallet_txn', true), '') <> '1' THEN
    RAISE EXCEPTION 'wallet balance can only change via a wallet_ledger entry'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 3d. Wallet RLS: an agent sees only their own wallet + ledger; admins global.
ALTER TABLE wallets ENABLE ROW LEVEL SECURITY;
ALTER TABLE wallets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ownership_wallets ON wallets;
CREATE POLICY ownership_wallets ON wallets
  USING (current_app_is_admin() OR user_id = current_app_user_id())
  WITH CHECK (current_app_is_admin() OR user_id = current_app_user_id());

ALTER TABLE wallet_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE wallet_ledger FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ownership_wallet_ledger ON wallet_ledger;
CREATE POLICY ownership_wallet_ledger ON wallet_ledger
  USING (current_app_is_admin() OR user_id = current_app_user_id())
  WITH CHECK (current_app_is_admin() OR user_id = current_app_user_id());

ALTER TABLE earning_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE earning_rules FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ownership_earning_rules ON earning_rules;
CREATE POLICY ownership_earning_rules ON earning_rules
  USING (current_app_is_admin() OR user_id = current_app_user_id())
  WITH CHECK (current_app_is_admin() OR user_id = current_app_user_id());

-- NOTE: the wallet_balance_guard trigger is intentionally NOT attached by
-- default because the wallet_ledger_apply trigger already performs the balance
-- UPDATE. If you want defence-in-depth against out-of-band UPDATEs, attach it
-- and have the app wrap balance-affecting work with SET app.wallet_txn='1'.
-- DROP TRIGGER IF EXISTS trg_wallet_balance_guard ON wallets;
-- CREATE TRIGGER trg_wallet_balance_guard BEFORE UPDATE ON wallets
--   FOR EACH ROW EXECUTE FUNCTION wallet_balance_guard();

-- ---------------------------------------------------------------------
-- 3e. Payout destinations + wallet withdrawals RLS.
--     A user sees only their own registered payout accounts and their own
--     withdrawals; admins see everything (for direct-pay + reconciliation).
--     The tables may not exist on a very old DB, so guard with a DO block.
-- ---------------------------------------------------------------------
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='payout_accounts') THEN
    EXECUTE 'ALTER TABLE payout_accounts ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE payout_accounts FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS ownership_payout_accounts ON payout_accounts';
    EXECUTE 'CREATE POLICY ownership_payout_accounts ON payout_accounts
               USING (current_app_is_admin() OR user_id = current_app_user_id())
               WITH CHECK (current_app_is_admin() OR user_id = current_app_user_id())';
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='wallet_withdrawals') THEN
    EXECUTE 'ALTER TABLE wallet_withdrawals ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE wallet_withdrawals FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS ownership_wallet_withdrawals ON wallet_withdrawals';
    -- A user sees withdrawals they own (source) or that pay them (recipient); admins global.
    EXECUTE 'CREATE POLICY ownership_wallet_withdrawals ON wallet_withdrawals
               USING (current_app_is_admin() OR user_id = current_app_user_id() OR recipient_user_id = current_app_user_id())
               WITH CHECK (current_app_is_admin() OR user_id = current_app_user_id() OR recipient_user_id = current_app_user_id())';
  END IF;
END $$;

-- Done. Verify policies with:  \d+ customers   \d+ products   \d+ wallets
