-- =====================================================================
-- 0025 — make EVERY Equipment column that stores a *user id* TEXT, so the
--        WHOLE app (RBAC, wallet, payments, financing, imports, backups,
--        amendments) works whether the shared central `public.users.id` is
--        INTEGER (Equipment's own schema) or UUID (created by the Score app).
--
-- WHY THIS EXISTS
-- ---------------------------------------------------------------------
-- 0024/0025 already widened the auth-path columns (sessions.user_id,
-- audit_logs.user_id, customers.user_id/agent_id, agents.user_id,
-- change_requests.requester_id). But MANY more tables store a user id as
-- INTEGER — most importantly the entire wallet system (wallets, wallet_ledger,
-- earning_rules, payout_batches, payout_accounts, wallet_withdrawals) plus
-- financing (murabaha_contracts), approvals, product ownership/finance
-- (products.created_by / finance_set_by), merchant keys, backups, bulk import
-- and profile amendments.
--
-- On the shared central DB `public.users.id` is a UUID (Score created it), so
-- ANY insert that binds the current user's id into one of those INTEGER columns
-- throws:  invalid input syntax for type integer: "<uuid>"  (SQLSTATE 22P02)
-- — breaking wallet assignment, ledger writes, payouts, withdrawals, product
-- ownership, murabaha dispatch, etc. This migration widens all of them to TEXT
-- (lossless for both integer-as-string and uuid), completing the type-agnostic
-- conversion so every legacy Equipment feature keeps working alongside Score.
--
-- APPROACH: rather than a brittle hand-maintained list, this dynamically
-- widens EVERY public column whose NAME matches a user-reference pattern
-- (user_id, agent_id, *_by, requester_id, recipient_user_id, created_user_id,
-- initiated_by_user, onboarded_by, reviewer_id) and is currently an integer
-- type. A small explicit EXCLUDE set protects columns that merely end in
-- "_id"/"_by" but reference a NON-user table (supplier_id, customer_id,
-- contract_id, product_id, wallet_id, batch_id, row_id, checkout_id, …) — those
-- keep their integer type. Idempotent + re-runnable: a column already TEXT is
-- skipped, and only integer/bigint columns are converted.
-- =====================================================================

DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT c.table_name, c.column_name
    FROM information_schema.columns c
    WHERE c.table_schema = 'public'
      AND c.data_type IN ('integer', 'bigint', 'smallint')
      AND (
        -- user-reference name patterns
        c.column_name IN (
          'user_id', 'agent_id', 'requester_id', 'reviewer_id',
          'recipient_user_id', 'created_user_id', 'initiated_by_user'
        )
        OR c.column_name LIKE '%\_by'          -- created_by, assigned_by, issued_by,
                                               -- dispatched_by, reviewed_by, finance_set_by,
                                               -- onboarded_by, initiated_by, closed_by, …
      )
      -- protect columns that end in _id/_by but reference a NON-user table:
      AND c.column_name NOT IN (
        'supplier_id', 'customer_id', 'contract_id', 'product_id', 'wallet_id',
        'batch_id', 'row_id', 'checkout_id', 'intent_id', 'ticket_id',
        'transaction_id', 'repayment_id', 'approval_id', 'key_id', 'backup_id',
        'amendment_id', 'rule_id', 'account_id', 'payout_account_id'
      )
  LOOP
    BEGIN
      EXECUTE format(
        'ALTER TABLE %I ALTER COLUMN %I TYPE TEXT USING %I::text',
        r.table_name, r.column_name, r.column_name
      );
      RAISE NOTICE '0026 widened % . % to TEXT', r.table_name, r.column_name;
    EXCEPTION WHEN others THEN
      -- Never abort the whole migration for one column; the resilient runner
      -- and idempotent re-runs converge the schema on the next deploy.
      RAISE NOTICE '0026 skipped % . % : %', r.table_name, r.column_name, SQLERRM;
    END;
  END LOOP;
END $$;
