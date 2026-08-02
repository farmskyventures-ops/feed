-- =====================================================================
-- 0019 — Demo account phone refresh, KYC gating flags, and uniqueness
--   * Refresh the four demo/login accounts to the new phone numbers.
--   * Add a customers.kyc_completed_at marker so we can gate FINANCED
--     checkouts behind completed KYC (ID docs + liveliness + TransUnion),
--     while still allowing CASH checkouts without it.
--   * Enforce national_id uniqueness (phone is already UNIQUE on users).
-- These statements are idempotent and safe to re-run on an existing DB.
-- =====================================================================

-- --- Demo account phone numbers (kept in sync with seed.sql) -----------
-- These originally matched on the integer seed ids (WHERE id = 1..4). On the
-- shared central DB, users.id is a UUID, so `id = 1` raises
-- `operator does not exist: uuid = integer` (42883). We therefore guard the
-- integer-id UPDATEs behind a data-type check and ONLY run them when users.id
-- is actually an integer type (Feed's own standalone schema). On a UUID
-- users table the demo phones are seeded by 0026 / normal onboarding instead,
-- so skipping here is correct and lossless.
DO $$
DECLARE id_type text;
BEGIN
  SELECT data_type INTO id_type
    FROM information_schema.columns
   WHERE table_schema = 'public' AND table_name = 'users' AND column_name = 'id';

  IF id_type IN ('integer', 'bigint', 'smallint') THEN
    UPDATE users SET phone = '+2547500000' WHERE id = 1 AND role = 'super_admin';
    UPDATE users SET phone = '+2547400000' WHERE id = 2 AND role = 'agent';
    UPDATE users SET phone = '+2547300000' WHERE id = 3 AND role = 'customer';
    UPDATE users SET phone = '+2547200000' WHERE id = 4 AND role = 'support';
  END IF;
END $$;

-- Keep the linked customer record's mobile aligned with the farmer login.
-- customers.user_id was widened to TEXT (migration 0024) so it can hold an
-- integer-as-string or a UUID. Match it as text to stay type-safe on both DB
-- shapes (this is a no-op when no such row exists).
UPDATE customers SET mobile = '+2547300000' WHERE CAST(user_id AS TEXT) = '3';

-- --- KYC gating marker -------------------------------------------------
-- Set once a customer completes ID upload + liveliness + TransUnion. Used to
-- block financed checkout until KYC is done (cash checkout is always allowed).
ALTER TABLE customers ADD COLUMN IF NOT EXISTS kyc_completed_at TIMESTAMP;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS liveliness_passed INTEGER DEFAULT 0;

-- --- Uniqueness --------------------------------------------------------
-- national_id must be unique across customers (ignoring NULL/empty).
-- A partial unique index keeps legacy NULL/blank rows valid.
CREATE UNIQUE INDEX IF NOT EXISTS ux_customers_national_id
  ON customers (national_id)
  WHERE national_id IS NOT NULL AND national_id <> '';
