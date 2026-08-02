-- =====================================================================
-- Widen epoch-millisecond columns to BIGINT for PostgreSQL compatibility.
--
-- The application stores `expires_at` as an epoch-millisecond integer
-- (see payment-gateway.ts: `Number(row.expires_at) < Date.now()`), so the
-- target type is BIGINT. This migration is CONDITIONAL + IDEMPOTENT so it is
-- safe on any pre-existing database:
--
--   * already BIGINT            -> nothing to do (skip).
--   * INTEGER / other numeric   -> straight widen to BIGINT.
--   * TIMESTAMP / TIMESTAMPTZ   -> a legacy database created these columns as
--     timestamps. PostgreSQL cannot cast timestamptz -> bigint directly
--     (that produced: "cannot cast type timestamp with time zone to bigint"
--     which aborted the whole init). Convert to epoch MILLISECONDS instead so
--     the value matches what the app expects.
--
-- Written as PL/pgSQL DO blocks so each column is inspected first. PostgreSQL.
-- =====================================================================

DO $$
DECLARE
  t record;
  col_type text;
BEGIN
  FOR t IN
    SELECT * FROM (VALUES ('sessions'), ('otp_codes')) AS v(tbl)
  LOOP
    -- Skip tables that don't exist yet (fresh DB: created later as INTEGER).
    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = t.tbl AND column_name = 'expires_at'
    ) THEN
      CONTINUE;
    END IF;

    SELECT data_type INTO col_type
    FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = t.tbl AND column_name = 'expires_at';

    IF col_type = 'bigint' THEN
      -- Already the desired type.
      CONTINUE;

    ELSIF col_type IN ('timestamp with time zone', 'timestamp without time zone') THEN
      -- Legacy timestamp column: convert to epoch milliseconds (BIGINT).
      -- A timestamp default (e.g. now()/CURRENT_TIMESTAMP) cannot be auto-cast
      -- to bigint, so drop the default before changing the type.
      RAISE NOTICE '[migrate] %.expires_at is % -> converting to epoch-millis BIGINT', t.tbl, col_type;
      EXECUTE format('ALTER TABLE %I ALTER COLUMN expires_at DROP DEFAULT', t.tbl);
      EXECUTE format(
        'ALTER TABLE %I ALTER COLUMN expires_at TYPE BIGINT USING (EXTRACT(EPOCH FROM expires_at) * 1000)::BIGINT',
        t.tbl
      );

    ELSE
      -- INTEGER / numeric / text-of-digits: widen straight to BIGINT.
      RAISE NOTICE '[migrate] %.expires_at is % -> widening to BIGINT', t.tbl, col_type;
      EXECUTE format('ALTER TABLE %I ALTER COLUMN expires_at DROP DEFAULT', t.tbl);
      EXECUTE format(
        'ALTER TABLE %I ALTER COLUMN expires_at TYPE BIGINT USING expires_at::BIGINT',
        t.tbl
      );
    END IF;
  END LOOP;
END $$;
