-- =====================================================================
-- 0000 — Normalize boolean-ish flag columns to INTEGER (runs FIRST).
--
-- WHY THIS RUNS BEFORE EVERYTHING ELSE
-- ------------------------------------
-- Equipment shares one central PostgreSQL database with the Score platform
-- (and the feed / input marketplaces). Several flag columns that Equipment's
-- code reads/writes as INTEGER 1/0 (SQLite heritage) may already exist on the
-- shared DB as native BOOLEAN, created by another app or an older schema.
--
-- Because Equipment's `CREATE TABLE IF NOT EXISTS ...` silently skips a table
-- that already exists, later statements then hit the pre-existing BOOLEAN
-- column and PostgreSQL aborts. Two concrete production failures this fixes:
--
--   1) Migration 0008/0011 seed:
--        INSERT INTO app_clients (... is_active) VALUES (..., 1)
--        -> column "is_active" is of type boolean but expression is of type integer
--      This aborted migration 0008, so NO later migration ran — which is why
--      0022 (below, folded in here) never applied in production.
--
--   2) Runtime issueOtp()/verifyOtp():
--        UPDATE otp_codes SET consumed=1 WHERE ... AND consumed=0
--        -> operator does not exist: boolean = integer   (SQLSTATE 42883)
--
-- By normalizing ALL known flag columns to INTEGER up-front, every subsequent
-- migration INSERT and every runtime 1/0 comparison works against a consistent
-- INTEGER type. This file is CONDITIONAL + IDEMPOTENT: it inspects each
-- column's current type and only rewrites BOOLEAN columns (TRUE->1, FALSE->0);
-- columns that are already integer, or tables that do not exist yet on a fresh
-- database, are skipped. Safe to re-run on every boot.
--
-- (This supersedes the old 0022_normalize_boolean_flags.sql, which sorted AFTER
--  the failing 0008 and therefore never got a chance to run in production.)
-- =====================================================================

DO $$
DECLARE
  t record;
  col_type text;
  has_default boolean;
BEGIN
  -- (table, column, default_or_NULL) — the flags Equipment treats as INTEGER.
  -- default_or_null: the numeric default to restore, or NULL to leave nullable
  -- with no default (e.g. audit flags that are legitimately nullable).
  FOR t IN
    SELECT * FROM (VALUES
      ('otp_codes',          'consumed',          '0'),
      ('otp_codes',          'attempts',          '0'),
      ('products',           'cash_enabled',      '1'),
      ('products',           'financing_enabled', '1'),
      ('role_templates',     'is_system',         '0'),
      ('app_clients',        'is_active',         '1'),
      ('central_callbacks',  'signature_valid',   NULL),
      ('marketplaces',       'is_main',           '0'),
      ('marketplaces',       'is_active',         '1'),
      ('earning_rules',      'is_active',         '1'),
      ('payout_accounts',    'is_verified',       '0'),
      ('payout_accounts',    'is_default',        '0'),
      ('merchant_keys',      'is_active',         '1'),
      ('users',              'is_temp_password',  '0')
    ) AS v(tbl, col, dflt)
  LOOP
    -- Skip if the table/column does not exist yet (fresh DB: later migrations
    -- create them as INTEGER, so there is nothing to normalize here).
    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = t.tbl AND column_name = t.col
    ) THEN
      CONTINUE;
    END IF;

    SELECT data_type INTO col_type
    FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = t.tbl AND column_name = t.col;

    IF col_type = 'boolean' THEN
      RAISE NOTICE '[0000] %.% is boolean -> converting to integer (TRUE=1, FALSE=0)', t.tbl, t.col;
      -- Drop any boolean default first so the type change is clean, convert
      -- with a CASE expression, then restore the numeric default (or leave
      -- nullable/no-default for audit-style flags).
      EXECUTE format('ALTER TABLE %I ALTER COLUMN %I DROP DEFAULT', t.tbl, t.col);
      EXECUTE format(
        'ALTER TABLE %I ALTER COLUMN %I TYPE integer USING (CASE WHEN %I THEN 1 ELSE 0 END)',
        t.tbl, t.col, t.col
      );
      IF t.dflt IS NOT NULL THEN
        EXECUTE format('ALTER TABLE %I ALTER COLUMN %I SET DEFAULT %s', t.tbl, t.col, t.dflt);
        -- Backfill any NULLs to the default, then enforce NOT NULL to match the
        -- canonical schema (only for columns that carry a default).
        EXECUTE format('UPDATE %I SET %I = %s WHERE %I IS NULL', t.tbl, t.col, t.dflt, t.col);
        EXECUTE format('ALTER TABLE %I ALTER COLUMN %I SET NOT NULL', t.tbl, t.col);
      END IF;
    ELSE
      RAISE NOTICE '[0000] %.% is % (not boolean) -> leaving as-is', t.tbl, t.col, col_type;
    END IF;
  END LOOP;
END $$;
