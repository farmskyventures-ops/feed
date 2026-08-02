-- =====================================================================
-- 0024 — make every Equipment column that stores a *user id* TEXT, so it
--        works whether the shared central `public.users.id` is INTEGER
--        (Equipment's own schema) or UUID (created by the Score app).
--
-- WHY THIS EXISTS
-- ---------------------------------------------------------------------
-- Equipment shares ONE central PostgreSQL database (public schema) with the
-- Score app, whose `users` table uses a UUID primary key. On that shared DB
-- the following Equipment columns — declared INTEGER and originally carrying a
-- `REFERENCES users(id)` foreign key — could not store a UUID user id and, at
-- table-creation time, their cross-type FK made Postgres reject the WHOLE
-- CREATE TABLE (42804 "foreign key constraint cannot be implemented"). The
-- resilient migration runner then skipped the entire table, so `customers`,
-- `agents` and `change_requests` were MISSING in production, surfacing as
--   error: relation "customers" does not exist            (42P01)
-- during signup (right after createSession).
--
-- FIX (two parts)
-- ---------------------------------------------------------------------
--   1. backend/db-init.ts now STRIPS the inline `REFERENCES users(id)` FK
--      clauses from CREATE TABLE statements, so the tables always create.
--   2. This migration widens the user-id-bearing columns to TEXT so they
--      losslessly hold an integer-as-string OR a UUID string, matching the
--      0024 treatment of sessions.user_id / audit_logs.user_id.
--
-- Idempotent: each column is only altered when it exists and is not already
-- text/varchar. Safe to re-run.
-- =====================================================================

-- helper pattern repeated per (table, column): convert INTEGER/other → TEXT
-- only when the table+column exist and aren't already textual.

-- customers.user_id  (the farmer's login user id)
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema='public' AND table_name='customers' AND column_name='user_id'
      AND data_type NOT IN ('text','character varying')
  ) THEN
    ALTER TABLE customers ALTER COLUMN user_id TYPE TEXT USING user_id::text;
  END IF;
END $$;

-- customers.agent_id  (the onboarding agent's user id)
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema='public' AND table_name='customers' AND column_name='agent_id'
      AND data_type NOT IN ('text','character varying')
  ) THEN
    ALTER TABLE customers ALTER COLUMN agent_id TYPE TEXT USING agent_id::text;
  END IF;
END $$;

-- agents.user_id
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema='public' AND table_name='agents' AND column_name='user_id'
      AND data_type NOT IN ('text','character varying')
  ) THEN
    ALTER TABLE agents ALTER COLUMN user_id TYPE TEXT USING user_id::text;
  END IF;
END $$;

-- change_requests.requester_id
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema='public' AND table_name='change_requests' AND column_name='requester_id'
      AND data_type NOT IN ('text','character varying')
  ) THEN
    ALTER TABLE change_requests ALTER COLUMN requester_id TYPE TEXT USING requester_id::text;
  END IF;
END $$;
