-- =====================================================================
-- 0023 — make sessions.user_id TEXT so it can hold EITHER an INTEGER user id
--        (Equipment's own schema) OR a UUID user id (when the shared central
--        `public.users` table was created by a sibling app such as Score).
--
-- WHY THIS EXISTS
-- ---------------------------------------------------------------------
-- Equipment shares ONE central PostgreSQL database (public schema) with the
-- Score app. Score's `users` table uses a UUID primary key. On the shared DB
-- the `public.users` table can therefore end up UUID-keyed, while Equipment's
-- `sessions.user_id` was declared INTEGER (0001_initial_schema.sql).
--
-- createSession() inserts `user.id` (the value read back from `users`) into
-- `sessions.user_id`. When `users.id` is a UUID string, inserting it into an
-- INTEGER column fails with:
--   error: invalid input syntax for type integer:
--          "90ebd36d-fde8-4554-9d06-97e3ffd91ddf"   (SQLSTATE 22P02)
-- at createSession — breaking signup, OTP verification AND login (every path
-- that mints a session).
--
-- FIX
-- ---------------------------------------------------------------------
-- Widen sessions.user_id to TEXT. TEXT losslessly stores an integer-as-string
-- ("5") or a UUID string ("90ebd36d-..."), so the session INSERT never again
-- hits a type-cast error regardless of how `users.id` is typed. The session
-- read path joins with `users.id::text = sessions.user_id`, so both id shapes
-- compare correctly. Idempotent: only converts when the column is not already
-- TEXT/character varying.
-- =====================================================================

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name   = 'sessions'
      AND column_name  = 'user_id'
      AND data_type NOT IN ('text', 'character varying')
  ) THEN
    -- USING ...::text converts any existing integer/uuid values to their text form.
    ALTER TABLE sessions ALTER COLUMN user_id TYPE TEXT USING user_id::text;
  END IF;
END $$;

-- Same defensive widening for audit_logs.user_id: on a shared central DB the
-- actor id may be a UUID. audit() is best-effort (wrapped in try/catch) so a
-- UUID→INTEGER failure only silently DROPPED audit rows; widening to TEXT lets
-- those audit entries be written regardless of how users.id is typed.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name   = 'audit_logs'
      AND column_name  = 'user_id'
      AND data_type NOT IN ('text', 'character varying')
  ) THEN
    ALTER TABLE audit_logs ALTER COLUMN user_id TYPE TEXT USING user_id::text;
  END IF;
END $$;
