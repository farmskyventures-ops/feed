-- =====================================================================
-- 0023 — DEFENSIVE: guarantee every column the Equipment app writes to
--        public.users actually exists, regardless of how / by whom the
--        users table was first created.
--
-- WHY THIS EXISTS
-- ---------------------------------------------------------------------
-- Equipment shares ONE central PostgreSQL database with sibling apps
-- (Score / Farmsky-APIs, etc.). Score creates its own UUID-based
-- `users` table. If a sibling app created a `users` table in the
-- `public` schema BEFORE Equipment's 0001_initial_schema.sql ran, then
-- 0001's `CREATE TABLE IF NOT EXISTS users (...)` silently did nothing —
-- leaving Equipment operating against a foreign `users` table that has
-- NO `password` (and possibly none of Equipment's other) columns.
--
-- That produced the production failure:
--   error: column "password" of relation "users" does not exist  (42703)
-- on INSERT/UPDATE ... users ... password ...
--
-- Because every later ALTER used bare `ADD COLUMN` (idempotent only via
-- the runner's "duplicate column" swallow) and `password` itself was
-- never re-added after 0001, the column could go permanently missing.
--
-- FIX
-- ---------------------------------------------------------------------
-- Idempotently ADD COLUMN IF NOT EXISTS for the FULL set of columns the
-- Equipment backend reads/writes on `users`, with the correct Postgres
-- types. This runs LAST (0023) so it converges the schema no matter what
-- earlier files did or in what order the table was born. Safe to re-run.
--
-- NOTE ON TYPES
--   * epoch-millis columns use BIGINT (32-bit INTEGER overflows).
--   * boolean-ish flags stored as INTEGER (0/1) to match app bind values,
--     EXCEPT schedule_enabled which 0009 defined as BOOLEAN — kept BOOLEAN
--     here for consistency with that migration.
--   * access_days is JSONB (matches 0009); the app binds a JSON string,
--     which PostgreSQL accepts into JSONB.
-- =====================================================================

-- 0. First make sure the table itself exists (in case NEITHER Equipment's
--    0001 nor any sibling ever created it). Minimal shape; the ADD COLUMNs
--    below fill in the rest. Uses Equipment's INTEGER id convention.
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT
);

-- 1. Core identity / auth columns (from 0001 + 0003).
ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password TEXT;         -- the column that went missing in prod
ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'customer';
ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active';
ALTER TABLE users ADD COLUMN IF NOT EXISTS region TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_set INTEGER DEFAULT 1;

-- 2. RBAC / labelling / permissions (from 0004).
ALTER TABLE users ADD COLUMN IF NOT EXISTS label TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS permissions TEXT;

-- 3. Self-service profile (from 0010).
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT;

-- 4. Access scheduling (from 0009).
ALTER TABLE users ADD COLUMN IF NOT EXISTS access_days JSONB;
ALTER TABLE users ADD COLUMN IF NOT EXISTS access_start TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS access_end TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS schedule_enabled BOOLEAN DEFAULT FALSE;

-- 5. Password lifecycle (from 0014).
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_temp_password INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS temp_password_expires_at BIGINT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS created_by INTEGER;

-- 6. Safety: if temp_password_expires_at pre-existed as 32-bit INTEGER,
--    widen it to BIGINT (epoch-millis overflow). No-op if already BIGINT.
ALTER TABLE users ALTER COLUMN temp_password_expires_at TYPE BIGINT
  USING temp_password_expires_at::BIGINT;

-- 7. Helpful lookup indexes. Kept as plain (non-unique) indexes so they can
--    never fail on a pre-existing table that happens to hold duplicate phones
--    (uniqueness is enforced at the app layer + the original 0001 schema).
CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
