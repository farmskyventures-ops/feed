-- =====================================================================
-- 0017 — Contract controls, conditional deletion, strict uniqueness,
--        and the profile-amendment review workflow.
--
--   SCHEMA + SEED only (idempotent DDL/DML applied by backend/db-init.ts on
--   every boot). SQLite-flavoured; db-init transforms to PostgreSQL and
--   swallows "already exists" (42701/42P07/42P06/23505) so re-running is safe.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. RBAC — two new granular permission keys.
--    * can_manage_contracts : may edit / cancel any contract (Feature 1)
--    * can_delete_users     : may delete a platform user, subject to the
--                             cancelled-contract precondition (Feature 2)
--    Admins & super_admins get everything via code; these entries make the
--    intent explicit and drive the frontend check-boxes / role defaults.
-- ---------------------------------------------------------------------
INSERT OR IGNORE INTO permission_catalog (permission_key, label, description, category) VALUES
  ('can_manage_contracts', 'Manage contracts (edit / cancel)', 'Edit contract terms and cancel active or pending contracts', 'finance'),
  ('can_delete_users',     'Delete platform users',           'Remove a user account, provided their contracts are all cancelled', 'users');

-- Grant both keys to admins & super admins by default. jsonb '||' merges the
-- keys without disturbing existing ones (Postgres-native; on SQLite/D1 db-init
-- swallows the unsupported cast and roles fall back to code defaults which
-- already grant admins everything).
UPDATE role_templates
   SET permissions = (permissions::jsonb || '{"can_manage_contracts":true,"can_delete_users":true}'::jsonb)::text
 WHERE role_key IN ('super_admin', 'admin');

-- Operations & finance may manage contracts (edit / cancel) as part of their
-- financing authority, but NOT delete users.
UPDATE role_templates
   SET permissions = (permissions::jsonb || '{"can_manage_contracts":true}'::jsonb)::text
 WHERE role_key = 'operations_finance';

-- ---------------------------------------------------------------------
-- 2. Strict field uniqueness (Feature 3).
--    users.phone is ALREADY "UNIQUE NOT NULL" (migration 0001). Add a
--    database-level UNIQUE constraint on customers.national_id so the DB
--    itself blocks any duplicate National ID at sign-up, on top of the
--    existing application-level check. A partial unique index skips
--    NULL / empty values so legacy rows without an ID are unaffected.
-- ---------------------------------------------------------------------
CREATE UNIQUE INDEX IF NOT EXISTS uq_customers_national_id
  ON customers (national_id)
  WHERE national_id IS NOT NULL AND national_id <> '';

-- Defensive: also assert phone uniqueness on the users table via a named
-- index (the column constraint from 0001 already enforces this; this makes
-- the guarantee explicit and survives any table rebuild).
CREATE UNIQUE INDEX IF NOT EXISTS uq_users_phone ON users (phone);

-- ---------------------------------------------------------------------
-- 3. Profile amendment workflow (Feature 4).
--    Locked identity fields (National ID + phone) can only be changed by
--    submitting a request here. Authorized admins review it on a pending
--    dashboard and accept / reject. On accept, the new values are applied
--    to the user + customer records.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS profile_amendments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,                       -- the requester
  customer_id INTEGER,                            -- linked farmer record (nullable)
  field TEXT NOT NULL,                            -- 'national_id' | 'phone' | 'both'
  current_national_id TEXT,                       -- snapshot at request time
  current_phone TEXT,
  new_national_id TEXT,                           -- requested new value (nullable)
  new_phone TEXT,                                 -- requested new value (nullable)
  reason TEXT NOT NULL,                           -- why the change is needed
  status TEXT NOT NULL DEFAULT 'pending',         -- pending | approved | rejected
  reviewed_by INTEGER,                            -- admin who decided
  review_notes TEXT,
  reviewed_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_profile_amendments_user   ON profile_amendments(user_id);
CREATE INDEX IF NOT EXISTS idx_profile_amendments_status ON profile_amendments(status);
