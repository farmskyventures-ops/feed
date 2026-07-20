-- =====================================================================
-- MULTI-USER ONBOARDING & PASSWORD LIFECYCLE
-- When one party (agent / admin) creates another user, the system issues a
-- random TEMPORARY password that:
--   * must be changed on first login  (must_change_password = 1)
--   * expires after a fixed window     (temp_password_expires_at)
--   * is flagged as temporary          (is_temp_password = 1)
-- On first successful change these flags clear. If the temp password expires
-- before use, the login screen lets the user request an admin-triggered reset.
-- =====================================================================

-- 1 = the user must replace their (temporary) password before using the app.
ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;

-- 1 = the current password stored is a system-generated temporary one.
ALTER TABLE users ADD COLUMN is_temp_password INTEGER NOT NULL DEFAULT 0;

-- Epoch-millis deadline after which the temporary password can no longer be
-- used to sign in (NULL = no expiry / a self-chosen password). BIGINT because
-- epoch-milliseconds overflow a 32-bit INTEGER in PostgreSQL.
ALTER TABLE users ADD COLUMN temp_password_expires_at BIGINT;

-- Who created this user (agent/admin) via the multi-user onboarding flow.
ALTER TABLE users ADD COLUMN created_by INTEGER;

-- Safety: widen the epoch column to BIGINT for deployments where an earlier
-- version of this migration created it as a 32-bit INTEGER (PostgreSQL only;
-- ignored on SQLite where INTEGER is already 64-bit).
ALTER TABLE users ALTER COLUMN temp_password_expires_at TYPE BIGINT USING temp_password_expires_at::BIGINT;
