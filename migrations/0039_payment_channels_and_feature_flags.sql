-- =====================================================================
-- 0039 — Payment Channel Management + Feature Management & QA
--
-- Two centralized governance modules sharing the same three-step lifecycle
-- (sandbox → testing → live) and global-or-per-user scoping:
--
--   payment_channels    — one row per payment rail (mpesa | sasapay | buni).
--     stage: 'sandbox' (Super-Admin only), 'testing' (whitelisted pilot users),
--     'live' (selected users OR global/system-wide). `global_enabled` makes it
--     available to everyone when live.
--   payment_channel_users — per-user grants for a channel during testing/live
--     (the restricted subset / selected users).
--
--   feature_flags       — one row per governed feature.
--     Same stage model: sandbox (hidden from end users), testing (whitelist),
--     live (selected users or global). Features must be approved by a
--     Super-Admin (or delegate) before rendering on standard user interfaces.
--   feature_flag_users  — per-user whitelist/grant for a feature.
--
-- RBAC: `manage_payment_channels` and `manage_features` are delegable
-- permissions (Super-Admin by default) so a Super-Admin can assign management of
-- each module to other users. Configuration (stage, scope, whitelist) remains
-- restricted to Super-Admins or holders of the matching permission.
--
-- Idempotent + auto-applied by db-init on boot.
-- =====================================================================

-- Payment channels -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS payment_channels (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  channel_key    TEXT UNIQUE NOT NULL,          -- 'mpesa' | 'sasapay' | 'buni'
  label          TEXT NOT NULL,
  stage          TEXT NOT NULL DEFAULT 'sandbox', -- sandbox | testing | live
  global_enabled INTEGER NOT NULL DEFAULT 0,     -- when live: 1 = system-wide
  active         INTEGER NOT NULL DEFAULT 1,
  updated_by     TEXT,
  updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS payment_channel_users (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  channel_key TEXT NOT NULL,
  user_id     TEXT NOT NULL,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_pcu_channel ON payment_channel_users(channel_key);
CREATE INDEX IF NOT EXISTS idx_pcu_user ON payment_channel_users(user_id);

-- Seed the three known rails. M-Pesa + SasaPay default to LIVE + global (they
-- were already system-wide before this module existed, so we preserve behaviour);
-- Buni starts in sandbox for controlled rollout.
INSERT OR IGNORE INTO payment_channels (channel_key, label, stage, global_enabled, active) VALUES
  ('mpesa',   'M-Pesa',       'live',    1, 1),
  ('sasapay', 'SasaPay',      'live',    1, 1),
  ('buni',    'KCB (Buni)',   'sandbox', 0, 1);

-- Feature flags --------------------------------------------------------------
CREATE TABLE IF NOT EXISTS feature_flags (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  feature_key    TEXT UNIQUE NOT NULL,
  label          TEXT NOT NULL,
  description    TEXT,
  stage          TEXT NOT NULL DEFAULT 'sandbox', -- sandbox | testing | live
  global_enabled INTEGER NOT NULL DEFAULT 0,
  updated_by     TEXT,
  updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS feature_flag_users (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  feature_key TEXT NOT NULL,
  user_id     TEXT NOT NULL,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_ffu_feature ON feature_flag_users(feature_key);
CREATE INDEX IF NOT EXISTS idx_ffu_user ON feature_flag_users(user_id);

-- RBAC permissions (delegable; Super-Admin by default) ------------------------
INSERT OR IGNORE INTO permission_catalog (permission_key, label, description, category) VALUES
  ('manage_payment_channels', 'Payment Channel Management', 'Configure payment-channel visibility, scope (global/per-user) and the sandbox/testing/live lifecycle.', 'payments'),
  ('manage_features', 'Feature Management & QA', 'Govern feature release: sandbox/testing/live lifecycle, per-user whitelist and global activation.', 'system');

UPDATE role_templates
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb || '{"manage_payment_channels":true,"manage_features":true}'::jsonb)::text
 WHERE role_key = 'super_admin';
UPDATE users
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb || '{"manage_payment_channels":true,"manage_features":true}'::jsonb)::text
 WHERE role = 'super_admin';
