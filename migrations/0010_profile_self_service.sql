-- =====================================================================
-- Self-service profile support:
--   * avatar_url on users (profile picture for every user type)
-- =====================================================================

ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT;
