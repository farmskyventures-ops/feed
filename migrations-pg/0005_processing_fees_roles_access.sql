-- =====================================================================
-- 0005: Processing fees, dynamic roles, granular permissions,
--       data-object visibility, and time-based access control.
-- =====================================================================

-- ---------------------------------------------------------------------
-- Global application settings (key/value JSON store). Used for the
-- Financing & Markup settings incl. the Processing Fee configuration.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_settings (
  key         TEXT PRIMARY KEY,
  value       TEXT,                       -- JSON payload
  updated_by  INTEGER,
  updated_at  TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Seed a sensible default processing-fee configuration (disabled).
--   mode: 'none' | 'percentage' | 'tiered'
--   percentage_rate: flat % of the amount borrowed (used when mode='percentage')
--   tiers: [{ min, max, fee }] flat fee per bracket (used when mode='tiered')
INSERT INTO app_settings (key, value)
VALUES ('processing_fee', '{"mode":"none","percentage_rate":0,"tiers":[]}')
ON CONFLICT (key) DO NOTHING;

-- Seed a default global finance markup (per-product markup still overrides).
INSERT INTO app_settings (key, value)
VALUES ('finance_markup', '{"default_markup_pct":20}')
ON CONFLICT (key) DO NOTHING;

-- ---------------------------------------------------------------------
-- Time-Based Access Control (login window) per user.
--   access_days  : JSON array of active weekday numbers (0=Sun .. 6=Sat)
--   access_start : "HH:MM" local start of the allowed login window
--   access_end   : "HH:MM" local end of the allowed login window
-- NULL / empty => no restriction (24/7 access).
-- ---------------------------------------------------------------------
ALTER TABLE users ADD COLUMN IF NOT EXISTS access_days  TEXT;   -- JSON array of 0-6
ALTER TABLE users ADD COLUMN IF NOT EXISTS access_start TEXT;   -- "HH:MM"
ALTER TABLE users ADD COLUMN IF NOT EXISTS access_end   TEXT;   -- "HH:MM"

-- Store the processing fee actually charged on a contract for auditability.
ALTER TABLE murabaha_contracts ADD COLUMN IF NOT EXISTS processing_fee DOUBLE PRECISION DEFAULT 0;
