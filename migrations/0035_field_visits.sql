-- =====================================================================
-- 0035 — Field Visit & Conversion Workflow
--
-- Field agents log interactions with PROSPECTS during field operations,
-- capturing visit metrics + a farming (Livestock/Crop) or AgSME business
-- profile, then CONVERT a prospect into an onboarded user (which provisions
-- a login + SMS credentials via the existing onboarding path).
--
--   field_visits — one row per logged prospect interaction. The rich,
--     conditional profile (livestock/crop/agsme details, multi-input crop
--     rows, etc.) is stored as JSON in `profile_json` so the schema stays
--     stable as the form evolves. Flat columns hold the common/filterable
--     fields + the conversion linkage.
--
-- RBAC: a new delegable permission `manage_field_visits` lets Super-Admins
-- grant the capability to agents (default) and any other role/user.
--
-- Idempotent + auto-applied by db-init on boot.
-- =====================================================================

CREATE TABLE IF NOT EXISTS field_visits (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  visit_ref      TEXT UNIQUE NOT NULL,
  agent_id       TEXT NOT NULL,               -- the field agent / logging user
  visit_date     TEXT,
  location       TEXT,                         -- Location / Market / Town
  notes          TEXT,
  prospect_name  TEXT NOT NULL,
  contact_phone  TEXT,
  profile_type   TEXT,                         -- 'farming' | 'agsme'
  farming_type   TEXT,                         -- 'livestock' | 'crop' (when farming)
  profile_json   TEXT,                         -- full conditional profile payload
  status         TEXT NOT NULL DEFAULT 'prospect', -- prospect | converted
  converted_customer_id INTEGER,               -- set on conversion
  converted_at   TIMESTAMP,
  converted_by   TEXT,
  created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_field_visits_agent ON field_visits(agent_id);
CREATE INDEX IF NOT EXISTS idx_field_visits_status ON field_visits(status);
CREATE INDEX IF NOT EXISTS idx_field_visits_phone ON field_visits(contact_phone);

-- RBAC permission -----------------------------------------------------------
INSERT OR IGNORE INTO permission_catalog (permission_key, label, description, category) VALUES
  ('manage_field_visits', 'Field Visits & Conversion', 'Log field visits with prospects and convert them into onboarded users.', 'field');

-- Grant to admin role templates + existing admins (pre-checked in the panel).
UPDATE role_templates
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb || '{"manage_field_visits":true}'::jsonb)::text
 WHERE role_key IN ('super_admin', 'admin');
UPDATE users
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb || '{"manage_field_visits":true}'::jsonb)::text
 WHERE role IN ('super_admin', 'admin');

-- Agents get field visits by default (it is a core field-agent capability).
UPDATE role_templates
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb || '{"manage_field_visits":true}'::jsonb)::text
 WHERE role_key = 'agent';
