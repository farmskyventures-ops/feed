-- =====================================================================
-- Processing fees, role scheduling (time-based access), and expanded
-- granular permissions (feature config + data visibility).
-- =====================================================================

-- Fix for "column does not exist" error: Clean out any old/conflicting object
-- (table, view, or materialized view) named app_settings so the canonical
-- schema below always applies, regardless of pre-existing remote DB state.
DROP VIEW IF EXISTS app_settings CASCADE;
DROP MATERIALIZED VIEW IF EXISTS app_settings CASCADE;
DROP TABLE IF EXISTS app_settings CASCADE;

-- 1. Global application settings (using JSONB for native PostgreSQL JSON optimization)
CREATE TABLE IF NOT EXISTS app_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value JSONB,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Belt-and-braces: guarantee the canonical columns exist even if an older
-- table survived (CREATE IF NOT EXISTS is a no-op when the table pre-exists).
ALTER TABLE app_settings ADD COLUMN IF NOT EXISTS setting_key TEXT;
ALTER TABLE app_settings ADD COLUMN IF NOT EXISTS setting_value JSONB;
ALTER TABLE app_settings ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;

-- Seed the default processing-fee configuration
INSERT INTO app_settings (setting_key, setting_value) VALUES
    ('processing_fee', '{"enabled":false,"mode":"percentage","percentage_rate":0,"tiers":[]}'::jsonb),
    ('financing_markup', '{"default_cash_markup_pct":10,"default_credit_markup_pct":20}'::jsonb)
ON CONFLICT (setting_key) DO NOTHING;

-- 2. Time-based login window controls, per role template
-- Rendered as JSONB for structured days, TEXT for HH:MM time strings, and native BOOLEAN.
ALTER TABLE role_templates 
    ADD COLUMN IF NOT EXISTS access_days JSONB,
    ADD COLUMN IF NOT EXISTS access_start TEXT,
    ADD COLUMN IF NOT EXISTS access_end TEXT,
    ADD COLUMN IF NOT EXISTS schedule_enabled BOOLEAN DEFAULT FALSE;

-- 3. Per-user override of the login window (optional; falls back to role)
ALTER TABLE users 
    ADD COLUMN IF NOT EXISTS access_days JSONB,
    ADD COLUMN IF NOT EXISTS access_start TEXT,
    ADD COLUMN IF NOT EXISTS access_end TEXT,
    ADD COLUMN IF NOT EXISTS schedule_enabled BOOLEAN DEFAULT FALSE;

-- 4. New granular permission catalog entries
-- Assumes permission_key is the PRIMARY KEY or has a UNIQUE constraint in permission_catalog.
INSERT INTO permission_catalog (permission_key, label, description, category) VALUES
    ('manage_processing_fees', 'Manage Processing Fees', 'Set up and alter processing fee structures (percentage vs range)', 'feature_config'),
    ('manage_markup_pct', 'Manage Markup Percentage', 'Set up and alter the financing markup percentages', 'feature_config'),
    ('view_cash_sales', 'View Cash Sales', 'See cash sales / purchases', 'sales_visibility'),
    ('view_financed_sales', 'View Financed Sales', 'See financed / credit sales', 'sales_visibility'),
    ('view_farmer_profile_data', 'View Farmer Profile Data', 'See farmer profile fields (name, county, value chain, etc.)', 'data_visibility'),
    ('view_financial_data', 'View Financial Data', 'See financial data (loans, deposits, pricing, credit)', 'data_visibility'),
    ('view_document_attachments', 'View Document Attachments', 'See Front ID, Back ID and passport / selfie photos', 'data_visibility')
ON CONFLICT (permission_key) DO NOTHING;

-- 5. Grant the new permissions to full-access system roles
-- Converted string to native PostgreSQL JSONB format.
UPDATE role_templates
   SET permissions = '{"view":true,"edit":true,"delete":true,"deactivate":true,"approve":true,"dispatch":true,"add_farmer":true,"view_farmers":true,"view_credit_purchases":true,"manage_users":true,"request_admin_action":true,"manage_processing_fees":true,"manage_markup_pct":true,"view_cash_sales":true,"view_financed_sales":true,"view_farmer_profile_data":true,"view_financial_data":true,"view_document_attachments":true}'::jsonb
 WHERE role_key IN ('super_admin', 'admin');
