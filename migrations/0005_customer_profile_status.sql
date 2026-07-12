-- =====================================================================
-- Customer profile administration updates
-- =====================================================================

ALTER TABLE customers ADD COLUMN status TEXT DEFAULT 'active';
