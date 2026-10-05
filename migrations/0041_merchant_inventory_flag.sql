-- =====================================================================
-- 0041 — "Merchant" inventory source flag on users
--
-- During onboarding, when a user is granted the Inventory Management role
-- (can_manage_inventory), a Super-Admin may mark that user's inventory source
-- as "Merchant". Every product such a user creates is then permanently tagged
-- source_platform='merchant' (while keeping the existing marketplace category
-- split: Equipment / Feeds / Crop Inputs).
--
-- Idempotent + auto-applied by db-init on boot.
-- =====================================================================

ALTER TABLE users ADD COLUMN IF NOT EXISTS inventory_is_merchant INTEGER NOT NULL DEFAULT 0;
