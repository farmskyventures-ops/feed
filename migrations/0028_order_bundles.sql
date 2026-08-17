-- =====================================================================
-- 0028 — Multi-product bundled checkout.
--
--   A "bundle" groups several individual murabaha_contracts rows (one per
--   product, each keeping its own payment_type / term / deposit so every item
--   independently respects its listing or finance-specified conditions) under
--   a single shared bundle_ref. This lets both AGENTS (Buy-For) and FARMERS
--   place one checkout that contains multiple products.
--
--   SCHEMA only (idempotent DDL applied by backend/db-init.ts on every boot).
--   db-init swallows "duplicate column" (42701) so re-running is safe.
-- =====================================================================

-- Shared reference stamped on every contract created in the same bundled
-- checkout. NULL for legacy / single-item orders placed the old way.
ALTER TABLE murabaha_contracts ADD COLUMN bundle_ref TEXT;

-- Speed up "fetch all items in this bundle" lookups.
CREATE INDEX IF NOT EXISTS idx_murabaha_bundle_ref ON murabaha_contracts (bundle_ref);
