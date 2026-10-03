-- =====================================================================
-- 0038 — Inventory: "Show buyer" supplier-cost / markup visibility toggle
--
-- Adds a per-product flag controlling whether the BUYER sees the full price
-- breakdown (supplier/buying cost + markups) at checkout, or only the final
-- payable price. Default 0 (hidden) — buyers see only the final price unless the
-- lister explicitly opts in, matching the spec's privacy-first default.
--
-- Idempotent + auto-applied by db-init on boot.
-- =====================================================================

ALTER TABLE products ADD COLUMN IF NOT EXISTS show_buyer INTEGER DEFAULT 0;
