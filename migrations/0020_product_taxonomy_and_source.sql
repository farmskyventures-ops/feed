-- =====================================================================
-- 0020 — Product taxonomy + permanent source-platform tagging
--
--   * source_platform  : the ORIGIN app a product was created in. Permanent —
--                        set at insert time, never rewritten. One of:
--                          'equipment' | 'feed' | 'mazao' | 'merchant'
--   * marketplace      : which STOREFRONT section the product displays under.
--                          'equipment' | 'feeds' | 'inputs'
--   * subcategory      : optional second level under category
--                        (e.g. category='Farm Implements', subcategory='Soil Cultivation')
--
--   Isolation rule (enforced in the app layer, defence-in-depth here):
--     - The Equipment app (MAIN) can see EVERY product.
--     - Secondary apps (feed / mazao) may only see rows whose source_platform
--       matches their own key.
--   All marketplaces still share this single central database.
--
--   Idempotent + safe to re-run. On SQLite/D1 the ALTERs degrade gracefully.
-- =====================================================================

ALTER TABLE products ADD COLUMN IF NOT EXISTS source_platform TEXT DEFAULT 'equipment';
ALTER TABLE products ADD COLUMN IF NOT EXISTS marketplace     TEXT DEFAULT 'equipment';
ALTER TABLE products ADD COLUMN IF NOT EXISTS subcategory     TEXT;

-- Backfill existing rows: derive marketplace/source from the legacy product_type.
UPDATE products SET source_platform = 'feed',      marketplace = 'feeds'
 WHERE (source_platform IS NULL OR source_platform = 'equipment')
   AND lower(coalesce(product_type,'')) IN ('feed','feeds');

UPDATE products SET source_platform = 'mazao',     marketplace = 'inputs'
 WHERE (source_platform IS NULL OR source_platform = 'equipment')
   AND lower(coalesce(product_type,'')) IN ('input','inputs','mazao');

-- Everything else stays equipment/equipment (the default).
UPDATE products SET source_platform = 'equipment' WHERE source_platform IS NULL;
UPDATE products SET marketplace     = 'equipment' WHERE marketplace IS NULL;

CREATE INDEX IF NOT EXISTS idx_products_source_platform ON products(source_platform);
CREATE INDEX IF NOT EXISTS idx_products_marketplace     ON products(marketplace);
CREATE INDEX IF NOT EXISTS idx_products_subcategory     ON products(subcategory);
