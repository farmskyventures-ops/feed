-- =====================================================================
-- 0033 — Agreement source mode (Upload Document vs Type Agreement)
--
-- When listing inventory + setting up cash / financing (Murabaha) terms, the
-- person adding the agreement can now CHOOSE, via a dropdown, HOW the agreement
-- is supplied for each payment path:
--
--   'upload' — Document Upload: a PDF or Word document is stored on the
--              product and rendered at checkout for digital acceptance or
--              offline download & signing.
--   'editor' — Built-in Text Editor: rich-text content typed directly and
--              saved on the product, displayed at checkout for digital
--              acceptance or offline download & signing.
--
-- Existing rows are backfilled: if a doc URL is present the mode is 'upload',
-- otherwise 'editor' (preserving current behaviour).
--
-- Idempotent + auto-applied by db-init on boot.
-- =====================================================================

ALTER TABLE products ADD COLUMN IF NOT EXISTS cash_agreement_source TEXT DEFAULT 'editor';
ALTER TABLE products ADD COLUMN IF NOT EXISTS financing_agreement_source TEXT DEFAULT 'editor';

UPDATE products
   SET cash_agreement_source = CASE
         WHEN cash_terms_doc_url IS NOT NULL AND cash_terms_doc_url <> '' THEN 'upload'
         ELSE 'editor' END
 WHERE cash_agreement_source IS NULL OR cash_agreement_source = '';

UPDATE products
   SET financing_agreement_source = CASE
         WHEN financing_terms_doc_url IS NOT NULL AND financing_terms_doc_url <> '' THEN 'upload'
         ELSE 'editor' END
 WHERE financing_agreement_source IS NULL OR financing_agreement_source = '';
