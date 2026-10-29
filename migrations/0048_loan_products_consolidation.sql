-- =====================================================================
-- 0048 — Loan/Financing Products consolidation + explicit product states
--
-- Resolves the TRIPLE-REDUNDANCY of financing configuration (inventory form,
-- finance settings, approval queue) by making `financing_types` the SOLE
-- authoring tool for financing rules. The inventory form becomes a MAPPING step
-- (link a product to pre-configured loan products) and the approval queue
-- approves/rejects LINK requests only.
--
-- 1. Extend `financing_types` into full "Loan/Financing Products": the rate,
--    term, deposit, markup, processing-fee and agreement fields that were
--    previously authored inline on each product now live here (one source of
--    truth). All columns are ADDITIVE + nullable so existing rows keep working.
-- 2. Add explicit product finance states on `products`:
--      CASH_ONLY_ACTIVE | FINANCE_PENDING_APPROVAL | FINANCE_APPROVED
--    stored in the existing finance_status column alongside the legacy values,
--    via a derived finance_state column kept in sync by the app.
-- 3. A product↔loan-product mapping is captured by `financing_type_key` (already
--    on products) plus a new `finance_pending_type_key` holding the requested
--    (not-yet-approved) link so cash stays active while finance is pending.
--
-- STRICTLY ADDITIVE / NON-BREAKING. Idempotent. Mirrored across all 3 apps.
-- =====================================================================

-- 1. Promote financing_types to full loan products (additive columns).
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS interest_pct REAL;
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS markup_pct REAL;
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS deposit_pct REAL;
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS term_min_months INTEGER;
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS term_max_months INTEGER;
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS tenure_unit TEXT;           -- monthly | yearly | custom
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS rate_per_cycle REAL;
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS amount_per_cycle REAL;
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS cycle_count INTEGER;
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS cycle_length_days INTEGER;
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS frequency TEXT;             -- daily | weekly | monthly
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS processing_fee_json TEXT;   -- per-loan-product processing fee config
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS terms_text TEXT;
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS terms_doc_url TEXT;

-- 2. Explicit product finance-state machine (additive; legacy finance_status kept).
--    finance_state is the NEW canonical state; finance_status is retained for
--    back-compat with existing queries ('published' == FINANCE_APPROVED or
--    CASH_ONLY_ACTIVE; 'pending_finance' == FINANCE_PENDING_APPROVAL).
ALTER TABLE products ADD COLUMN IF NOT EXISTS finance_state TEXT;
-- The pre-configured loan product a lister REQUESTED but which is not yet
-- approved. Kept separate from financing_type_key so cash stays active and the
-- approved link is only promoted into financing_type_key on approval.
ALTER TABLE products ADD COLUMN IF NOT EXISTS finance_pending_type_key TEXT;

-- 3. Backfill finance_state from the legacy columns (one-time, idempotent).
UPDATE products
   SET finance_state = CASE
     WHEN finance_status = 'pending_finance' THEN 'FINANCE_PENDING_APPROVAL'
     WHEN financing_enabled = 1 AND finance_status = 'published' THEN 'FINANCE_APPROVED'
     ELSE 'CASH_ONLY_ACTIVE'
   END
 WHERE finance_state IS NULL;
