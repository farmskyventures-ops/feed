-- =====================================================================
-- 0042 — Realign the products primary-key sequence
--
-- BUG: seed.sql inserts products with EXPLICIT id values (INSERT ... (id, ...)).
-- On PostgreSQL, inserting an explicit value into a BIGSERIAL/IDENTITY column
-- does NOT advance the column's sequence. So the next app insert (which relies on
-- native auto-generation, correctly supplying no id) gets an id that collides
-- with an already-seeded row → "duplicate key value violates unique constraint
-- products_pkey". It only succeeds after enough retries to walk the sequence past
-- the seeded max.
--
-- FIX: reset the products id sequence to MAX(id)+1 so auto-generated ids always
-- start past the highest existing record. Idempotent + safe to re-run; guarded so
-- it is a no-op on a UUID-keyed products table (shared central DB shape) or when
-- the column has no owned sequence.
--
-- The application insertion logic already relies entirely on native auto-gen (no
-- query in the codebase supplies products.id); this migration closes the gap the
-- explicit-id SEED rows created.
--
-- Auto-applied by db-init on boot (dollar-quote aware runner).
-- =====================================================================

DO $$
DECLARE
  seq text;
  maxid bigint;
BEGIN
  -- Resolve the sequence that owns products.id (NULL if none, e.g. UUID PK).
  seq := pg_get_serial_sequence('products', 'id');
  IF seq IS NOT NULL THEN
    EXECUTE 'SELECT COALESCE(MAX(id), 0) FROM products' INTO maxid;
    -- is_called = true → nextval() returns maxid+1 (the next free id).
    PERFORM setval(seq, GREATEST(maxid, 1), maxid > 0);
  END IF;
END $$;
