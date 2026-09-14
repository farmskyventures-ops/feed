-- =====================================================================
-- 0034 — Quick Communication contacts + CRM Ticketing System
--
-- A) Communication contacts
--    Adds an optional WhatsApp number to users + customers so the per-row
--    quick-action buttons (Call / Email / SMS / WhatsApp) can pre-fill the
--    right number. Phone/email already exist; whatsapp defaults to the mobile.
--
-- B) CRM ticketing
--    crm_ticket_categories   — configurable headers (Sales, Technical, …)
--    crm_category_assignees  — which users/teams handle each category
--    crm_tickets             — the tickets themselves (status, priority,
--                              category, subject user/customer, assignee)
--    crm_ticket_notes        — timeline of notes / status changes / escalations
--
-- C) RBAC permissions
--    view_crm                — see the CRM + tickets in one's categories
--    manage_crm              — create / update / resolve / escalate tickets
--    manage_ticket_categories— Super-Admin: configure categories + assignees
--
-- Idempotent + auto-applied by db-init on boot.
-- =====================================================================

-- A) Communication contacts -------------------------------------------------
ALTER TABLE users ADD COLUMN IF NOT EXISTS whatsapp TEXT;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS whatsapp TEXT;

-- B) CRM tables -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS crm_ticket_categories (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  category_key TEXT UNIQUE NOT NULL,
  name        TEXT NOT NULL,
  description TEXT,
  active      INTEGER NOT NULL DEFAULT 1,
  sort_order  INTEGER NOT NULL DEFAULT 100,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS crm_category_assignees (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  category_id INTEGER NOT NULL,
  user_id     TEXT NOT NULL,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_crm_cat_assignee_cat ON crm_category_assignees(category_id);
CREATE INDEX IF NOT EXISTS idx_crm_cat_assignee_user ON crm_category_assignees(user_id);

CREATE TABLE IF NOT EXISTS crm_tickets (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  ticket_ref     TEXT UNIQUE NOT NULL,
  subject        TEXT NOT NULL,
  description    TEXT,
  category_id    INTEGER,
  status         TEXT NOT NULL DEFAULT 'open',       -- open|in_progress|escalated|resolved|closed
  priority       TEXT NOT NULL DEFAULT 'medium',     -- low|medium|high|urgent
  customer_id    INTEGER,                             -- linked farmer (optional)
  subject_user_id TEXT,                               -- linked user account (optional)
  contact_name   TEXT,
  contact_phone  TEXT,
  contact_email  TEXT,
  assigned_to    TEXT,                                -- user id currently owning it
  created_by     TEXT NOT NULL,
  resolution     TEXT,
  resolved_at    TIMESTAMP,
  resolved_by    TEXT,
  created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_crm_tickets_status ON crm_tickets(status);
CREATE INDEX IF NOT EXISTS idx_crm_tickets_category ON crm_tickets(category_id);
CREATE INDEX IF NOT EXISTS idx_crm_tickets_assigned ON crm_tickets(assigned_to);
CREATE INDEX IF NOT EXISTS idx_crm_tickets_customer ON crm_tickets(customer_id);
CREATE INDEX IF NOT EXISTS idx_crm_tickets_priority ON crm_tickets(priority);

CREATE TABLE IF NOT EXISTS crm_ticket_notes (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ticket_id   INTEGER NOT NULL,
  author_id   TEXT,
  note        TEXT NOT NULL,
  action      TEXT,                                   -- comment|status|escalate|resolve|assign|create
  is_internal INTEGER NOT NULL DEFAULT 1,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_crm_notes_ticket ON crm_ticket_notes(ticket_id);

-- C) RBAC permissions -------------------------------------------------------
INSERT OR IGNORE INTO permission_catalog (permission_key, label, description, category) VALUES
  ('view_crm', 'View CRM & Tickets', 'Access the Sales & Support CRM and view tickets within assigned categories.', 'crm'),
  ('manage_crm', 'Manage CRM Tickets', 'Create, update, resolve and escalate CRM tickets on behalf of users/customers.', 'crm'),
  ('manage_ticket_categories', 'Configure Ticket Categories', 'Create ticket categories/headers and assign the users/teams who handle each.', 'crm');

-- Grant CRM permissions to admin role templates + existing admin users so they
-- render pre-checked in the permission panel.
UPDATE role_templates
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb
        || '{"view_crm":true,"manage_crm":true,"manage_ticket_categories":true}'::jsonb)::text
 WHERE role_key IN ('super_admin', 'admin');
UPDATE users
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb
        || '{"view_crm":true,"manage_crm":true,"manage_ticket_categories":true}'::jsonb)::text
 WHERE role IN ('super_admin', 'admin');

-- Agents + support can view and work tickets by default (categories still gate
-- WHICH tickets they see).
UPDATE role_templates
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb
        || '{"view_crm":true,"manage_crm":true}'::jsonb)::text
 WHERE role_key IN ('agent', 'support', 'operations_finance');

-- Seed the default ticket categories.
INSERT OR IGNORE INTO crm_ticket_categories (category_key, name, description, sort_order) VALUES
  ('sales', 'Sales', 'Sales enquiries, quotations and new orders.', 10),
  ('technical', 'Technical', 'Technical issues with equipment, the platform or accounts.', 20),
  ('payments', 'Payments', 'Payment, repayment, wallet and settlement issues.', 30),
  ('agronomy', 'Agronomy', 'Agronomic support and advisory requests.', 40);

-- Backfill whatsapp from the existing mobile/phone where empty so the WhatsApp
-- button has a sensible default.
UPDATE customers SET whatsapp = mobile WHERE (whatsapp IS NULL OR whatsapp = '') AND mobile IS NOT NULL AND mobile <> '';
UPDATE users SET whatsapp = phone WHERE (whatsapp IS NULL OR whatsapp = '') AND phone IS NOT NULL AND phone <> '';
