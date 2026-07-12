-- =====================================================================
-- Custom permission catalog + role templates (managed by Super Admin)
-- =====================================================================

CREATE TABLE IF NOT EXISTS permission_catalog (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  permission_key TEXT UNIQUE NOT NULL,
  label TEXT NOT NULL,
  description TEXT,
  category TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS role_templates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  role_key TEXT UNIQUE NOT NULL,
  label TEXT NOT NULL,
  description TEXT,
  permissions TEXT,
  is_system INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO permission_catalog (permission_key, label, description, category) VALUES
  ('view', 'View dashboards & lists', 'Read-only access to the platform views', 'general'),
  ('edit', 'Edit records', 'Modify customers, equipment, contracts', 'records'),
  ('delete', 'Delete records', 'Remove records permanently', 'records'),
  ('deactivate', 'Suspend / activate accounts', 'Toggle account status for users and farmers', 'users'),
  ('approve', 'Approve financing applications', 'Approve or reject contracts', 'financing'),
  ('dispatch', 'Dispatch equipment', 'Mark approved orders as dispatched', 'logistics'),
  ('add_farmer', 'Onboard farmers', 'Create farmer profiles and complete KYC', 'customers'),
  ('view_farmers', 'View farmer profiles', 'See farmer lists and details', 'customers'),
  ('view_credit_purchases', 'View credit purchases', 'See farmer financing contracts', 'customers'),
  ('manage_users', 'Manage user accounts', 'Create / edit user accounts and roles', 'users'),
  ('request_admin_action', 'Request admin changes', 'Submit change requests for admin review', 'workflow');

INSERT OR IGNORE INTO role_templates (role_key, label, description, permissions, is_system) VALUES
  ('super_admin', 'Super Admin', 'Full control of the platform, including custom role management', '{"view":true,"edit":true,"delete":true,"deactivate":true,"approve":true,"dispatch":true,"add_farmer":true,"view_farmers":true,"view_credit_purchases":true,"manage_users":true,"request_admin_action":true}', 1),
  ('admin', 'Admin', 'Operational administrator with full CRUD access', '{"view":true,"edit":true,"delete":true,"deactivate":true,"approve":true,"dispatch":true,"add_farmer":true,"view_farmers":true,"view_credit_purchases":true,"manage_users":true,"request_admin_action":true}', 1),
  ('operations_finance', 'Operations & Finance', 'Approve, dispatch, and request admin changes', '{"view":true,"approve":true,"dispatch":true,"view_farmers":true,"view_credit_purchases":true,"request_admin_action":true}', 1),
  ('agent', 'Agent', 'Field agent onboarding farmers and tracking purchases', '{"view":true,"add_farmer":true,"view_farmers":true,"view_credit_purchases":true}', 1),
  ('customer', 'Farmer', 'Farmer using the platform', '{"view":true}', 1),
  ('support', 'Support', 'Customer support read access', '{"view":true,"view_farmers":true,"view_credit_purchases":true}', 1);
