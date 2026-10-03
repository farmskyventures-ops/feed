-- =====================================================================
-- 0037 — Field Visit DELETE action (RBAC)
--
-- Adds a dedicated, delegable permission that gates the destructive "Delete"
-- action on Field Visits. Default access is restricted to Super-Admins ONLY;
-- any other user (including plain admins) can delete a field visit only if a
-- Super-Admin explicitly grants them `delete_field_visits` via the RBAC module.
--
-- Idempotent + auto-applied by db-init on boot.
-- =====================================================================

INSERT OR IGNORE INTO permission_catalog (permission_key, label, description, category) VALUES
  ('delete_field_visits', 'Delete Field Visits', 'Permanently delete field-visit records. Destructive; Super-Admin only by default, delegable via RBAC.', 'field');

-- Seed the permission to Super-Admins only (NOT plain admins) so the default
-- matches the spec: Super-Admin by default, delegated to others explicitly.
UPDATE role_templates
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb || '{"delete_field_visits":true}'::jsonb)::text
 WHERE role_key = 'super_admin';
UPDATE users
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb || '{"delete_field_visits":true}'::jsonb)::text
 WHERE role = 'super_admin';
