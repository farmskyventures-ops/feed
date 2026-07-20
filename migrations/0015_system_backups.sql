-- =====================================================================
-- AUTOMATED SYSTEM BACKUPS
-- Stores point-in-time JSON snapshots of all user profiles, transactional
-- records and system-wide data. Backups can be created on demand by an admin
-- or triggered automatically on a fixed cadence (see backend auto-backup gate).
-- =====================================================================

CREATE TABLE IF NOT EXISTS system_backups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  -- 'manual' = admin clicked "Back up now"; 'auto' = cadence-triggered.
  trigger_type TEXT NOT NULL DEFAULT 'manual',
  -- Human summary of what the snapshot contains (row counts per dataset).
  summary TEXT,
  -- Total number of records captured across every dataset.
  record_count INTEGER NOT NULL DEFAULT 0,
  -- Size of the serialized snapshot in bytes.
  size_bytes INTEGER NOT NULL DEFAULT 0,
  -- The full snapshot payload (JSON: { dataset: rows[] }).
  payload TEXT,
  -- 'success' | 'failed'
  status TEXT NOT NULL DEFAULT 'success',
  error TEXT,
  created_by INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_system_backups_created_at ON system_backups (created_at);
CREATE INDEX IF NOT EXISTS idx_system_backups_trigger ON system_backups (trigger_type);
