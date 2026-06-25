-- =====================================================================
-- OTP storage for SMS-based sign-up, sign-in and password reset.
-- =====================================================================
CREATE TABLE IF NOT EXISTS otp_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT NOT NULL,
  code TEXT NOT NULL,
  purpose TEXT NOT NULL DEFAULT 'signup',   -- signup | reset | login
  expires_at INTEGER NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_otp_phone ON otp_codes(phone);

-- Track whether a user has set their own password yet (vs. admin-generated).
ALTER TABLE users ADD COLUMN password_set INTEGER DEFAULT 1;
