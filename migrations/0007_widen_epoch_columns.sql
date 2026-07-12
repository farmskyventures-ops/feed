-- =====================================================================
-- Widen epoch-millisecond columns to BIGINT for PostgreSQL compatibility.
-- =====================================================================

ALTER TABLE sessions ALTER COLUMN expires_at TYPE BIGINT USING expires_at::BIGINT;
ALTER TABLE otp_codes ALTER COLUMN expires_at TYPE BIGINT USING expires_at::BIGINT;
