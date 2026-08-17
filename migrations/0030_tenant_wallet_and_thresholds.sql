-- =====================================================================
-- 0031 — Tenant wallet balances, low-balance thresholds & alert state
--        (Complete Payment & Wallet Architecture — Credit API tenant)
--
--   Adds the pieces the central Equipment gateway needs to act as the
--   universal MASTER WALLET LEDGER for metered API-call billing:
--
--     1. app_clients gains alert-webhook + status metadata columns so
--        the /admin/tenants dashboard can manage tenants dynamically
--        (webhook endpoint, secret rotation, suspend/resume) WITHOUT a
--        service restart.
--
--     2. tenant_wallets — a per-tenant, per-user master balance the
--        gateway debits for usage-based (pay-as-you-go) API calls. The
--        Credit app (credit.farmsky.africa) issues signed /wallet/debit
--        requests; the gateway is the single source of truth for the
--        balance. Mirrors the primary Score ledger but is authoritative
--        for the CENTRAL debit path described in the architecture spec.
--
--     3. tenant_alert_settings — per (client_key, user_ref) warning /
--        critical thresholds + channel toggles, synced from the Credit
--        dashboard billing settings. NULL user_ref = tenant default.
--
--     4. tenant_alert_state — dedup / cooldown ledger so a low-balance
--        alert fires at most once per level per 24h window and resets on
--        a top-up that clears the warning threshold.
--
--   Idempotent + safe to re-run. SQLite dialect, transformed to
--   PostgreSQL by backend/db-init.ts. Non-breaking: every statement is
--   additive (CREATE TABLE IF NOT EXISTS / ADD COLUMN IF NOT EXISTS).
-- =====================================================================

-- (1) Tenant/client management metadata for the /admin/tenants dashboard.
ALTER TABLE app_clients ADD COLUMN IF NOT EXISTS webhook_url TEXT;                 -- low-balance / event webhook target (falls back to callback_url)
ALTER TABLE app_clients ADD COLUMN IF NOT EXISTS secret_rotated_at TIMESTAMP;      -- last HMAC-secret rotation time
ALTER TABLE app_clients ADD COLUMN IF NOT EXISTS provisioned_via TEXT DEFAULT 'seed'; -- seed | env | admin_ui
ALTER TABLE app_clients ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- (2) Central master wallet — one balance row per (tenant, user_ref).
--     user_ref is the CALLING app's own user/org identifier (opaque to
--     the gateway); '' means the tenant-wide pooled wallet.
CREATE TABLE IF NOT EXISTS tenant_wallets (
  id            BIGSERIAL PRIMARY KEY,
  client_key    TEXT NOT NULL,                    -- app_clients.client_key
  user_ref      TEXT NOT NULL DEFAULT '',         -- tenant's user/org id ('' = pooled)
  balance_kes   NUMERIC(14,2) NOT NULL DEFAULT 0,
  currency      TEXT NOT NULL DEFAULT 'KES',
  updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (client_key, user_ref)
);
CREATE INDEX IF NOT EXISTS idx_tenant_wallets_client ON tenant_wallets(client_key);

-- Per-tenant master-wallet ledger — every central debit/credit movement.
CREATE TABLE IF NOT EXISTS tenant_wallet_ledger (
  id            BIGSERIAL PRIMARY KEY,
  client_key    TEXT NOT NULL,
  user_ref      TEXT NOT NULL DEFAULT '',
  direction     TEXT NOT NULL,                    -- credit | debit
  amount_kes    NUMERIC(14,2) NOT NULL DEFAULT 0,
  balance_after NUMERIC(14,2),
  origin_reference TEXT,                           -- caller's reference (e.g. CALL_AGSCORE_..)
  description   TEXT NOT NULL DEFAULT '',
  transaction_ref TEXT UNIQUE,                     -- gateway-issued ref (idempotency)
  meta          TEXT NOT NULL DEFAULT '{}',
  created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_tenant_ledger_client ON tenant_wallet_ledger(client_key, user_ref);
CREATE INDEX IF NOT EXISTS idx_tenant_ledger_created ON tenant_wallet_ledger(created_at);

-- (3) Per-tenant/user low-balance alert settings (synced from Credit UI).
CREATE TABLE IF NOT EXISTS tenant_alert_settings (
  id                 BIGSERIAL PRIMARY KEY,
  client_key         TEXT NOT NULL,
  user_ref           TEXT NOT NULL DEFAULT '',    -- '' = tenant default
  currency           TEXT NOT NULL DEFAULT 'KES',
  warning_threshold  NUMERIC(14,2) NOT NULL DEFAULT 1000,
  critical_threshold NUMERIC(14,2) NOT NULL DEFAULT 250,
  email_enabled      INTEGER NOT NULL DEFAULT 1,
  sms_enabled        INTEGER NOT NULL DEFAULT 1,
  webhook_enabled    INTEGER NOT NULL DEFAULT 1,
  notify_email       TEXT,                         -- override recipient
  notify_phone       TEXT,                         -- override recipient
  updated_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (client_key, user_ref)
);
CREATE INDEX IF NOT EXISTS idx_tenant_alert_settings_client ON tenant_alert_settings(client_key);

-- (4) Alert dedup / cooldown state — at most one alert per level per window.
CREATE TABLE IF NOT EXISTS tenant_alert_state (
  id            BIGSERIAL PRIMARY KEY,
  client_key    TEXT NOT NULL,
  user_ref      TEXT NOT NULL DEFAULT '',
  alert_level   TEXT NOT NULL,                    -- warning | critical
  last_sent_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  cleared       INTEGER NOT NULL DEFAULT 0,       -- reset to 0 on a top-up above warning
  UNIQUE (client_key, user_ref, alert_level)
);
CREATE INDEX IF NOT EXISTS idx_tenant_alert_state_client ON tenant_alert_state(client_key, user_ref);
