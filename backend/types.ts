import type { MpesaEnv } from './mpesa'
import type { SmsEnv } from './sms'
import type { EmailEnv } from './email'
import type { SasaPayEnv } from './sasapay'
import type { BuniEnv } from './buni'
import type { GatewayEnv } from './payment-gateway-client'

export type Bindings = MpesaEnv & SmsEnv & EmailEnv & SasaPayEnv & BuniEnv & GatewayEnv & {
  DB: any
  TRANSUNION_API_URL?: string
  TRANSUNION_API_KEY?: string
  TRANSUNION_CLIENT_ID?: string
  TRANSUNION_ENV?: string
  // Auth/session signing secret (fail-closed in production if unset)
  SESSION_SECRET?: string
  // ---- Cross-platform (Equipment <-> Feed) configuration ----
  APP_TYPE?: string                 // 'equipment' | 'feed' — data-scope + payment-host context
  PUBLIC_BASE_URL?: string          // this app's public origin (hosted checkout URLs)
  CROSS_APP_URL?: string            // sibling app origin ('Shop Equipment'/'Shop Feeds' target)
  CROSS_APP_HMAC_SECRET?: string    // shared secret for cross-app SSO handoff tokens
  // Phase 4 — standardized auth hashing (must match sibling app)
  AUTH_HASH_ITERATIONS?: string
  AUTH_HASH_KEYLEN?: string
  AUTH_PEPPER?: string
  // ---- Farmsky Score cross-app SSO ----
  SCORE_APP_URL?: string
  // ---- Shared central-DB isolation / tenancy ----
  DB_SCHEMA?: string                // optional schema pin on a shared central Postgres DB
  EQUIPMENT_ORG_ID?: string         // default tenant for rows created outside an admin session
  DEFAULT_ORG_ID?: string           // alias/fallback default tenant
  // ---- Automated backup email delivery + external cron trigger ----
  BACKUP_EMAIL_TO?: string
  BACKUP_NOTIFY_EMAIL?: string
  ADMIN_TASK_TOKEN?: string
  INTERNAL_SCHEDULER_NONCE?: string
}

export type SessionUser = {
  // Normally an INTEGER id; on a shared central DB the users table may be
  // UUID-keyed (created by a sibling app such as Score), so allow string too.
  id: number | string
  // Multitenant scope on the shared central DB (users.org_id UUID). Null on the
  // Feed-only dev DB shape that has no org_id column.
  org_id?: string | null
  full_name: string
  phone: string
  email?: string | null
  avatar_url?: string | null
  role: string
  region?: string
  label?: string
  permissions?: Record<string, boolean>
}
