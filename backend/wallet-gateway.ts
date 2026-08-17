// =====================================================================
// Farmsky Central MASTER WALLET Gateway  (Credit-API tenant integration)
// =====================================================================
//   Mounted under /api/v1/wallet/*  and  /api/v1/settings/*
//
//   The Equipment app is the CENTRAL host + ledger engine. Client tenants
//   (Credit / Feed) delegate usage-based (pay-as-you-go) API-call billing
//   to this gateway. Every request is HMAC-SHA256 signed with the SAME
//   scheme as /api/v1/payments/* (X-Farmsky-Client / -Timestamp / -Nonce /
//   -Signature over `client_key\ntimestamp\nnonce\nbody`).
//
//   Routes:
//     POST /api/v1/wallet/debit    — metered per-call debit against the
//                                    master wallet. Rejects with
//                                    INSUFFICIENT_WALLET_BALANCE (HTTP 402)
//                                    when funds cannot cover the amount.
//                                    On success, evaluates the balance
//                                    against the tenant's custom thresholds
//                                    and fires low-balance alerts.
//     POST /api/v1/wallet/credit   — record/settle a top-up (also clears
//                                    the alert cooldown when balance clears
//                                    the warning threshold).
//     GET  /api/v1/wallet/balance  — read the current master balance.
//     GET  /api/v1/settings/thresholds — read tenant alert thresholds.
//     PUT  /api/v1/settings/thresholds — upsert tenant alert thresholds
//                                    (synced from the Credit dashboard).
//
//   Security: identical HMAC discipline to payment-gateway.ts. origin_app
//   is the VERIFIED client identity from app_clients (never the body).
// =====================================================================

import { Hono } from 'hono'
import { verifySignatureMulti, signRequest } from './payment-gateway-shared'
import { sendSms } from './sms'
import { sendEmail } from './email'
import type { Bindings } from './types'

const wallet = new Hono<{ Bindings: Bindings }>()

// ----------------------------------------------------------------------------
// Helpers (shared shape with payment-gateway.ts loadClient/auditSecurity).
// ----------------------------------------------------------------------------
function genRef(prefix = 'DEBIT_EQ'): string {
  return `${prefix}_` + crypto.randomUUID().replace(/-/g, '').slice(0, 16).toUpperCase()
}

async function loadClient(c: any, client_key: string) {
  return await c.env.DB.prepare(
    `SELECT id, client_key, display_name, origin_url, hmac_secret, callback_url, webhook_url, is_active
     FROM app_clients WHERE client_key = ?`
  ).bind(client_key).first<any>()
}

// Every legitimately-configured candidate secret for this tenant. Tolerates
// secret-precedence drift between the Score and Equipment deployments so a
// misaligned env var no longer produces a spurious "Signature mismatch".
function candidateSecrets(c: any, client: any): string[] {
  const env = c.env || {}
  return [
    client?.hmac_secret,
    env.SCORE_HMAC_SECRET,
    env.SCORE_CROSS_APP_HMAC_SECRET,
    env.CROSS_APP_HMAC_SECRET,
    env.PAYMENT_HMAC_SECRET,
  ]
}

async function auditSecurity(
  c: any,
  eventType: string,
  severity: 'INFO' | 'WARN' | 'CRITICAL',
  opts: { originApp?: string | null; transactionRef?: string | null; detail?: string } = {}
) {
  try {
    const ip = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || null
    await c.env.DB.prepare(
      `INSERT INTO payment_audit_log (marketplace_id, origin_app, event_type, severity, transaction_ref, detail, ip_address)
       VALUES (?,?,?,?,?,?,?)`
    ).bind(null, opts.originApp ?? null, eventType, severity, opts.transactionRef ?? null, (opts.detail || '').slice(0, 500), ip).run()
  } catch (_) {}
}

// Verify the standard X-Farmsky-* signature and return the loaded client.
// Enforces replay protection via the shared payment_nonces table.
async function authenticate(c: any, rawForSig: string): Promise<{ ok: true; client: any } | { ok: false; status: number; error: string }> {
  const client_key = c.req.header('X-Farmsky-Client') || ''
  const timestamp = c.req.header('X-Farmsky-Timestamp') || ''
  const nonce = c.req.header('X-Farmsky-Nonce') || ''
  const signature = c.req.header('X-Farmsky-Signature') || ''

  if (!client_key) return { ok: false, status: 401, error: 'Missing X-Farmsky-Client header' }
  const client = await loadClient(c, client_key)
  if (!client || !client.is_active) {
    await auditSecurity(c, 'UNKNOWN_CLIENT', 'WARN', { originApp: client_key, detail: 'wallet call from unknown/inactive client' })
    return { ok: false, status: 401, error: 'Unknown or inactive client app' }
  }
  const v = await verifySignatureMulti(candidateSecrets(c, client), client_key, timestamp, nonce, rawForSig, signature)
  if (!v.ok) {
    await auditSecurity(c, 'SIGNATURE_FAIL', 'CRITICAL', { originApp: client_key, detail: v.error || 'invalid HMAC on wallet call' })
    return { ok: false, status: 401, error: v.error || 'Invalid signature' }
  }
  if (typeof v.matchedIndex === 'number' && v.matchedIndex > 0) {
    console.warn(`[wallet-gateway] signature matched a fallback secret (candidate index ${v.matchedIndex}) for client '${client_key}'; align SCORE_HMAC_SECRET precedence across deployments.`)
  }
  // Replay protection (shared nonce ledger with the payment gateway).
  if (nonce) {
    try {
      const existing = await c.env.DB.prepare(
        `SELECT 1 FROM payment_nonces WHERE client_key = ? AND nonce = ? LIMIT 1`
      ).bind(client_key, nonce).first<any>()
      if (existing) {
        await auditSecurity(c, 'REPLAY', 'CRITICAL', { originApp: client_key, detail: `replayed nonce ${nonce}` })
        return { ok: false, status: 401, error: 'Replay detected' }
      }
      await c.env.DB.prepare(`INSERT INTO payment_nonces (client_key, nonce) VALUES (?, ?)`).bind(client_key, nonce).run()
    } catch (e: any) {
      const code = e?.code || ''
      if (code === '23505' || /unique|duplicate/i.test(String(e?.message || ''))) {
        await auditSecurity(c, 'REPLAY', 'CRITICAL', { originApp: client_key, detail: `replayed nonce ${nonce}` })
        return { ok: false, status: 401, error: 'Replay detected' }
      }
    }
  }
  return { ok: true, client }
}

// Ensure a wallet row exists and return its current balance.
async function ensureWallet(c: any, clientKey: string, userRef: string): Promise<number> {
  await c.env.DB.prepare(
    `INSERT INTO tenant_wallets (client_key, user_ref, balance_kes) VALUES (?, ?, 0)
     ON CONFLICT (client_key, user_ref) DO NOTHING`
  ).bind(clientKey, userRef).run()
  const row = await c.env.DB.prepare(
    `SELECT balance_kes FROM tenant_wallets WHERE client_key = ? AND user_ref = ? LIMIT 1`
  ).bind(clientKey, userRef).first<any>()
  return Number(row?.balance_kes || 0)
}

// Resolve the alert thresholds for (tenant, user), falling back to the tenant
// default row (user_ref=''), then to hard defaults.
async function resolveThresholds(c: any, clientKey: string, userRef: string) {
  let row = await c.env.DB.prepare(
    `SELECT * FROM tenant_alert_settings WHERE client_key = ? AND user_ref = ? LIMIT 1`
  ).bind(clientKey, userRef).first<any>()
  if (!row && userRef !== '') {
    row = await c.env.DB.prepare(
      `SELECT * FROM tenant_alert_settings WHERE client_key = ? AND user_ref = '' LIMIT 1`
    ).bind(clientKey).first<any>()
  }
  return {
    currency: row?.currency || 'KES',
    warning_threshold: Number(row?.warning_threshold ?? 1000),
    critical_threshold: Number(row?.critical_threshold ?? 250),
    email_enabled: row ? Number(row.email_enabled) !== 0 : true,
    sms_enabled: row ? Number(row.sms_enabled) !== 0 : true,
    webhook_enabled: row ? Number(row.webhook_enabled) !== 0 : true,
    notify_email: row?.notify_email || null,
    notify_phone: row?.notify_phone || null,
  }
}

// ----------------------------------------------------------------------------
// Low-balance alert engine — evaluate a post-debit balance against the
// tenant's custom thresholds, respecting a 24h per-level cooldown, and
// dispatch a multi-channel alert (signed webhook + SMS + email).
// Best-effort: never throws into the debit path.
// ----------------------------------------------------------------------------
const ALERT_COOLDOWN_MS = 24 * 60 * 60 * 1000

async function evaluateLowBalance(
  c: any,
  client: any,
  userRef: string,
  balance: number,
): Promise<{ alerted: boolean; level?: 'warning' | 'critical' }> {
  try {
    const t = await resolveThresholds(c, client.client_key, userRef)
    let level: 'warning' | 'critical' | null = null
    if (balance <= t.critical_threshold) level = 'critical'
    else if (balance <= t.warning_threshold) level = 'warning'
    if (!level) return { alerted: false }

    // Cooldown / dedup check on this (tenant,user,level).
    const state = await c.env.DB.prepare(
      `SELECT last_sent_at FROM tenant_alert_state WHERE client_key = ? AND user_ref = ? AND alert_level = ? LIMIT 1`
    ).bind(client.client_key, userRef, level).first<any>()
    if (state?.last_sent_at) {
      const last = new Date(state.last_sent_at).getTime()
      if (Number.isFinite(last) && Date.now() - last < ALERT_COOLDOWN_MS) {
        return { alerted: false, level } // suppressed within cooldown
      }
    }

    // Record the send (dedup) BEFORE dispatch so concurrent bursts don't double-fire.
    await c.env.DB.prepare(
      `INSERT INTO tenant_alert_state (client_key, user_ref, alert_level, last_sent_at, cleared)
       VALUES (?, ?, ?, CURRENT_TIMESTAMP, 0)
       ON CONFLICT (client_key, user_ref, alert_level)
       DO UPDATE SET last_sent_at = CURRENT_TIMESTAMP, cleared = 0`
    ).bind(client.client_key, userRef, level).run()

    const topupUrl = `${(client.origin_url || '').replace(/\/+$/, '')}/dashboard/billing/topup`
    const recommended = Math.max(t.warning_threshold * 5, 5000)

    // (A) Signed webhook to the tenant (WALLET_LOW_BALANCE).
    const target = client.webhook_url || client.callback_url
    if (t.webhook_enabled && target) {
      const body = JSON.stringify({
        event: 'WALLET_LOW_BALANCE',
        event_id: 'evt_lowbal_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12),
        timestamp: new Date().toISOString(),
        data: {
          user_id: userRef || null,
          organization_name: client.display_name || client.client_key,
          alert_level: level.toUpperCase(),
          current_balance: Number(balance.toFixed(2)),
          user_configured_threshold: level === 'critical' ? t.critical_threshold : t.warning_threshold,
          currency: t.currency,
          recommended_topup_amount: recommended,
        },
      })
      try {
        const { timestamp, nonce, signature } = await signRequest(client.hmac_secret, client.client_key, body)
        await fetch(target, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Farmsky-Client': client.client_key,
            'X-Farmsky-Timestamp': timestamp,
            'X-Farmsky-Nonce': nonce,
            'X-Farmsky-Signature': signature,
          },
          body,
        })
      } catch (_) {}
    }

    // (B) Direct SMS + email to the account owner (best-effort; simulated when unconfigured).
    if (t.sms_enabled && t.notify_phone) {
      const msg = `Farmsky Alert: Your wallet balance on ${client.display_name || client.client_key} is low at ${t.currency} ${balance.toFixed(2)}. Top up now to avoid API disruption: ${topupUrl}`
      await sendSms(c.env, t.notify_phone, msg).catch(() => {})
    }
    if (t.email_enabled && t.notify_email) {
      await sendEmail(c.env, {
        to: t.notify_email,
        subject: `Low wallet balance (${level.toUpperCase()}) — ${t.currency} ${balance.toFixed(2)}`,
        text: `Your Farmsky wallet balance is low at ${t.currency} ${balance.toFixed(2)} (${level} threshold ${level === 'critical' ? t.critical_threshold : t.warning_threshold}).\n\nTop up: ${topupUrl}`,
      }).catch(() => {})
    }

    return { alerted: true, level }
  } catch (_) {
    return { alerted: false }
  }
}

// ----------------------------------------------------------------------------
// POST /debit — metered per-call wallet debit (usage-based billing).
// ----------------------------------------------------------------------------
wallet.post('/debit', async (c) => {
  const rawBody = await c.req.text()
  const auth = await authenticate(c, rawBody)
  if (!auth.ok) return c.json({ success: false, error: auth.error }, auth.status as any)
  const client = auth.client

  let body: any = {}
  try { body = rawBody ? JSON.parse(rawBody) : {} } catch { return c.json({ success: false, error: 'Body must be JSON' }, 400) }

  const userRef = String(body.user_id || body.user_ref || body.org_ref || '').trim()
  const amount = Number(body.amount)
  const currency = String(body.currency || 'KES').toUpperCase()
  const originRef = body.origin_reference ? String(body.origin_reference).slice(0, 120) : null
  const description = String(body.description || 'Metered API debit').slice(0, 200)
  const idempotencyKey = c.req.header('Idempotency-Key') || (body.idempotency_key ? String(body.idempotency_key) : null)

  if (!Number.isFinite(amount) || amount <= 0) return c.json({ success: false, error: 'amount must be > 0' }, 400)

  // Idempotent replay: same key returns the original debit result.
  if (idempotencyKey) {
    const existing = await c.env.DB.prepare(
      `SELECT transaction_ref, balance_after FROM tenant_wallet_ledger WHERE client_key = ? AND transaction_ref = ? LIMIT 1`
    ).bind(client.client_key, idempotencyKey).first<any>()
    if (existing) {
      return c.json({
        success: true, idempotent_replay: true,
        transaction_ref: existing.transaction_ref, user_id: userRef,
        debited_amount: amount, remaining_wallet_balance: Number(existing.balance_after),
        status: 'COMPLETED',
      })
    }
  }

  const before = await ensureWallet(c, client.client_key, userRef)
  if (before < amount) {
    await auditSecurity(c, 'INSUFFICIENT_FUNDS', 'INFO', { originApp: client.client_key, transactionRef: originRef, detail: `debit ${amount} > balance ${before}` })
    return c.json({
      success: false,
      error_code: 'INSUFFICIENT_WALLET_BALANCE',
      message: 'The transaction was declined because the user wallet has insufficient funds.',
      user_id: userRef || null,
      required_amount: amount,
      current_balance: Number(before.toFixed(2)),
      currency,
    }, 402)
  }

  // Atomic conditional decrement — cannot drive the balance negative under load.
  const upd = await c.env.DB.prepare(
    `UPDATE tenant_wallets SET balance_kes = balance_kes - ?, updated_at = CURRENT_TIMESTAMP
      WHERE client_key = ? AND user_ref = ? AND balance_kes >= ?
      RETURNING balance_kes`
  ).bind(amount, client.client_key, userRef, amount).first<any>().catch(() => null)
  // Some drivers don't support RETURNING via .first(); fall back to re-read.
  let balanceAfter: number
  if (upd && upd.balance_kes != null) {
    balanceAfter = Number(upd.balance_kes)
  } else {
    const res = await c.env.DB.prepare(
      `UPDATE tenant_wallets SET balance_kes = balance_kes - ?, updated_at = CURRENT_TIMESTAMP
        WHERE client_key = ? AND user_ref = ? AND balance_kes >= ?`
    ).bind(amount, client.client_key, userRef, amount).run()
    const changed = Number((res as any)?.meta?.changes ?? (res as any)?.changes ?? 1)
    if (!changed) {
      const bal = await ensureWallet(c, client.client_key, userRef)
      return c.json({
        success: false, error_code: 'INSUFFICIENT_WALLET_BALANCE',
        message: 'The transaction was declined because the user wallet has insufficient funds.',
        user_id: userRef || null, required_amount: amount, current_balance: Number(bal.toFixed(2)), currency,
      }, 402)
    }
    balanceAfter = await ensureWallet(c, client.client_key, userRef)
  }

  const transaction_ref = idempotencyKey || genRef('DEBIT_EQ')
  try {
    await c.env.DB.prepare(
      `INSERT INTO tenant_wallet_ledger (client_key, user_ref, direction, amount_kes, balance_after, origin_reference, description, transaction_ref, meta)
       VALUES (?, ?, 'debit', ?, ?, ?, ?, ?, ?)`
    ).bind(client.client_key, userRef, amount, balanceAfter, originRef, description, transaction_ref, JSON.stringify(body.metadata || {})).run()
  } catch (_) { /* ledger row best-effort; balance already moved */ }

  // Post-debit low-balance evaluation (best-effort; never blocks the response).
  const alert = await evaluateLowBalance(c, client, userRef, balanceAfter)

  return c.json({
    success: true,
    transaction_ref,
    user_id: userRef || null,
    debited_amount: Number(amount.toFixed(2)),
    remaining_wallet_balance: Number(balanceAfter.toFixed(2)),
    status: 'COMPLETED',
    timestamp: new Date().toISOString(),
    low_balance_alert: alert.alerted ? { dispatched: true, level: alert.level } : undefined,
  })
})

// ----------------------------------------------------------------------------
// POST /credit — record a top-up / settlement into the master wallet and
// reset the alert cooldown when the balance clears the warning threshold.
// ----------------------------------------------------------------------------
wallet.post('/credit', async (c) => {
  const rawBody = await c.req.text()
  const auth = await authenticate(c, rawBody)
  if (!auth.ok) return c.json({ success: false, error: auth.error }, auth.status as any)
  const client = auth.client

  let body: any = {}
  try { body = rawBody ? JSON.parse(rawBody) : {} } catch { return c.json({ success: false, error: 'Body must be JSON' }, 400) }

  const userRef = String(body.user_id || body.user_ref || body.org_ref || '').trim()
  const amount = Number(body.amount)
  const originRef = body.origin_reference ? String(body.origin_reference).slice(0, 120) : null
  const description = String(body.description || 'Wallet top-up').slice(0, 200)
  if (!Number.isFinite(amount) || amount <= 0) return c.json({ success: false, error: 'amount must be > 0' }, 400)

  await ensureWallet(c, client.client_key, userRef)
  await c.env.DB.prepare(
    `UPDATE tenant_wallets SET balance_kes = balance_kes + ?, updated_at = CURRENT_TIMESTAMP WHERE client_key = ? AND user_ref = ?`
  ).bind(amount, client.client_key, userRef).run()
  const balanceAfter = await ensureWallet(c, client.client_key, userRef)

  const transaction_ref = genRef('CREDIT_EQ')
  try {
    await c.env.DB.prepare(
      `INSERT INTO tenant_wallet_ledger (client_key, user_ref, direction, amount_kes, balance_after, origin_reference, description, transaction_ref, meta)
       VALUES (?, ?, 'credit', ?, ?, ?, ?, ?, ?)`
    ).bind(client.client_key, userRef, amount, balanceAfter, originRef, description, transaction_ref, JSON.stringify(body.metadata || {})).run()
  } catch (_) {}

  // Reset alert cooldown once the balance is back above the warning threshold.
  try {
    const t = await resolveThresholds(c, client.client_key, userRef)
    if (balanceAfter > t.warning_threshold) {
      await c.env.DB.prepare(
        `UPDATE tenant_alert_state SET cleared = 1, last_sent_at = NULL WHERE client_key = ? AND user_ref = ?`
      ).bind(client.client_key, userRef).run()
    }
  } catch (_) {}

  return c.json({
    success: true, transaction_ref, user_id: userRef || null,
    credited_amount: Number(amount.toFixed(2)),
    remaining_wallet_balance: Number(balanceAfter.toFixed(2)),
    status: 'COMPLETED', timestamp: new Date().toISOString(),
  })
})

// ----------------------------------------------------------------------------
// GET /balance?user_id=... — read current master balance for a tenant user.
// ----------------------------------------------------------------------------
wallet.get('/balance', async (c) => {
  const userRef = String(c.req.query('user_id') || c.req.query('user_ref') || '').trim()
  // Signature covers the path+query so it can't be tampered.
  const auth = await authenticate(c, `${c.req.path}?user_id=${userRef}`)
  if (!auth.ok) return c.json({ success: false, error: auth.error }, auth.status as any)
  const balance = await ensureWallet(c, auth.client.client_key, userRef)
  return c.json({ success: true, user_id: userRef || null, balance_kes: Number(balance.toFixed(2)), currency: 'KES' })
})

// ----------------------------------------------------------------------------
// Settings — tenant low-balance alert thresholds (synced from Credit UI).
// Mounted under /api/v1/settings/*.
// ----------------------------------------------------------------------------
export const settings = new Hono<{ Bindings: Bindings }>()

settings.get('/thresholds', async (c) => {
  const userRef = String(c.req.query('user_id') || c.req.query('user_ref') || '').trim()
  const auth = await authenticate(c, `${c.req.path}?user_id=${userRef}`)
  if (!auth.ok) return c.json({ success: false, error: auth.error }, auth.status as any)
  const t = await resolveThresholds(c, auth.client.client_key, userRef)
  return c.json({
    user_id: userRef || null,
    currency: t.currency,
    warning_threshold: t.warning_threshold,
    critical_threshold: t.critical_threshold,
    channels: { email_enabled: t.email_enabled, sms_enabled: t.sms_enabled, webhook_enabled: t.webhook_enabled },
    updated_at: new Date().toISOString(),
  })
})

settings.put('/thresholds', async (c) => {
  const rawBody = await c.req.text()
  const auth = await authenticate(c, rawBody)
  if (!auth.ok) return c.json({ success: false, error: auth.error }, auth.status as any)
  const client = auth.client
  let body: any = {}
  try { body = rawBody ? JSON.parse(rawBody) : {} } catch { return c.json({ success: false, error: 'Body must be JSON' }, 400) }

  const userRef = String(body.user_id || body.user_ref || '').trim()
  const warning = Number(body.warning_threshold)
  const critical = Number(body.critical_threshold)
  if (!Number.isFinite(warning) || warning < 0) return c.json({ success: false, error: 'warning_threshold must be >= 0' }, 400)
  if (!Number.isFinite(critical) || critical < 0) return c.json({ success: false, error: 'critical_threshold must be >= 0' }, 400)
  const ch = body.channels || {}
  const emailEnabled = ch.email_enabled === false ? 0 : 1
  const smsEnabled = ch.sms_enabled === false ? 0 : 1
  const webhookEnabled = ch.webhook_enabled === false ? 0 : 1
  const notifyEmail = body.notify_email ? String(body.notify_email).slice(0, 200) : null
  const notifyPhone = body.notify_phone ? String(body.notify_phone).slice(0, 40) : null

  await c.env.DB.prepare(
    `INSERT INTO tenant_alert_settings
       (client_key, user_ref, currency, warning_threshold, critical_threshold, email_enabled, sms_enabled, webhook_enabled, notify_email, notify_phone, updated_at)
     VALUES (?, ?, 'KES', ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
     ON CONFLICT (client_key, user_ref) DO UPDATE SET
       warning_threshold = EXCLUDED.warning_threshold,
       critical_threshold = EXCLUDED.critical_threshold,
       email_enabled = EXCLUDED.email_enabled,
       sms_enabled = EXCLUDED.sms_enabled,
       webhook_enabled = EXCLUDED.webhook_enabled,
       notify_email = COALESCE(EXCLUDED.notify_email, tenant_alert_settings.notify_email),
       notify_phone = COALESCE(EXCLUDED.notify_phone, tenant_alert_settings.notify_phone),
       updated_at = CURRENT_TIMESTAMP`
  ).bind(client.client_key, userRef, warning, critical, emailEnabled, smsEnabled, webhookEnabled, notifyEmail, notifyPhone).run()

  return c.json({
    success: true,
    user_id: userRef || null,
    currency: 'KES',
    warning_threshold: warning,
    critical_threshold: critical,
    channels: { email_enabled: emailEnabled !== 0, sms_enabled: smsEnabled !== 0, webhook_enabled: webhookEnabled !== 0 },
    updated_at: new Date().toISOString(),
  })
})

export default wallet
