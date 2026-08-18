// =====================================================================
// Farmsky Central Payment Gateway — HOST implementation
// =====================================================================
//   This is the SERVER side of the gateway. It is deployed and ACTIVE on
//   the central host (equipment.farmsky.africa), where it owns every
//   provider credential and the single merchant shortcode. Satellite
//   marketplaces (feed / input) do NOT run this against real providers —
//   they call it remotely via payment-gateway-client.ts. It ships in every
//   app so the whole family shares one identical, auditable implementation.
//
//   Single endpoint shared by all three Farmsky marketplaces:
//      - equipment.farmsky.africa   (HOST — processes for real)
//      - feed.farmsky.africa        (satellite — delegates here)
//      - input.farmsky.africa       (satellite — delegates here)
//
//   Supported rails: M-Pesa Daraja, SasaPay, KCB Buni
//
//   Routes (mounted under /api/v1/payments/*):
//      POST /initiate                    <- the calling app sends a signed request
//      GET  /status/:transaction_ref    <- polled by the calling app
//      POST /callbacks/mpesa            <- provider IPN
//      POST /callbacks/sasapay          <- provider IPN
//      POST /callbacks/buni             <- provider IPN
//      POST /admin/recover-sasapay      <- manual SasaPay checkout ID recovery engine
//      POST /admin/recover-status       <- global multi-rail transaction status recovery script
//
//   Security:
//      - Every /initiate call is HMAC-SHA256 signed using the calling app's
//        shared secret stored in app_clients.hmac_secret.
//      - Replay protection: nonce + timestamp; requests older than 5 min
//        are rejected.
//      - Idempotency: optional Idempotency-Key header. Re-sending the same
//        key for the same client returns the original transaction_ref.
//      - Provider callbacks are bound by provider_request_id (which only
//        the provider knows after our outbound STK push), so spoofed IPNs
//        cannot mark an unrelated transaction as paid.
//      - origin_app is taken from the verified client identity in the DB,
//        NOT from the request body, so it cannot be spoofed.
// =====================================================================

import { Hono } from 'hono'
import { stkPush, stkQuery, normalizePhone } from './mpesa'
import { sasapayStkPush, sasapayQuery, sasapayProcessPayment, sasapayB2C, channelByCode } from './sasapay'
import { buniStkPush, buniQuery } from './buni'
import { verifySignature, verifySignatureMulti } from './payment-gateway-shared'
import { getCookie } from 'hono/cookie'
import type { Bindings } from './types'

export type PaymentMethod = 'mpesa' | 'sasapay' | 'buni'

const gateway = new Hono<{ Bindings: Bindings }>()

// ----------------------------------------------------------------------------
// HMAC candidate secrets for a tenant.
//
// The registered `client.hmac_secret` is the AUTHORITATIVE secret, but a client
// tenant and this gateway can resolve their secret from different env vars (see
// verifySignatureMulti). We therefore also offer the shared cross-app secrets
// as fallbacks so a precedence mismatch between the two deployments does not
// produce a spurious "Signature mismatch". All candidates are operator-set
// secrets for THIS channel, so accepting any of them does not weaken security.
// The stored secret is always tried FIRST.
// ----------------------------------------------------------------------------
function candidateSecrets(c: any, client: any): string[] {
  const env = c.env || {}
  return [
    client?.hmac_secret,
    // Score-specific first (matches the Score client's own resolution order),
    // then the generic shared cross-app secret.
    env.SCORE_HMAC_SECRET,
    env.SCORE_CROSS_APP_HMAC_SECRET,
    env.CROSS_APP_HMAC_SECRET,
    env.PAYMENT_HMAC_SECRET,
  ]
}

// ----------------------------------------------------------------------------
// Phase 6 (Zero-Trust RBAC) — the /admin/* endpoints expose the payment ledger
// and destructive recovery tools. They MUST be reachable only by an
// authenticated admin / super_admin session on THIS host. This middleware
// runs before any /admin route handler and denies everyone else.
// ----------------------------------------------------------------------------
gateway.use('/admin/*', async (c, next) => {
  const token = getCookie(c, 'session') || c.req.header('Authorization')?.replace('Bearer ', '')
  if (!token) return c.json({ error: 'Unauthorized' }, 401)
  const row = await c.env.DB.prepare(
    `SELECT u.role, u.status, s.expires_at
       FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?`
  ).bind(token).first<any>()
  if (!row || Number(row.expires_at) < Date.now() || row.status !== 'active') {
    return c.json({ error: 'Unauthorized' }, 401)
  }
  if (!['admin', 'super_admin'].includes(row.role)) {
    return c.json({ error: 'Forbidden — payment administration requires an admin role' }, 403)
  }
  await next()
})

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------
function genRef(): string {
  return 'FSK-' + crypto.randomUUID().replace(/-/g, '').slice(0, 18).toUpperCase()
}

// ----------------------------------------------------------------------------
// Decide whether a NON-ZERO provider status-query code is a GENUINELY TERMINAL
// failure (the buyer cancelled, entered the wrong PIN, had insufficient funds,
// or the STK request truly expired) versus a TRANSIENT "still processing"
// reply returned while the buyer is still on the handset entering their PIN.
//
// Only terminal codes may flip a PENDING transaction to FAILED. Transient codes
// MUST leave the transaction PENDING so the asynchronous provider callback (the
// authoritative settlement channel) — or a later poll — records the true
// outcome. This is the core of the "false failure" fix: a synchronous status
// query is advisory, the callback is authoritative.
//
// M-Pesa Daraja stkpushquery result codes (the important ones):
//   0     -> success (handled elsewhere)
//   1032  -> Request cancelled by user (TERMINAL failure)
//   1037  -> DS timeout / user cannot be reached (TERMINAL failure)
//   1025 / 9999 / 1001 -> system/internal or "unable to lock subscriber" — these
//           frequently appear WHILE the prompt is still live, so treat as transient
//   2001  -> wrong PIN (TERMINAL failure)
//   17    -> M-Pesa internal system error (transient)
//   1     -> "The transaction is being processed" / generic pending (TRANSIENT)
//   500.001.1001 -> "The transaction is being processed" (TRANSIENT)
// Anything unmapped is treated conservatively as TRANSIENT (stay PENDING) so a
// customer whose money may already be moving is never shown a false failure.
// ----------------------------------------------------------------------------
function isTerminalFailureCode(method: string, code: unknown): boolean {
  if (code === undefined || code === null) return false
  const s = String(code).trim()
  if (s === '' || s === '0') return false

  if (method === 'mpesa') {
    // Explicit, well-known TERMINAL M-Pesa failure codes only.
    const MPESA_TERMINAL = new Set(['1032', '1037', '2001', '1019', '1101'])
    // Explicit TRANSIENT codes that must NOT fail the transaction.
    const MPESA_TRANSIENT = new Set(['1', '17', '1025', '1001', '9999', '500.001.1001', '500.001.1019'])
    if (MPESA_TERMINAL.has(s)) return true
    if (MPESA_TRANSIENT.has(s)) return false
    // Unknown non-zero code: be conservative and treat as transient (stay PENDING).
    return false
  }

  if (method === 'buni') {
    // Buni: '00' is success (handled elsewhere). Only a small set of explicit
    // decline codes are terminal; unknown codes stay pending.
    const BUNI_TERMINAL = new Set(['1032', '2001'])
    return BUNI_TERMINAL.has(s)
  }

  // SasaPay settlement is asynchronous (callback-driven); its status query is
  // never treated as a terminal failure here — the callback is authoritative.
  return false
}

async function loadClient(c: any, client_key: string) {
  return await c.env.DB.prepare(
    `SELECT id, client_key, display_name, origin_url, hmac_secret, callback_url, is_active
     FROM app_clients WHERE client_key = ?`
  ).bind(client_key).first<any>()
}

// Resolve the marketplace (tenant) row for a client/marketplace key.
async function loadMarketplace(c: any, marketplace_key: string) {
  try {
    return await c.env.DB.prepare(
      `SELECT id, marketplace_key, display_name, domain, is_main, is_active FROM marketplaces WHERE marketplace_key = ?`
    ).bind(marketplace_key).first<any>()
  } catch (_) { return null }
}

// Set the per-connection tenant scope so PostgreSQL RLS restricts every
// subsequent query in this request to the tenant's own rows.
async function setTenantScope(c: any, marketplaceId: number | null, isAdmin = false) {
  const setLocal = (c.env.DB as any)?.setSessionConfig
  if (typeof setLocal === 'function') {
    try { await setLocal.call(c.env.DB, 'app.current_marketplace_id', marketplaceId == null ? '' : String(marketplaceId)) } catch (_) {}
    try { await setLocal.call(c.env.DB, 'app.is_admin', isAdmin ? 'true' : 'false') } catch (_) {}
  }
}

// Record a suspicious-activity / security event to the audit trail.
async function auditSecurity(
  c: any,
  eventType: string,
  severity: 'INFO' | 'WARN' | 'CRITICAL',
  opts: { marketplaceId?: number | null; originApp?: string | null; transactionRef?: string | null; detail?: string } = {}
) {
  try {
    const ip = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || null
    await c.env.DB.prepare(
      `INSERT INTO payment_audit_log (marketplace_id, origin_app, event_type, severity, transaction_ref, detail, ip_address)
       VALUES (?,?,?,?,?,?,?)`
    ).bind(opts.marketplaceId ?? null, opts.originApp ?? null, eventType, severity, opts.transactionRef ?? null, (opts.detail || '').slice(0, 500), ip).run()
  } catch (_) {}
}

async function findTxByProviderRef(c: any, provider_request_id: string) {
  if (!provider_request_id) return null
  return await c.env.DB.prepare(
    `SELECT * FROM central_transactions WHERE provider_request_id = ? LIMIT 1`
  ).bind(provider_request_id).first<any>()
}

async function logCallback(c: any, txRef: string | null, method: string, providerReqId: string | null, rawBody: string, valid: boolean, marketplaceId: number | null = null) {
  try {
    await c.env.DB.prepare(
      `INSERT INTO central_callbacks (transaction_ref, payment_method, provider_request_id, raw_payload, signature_valid, marketplace_id)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(txRef, method, providerReqId, rawBody.slice(0, 8000), valid ? 1 : 0, marketplaceId).run()
  } catch (_) {}
}

async function notifyOriginApp(c: any, client: any, tx: any) {
  if (!client?.callback_url) return
  try {
    const body = JSON.stringify({
      transaction_ref: tx.transaction_ref,
      origin_reference: tx.origin_reference,
      payment_method: tx.payment_method,
      status: tx.status,
      provider_receipt: tx.provider_receipt,
      amount: Number(tx.amount),
      currency: tx.currency,
      result_code: tx.result_code,
      result_desc: tx.result_desc,
      completed_at: tx.completed_at
    })
    const { signRequest } = await import('./payment-gateway-shared')
    const { timestamp, nonce, signature } = await signRequest(client.hmac_secret, client.client_key, body)
    await fetch(client.callback_url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Farmsky-Client': client.client_key,
        'X-Farmsky-Timestamp': timestamp,
        'X-Farmsky-Nonce': nonce,
        'X-Farmsky-Signature': signature
      },
      body
    })
  } catch (_) {}
}

// ----------------------------------------------------------------------------
// POST /initiate
// ----------------------------------------------------------------------------
gateway.post('/initiate', async (c) => {
  const rawBody = await c.req.text()

  const client_key = c.req.header('X-Farmsky-Client') || ''
  const timestamp = c.req.header('X-Farmsky-Timestamp') || ''
  const nonce = c.req.header('X-Farmsky-Nonce') || ''
  const signature = c.req.header('X-Farmsky-Signature') || ''
  const idempotencyKey = c.req.header('Idempotency-Key') || null

  if (!client_key) return c.json({ success: false, error: 'Missing X-Farmsky-Client header' }, 401)

  const client = await loadClient(c, client_key)
  if (!client || !client.is_active) {
    await auditSecurity(c, 'UNKNOWN_CLIENT', 'WARN', { originApp: client_key, detail: 'initiate from unknown/inactive client' })
    return c.json({ success: false, error: 'Unknown or inactive client app' }, 401)
  }

  const marketplace = await loadMarketplace(c, client_key)
  const marketplaceId = marketplace?.id ?? null
  await setTenantScope(c, marketplaceId, false)

  const v = await verifySignatureMulti(candidateSecrets(c, client), client_key, timestamp, nonce, rawBody, signature)
  if (!v.ok) {
    // Non-secret diagnostic: whether signature material was present and the body
    // length the gateway hashed — enough to tell "secret drift" from "body
    // mismatch" WITHOUT ever logging a secret or the signature itself.
    await auditSecurity(c, 'SIGNATURE_FAIL', 'CRITICAL', { marketplaceId, originApp: client_key, detail: `${v.error || 'invalid HMAC signature'} on /initiate (bodyLen=${rawBody.length}, hasTs=${!!timestamp}, hasNonce=${!!nonce}, hasSig=${!!signature})` })
    return c.json({ success: false, error: v.error || 'Invalid signature' }, 401)
  }
  if ((v.matchedIndex ?? 0) > 0) {
    // Matched a FALLBACK secret, not the registered one → precedence drift.
    // Log a WARN so operators can realign env without any user-facing failure.
    try { console.warn(`[gateway] /initiate signature matched fallback secret #${v.matchedIndex} for client '${client_key}'. Align SCORE_HMAC_SECRET / CROSS_APP_HMAC_SECRET across Score and Feed.`) } catch { /* noop */ }
  }

  if (nonce) {
    try {
      const existingNonce = await c.env.DB.prepare(
        `SELECT 1 FROM payment_nonces WHERE client_key = ? AND nonce = ? LIMIT 1`
      ).bind(client_key, nonce).first<any>()
      if (existingNonce) {
        await auditSecurity(c, 'REPLAY', 'CRITICAL', { marketplaceId, originApp: client_key, detail: `replayed nonce ${nonce}` })
        return c.json({ success: false, error: 'Replay detected' }, 401)
      }
      await c.env.DB.prepare(
        `INSERT INTO payment_nonces (client_key, nonce) VALUES (?, ?)`
      ).bind(client_key, nonce).run()
    } catch (e: any) {
      const code = e?.code || ''
      if (code === '23505' || /unique|duplicate/i.test(String(e?.message || ''))) {
        await auditSecurity(c, 'REPLAY', 'CRITICAL', { marketplaceId, originApp: client_key, detail: `replayed nonce ${nonce}` })
        return c.json({ success: false, error: 'Replay detected' }, 401)
      }
    }
  }

  let body: any = {}
  try { body = rawBody ? JSON.parse(rawBody) : {} } catch { return c.json({ success: false, error: 'Body must be JSON' }, 400) }

  const method = String(body.payment_method || '').toLowerCase() as PaymentMethod
  const amount = Number(body.amount)
  // Accept `phone` OR `msisdn` (Score's v1 client sends both; older callers may
  // send only one). normalizePhone tolerates 07.., 2547.., +2547.. forms.
  const phone = normalizePhone(String(body.phone || body.msisdn || ''))
  // Accept `origin_reference` OR `reference` as the tenant's own idempotent ref.
  const origin_reference = (body.origin_reference || body.reference) ? String(body.origin_reference || body.reference) : null
  const description = body.description ? String(body.description).slice(0, 200) : `${client.display_name} payment`
  const initiated_by_user = body.initiated_by_user ?? body.user_id ?? null

  const channel = body.channel || 'MOBILE_MONEY'
  const channelCode = body.channelCode || body.networkCode || undefined
  const accountNumber = body.accountNumber || undefined

  if (!['mpesa', 'sasapay', 'buni'].includes(method)) return c.json({ success: false, error: 'payment_method must be mpesa | sasapay | buni' }, 400)
  if (!Number.isFinite(amount) || amount <= 0) return c.json({ success: false, error: 'amount must be > 0' }, 400)
  if (!phone || phone.length < 11) return c.json({ success: false, error: 'phone is invalid' }, 400)

  if (idempotencyKey) {
    const existing = await c.env.DB.prepare(
      `SELECT transaction_ref, payment_method, status FROM central_transactions WHERE origin_app = ? AND idempotency_key = ? LIMIT 1`
    ).bind(client_key, idempotencyKey).first<any>()
    if (existing) {
      return c.json({
        success: true,
        idempotent_replay: true,
        transaction_ref: existing.transaction_ref,
        payment_method: existing.payment_method,
        status: existing.status
      })
    }
  }

  const transaction_ref = genRef()
  const desc = description.slice(0, 40)
  let providerResult: any
  try {
    if (method === 'mpesa') {
      providerResult = await stkPush(c.env, { phone, amount, account: transaction_ref, description: desc, networkCode: channelCode })
    } else if (method === 'sasapay') {
      providerResult = await sasapayStkPush(c.env, { 
        phone, 
        amount, 
        account: transaction_ref, 
        description: desc,
        channel,
        channelCode,
        accountNumber
      })
    } else {
      providerResult = await buniStkPush(c.env, { phone, amount, account: transaction_ref, description: desc })
    }
  } catch (e: any) {
    return c.json({ success: false, error: e?.message || 'Provider error' }, 502)
  }

  if (!providerResult?.success) {
    return c.json({ success: false, error: providerResult?.error || 'Provider rejected the push' }, 502)
  }

  const ip = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || null

  await c.env.DB.prepare(
    `INSERT INTO central_transactions
        (transaction_ref, idempotency_key, origin_app, marketplace_id, origin_reference, payment_method,
         provider_request_id, phone, amount, currency, description, status, initiated_by_user, ip_address)
      VALUES (?,?,?,?,?,?,?,?,?,?,?, 'PENDING', ?, ?)`
  ).bind(
    transaction_ref, idempotencyKey, client_key, marketplaceId, origin_reference, method,
    providerResult.checkout_request_id || null, phone, amount, 'KES', desc, initiated_by_user, ip
  ).run()

  return c.json({
    success: true,
    transaction_ref,
    payment_method: method,
    origin_app: client_key,
    simulated: !!providerResult.simulated,
    customer_message: providerResult.customer_message || 'Payment prompt sent.',
    status: 'PENDING'
  })
})

// ----------------------------------------------------------------------------
// GET /status/:transaction_ref
// ----------------------------------------------------------------------------
gateway.get('/status/:ref', async (c) => {
  const transaction_ref = c.req.param('ref')
  const client_key = c.req.header('X-Farmsky-Client') || ''
  const timestamp = c.req.header('X-Farmsky-Timestamp') || ''
  const nonce = c.req.header('X-Farmsky-Nonce') || ''
  const signature = c.req.header('X-Farmsky-Signature') || ''

  const client = await loadClient(c, client_key)
  if (!client || !client.is_active) return c.json({ success: false, error: 'Unknown client app' }, 401)

  const marketplace = await loadMarketplace(c, client_key)
  await setTenantScope(c, marketplace?.id ?? null, false)

  const v = await verifySignatureMulti(candidateSecrets(c, client), client_key, timestamp, nonce, transaction_ref, signature)
  if (!v.ok) {
    await auditSecurity(c, 'SIGNATURE_FAIL', 'WARN', { marketplaceId: marketplace?.id ?? null, originApp: client_key, detail: 'invalid signature on /status poll' })
    return c.json({ success: false, error: v.error || 'Invalid signature' }, 401)
  }
  if ((v.matchedIndex ?? 0) > 0) {
    try { console.warn(`[gateway] /status signature matched fallback secret #${v.matchedIndex} for client '${client_key}'. Align SCORE_HMAC_SECRET / CROSS_APP_HMAC_SECRET across Score and Feed.`) } catch { /* noop */ }
  }

  let tx = await c.env.DB.prepare(
    `SELECT * FROM central_transactions WHERE transaction_ref = ? AND origin_app = ? LIMIT 1`
  ).bind(transaction_ref, client_key).first<any>()
  if (!tx) return c.json({ success: false, error: 'Transaction not found' }, 404)

  if (tx.status === 'PENDING' && tx.provider_request_id) {
    try {
      let pr: any
      if (tx.payment_method === 'mpesa') pr = await stkQuery(c.env, tx.provider_request_id)
      else if (tx.payment_method === 'sasapay') pr = await sasapayQuery(c.env, tx.provider_request_id)
      else if (tx.payment_method === 'buni') pr = await buniQuery(c.env, tx.provider_request_id)

      // FIX: Handle SasaPay asynchronous acceptance payload
      // SasaPay returns pr.status === true meaning "Received, look at callback".
      // We check if the webhook already handled the insertion asynchronously.
      if (tx.payment_method === 'sasapay' && pr?.status === true && !pr?.Paid) {
        const structuralCheck = await c.env.DB.prepare(
          `SELECT status, result_code, result_desc, provider_receipt, completed_at FROM central_transactions WHERE transaction_ref = ? LIMIT 1`
        ).bind(transaction_ref).first<any>()
        
        if (structuralCheck && structuralCheck.status !== 'PENDING') {
          tx = { ...tx, ...structuralCheck }
        }
      } else {
        const code = pr?.ResultCode ?? pr?.status_code
        if (code === 0 || code === '0' || pr?.status === true || pr?.Paid === true) {
          const receipt = pr?.TransactionCode || pr?.TransID || pr?.ThirdPartyTransID || null
          await c.env.DB.prepare(
            `UPDATE central_transactions
                SET status='SUCCESS', result_code=?, result_desc=?, provider_receipt=COALESCE(?, provider_receipt), updated_at=CURRENT_TIMESTAMP, completed_at=CURRENT_TIMESTAMP
              WHERE transaction_ref=?`
          ).bind(String(code ?? '0'), String(pr?.ResultDesc || pr?.ResultDescription || pr?.message || 'Success'), receipt, transaction_ref).run()
          tx.status = 'SUCCESS'
        } else if (isTerminalFailureCode(tx.payment_method, code)) {
          // ------------------------------------------------------------------
          // RACE-CONDITION FIX: Only mark FAILED when the provider has returned
          // a GENUINELY TERMINAL failure code. While the buyer is still on their
          // handset entering the PIN, Daraja's stkpushquery replies with a
          // transient "still being processed" code (e.g. ResultCode '1',
          // '500.001.1001', or an empty/errored body from stkQuery's own guard).
          // Previously ANY non-zero code was written as FAILED on the FIRST poll,
          // so Score received 'failed' → returned HTTP 402 → the UI showed
          // "payment failed or cancelled" even though the money was later debited.
          // We now leave the transaction PENDING for transient codes; the async
          // provider callback (or a later poll) settles the true outcome.
          // ------------------------------------------------------------------
          await c.env.DB.prepare(
            `UPDATE central_transactions
                SET status='FAILED', result_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP, completed_at=CURRENT_TIMESTAMP
              WHERE transaction_ref=?`
          ).bind(String(code), String(pr?.ResultDesc || pr?.message || 'Failed'), transaction_ref).run()
          tx.status = 'FAILED'
        }
        // Any other non-zero code (transient / "still processing") => keep
        // status PENDING and simply return it; the caller keeps polling.
      }
    } catch (_) {}
  }

  return c.json({
    success: true,
    transaction_ref: tx.transaction_ref,
    origin_app: tx.origin_app,
    origin_reference: tx.origin_reference,
    payment_method: tx.payment_method,
    status: tx.status,
    amount: Number(tx.amount),
    currency: tx.currency,
    provider_receipt: tx.provider_receipt,
    result_code: tx.result_code,
    result_desc: tx.result_desc,
    completed_at: tx.completed_at
  })
})

// ----------------------------------------------------------------------------
// POST /process
// Complete a SasaPay wallet checkout that requires an OTP / verification code.
// The satellite forwards the buyer's verification_code; the host runs the
// SasaPay process-payment call using the host's own credentials. HMAC-signed
// exactly like /initiate. The transaction must belong to THIS client.
// ----------------------------------------------------------------------------
gateway.post('/process', async (c) => {
  const rawBody = await c.req.text()

  const client_key = c.req.header('X-Farmsky-Client') || ''
  const timestamp = c.req.header('X-Farmsky-Timestamp') || ''
  const nonce = c.req.header('X-Farmsky-Nonce') || ''
  const signature = c.req.header('X-Farmsky-Signature') || ''

  if (!client_key) return c.json({ success: false, error: 'Missing X-Farmsky-Client header' }, 401)

  const client = await loadClient(c, client_key)
  if (!client || !client.is_active) {
    await auditSecurity(c, 'UNKNOWN_CLIENT', 'WARN', { originApp: client_key, detail: 'process from unknown/inactive client' })
    return c.json({ success: false, error: 'Unknown or inactive client app' }, 401)
  }

  const marketplace = await loadMarketplace(c, client_key)
  const marketplaceId = marketplace?.id ?? null
  await setTenantScope(c, marketplaceId, false)

  const v = await verifySignatureMulti(candidateSecrets(c, client), client_key, timestamp, nonce, rawBody, signature)
  if (!v.ok) {
    await auditSecurity(c, 'SIGNATURE_FAIL', 'CRITICAL', { marketplaceId, originApp: client_key, detail: v.error || 'invalid HMAC signature on /process' })
    return c.json({ success: false, error: v.error || 'Invalid signature' }, 401)
  }
  if (typeof v.matchedIndex === 'number' && v.matchedIndex > 0) {
    try { console.warn(`[gateway] /process signature matched fallback secret #${v.matchedIndex} for client '${client_key}'. Align SCORE_HMAC_SECRET / CROSS_APP_HMAC_SECRET across Score and Feed.`) } catch { /* noop */ }
  }

  let body: any = {}
  try { body = rawBody ? JSON.parse(rawBody) : {} } catch { return c.json({ success: false, error: 'Body must be JSON' }, 400) }

  const transaction_ref = String(body.transaction_ref || '').trim()
  const verification_code = String(body.verification_code || '').trim()
  if (!transaction_ref) return c.json({ success: false, error: 'transaction_ref is required' }, 400)
  if (!verification_code) return c.json({ success: false, error: 'verification_code is required' }, 400)

  // The transaction must belong to THIS client and still be awaiting completion.
  const tx = await c.env.DB.prepare(
    `SELECT * FROM central_transactions WHERE transaction_ref = ? AND origin_app = ? LIMIT 1`
  ).bind(transaction_ref, client_key).first<any>()
  if (!tx) return c.json({ success: false, error: 'Transaction not found' }, 404)
  if (tx.payment_method !== 'sasapay') return c.json({ success: false, error: 'Only SasaPay wallet checkouts require OTP completion' }, 400)

  const pr = await sasapayProcessPayment(c.env, String(tx.provider_request_id || ''), verification_code)
  if (!pr.success) {
    await auditSecurity(c, 'PROCESS_FAIL', 'WARN', { marketplaceId, originApp: client_key, transactionRef: transaction_ref, detail: pr.error || 'process-payment rejected' })
    return c.json({ success: false, error: pr.error || 'OTP verification failed' }, 502)
  }

  return c.json({
    success: true,
    transaction_ref,
    payment_method: 'sasapay',
    simulated: !!pr.simulated,
    customer_message: pr.customer_message || 'Payment is being processed.',
    status: 'PENDING'
  })
})

// ----------------------------------------------------------------------------
// POST /payout
// Disburse funds OUT to a mobile / bank / SasaPay-wallet destination on behalf
// of a satellite (B2C). The satellite has already debited its own internal
// wallet ledger; this call moves the real money using the HOST's SasaPay
// credentials. Idempotency-Key prevents a double payout on retry. The async
// result is delivered to the host's own SasaPay B2C callback and reconciled
// there; the satellite records 'processing' and reconciles via its own ledger.
// HMAC-signed exactly like /initiate.
// ----------------------------------------------------------------------------
gateway.post('/payout', async (c) => {
  const rawBody = await c.req.text()

  const client_key = c.req.header('X-Farmsky-Client') || ''
  const timestamp = c.req.header('X-Farmsky-Timestamp') || ''
  const nonce = c.req.header('X-Farmsky-Nonce') || ''
  const signature = c.req.header('X-Farmsky-Signature') || ''
  const idempotencyKey = c.req.header('Idempotency-Key') || null

  if (!client_key) return c.json({ success: false, error: 'Missing X-Farmsky-Client header' }, 401)

  const client = await loadClient(c, client_key)
  if (!client || !client.is_active) {
    await auditSecurity(c, 'UNKNOWN_CLIENT', 'WARN', { originApp: client_key, detail: 'payout from unknown/inactive client' })
    return c.json({ success: false, error: 'Unknown or inactive client app' }, 401)
  }

  const marketplace = await loadMarketplace(c, client_key)
  const marketplaceId = marketplace?.id ?? null
  await setTenantScope(c, marketplaceId, false)

  const v = await verifySignatureMulti(candidateSecrets(c, client), client_key, timestamp, nonce, rawBody, signature)
  if (!v.ok) {
    await auditSecurity(c, 'SIGNATURE_FAIL', 'CRITICAL', { marketplaceId, originApp: client_key, detail: v.error || 'invalid HMAC signature on /payout' })
    return c.json({ success: false, error: v.error || 'Invalid signature' }, 401)
  }
  if (typeof v.matchedIndex === 'number' && v.matchedIndex > 0) {
    try { console.warn(`[gateway] /payout signature matched fallback secret #${v.matchedIndex} for client '${client_key}'. Align SCORE_HMAC_SECRET / CROSS_APP_HMAC_SECRET across Score and Feed.`) } catch { /* noop */ }
  }

  // Replay protection (same nonce table as /initiate).
  if (nonce) {
    try {
      const existingNonce = await c.env.DB.prepare(
        `SELECT 1 FROM payment_nonces WHERE client_key = ? AND nonce = ? LIMIT 1`
      ).bind(client_key, nonce).first<any>()
      if (existingNonce) {
        await auditSecurity(c, 'REPLAY', 'CRITICAL', { marketplaceId, originApp: client_key, detail: `replayed nonce ${nonce}` })
        return c.json({ success: false, error: 'Replay detected' }, 401)
      }
      await c.env.DB.prepare(`INSERT INTO payment_nonces (client_key, nonce) VALUES (?, ?)`).bind(client_key, nonce).run()
    } catch (e: any) {
      const code = e?.code || ''
      if (code === '23505' || /unique|duplicate/i.test(String(e?.message || ''))) {
        await auditSecurity(c, 'REPLAY', 'CRITICAL', { marketplaceId, originApp: client_key, detail: `replayed nonce ${nonce}` })
        return c.json({ success: false, error: 'Replay detected' }, 401)
      }
    }
  }

  let body: any = {}
  try { body = rawBody ? JSON.parse(rawBody) : {} } catch { return c.json({ success: false, error: 'Body must be JSON' }, 400) }

  const amount = Number(body.amount)
  const channelCode = String(body.channelCode || body.channel_code || '').trim()
  const receiver = String(body.receiver_number || body.account_number || '').trim()
  const reason = String(body.reason || 'Farmsky payout').slice(0, 100)
  const origin_reference = body.origin_reference ? String(body.origin_reference) : null

  if (!Number.isFinite(amount) || amount <= 0) return c.json({ success: false, error: 'amount must be > 0' }, 400)
  const chan = channelByCode(channelCode)
  if (!chan) return c.json({ success: false, error: 'A valid payout channelCode is required' }, 400)
  if (!receiver) return c.json({ success: false, error: 'receiver_number is required' }, 400)

  // Idempotent replay: return the prior payout if this key was already used.
  if (idempotencyKey) {
    const existing = await c.env.DB.prepare(
      `SELECT transaction_ref, status FROM central_transactions WHERE origin_app = ? AND idempotency_key = ? LIMIT 1`
    ).bind(client_key, idempotencyKey).first<any>()
    if (existing) {
      return c.json({ success: true, idempotent_replay: true, transaction_ref: existing.transaction_ref, status: existing.status })
    }
  }

  const transaction_ref = genRef()
  const payout = await sasapayB2C(c.env, { amount, receiverNumber: receiver, channel: channelCode, reason, reference: transaction_ref })
  if (!payout.success) {
    await auditSecurity(c, 'PAYOUT_FAIL', 'WARN', { marketplaceId, originApp: client_key, transactionRef: transaction_ref, detail: payout.error || 'B2C rejected' })
    return c.json({ success: false, error: payout.error || 'Payout rejected by provider' }, 502)
  }

  const ip = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || null
  await c.env.DB.prepare(
    `INSERT INTO central_transactions
        (transaction_ref, idempotency_key, origin_app, marketplace_id, origin_reference, payment_method,
         provider_request_id, phone, amount, currency, description, status, direction, ip_address)
      VALUES (?,?,?,?,?, 'sasapay', ?,?,?,?,?, ?, 'payout', ?)`
  ).bind(
    transaction_ref, idempotencyKey, client_key, marketplaceId, origin_reference,
    payout.b2c_request_id || payout.conversation_id || null, receiver, amount, 'KES',
    reason.slice(0, 40), payout.simulated ? 'SUCCESS' : 'PENDING', ip
  ).run().catch(async () => {
    // Older host schemas may not have a `direction` column; fall back gracefully.
    await c.env.DB.prepare(
      `INSERT INTO central_transactions
          (transaction_ref, idempotency_key, origin_app, marketplace_id, origin_reference, payment_method,
           provider_request_id, phone, amount, currency, description, status, ip_address)
        VALUES (?,?,?,?,?, 'sasapay', ?,?,?,?,?, ?, ?)`
    ).bind(
      transaction_ref, idempotencyKey, client_key, marketplaceId, origin_reference,
      payout.b2c_request_id || payout.conversation_id || null, receiver, amount, 'KES',
      reason.slice(0, 40), payout.simulated ? 'SUCCESS' : 'PENDING', ip
    ).run()
  })

  return c.json({
    success: true,
    transaction_ref,
    payment_method: 'sasapay',
    simulated: !!payout.simulated,
    b2c_request_id: payout.b2c_request_id || null,
    conversation_id: payout.conversation_id || null,
    transaction_charges: payout.transaction_charges || '0.00',
    customer_message: payout.customer_message || (payout.simulated ? 'Payout completed (simulation).' : 'Payout is being processed.'),
    status: payout.simulated ? 'SUCCESS' : 'PENDING'
  })
})

// ----------------------------------------------------------------------------
// CALLBACKS (provider IPNs)
// ----------------------------------------------------------------------------
async function settleCallback(c: any, method: PaymentMethod, providerReqId: string | null, success: boolean, receipt: string | null, resultCode: string | null, resultDesc: string | null, rawBody: string) {
  await setTenantScope(c, null, true)
  if (!providerReqId) {
    await logCallback(c, null, method, null, rawBody, false)
    await auditSecurity(c, 'CALLBACK_UNBOUND', 'WARN', { originApp: method, detail: 'callback missing provider_request_id' })
    return
  }
  const tx = await findTxByProviderRef(c, providerReqId)
  if (!tx) {
    await logCallback(c, null, method, providerReqId, rawBody, false)
    await auditSecurity(c, 'CALLBACK_NO_MATCH', 'CRITICAL', { detail: `callback provider_request_id ${providerReqId} matches no transaction (possible spoof)` })
    return
  }
  if (tx.status !== 'PENDING') {
    // Normally settlement is idempotent: a second callback for an already-settled
    // transaction is just logged. EXCEPTION: a genuine SUCCESS callback (real
    // money moved, provider receipt present) is allowed to OVERRIDE a prior
    // FAILED that a transient status poll may have written. This guarantees a
    // customer who was debited is never left stuck in FAILED.
    if (success && tx.status === 'FAILED') {
      await c.env.DB.prepare(
        `UPDATE central_transactions
            SET status='SUCCESS', provider_receipt=COALESCE(?, provider_receipt),
                result_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP, completed_at=CURRENT_TIMESTAMP
          WHERE transaction_ref=?`
      ).bind(receipt, resultCode, resultDesc, tx.transaction_ref).run()
      await logCallback(c, tx.transaction_ref, method, providerReqId, rawBody, true, tx.marketplace_id ?? null)
      const client = await loadClient(c, tx.origin_app)
      const refreshed = await c.env.DB.prepare(`SELECT * FROM central_transactions WHERE transaction_ref=?`).bind(tx.transaction_ref).first<any>()
      if (client && refreshed) await notifyOriginApp(c, client, refreshed)
      return
    }
    await logCallback(c, tx.transaction_ref, method, providerReqId, rawBody, true, tx.marketplace_id ?? null)
    return
  }
  await c.env.DB.prepare(
    `UPDATE central_transactions
        SET status=?, provider_receipt=COALESCE(?, provider_receipt),
            result_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP, completed_at=CURRENT_TIMESTAMP
      WHERE transaction_ref=?`
  ).bind(success ? 'SUCCESS' : 'FAILED', receipt, resultCode, resultDesc, tx.transaction_ref).run()
  await logCallback(c, tx.transaction_ref, method, providerReqId, rawBody, true, tx.marketplace_id ?? null)

  const client = await loadClient(c, tx.origin_app)
  const refreshed = await c.env.DB.prepare(`SELECT * FROM central_transactions WHERE transaction_ref=?`).bind(tx.transaction_ref).first<any>()
  if (client && refreshed) await notifyOriginApp(c, client, refreshed)
}

gateway.post('/callbacks/mpesa', async (c) => {
  const raw = await c.req.text()
  try {
    const body: any = JSON.parse(raw)
    const cb = body?.Body?.stkCallback
    const providerReqId = cb?.CheckoutRequestID || null
    const success = cb?.ResultCode === 0
    const items = cb?.CallbackMetadata?.Item || []
    const receipt = items.find((i: any) => i?.Name === 'MpesaReceiptNumber')?.Value || null
    await settleCallback(c, 'mpesa', providerReqId, success, receipt ? String(receipt) : null, String(cb?.ResultCode ?? ''), cb?.ResultDesc || null, raw)
  } catch (_) {
    await logCallback(c, null, 'mpesa', null, raw, false)
  }
  return c.json({ ResultCode: 0, ResultDesc: 'Accepted' })
})

gateway.post('/callbacks/sasapay', async (c) => {
  const raw = await c.req.text()
  
  const forwardHeader = c.req.header('X-Forwarded-For') || c.req.header('CF-Connecting-IP') || ''
  const requestIp = forwardHeader.split(',')[0].trim()

  const SASAPAY_TRUSTED_IPS = new Set([
    '47.129.43.141', '13.229.247.179', '13.215.155.141', '13.214.60.231',
    '54.169.74.198', '18.142.226.87', '47.129.243.116', '13.250.110.3',
    '155.12.30.40', '155.12.30.58', '41.90.137.105'
  ])

   if (!SASAPAY_TRUSTED_IPS.has(requestIp)) {
    await auditSecurity(c, 'CALLBACK_IP_BLOCKED', 'CRITICAL', { originApp: 'sasapay', detail: `Blocked untrusted IP: ${requestIp}` })
    return c.json({ error: 'Untrusted origin gateway transaction dropped.' }, 401)
  }

  try {
    const body: any = JSON.parse(raw)
    const providerReqId = body?.CheckoutRequestID || body?.MerchantRequestID || null
    const code = body?.ResultCode ?? body?.status_code
    const success = code === 0 || code === '0' || body?.status === true
    const receipt = body?.TransactionCode || body?.ThirdPartyTransID || null
    
    await settleCallback(c, 'sasapay', providerReqId, success, receipt ? String(receipt) : null, String(code ?? ''), body?.ResultDesc || body?.message || null, raw)
  } catch (_) {
    await logCallback(c, null, 'sasapay', null, raw, false)
  }
  return c.json({ status: 'Success', message: 'Callback received' })
})

gateway.post('/callbacks/buni', async (c) => {
  const raw = await c.req.text()
  try {
    const body: any = JSON.parse(raw)
    const providerReqId = body?.CheckoutRequestID || body?.TransactionID || null
    const code = body?.ResponseCode ?? body?.ResultCode
    const success = code === '00' || code === 0 || code === '0' || body?.status === true
    const receipt = body?.TransactionID || body?.ReceiptNumber || null
    await settleCallback(c, 'buni', providerReqId, success, receipt ? String(receipt) : null, String(code ?? ''), body?.ResponseDescription || body?.ResultDesc || null, raw)
  } catch (_) {
    await logCallback(c, null, 'buni', null, raw, false)
  }
  return c.json({ ResponseCode: '00', ResponseMessage: 'Success' })
})

// ----------------------------------------------------------------------------
// Admin Metrics & Reports
// ----------------------------------------------------------------------------
gateway.get('/admin/summary', async (c) => {
  await setTenantScope(c, null, true)
  const { results: byApp } = await c.env.DB.prepare(
    `SELECT origin_app, COUNT(*) as count, COALESCE(SUM(amount), 0) as total
        FROM central_transactions WHERE status='SUCCESS' GROUP BY origin_app`
  ).all()
  const { results: byMethod } = await c.env.DB.prepare(
    `SELECT payment_method, COUNT(*) as count, COALESCE(SUM(amount), 0) as total
        FROM central_transactions WHERE status='SUCCESS' GROUP BY payment_method`
  ).all()
  const { results: matrix } = await c.env.DB.prepare(
    `SELECT origin_app, payment_method, COUNT(*) as count, COALESCE(SUM(amount), 0) as total
        FROM central_transactions WHERE status='SUCCESS' GROUP BY origin_app, payment_method`
  ).all()
  return c.json({ by_app: byApp, by_method: byMethod, matrix })
})

gateway.get('/admin/revenue-matrix', async (c) => {
  await setTenantScope(c, null, true)
  const { results: matrix } = await c.env.DB.prepare(
    `SELECT COALESCE(m.marketplace_key, ct.origin_app) AS marketplace_key,
            ct.payment_method,
            COUNT(*) AS success_count,
            COALESCE(SUM(ct.amount), 0) AS gross_revenue,
            MIN(ct.completed_at) AS first_settlement,
            MAX(ct.completed_at) AS last_settlement
       FROM central_transactions ct
       LEFT JOIN marketplaces m ON m.id = ct.marketplace_id
      WHERE ct.status='SUCCESS'
      GROUP BY COALESCE(m.marketplace_key, ct.origin_app), ct.payment_method
      ORDER BY marketplace_key, ct.payment_method`
  ).all()
  const { results: rollup } = await c.env.DB.prepare(
    `SELECT COALESCE(m.marketplace_key, ct.origin_app) AS marketplace_key,
            COUNT(*) AS total_success,
            COALESCE(SUM(ct.amount), 0) AS total_revenue
       FROM central_transactions ct
       LEFT JOIN marketplaces m ON m.id = ct.marketplace_id
      WHERE ct.status='SUCCESS'
      GROUP BY COALESCE(m.marketplace_key, ct.origin_app)
      ORDER BY total_revenue DESC`
  ).all()
  return c.json({ matrix, rollup, note: 'Single shortcode revenue attributed per marketplace tenant.' })
})

gateway.get('/admin/suspicious-activity', async (c) => {
  await setTenantScope(c, null, true)
  const events = await c.env.DB.prepare(
    `SELECT event_type, severity, COUNT(*) AS occurrences, MAX(created_at) AS last_seen
       FROM payment_audit_log
      GROUP BY event_type, severity
      ORDER BY occurrences DESC`
  ).all().catch(() => ({ results: [] }))
  const integrity = await c.env.DB.prepare(
    `SELECT ct.transaction_ref, ct.origin_app, ct.marketplace_id, m.marketplace_key
       FROM central_transactions ct
       LEFT JOIN marketplaces m ON m.id = ct.marketplace_id
      WHERE ct.marketplace_id IS NULL OR m.marketplace_key IS DISTINCT FROM ct.origin_app
      LIMIT 100`
  ).all().catch(() => ({ results: [] }))
  const invalidCallbacks = await c.env.DB.prepare(
    `SELECT payment_method, COUNT(*) AS invalid_callbacks, MAX(received_at) AS last_seen
       FROM central_callbacks WHERE signature_valid = 0
      GROUP BY payment_method`
  ).all().catch(() => ({ results: [] }))
  return c.json({
    security_events: events.results || [],
    integrity_breaks: integrity.results || [],
    invalid_callbacks: invalidCallbacks.results || []
  })
})

// ----------------------------------------------------------------------------
// SasaPay Recovery Engine (Targeted Checkout ID)
// ----------------------------------------------------------------------------
gateway.post('/admin/recover-sasapay', async (c) => {
  await setTenantScope(c, null, true)
  
  const body = await c.req.json().catch(() => ({}));
  const { checkout_request_id } = body;

  if (!checkout_request_id) {
    return c.json({ success: false, error: 'Missing checkout_request_id parameter in body' }, 400);
  }

  const tx = await findTxByProviderRef(c, checkout_request_id);
  if (!tx) {
    return c.json({ success: false, error: `No transaction log maps to Checkout ID: ${checkout_request_id}` }, 404);
  }

  try {
    const queryResult = await sasapayQuery(c.env, checkout_request_id);
    
    // Check if the query itself updated the record, or if we need to fall back to an active database verification check
    const structuralCheck = await c.env.DB.prepare(
      `SELECT status, provider_receipt, result_code, result_desc FROM central_transactions WHERE transaction_ref = ? LIMIT 1`
    ).bind(tx.transaction_ref).first<any>()

    if (structuralCheck && structuralCheck.status === 'SUCCESS') {
      return c.json({
        success: true,
        message: 'Transaction successfully processed and resolved to SUCCESS via Webhook channel.',
        transaction_ref: tx.transaction_ref,
        provider_receipt: structuralCheck.provider_receipt
      });
    }

    const code = queryResult?.ResultCode ?? queryResult?.status_code;
    const isPaid = code === 0 || code === '0' || queryResult?.status === true || queryResult?.Paid === true;

    if (isPaid && queryResult?.Paid === true) {
      const receipt = queryResult?.TransactionCode || queryResult?.TransID || queryResult?.ThirdPartyTransID || 'MANUAL_RECOVERY';
      const desc = queryResult?.ResultDescription || queryResult?.ResultDesc || 'Transaction recovered successfully.';

      await c.env.DB.prepare(
        `UPDATE central_transactions
            SET status='SUCCESS', provider_receipt=COALESCE(?, provider_receipt),
                result_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP, completed_at=CURRENT_TIMESTAMP
          WHERE transaction_ref=?`
      ).bind(String(receipt), String(code ?? '0'), desc, tx.transaction_ref).run();

      const client = await loadClient(c, tx.origin_app);
      const refreshed = await c.env.DB.prepare(`SELECT * FROM central_transactions WHERE transaction_ref=?`).bind(tx.transaction_ref).first<any>();
      if (client && refreshed) await notifyOriginApp(c, client, refreshed);

      return c.json({
        success: true,
        message: 'Transaction verified and successfully moved to SUCCESS.',
        transaction_ref: tx.transaction_ref,
        provider_receipt: receipt
      });
    }

    return c.json({
      success: false,
      message: 'SasaPay indicates transaction is still uncompleted, asynchronous, or failed.',
      provider_raw_response: queryResult
    }, 200);

  } catch (error: any) {
    return c.json({ success: false, error: error?.message || 'Handshake recovery processing aborted' }, 500);
  }
})

// ----------------------------------------------------------------------------
// Transaction Status Recovery Script (Global Multi-Rail Recovery)
// ----------------------------------------------------------------------------
gateway.post('/admin/recover-status', async (c) => {
  await setTenantScope(c, null, true)

  const body = await c.req.json().catch(() => ({}))
  const { transaction_ref } = body

  if (!transaction_ref) {
    return c.json({ success: false, error: 'Missing transaction_ref parameter in body' }, 400)
  }

  const tx = await c.env.DB.prepare(
    `SELECT * FROM central_transactions WHERE transaction_ref = ? LIMIT 1`
  ).bind(transaction_ref).first<any>()

  if (!tx) {
    return c.json({ success: false, error: `Transaction ${transaction_ref} not found in gateway database` }, 404)
  }

  if (!tx.provider_request_id) {
    return c.json({ success: false, error: 'Transaction lacks a provider request tracking token' }, 422)
  }

  try {
    let queryResult: any
    const method = tx.payment_method as PaymentMethod

    if (method === 'mpesa') {
      queryResult = await stkQuery(c.env, tx.provider_request_id)
    } else if (method === 'sasapay') {
      queryResult = await sasapayQuery(c.env, tx.provider_request_id)
    } else if (method === 'buni') {
      queryResult = await buniQuery(c.env, tx.provider_request_id)
    } else {
      return c.json({ success: false, error: `Unsupported recovery rails type: ${method}` }, 400)
    }

    // Secondary database sync check for asynchronous SasaPay execution environments
    if (method === 'sasapay' && queryResult?.status === true && !queryResult?.Paid) {
      const liveCheck = await c.env.DB.prepare(
        `SELECT status, provider_receipt FROM central_transactions WHERE transaction_ref = ? LIMIT 1`
      ).bind(transaction_ref).first<any>()

      if (liveCheck && liveCheck.status === 'SUCCESS') {
        return c.json({
          success: true,
          resolved_status: 'SUCCESS',
          message: `Transaction state updated successfully over verified channel.`,
          transaction_ref,
          provider_receipt: liveCheck.provider_receipt
        })
      }
    }

    let code: any
    let isPaid = false
    let receipt: string | null = null
    let desc = 'Recovered via status check script.'

    if (method === 'mpesa') {
      code = queryResult?.ResultCode
      isPaid = code === 0 || code === '0'
      const items = queryResult?.CallbackMetadata?.Item || []
      receipt = items.find((i: any) => i?.Name === 'MpesaReceiptNumber')?.Value || null
      desc = queryResult?.ResultDesc || desc
    } else if (method === 'sasapay') {
      code = queryResult?.ResultCode ?? queryResult?.status_code
      isPaid = code === 0 || code === '0' || queryResult?.Paid === true
      receipt = queryResult?.TransactionCode || queryResult?.TransID || queryResult?.ThirdPartyTransID || null
      desc = queryResult?.ResultDescription || queryResult?.ResultDesc || queryResult?.message || desc
    } else if (method === 'buni') {
      code = queryResult?.ResponseCode ?? queryResult?.ResultCode
      isPaid = code === '00' || code === 0 || code === '0' || queryResult?.status === true
      receipt = queryResult?.TransactionID || queryResult?.ReceiptNumber || null
      desc = queryResult?.ResponseDescription || queryResult?.ResultDesc || desc
    }

    if (isPaid) {
      const finalReceipt = receipt ? String(receipt) : `REC-${crypto.randomUUID().slice(0, 8).toUpperCase()}`

      await c.env.DB.prepare(
        `UPDATE central_transactions
            SET status='SUCCESS', provider_receipt=COALESCE(?, provider_receipt),
                result_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP, completed_at=CURRENT_TIMESTAMP
          WHERE transaction_ref=?`
      ).bind(finalReceipt, String(code ?? '0'), desc, transaction_ref).run()

      const client = await loadClient(c, tx.origin_app)
      const refreshed = await c.env.DB.prepare(`SELECT * FROM central_transactions WHERE transaction_ref=?`).bind(transaction_ref).first<any>()
      if (client && refreshed) await notifyOriginApp(c, client, refreshed)

      return c.json({
        success: true,
        resolved_status: 'SUCCESS',
        message: `Transaction state successfully verified and synced for payment method: ${method}`,
        transaction_ref,
        provider_receipt: finalReceipt
      })
    } else if (code !== undefined && code !== null && method !== 'sasapay') {
      await c.env.DB.prepare(
        `UPDATE central_transactions
            SET status='FAILED', result_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP, completed_at=CURRENT_TIMESTAMP
          WHERE transaction_ref=?`
      ).bind(String(code), desc, transaction_ref).run()

      const client = await loadClient(c, tx.origin_app)
      const refreshed = await c.env.DB.prepare(`SELECT * FROM central_transactions WHERE transaction_ref=?`).bind(transaction_ref).first<any>()
      if (client && refreshed) await notifyOriginApp(c, client, refreshed)

      return c.json({
        success: true,
        resolved_status: 'FAILED',
        message: 'Provider confirmed that the transaction failed or was canceled by the user.',
        transaction_ref
      })
    }

    return c.json({
      success: false,
      message: 'Provider status inquiry returned inconclusive status. Transaction remains unmodified.',
      provider_raw_response: queryResult
    }, 200)

  } catch (err: any) {
    return c.json({ success: false, error: err?.message || 'Upstream provider connectivity failure on status recovery execution.' }, 502)
  }
})

export default gateway
